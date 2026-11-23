using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ClosedXML.Excel;
using Microsoft.Data.Sqlite;

namespace AVAPHIScanner;

/// <summary>What one column becomes: its kind and the action the policy (or the person) chose for it.</summary>
public sealed record ColumnPlan(string Column, PhiKind Kind, ColumnAction Action);

/// <summary>What a de-identification run wrote, and how much it replaced.</summary>
public sealed class DeidentifyResult
{
    public string Output { get; set; } = "";
    /// <summary>The files written, relative to <see cref="Output"/>.</summary>
    public List<string> Files { get; } = [];
    public long Rows { get; set; }
    public Dictionary<PhiKind, int> Replaced { get; } = [];
    /// <summary>Columns left out of the copy.</summary>
    public int Dropped { get; set; }
    public List<string> Problems { get; } = [];
    public string Policy { get; set; } = "";

    public string Summary =>
        $"{Files.Count} file{(Files.Count == 1 ? "" : "s")}, {Rows} rows; replaced {Replaced.Values.Sum()} values" +
        (Replaced.Count > 0 ? " (" + string.Join(", ", Replaced.OrderByDescending(r => r.Value).Select(r => $"{r.Value} {Kinds.Label(r.Key).ToLowerInvariant()}")) + ")" : "") +
        (Dropped > 0 ? $"; {Dropped} column{(Dropped == 1 ? "" : "s")} left out" : "");
}

/// <summary>
/// Writes a de-identified copy of a project's sources into a folder: each file as the same kind of file (CSV, TSV,
/// workbook, JSON, JSON lines, text), a SQLite database as a SQLite database, and a server's tables as CSV files or one
/// SQLite database. Sources are only ever read. Amounts, codes and clinical values are copied as they are.
/// </summary>
public static class DeidentifyRun
{
    public static DeidentifyResult Run(Project project, Inventory inventory, string root, string output, byte[] key,
        Func<string, Sources.ConnectionInfo?>? connections = null, bool overwrite = false, DateOnly? today = null, CancellationToken cancel = default, IProgress<string>? progress = null)
    {
        var outFull = Path.GetFullPath(output);
        var result = new DeidentifyResult { Output = outFull, Policy = project.Policy.Describe() };
        CheckOutput(project, root, outFull);
        var d = new Deidentifier(key, project.Policy, inventory.Known, today).For(project);
        var multi = project.Sources.Count > 1;
        foreach (var source in project.Sources)
        {
            List<Dataset> datasets;
            try { datasets = Sources.Expand(source, root, connections, outFull); }
            catch (Exception e) when (e is IOException or InvalidOperationException or ArgumentException or System.Data.Common.DbException)
            {
                result.Problems.Add($"Source {source.Id}: {Scanner.Safe(e)}");
                continue;
            }
            foreach (var group in datasets.GroupBy(x => (x.Location, x.FilePath)))
            {
                cancel.ThrowIfCancellationRequested();
                var first = group.First();
                var rel = OutputPath(source, first, multi, project.Policy.DatabaseOutput);
                var target = Path.Combine(outFull, rel);
                progress?.Report($"Writing {Mask.Label(rel)}…");
                try
                {
                    if (first.FilePath is { } src && Path.GetFullPath(src) == Path.GetFullPath(target))
                        throw new IOException("The copy would go over its source.");
                    if (!overwrite && File.Exists(target) && first.Format != SourceFormat.Database)
                        throw new IOException($"{Mask.Label(rel)} exists in the output folder; choose an empty folder, or allow overwriting.");
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    switch (first.Format)
                    {
                        case SourceFormat.Csv or SourceFormat.Tsv:
                            result.Rows += WriteCsv(first, target, Plans(project, inventory, first), d, result);
                            break;
                        case SourceFormat.Xlsx:
                            result.Rows += WriteXlsx(group.ToList(), target, project, inventory, d, result);
                            break;
                        case SourceFormat.Json or SourceFormat.JsonLines:
                            result.Rows += WriteJson(first, target, Plans(project, inventory, first), d, result);
                            break;
                        case SourceFormat.Text:
                            if (WriteText(first, target, Plans(project, inventory, first), d)) result.Rows++;
                            else continue;
                            break;
                        case SourceFormat.Database:
                            result.Rows += WriteDatabase(group.ToList(), target, project, inventory, d, result, overwrite);
                            break;
                    }
                    if (first.Format == SourceFormat.Database && project.Policy.DatabaseOutput != "sqlite" && source.Kind == "database")
                        result.Files.AddRange(group.Select(t => Path.GetRelativePath(outFull, Path.Combine(target, t.Table + ".csv")).Replace('\\', '/')));
                    else result.Files.Add(rel.Replace('\\', '/'));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or JsonException or System.Data.Common.DbException or InvalidDataException or FormatException)
                {
                    result.Problems.Add($"{Mask.Label(first.Location)}: {Scanner.Safe(e)}");
                }
            }
        }
        foreach (var (k, v) in d.Replaced) result.Replaced[k] = v;
        return result;
    }

    /// <summary>Refuses an output folder that is, or is inside, a source folder or file (the copy must never mix with the data).</summary>
    public static void CheckOutput(Project project, string root, string outFull)
    {
        var o = Path.TrimEndingDirectorySeparator(outFull);
        foreach (var s in project.Sources)
        {
            if (s.Kind == "database" || s.Path is null) continue;
            var p = Path.TrimEndingDirectorySeparator(Sources.Full(root, s.Path));
            var cmp = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (string.Equals(o, p, cmp)) throw new IOException("The output folder is a source: choose a folder of its own for the copy.");
            if (s.Kind == "folder" && o.StartsWith(p + Path.DirectorySeparatorChar, cmp))
                throw new IOException("The output folder is inside a source folder, where the next scan would read the copy as data: choose a folder outside it.");
        }
    }

    /// <summary>Where a dataset's copy goes inside the output folder.</summary>
    public static string OutputPath(SourceSpec source, Dataset d, bool multi, string databaseOutput)
    {
        string prefix = "";
        if (multi)
            prefix = source.Kind switch
            {
                "folder" => Path.GetFileName(Path.TrimEndingDirectorySeparator(source.Path ?? source.Id)) is { Length: > 0 } n ? n : source.Id,
                _ => "",
            };
        if (source.Kind == "database")
        {
            var name = Safe(Path.GetFileNameWithoutExtension(d.Location) is { Length: > 0 } stem ? stem : d.Location);
            if (multi) name = $"{source.Id}-{name}";
            return databaseOutput == "sqlite" ? name + ".sqlite" : name;
        }
        return Path.Combine(prefix, d.Location);
    }

    private static string Safe(string name) => new(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray());

    /// <summary>Each column's plan, from the scan and the project; columns the scan didn't see get one from their header.</summary>
    public static Dictionary<string, ColumnPlan> Plans(Project project, Inventory inventory, Dataset d)
    {
        var plans = new Dictionary<string, ColumnPlan>(StringComparer.Ordinal);
        foreach (var c in inventory.Columns.Where(c => c.SourceId == d.Source.Id && c.Location == d.Location && c.Table == d.Table))
        {
            var kind = project.EffectiveKind(c.Key, c.Detected);
            plans[c.Column] = new ColumnPlan(c.Column, kind, project.Policy.ActionFor(c.Key, kind));
        }
        return plans;
    }

    /// <summary>A plan for a column the scan didn't see (past the sample): by its header, else scrubbed as text.</summary>
    private static ColumnPlan Unseen(Project project, string column)
    {
        var hint = HeaderHints.Of(column);
        if (hint is { NotPhi: true }) return new ColumnPlan(column, PhiKind.None, ColumnAction.Keep);
        if (hint is { } h) return new ColumnPlan(column, h.Kind, project.Policy.ActionFor("", h.Kind));
        return new ColumnPlan(column, PhiKind.FreeText, ColumnAction.ScrubText);
    }

    /// <summary>The column whose values say whose row it is: the policy's, else member ID, MRN, then SSN.</summary>
    public static string? PersonColumn(Project project, IReadOnlyDictionary<string, ColumnPlan> plans)
    {
        if (project.Policy.PersonKey is { Length: > 0 } chosen && plans.Keys.FirstOrDefault(k => k.Equals(chosen, StringComparison.OrdinalIgnoreCase) || k.EndsWith("." + chosen, StringComparison.OrdinalIgnoreCase)) is { } c)
            return c;
        foreach (var kind in new[] { PhiKind.MemberId, PhiKind.Mrn, PhiKind.Ssn })
            if (plans.Values.FirstOrDefault(p => p.Kind == kind) is { } p) return p.Column;
        return null;
    }

    // ───────────────────────────── writers ─────────────────────────────

    private static long WriteCsv(Dataset ds, string target, Dictionary<string, ColumnPlan> plans, Deidentifier d, DeidentifyResult result)
    {
        var delimiter = ds.Format == SourceFormat.Tsv ? '\t' : Csv.Sniff(ds.FilePath!);
        using var reader = Sources.OpenText(ds.FilePath!);
        using var writer = new StreamWriter(target, false, new UTF8Encoding(false));
        List<ColumnPlan>? columns = null;
        var person = -1;
        long rows = 0;
        foreach (var row in Csv.Read(reader, delimiter))
        {
            if (columns is null)
            {
                var headers = Sources.Headers(row);
                columns = headers.Select(h => plans.TryGetValue(h, out var p) ? p : Unseen(d.ProjectFor(), h)).ToList();
                result.Dropped += columns.Count(c => c.Action == ColumnAction.Drop);
                person = PersonColumn(d.ProjectFor(), columns.ToDictionary(c => c.Column)) is { } pc ? headers.IndexOf(pc) : -1;
                writer.WriteLine(Csv.Line(row.Where((_, i) => i >= columns.Count || columns[i].Action != ColumnAction.Drop), delimiter));
                continue;
            }
            var who = person >= 0 && person < row.Length ? row[person] : null;
            var values = new List<string?>();
            for (var i = 0; i < row.Length; i++)
            {
                if (i < columns.Count && columns[i].Action == ColumnAction.Drop) continue;
                values.Add(i < columns.Count ? d.Apply(columns[i].Action, columns[i].Kind, row[i], who) : row[i]);
            }
            writer.WriteLine(Csv.Line(values, delimiter));
            rows++;
        }
        return rows;
    }

    private static long WriteXlsx(List<Dataset> sheets, string target, Project project, Inventory inventory, Deidentifier d, DeidentifyResult result)
    {
        using var book = new XLWorkbook(sheets[0].FilePath!);
        long rows = 0;
        foreach (var ds in sheets)
        {
            var sheet = book.Worksheet(ds.Table);
            var (header, dataRows) = Xlsx.Layout(sheet);
            if (header == 0) continue;
            var plans = Plans(project, inventory, ds);
            var lastCol = sheet.LastColumnUsed()?.ColumnNumber() ?? 0;
            var headers = Sources.Headers(Enumerable.Range(1, lastCol).Select(c => Xlsx.Text(sheet.Cell(header, c))).ToArray());
            var columns = headers.Select(h => plans.TryGetValue(h, out var p) ? p : Unseen(project, h)).ToList();
            var person = PersonColumn(project, columns.ToDictionary(c => c.Column)) is { } pc ? headers.IndexOf(pc) + 1 : 0;
            foreach (var r in dataRows.ToList())
            {
                var who = person > 0 ? Xlsx.Text(sheet.Cell(r, person)) : null;
                for (var c = 1; c <= columns.Count; c++)
                {
                    var plan = columns[c - 1];
                    if (plan.Action is ColumnAction.Keep or ColumnAction.Drop) continue;
                    var cell = sheet.Cell(r, c);
                    if (cell.Value.IsBlank) continue;
                    if (cell.Value.IsDateTime && plan.Action is ColumnAction.ShiftDate or ColumnAction.Generalise && Kinds.IsDate(plan.Kind))
                    {
                        var date = cell.Value.GetDateTime();
                        if (plan.Action == ColumnAction.ShiftDate) cell.Value = d.Shift(date, who, plan.Kind == PhiKind.BirthDate);
                        else
                        {
                            cell.Value = d.Year(date, plan.Kind == PhiKind.BirthDate);
                            cell.Style.NumberFormat.Format = "0";
                        }
                        d.Replaced[plan.Kind] = d.Replaced.GetValueOrDefault(plan.Kind) + 1;
                        continue;
                    }
                    var text = Xlsx.Text(cell);
                    var after = d.Apply(plan.Action, plan.Kind, text, who);
                    if (after != text) cell.Value = after ?? "";
                }
                rows++;
            }
            var drops = columns.Select((c, i) => (c, i)).Where(x => x.c.Action == ColumnAction.Drop).Select(x => x.i + 1).OrderDescending().ToList();
            foreach (var c in drops) sheet.Column(c).Delete();
            result.Dropped += drops.Count;
        }
        book.SaveAs(target);
        return rows;
    }

    private static long WriteJson(Dataset ds, string target, Dictionary<string, ColumnPlan> plans, Deidentifier d, DeidentifyResult result)
    {
        var project = d.ProjectFor();
        var person = PersonColumn(project, plans);
        long rows = 0;
        var dropped = new HashSet<string>();
        void Transform(JsonNode record)
        {
            string? who = null;
            if (person != null)
                who = JsonData.Leaves(record).FirstOrDefault(l => l.Path == person).Value;
            Walk(record, "", (path, value, parent, name, index) =>
            {
                var plan = plans.TryGetValue(path, out var p) ? p : Unseen(project, path);
                if (plan.Action == ColumnAction.Keep) return;
                if (plan.Action == ColumnAction.Drop)
                {
                    if (parent is JsonObject o && name != null) o.Remove(name);
                    else if (parent is JsonArray a && index >= 0) a[index] = null;
                    dropped.Add(path);
                    return;
                }
                var text = JsonData.Text(value);
                var after = d.Apply(plan.Action, plan.Kind, text, who);
                if (after == text) return;
                JsonNode? replacement = after is null ? null : JsonValue.Create(after);
                if (parent is JsonObject po && name != null) po[name] = replacement;
                else if (parent is JsonArray pa && index >= 0) pa[index] = replacement;
            });
            rows++;
        }
        var options = new JsonSerializerOptions { WriteIndented = ds.Format == SourceFormat.Json, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        if (ds.Format == SourceFormat.Json)
        {
            var root = JsonNode.Parse(File.ReadAllText(ds.FilePath!), documentOptions: JsonData.Reading);
            foreach (var record in JsonData.Records(root)) Transform(record);
            File.WriteAllText(target, root?.ToJsonString(options) ?? "null");
        }
        else
        {
            using var w = new StreamWriter(target, false, new UTF8Encoding(false));
            foreach (var record in JsonData.Lines(ds.FilePath!))
            {
                Transform(record);
                w.WriteLine(record.ToJsonString(options));
            }
        }
        result.Dropped += dropped.Count;
        return rows;
    }

    private delegate void LeafVisitor(string path, JsonValue value, JsonNode? parent, string? name, int index);

    /// <summary>Visits each leaf with where it hangs, so it can be replaced or removed (a copy of the keys is walked).</summary>
    private static void Walk(JsonNode node, string prefix, LeafVisitor visit)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (k, v) in o.ToList())
                {
                    var p = prefix.Length == 0 ? k : prefix + "." + k;
                    if (v is JsonValue jv) visit(p, jv, o, k, -1);
                    else if (v != null) Walk(v, p, visit);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue jv) visit(prefix + "[]", jv, a, null, i);
                    else if (a[i] is { } child) Walk(child, prefix + "[]", visit);
                }
                break;
        }
    }

    private static bool WriteText(Dataset ds, string target, Dictionary<string, ColumnPlan> plans, Deidentifier d)
    {
        var plan = plans.TryGetValue(Sources.TextColumn, out var p) ? p : new ColumnPlan(Sources.TextColumn, PhiKind.FreeText, ColumnAction.ScrubText);
        if (plan.Action == ColumnAction.Drop) return false;
        var text = Sources.ReadAllText(ds.FilePath!);
        var after = plan.Action switch
        {
            ColumnAction.Keep => text,
            ColumnAction.ScrubText => d.Scrub(text, d.PersonOf(text)),
            ColumnAction.Redact => Deidentifier.Marker(plan.Kind),
            _ => d.Scrub(text, d.PersonOf(text)),
        };
        File.WriteAllText(target, after, new UTF8Encoding(false));
        return true;
    }

    private static long WriteDatabase(List<Dataset> tables, string target, Project project, Inventory inventory, Deidentifier d, DeidentifyResult result, bool overwrite)
    {
        var first = tables[0];
        var toSqlite = first.Source.Kind != "database" || project.Policy.DatabaseOutput == "sqlite";
        long rows = 0;
        if (toSqlite)
        {
            if (File.Exists(target))
            {
                if (!overwrite) throw new IOException("The database copy exists in the output folder.");
                SqliteConnection.ClearAllPools();
                File.Delete(target);
            }
            using var conn = new SqliteConnection($"Data Source={target};Pooling=False");
            conn.Open();
            foreach (var t in tables)
            {
                var plans = Plans(project, inventory, t);
                var types = Db.DescribeColumns(t.Engine, t.ConnectionString!, t.Table).ToDictionary(c => c.Name, c => c.Type, StringComparer.Ordinal);
                using var tx = conn.BeginTransaction();
                SqliteCommand? insert = null;
                List<ColumnPlan>? columns = null;
                int person = -1;
                var name = t.Table.Contains('.') ? t.Table[(t.Table.IndexOf('.') + 1)..] : t.Table;
                DbRead.Stream(t.Engine, t.ConnectionString!, DbRead.Select(t.Engine, t.Table, null), cols =>
                {
                    columns = cols.Select(c => plans.TryGetValue(c, out var p) ? p : Unseen(project, c)).ToList();
                    person = PersonColumn(project, columns.ToDictionary(c => c.Column)) is { } pc ? cols.ToList().IndexOf(pc) : -1;
                    var kept = columns.Where(c => c.Action != ColumnAction.Drop).ToList();
                    result.Dropped += columns.Count - kept.Count;
                    using (var create = conn.CreateCommand())
                    {
                        create.Transaction = tx;
                        create.CommandText = $"CREATE TABLE {Q(name)} (" + string.Join(", ", kept.Select(c => $"{Q(c.Column)} {(c.Action == ColumnAction.Keep && types.TryGetValue(c.Column, out var ty) && ty.Length > 0 ? SqliteType(ty) : "TEXT")}")) + ")";
                        create.ExecuteNonQuery();
                    }
                    insert = conn.CreateCommand();
                    insert.Transaction = tx;
                    insert.CommandText = $"INSERT INTO {Q(name)} VALUES (" + string.Join(", ", kept.Select((_, i) => "$p" + i)) + ")";
                    for (var i = 0; i < kept.Count; i++) insert.Parameters.Add(new SqliteParameter("$p" + i, DBNull.Value));
                }, row =>
                {
                    var who = person >= 0 ? row[person] : null;
                    var n = 0;
                    for (var i = 0; i < columns!.Count; i++)
                    {
                        if (columns[i].Action == ColumnAction.Drop) continue;
                        insert!.Parameters[n++].Value = (object?)d.Apply(columns[i].Action, columns[i].Kind, row[i], who) ?? DBNull.Value;
                    }
                    insert!.ExecuteNonQuery();
                    rows++;
                    return true;
                });
                insert?.Dispose();
                tx.Commit();
            }
            return rows;
        }
        Directory.CreateDirectory(target);
        foreach (var t in tables)
        {
            var file = Path.Combine(target, t.Table + ".csv");
            if (File.Exists(file) && !overwrite) throw new IOException("A table's copy exists in the output folder.");
            var plans = Plans(project, inventory, t);
            using var w = new StreamWriter(file, false, new UTF8Encoding(false));
            List<ColumnPlan>? columns = null;
            int person = -1;
            DbRead.Stream(t.Engine, t.ConnectionString!, DbRead.Select(t.Engine, t.Table, null), cols =>
            {
                columns = cols.Select(c => plans.TryGetValue(c, out var p) ? p : Unseen(project, c)).ToList();
                person = PersonColumn(project, columns.ToDictionary(c => c.Column)) is { } pc ? cols.ToList().IndexOf(pc) : -1;
                result.Dropped += columns.Count(c => c.Action == ColumnAction.Drop);
                w.WriteLine(Csv.Line(cols.Where((_, i) => columns[i].Action != ColumnAction.Drop), ','));
            }, row =>
            {
                var who = person >= 0 ? row[person] : null;
                w.WriteLine(Csv.Line(row.Select((v, i) => (v, i)).Where(x => columns![x.i].Action != ColumnAction.Drop).Select(x => d.Apply(columns![x.i].Action, columns[x.i].Kind, x.v, who)), ','));
                rows++;
                return true;
            });
        }
        return rows;
    }

    private static string Q(string name) => "\"" + name.Replace("\"", "\"\"") + "\"";

    private static string SqliteType(string type)
    {
        var t = type.ToUpperInvariant();
        if (t.Contains("INT")) return "INTEGER";
        if (t.Contains("REAL") || t.Contains("FLOA") || t.Contains("DOUB") || t.Contains("DEC") || t.Contains("NUM") || t.Contains("MONEY")) return "REAL";
        return "TEXT";
    }
}

/// <summary>The project a de-identifier was made for (the writers need its policy's person key and unseen-column rules).</summary>
public sealed partial class Deidentifier
{
    private Project? _owner;

    internal Deidentifier For(Project project)
    {
        _owner = project;
        return this;
    }

    internal Project ProjectFor() => _owner ?? new Project { Policy = Policy };
}
