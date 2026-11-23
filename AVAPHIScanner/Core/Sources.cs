using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ClosedXML.Excel;

namespace AVAPHIScanner;

/// <summary>The kinds of data the scanner reads.</summary>
public enum SourceFormat { Csv, Tsv, Xlsx, Json, JsonLines, Text, Database }

/// <summary>
/// A place data comes from, as a project keeps it: a file, a folder of files (read through sub-folders), or a database
/// (SQL Server, PostgreSQL or SQLite; all its tables, or the ones listed). Paths are relative to the project's folder (or
/// the working folder) where they can be.
/// </summary>
public sealed class SourceSpec
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";

    /// <summary>"file", "folder" or "database".</summary>
    [JsonPropertyName("kind")] public string Kind { get; set; } = "file";

    [JsonPropertyName("path")] public string? Path { get; set; }

    /// <summary>For a database: "SQL Server", "PostgreSQL" or "SQLite".</summary>
    [JsonPropertyName("engine")] public string? Engine { get; set; }

    /// <summary>For a database: its connection string (with its password, if it has one: keep project files private).</summary>
    [JsonPropertyName("connection")] public string? Connection { get; set; }

    /// <summary>For a database chosen by name from the saved connections.</summary>
    [JsonPropertyName("connection_name")] public string? ConnectionName { get; set; }

    /// <summary>For a database: only these tables ("schema.table"); all of them when empty.</summary>
    [JsonPropertyName("tables")] public List<string>? Tables { get; set; }

    public SourceSpec Clone() => new() { Id = Id, Kind = Kind, Path = Path, Engine = Engine, Connection = Connection, ConnectionName = ConnectionName, Tables = Tables?.ToList() };
}

/// <summary>One thing to read: a file, one sheet of a workbook, or one database table.</summary>
public sealed class Dataset
{
    public required SourceSpec Source { get; init; }

    /// <summary>The file's path inside the source (for a folder), its name (for a file), or the database's name.</summary>
    public required string Location { get; init; }

    /// <summary>The sheet or "schema.table"; empty for a file that is one table.</summary>
    public string Table { get; init; } = "";

    public required SourceFormat Format { get; init; }

    /// <summary>The file's full path (a SQLite database's too).</summary>
    public string? FilePath { get; init; }

    public DbEngine Engine { get; init; }

    public string? ConnectionString { get; init; }

    /// <summary>"members.csv", "claims.xlsx › Claims", "clinic.db › main.patients".</summary>
    public string Display => Table.Length == 0 ? Location : $"{Location} › {Table}";
}

/// <summary>What was read from a dataset for scanning: its columns and the first rows (as text; null for empty).</summary>
public sealed class TableData
{
    public required Dataset Dataset { get; init; }
    public List<string> Columns { get; } = [];
    public List<string?[]> Rows { get; } = [];
    /// <summary>For JSON: which record each row came from (an array inside a record adds rows of its own).</summary>
    public List<int> Records { get; } = [];
    /// <summary>How many rows (records) the dataset has, when it's known.</summary>
    public long? TotalRows { get; set; }
    /// <summary>Reading stopped at the sample limit.</summary>
    public bool Sampled { get; set; }

    public int Column(string name)
    {
        var i = Columns.IndexOf(name);
        if (i >= 0) return i;
        Columns.Add(name);
        for (var r = 0; r < Rows.Count; r++)
            if (Rows[r].Length < Columns.Count) { var a = Rows[r]; Array.Resize(ref a, Columns.Count); Rows[r] = a; }
        return Columns.Count - 1;
    }
}

/// <summary>Finding the datasets in a source and reading them.</summary>
public static class Sources
{
    /// <summary>The column name a text file's text is read under.</summary>
    public const string TextColumn = "(text)";

    public static SourceFormat? FormatOf(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".csv" => SourceFormat.Csv,
        ".tsv" or ".tab" => SourceFormat.Tsv,
        ".xlsx" or ".xlsm" => SourceFormat.Xlsx,
        ".json" => SourceFormat.Json,
        ".jsonl" or ".ndjson" => SourceFormat.JsonLines,
        ".txt" or ".text" or ".md" or ".note" or ".notes" or ".log" => SourceFormat.Text,
        ".db" or ".sqlite" or ".sqlite3" => SourceFormat.Database,
        _ => null,
    };

    /// <summary>A path in a source made absolute: against <paramref name="root"/> when it's relative.</summary>
    public static string Full(string root, string path) => Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(root, path));

    private static readonly string[] SkipFolders = ["bin", "obj", ".git", ".vs", ".idea", "node_modules"];

    /// <summary>
    /// Every dataset in <paramref name="source"/>: each readable file in a folder (through sub-folders), each sheet of a
    /// workbook, each table of a database (SQLite files in a folder included). <paramref name="skip"/> leaves out a folder
    /// (the output of a de-identification, so it isn't read as a source).
    /// </summary>
    public static List<Dataset> Expand(SourceSpec source, string root, Func<string, ConnectionInfo?>? connections = null, string? skip = null)
    {
        var list = new List<Dataset>();
        switch (source.Kind)
        {
            case "database":
                var (engine, cs) = Connection(source, root, connections);
                var display = DbRead.DisplayName(engine, cs);
                foreach (var t in Tables(engine, cs, source.Tables))
                    list.Add(new Dataset { Source = source, Location = display, Table = t, Format = SourceFormat.Database, Engine = engine, ConnectionString = cs, FilePath = engine == DbEngine.Sqlite ? new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(cs).DataSource : null });
                break;
            case "folder":
                var folder = Full(root, source.Path ?? ".");
                if (!Directory.Exists(folder)) throw new DirectoryNotFoundException($"The folder {Mask.Label(source.Path ?? folder)} isn't there.");
                var skipFull = skip is null ? null : Path.TrimEndingDirectorySeparator(Path.GetFullPath(skip)) + Path.DirectorySeparatorChar;
                foreach (var file in Directory.EnumerateFiles(folder, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).Order(StringComparer.Ordinal))
                {
                    var rel = Path.GetRelativePath(folder, file).Replace('\\', '/');
                    if (rel.Split('/').Any(p => SkipFolders.Contains(p, StringComparer.OrdinalIgnoreCase) || p.StartsWith('.'))) continue;
                    if (skipFull != null && file.StartsWith(skipFull, StringComparison.Ordinal)) continue;
                    list.AddRange(FileDatasets(source, file, rel));
                }
                break;
            default:
                var path = Full(root, source.Path ?? "");
                if (!File.Exists(path)) throw new FileNotFoundException($"The file {Mask.Label(source.Path ?? path)} isn't there.");
                list.AddRange(FileDatasets(source, path, Path.GetFileName(path)));
                break;
        }
        return list;
    }

    private static IEnumerable<Dataset> FileDatasets(SourceSpec source, string file, string rel)
    {
        switch (FormatOf(file))
        {
            case null:
                yield break;
            case SourceFormat.Xlsx:
                List<string> sheets;
                try
                {
                    using var book = new XLWorkbook(file);
                    sheets = book.Worksheets.Select(w => w.Name).ToList();
                }
                catch (Exception e) when (e is IOException or InvalidDataException or ArgumentException or InvalidOperationException or FormatException)
                {
                    sheets = [];
                }
                foreach (var s in sheets)
                    yield return new Dataset { Source = source, Location = rel, Table = s, Format = SourceFormat.Xlsx, FilePath = file };
                break;
            case SourceFormat.Database:
                var cs = $"Data Source={file};Pooling=False";
                List<string> tables;
                try { tables = Tables(DbEngine.Sqlite, cs, null); }
                catch (Exception e) when (e is System.Data.Common.DbException or InvalidOperationException) { tables = []; }
                foreach (var t in tables)
                    yield return new Dataset { Source = source, Location = rel, Table = t, Format = SourceFormat.Database, Engine = DbEngine.Sqlite, ConnectionString = cs, FilePath = file };
                break;
            case { } f:
                yield return new Dataset { Source = source, Location = rel, Format = f, FilePath = file };
                break;
        }
    }

    /// <summary>A saved connection by name, as the store gives it.</summary>
    public sealed record ConnectionInfo(DbEngine Engine, string ConnectionString);

    public static (DbEngine Engine, string Cs) Connection(SourceSpec source, string root, Func<string, ConnectionInfo?>? connections)
    {
        if (source.ConnectionName is { Length: > 0 } name && connections?.Invoke(name) is { } saved) return (saved.Engine, saved.ConnectionString);
        if (source.Connection is { Length: > 0 } cs)
        {
            var engine = Db.ParseEngine(source.Engine ?? "sqlite");
            if (engine == DbEngine.Sqlite)
            {
                // A SQLite file named relative to the project.
                var b = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(cs);
                if (!Path.IsPathRooted(b.DataSource)) b.DataSource = Full(root, b.DataSource);
                return (engine, b.ConnectionString);
            }
            return (engine, cs);
        }
        if (source.Path is { Length: > 0 } p) return (DbEngine.Sqlite, $"Data Source={Full(root, p)};Pooling=False");
        throw new InvalidOperationException($"Source {source.Id} has no connection.");
    }

    /// <summary>Base tables (views left out: their rows are another table's), filtered to <paramref name="only"/> when given.</summary>
    private static List<string> Tables(DbEngine engine, string cs, List<string>? only)
    {
        var all = Db.ListTables(engine, cs).Where(t => !t.IsView).Select(t => t.FullName).ToList();
        if (only is not { Count: > 0 }) return all;
        return all.Where(t => only.Any(o => t.Equals(o, StringComparison.OrdinalIgnoreCase) || t.EndsWith("." + o, StringComparison.OrdinalIgnoreCase))).ToList();
    }

    // ───────────────────────────── reading for a scan ─────────────────────────────

    /// <summary>Reads the first <paramref name="sampleRows"/> rows of a dataset (records, for JSON; paragraphs, for text).</summary>
    public static TableData Read(Dataset d, int sampleRows)
    {
        var t = new TableData { Dataset = d };
        switch (d.Format)
        {
            case SourceFormat.Csv or SourceFormat.Tsv:
            {
                using var reader = OpenText(d.FilePath!);
                var delimiter = d.Format == SourceFormat.Tsv ? '\t' : Csv.Sniff(d.FilePath!);
                var first = true;
                long count = 0;
                foreach (var row in Csv.Read(reader, delimiter))
                {
                    if (first)
                    {
                        t.Columns.AddRange(Headers(row));
                        first = false;
                        continue;
                    }
                    count++;
                    if (t.Rows.Count < sampleRows) t.Rows.Add(Fit(row, t.Columns.Count));
                    else t.Sampled = true;
                }
                t.TotalRows = count;
                break;
            }
            case SourceFormat.Xlsx:
            {
                using var book = new XLWorkbook(d.FilePath!);
                var sheet = book.Worksheet(d.Table);
                var (header, rows) = Xlsx.Layout(sheet);
                if (header == 0) break;
                var lastCol = sheet.LastColumnUsed()?.ColumnNumber() ?? 0;
                t.Columns.AddRange(Headers(Enumerable.Range(1, lastCol).Select(c => Xlsx.Text(sheet.Cell(header, c))).ToArray()));
                long count = 0;
                foreach (var r in rows)
                {
                    count++;
                    if (t.Rows.Count >= sampleRows) { t.Sampled = true; continue; }
                    t.Rows.Add(Enumerable.Range(1, t.Columns.Count).Select(c => Xlsx.Text(sheet.Cell(r, c)) is { Length: > 0 } s ? s : null).ToArray());
                }
                t.TotalRows = count;
                break;
            }
            case SourceFormat.Json or SourceFormat.JsonLines:
            {
                var records = d.Format == SourceFormat.Json ? JsonData.Records(JsonNode.Parse(File.ReadAllText(d.FilePath!), documentOptions: JsonData.Reading)) : JsonData.Lines(d.FilePath!);
                var n = 0;
                long count = 0;
                foreach (var record in records)
                {
                    count++;
                    if (n >= sampleRows) { t.Sampled = true; continue; }
                    // Each leaf in a column of its own ("address.zip"; arrays as "phones[]"); a path seen again in the
                    // same record (an array's next item) starts a row of its own for that record.
                    var rowsOfRecord = new List<string?[]>();
                    foreach (var (path, value) in JsonData.Leaves(record))
                    {
                        var c = t.Column(path);
                        var target = rowsOfRecord.FirstOrDefault(r => r.Length <= c || r[c] is null);
                        if (target is null) { target = new string?[t.Columns.Count]; rowsOfRecord.Add(target); }
                        if (target.Length < t.Columns.Count)
                        {
                            var i = rowsOfRecord.IndexOf(target);
                            Array.Resize(ref target, t.Columns.Count);
                            rowsOfRecord[i] = target;
                        }
                        target[c] = value;
                    }
                    foreach (var r in rowsOfRecord)
                    {
                        t.Rows.Add(Fit(r, t.Columns.Count));
                        t.Records.Add(n);
                    }
                    n++;
                }
                for (var r = 0; r < t.Rows.Count; r++) t.Rows[r] = Fit(t.Rows[r], t.Columns.Count);
                t.TotalRows = count;
                break;
            }
            case SourceFormat.Text:
            {
                t.Columns.Add(TextColumn);
                var text = ReadAllText(d.FilePath!);
                var paragraphs = Paragraphs(text);
                foreach (var p in paragraphs)
                {
                    if (t.Rows.Count >= sampleRows) { t.Sampled = true; break; }
                    t.Rows.Add([p]);
                }
                t.TotalRows = paragraphs.Count;
                break;
            }
            case SourceFormat.Database:
            {
                DbRead.Stream(d.Engine, d.ConnectionString!, DbRead.Select(d.Engine, d.Table, sampleRows + 1), cols => t.Columns.AddRange(Headers([.. cols])), row =>
                {
                    if (t.Rows.Count >= sampleRows) { t.Sampled = true; return false; }
                    t.Rows.Add(row.Select(v => string.IsNullOrEmpty(v) ? null : v).ToArray());
                    return true;
                });
                t.TotalRows = t.Sampled ? DbRead.Count(d.Engine, d.ConnectionString!, d.Table) : t.Rows.Count;
                break;
            }
        }
        return t;
    }

    /// <summary>Headers made unique and non-empty ("Column3" for a blank one).</summary>
    public static List<string> Headers(string?[] row)
    {
        var list = new List<string>();
        for (var i = 0; i < row.Length; i++)
        {
            var h = string.IsNullOrWhiteSpace(row[i]) ? $"Column{i + 1}" : row[i]!.Trim();
            var unique = h;
            for (var n = 2; list.Contains(unique); n++) unique = $"{h}_{n}";
            list.Add(unique);
        }
        return list;
    }

    private static string?[] Fit(string?[] row, int count)
    {
        var a = new string?[count];
        for (var i = 0; i < Math.Min(count, row.Length); i++) a[i] = string.IsNullOrEmpty(row[i]) ? null : row[i];
        return a;
    }

    /// <summary>A text file's paragraphs (split at blank lines), each trimmed; empty ones left out.</summary>
    public static List<string> Paragraphs(string text) =>
        System.Text.RegularExpressions.Regex.Split(text.Replace("\r\n", "\n"), @"\n\s*\n").Select(p => p.Trim()).Where(p => p.Length > 0).ToList();

    public static StreamReader OpenText(string path) => new(path, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);

    public static string ReadAllText(string path)
    {
        using var r = OpenText(path);
        return r.ReadToEnd();
    }
}

/// <summary>Comma- and tab-separated files, as RFC 4180 has them: quoted fields may hold the delimiter, quotes and line breaks.</summary>
public static class Csv
{
    public static IEnumerable<string[]> Read(TextReader reader, char delimiter)
    {
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        var any = false;
        int c;
        while ((c = reader.Read()) != -1)
        {
            var ch = (char)c;
            any = true;
            if (quoted)
            {
                if (ch == '"')
                {
                    if (reader.Peek() == '"') { field.Append('"'); reader.Read(); }
                    else quoted = false;
                }
                else field.Append(ch);
                continue;
            }
            if (ch == '"' && field.Length == 0) quoted = true;
            else if (ch == delimiter) { row.Add(field.ToString()); field.Clear(); }
            else if (ch is '\r' or '\n')
            {
                if (ch == '\r' && reader.Peek() == '\n') reader.Read();
                row.Add(field.ToString());
                field.Clear();
                if (!(row.Count == 1 && row[0].Length == 0)) yield return row.ToArray();
                row.Clear();
                any = false;
            }
            else field.Append(ch);
        }
        if (any || field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            if (!(row.Count == 1 && row[0].Length == 0)) yield return row.ToArray();
        }
    }

    /// <summary>A .csv file's delimiter: a comma, unless its first line has more semicolons (or tabs).</summary>
    public static char Sniff(string path)
    {
        using var r = Sources.OpenText(path);
        var line = r.ReadLine() ?? "";
        var counts = new[] { (',', line.Count(c => c == ',')), (';', line.Count(c => c == ';')), ('\t', line.Count(c => c == '\t')) };
        return counts.MaxBy(x => x.Item2).Item2 > 0 ? counts.MaxBy(x => x.Item2).Item1 : ',';
    }

    public static string Field(string? v, char delimiter) =>
        v is null ? "" : v.IndexOfAny([delimiter, '"', '\n', '\r']) >= 0 || v.StartsWith(' ') || v.EndsWith(' ') ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;

    public static string Line(IEnumerable<string?> values, char delimiter) => string.Join(delimiter, values.Select(v => Field(v, delimiter)));
}

/// <summary>Reading workbook cells as text the way the scanner and the de-identifier want them.</summary>
public static class Xlsx
{
    /// <summary>A cell as text: dates as ISO dates (with the time when it has one), numbers invariant, text as it is.</summary>
    public static string Text(IXLCell cell)
    {
        var v = cell.Value;
        if (v.IsBlank) return "";
        if (v.IsDateTime) return DbRead.Text(v.GetDateTime());
        if (v.IsNumber) return v.GetNumber().ToString(CultureInfo.InvariantCulture);
        if (v.IsBoolean) return v.GetBoolean() ? "TRUE" : "FALSE";
        if (v.IsTimeSpan) return v.GetTimeSpan().ToString();
        if (v.IsError) return "";
        return v.GetText();
    }

    /// <summary>The header row (the first row with anything in it; 0 when the sheet is empty) and the data rows under it.</summary>
    public static (int Header, IEnumerable<int> Rows) Layout(IXLWorksheet sheet)
    {
        var first = sheet.FirstRowUsed()?.RowNumber() ?? 0;
        var last = sheet.LastRowUsed()?.RowNumber() ?? 0;
        if (first == 0) return (0, []);
        return (first, Enumerable.Range(first + 1, Math.Max(0, last - first)).Where(r => !sheet.Row(r).IsEmpty()));
    }
}

/// <summary>JSON records and their leaves.</summary>
public static class JsonData
{
    public static readonly JsonDocumentOptions Reading = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    /// <summary>
    /// A JSON document's records: an array's items; an object's largest array of objects (as {"members": [...]}); or the
    /// object itself.
    /// </summary>
    public static List<JsonNode> Records(JsonNode? root)
    {
        switch (root)
        {
            case JsonArray a:
                return a.Where(n => n is not null).Select(n => n!).ToList();
            case JsonObject o:
                var arrays = o.Where(p => p.Value is JsonArray arr && arr.Count > 0 && arr.All(x => x is JsonObject)).Select(p => (JsonArray)p.Value!).ToList();
                return arrays.Count > 0 ? arrays.MaxBy(a => a.Count)!.Select(n => n!).ToList() : [o];
            default:
                return root is null ? [] : [root];
        }
    }

    public static IEnumerable<JsonNode> Lines(string path)
    {
        using var r = Sources.OpenText(path);
        while (r.ReadLine() is { } line)
        {
            if (line.Trim().Length == 0) continue;
            JsonNode? node;
            try { node = JsonNode.Parse(line, documentOptions: Reading); }
            catch (JsonException) { continue; }
            if (node != null) yield return node;
        }
    }

    /// <summary>Every leaf value under <paramref name="node"/> with its path ("member.address.zip", "phones[]").</summary>
    public static IEnumerable<(string Path, string? Value)> Leaves(JsonNode node, string prefix = "")
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (k, v) in o)
                {
                    var p = prefix.Length == 0 ? k : prefix + "." + k;
                    if (v is null) { yield return (p, null); continue; }
                    foreach (var leaf in Leaves(v, p)) yield return leaf;
                }
                break;
            case JsonArray a:
                foreach (var item in a)
                    if (item != null)
                        foreach (var leaf in Leaves(item, prefix + "[]")) yield return leaf;
                break;
            case JsonValue v:
                yield return (prefix.Length == 0 ? "(value)" : prefix, Text(v));
                break;
        }
    }

    public static string? Text(JsonValue v) => v.GetValueKind() switch
    {
        JsonValueKind.String => v.GetValue<string>(),
        JsonValueKind.Null => null,
        _ => v.ToJsonString(),
    };
}
