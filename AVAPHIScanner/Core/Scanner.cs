using System.Text.RegularExpressions;

namespace AVAPHIScanner;

/// <summary>One identifier found in a cell of free text: its row (from 1) and kind, and the value masked.</summary>
public sealed record CellFinding(int Row, PhiKind Kind, string Masked);

/// <summary>What the scan found in one column, and why it thinks so. Examples are masked; raw values are never kept here.</summary>
public sealed class ColumnReport
{
    public string Id { get; set; } = "";
    public string Key { get; init; } = "";
    public string SourceId { get; init; } = "";
    public string Location { get; init; } = "";
    public string Table { get; init; } = "";
    public string Column { get; init; } = "";
    public SourceFormat Format { get; init; }

    public PhiKind Detected { get; set; }
    public double Confidence { get; set; }
    public string Reason { get; set; } = "";

    /// <summary>Values read (not empty).</summary>
    public int Values { get; set; }
    /// <summary>Values that are the detected kind (for free text: values with identifiers in them).</summary>
    public int Count { get; set; }
    /// <summary>For an age or birth-date column: how many are over 89.</summary>
    public int Over89 { get; set; }
    /// <summary>How many values looked like each kind.</summary>
    public Dictionary<PhiKind, int> ContentCounts { get; } = [];
    /// <summary>Masked examples.</summary>
    public List<string> Examples { get; } = [];
    /// <summary>Identifiers found inside free text, cell by cell (up to 200).</summary>
    public List<CellFinding> Findings { get; } = [];
    /// <summary>Identifiers found inside free text, by kind.</summary>
    public Dictionary<PhiKind, int> TextCounts { get; } = [];
    public long RowsRead { get; set; }
    public long? RowsTotal { get; set; }
    public bool Sampled { get; set; }

    /// <summary>"members.csv › last_name", "claims.xlsx › Claims › member_id".</summary>
    public string Display => string.Join(" › ", new[] { Location, Table, Column }.Where(p => p.Length > 0));

    /// <summary>The same, with any part that may be a name masked: what agents see.</summary>
    public string SafeDisplay => string.Join(" › ", new[] { Location, Table, Column }.Where(p => p.Length > 0).Select(Mask.Label));

    public static string MakeKey(string source, string location, string table, string column) => $"{source}|{location}|{table}|{column}";
}

/// <summary>A scan's results: every column of every dataset, what was found, and the problems met.</summary>
public sealed class Inventory
{
    public List<ColumnReport> Columns { get; } = [];
    /// <summary>Datasets that couldn't be read, and why (with names masked).</summary>
    public List<string> Problems { get; } = [];
    public KnownValues Known { get; } = new();
    public SensitiveValues Sensitive { get; } = new();
    public int Datasets { get; set; }
    public long RowsRead { get; set; }
    public DateTime When { get; set; } = DateTime.Now;

    /// <summary>
    /// A column by its id ("c7"), its key, its display path ("members.csv › last_name", with › or /), or its name alone
    /// when only one column has it. Throws, naming the choices, when there's none or more than one.
    /// </summary>
    public ColumnReport Find(string column)
    {
        var c = column.Trim();
        if (Columns.FirstOrDefault(x => x.Id.Equals(c, StringComparison.OrdinalIgnoreCase) || x.Key == c) is { } byId) return byId;
        var path = c.Replace(" / ", " › ").Replace(" > ", " › ");
        var matches = Columns.Where(x => x.Display.Equals(path, StringComparison.OrdinalIgnoreCase) || x.SafeDisplay.Equals(path, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0) matches = Columns.Where(x => x.Display.EndsWith("› " + path, StringComparison.OrdinalIgnoreCase) || x.Column.Equals(path, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 1) return matches[0];
        if (matches.Count > 1)
            throw new ArgumentException($"\"{c}\" is more than one column: {string.Join(", ", matches.Take(12).Select(m => $"{m.Id} ({m.SafeDisplay})"))}. Give its id.");
        throw new ArgumentException(Columns.Count == 0 ? "There's no scan yet: scan first." : $"There's no column \"{c}\". get_inventory lists them with their ids (c1, c2…).");
    }
}

/// <summary>
/// Every sensitive value the scan saw, kept in memory only, never written or shown: so that anything about to reach an
/// agent can be checked for them (<see cref="Redact"/>), and a de-identified copy can be checked for originals left in
/// it (<see cref="Verifier"/>).
/// </summary>
public sealed partial class SensitiveValues
{
    private readonly Dictionary<string, PhiKind> _whole = new(StringComparer.Ordinal);
    private readonly Dictionary<string, PhiKind> _tokens = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> _byFirstToken = new(StringComparer.Ordinal);
    private readonly HashSet<string> _nameWords = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    public int Count { get { lock (_lock) return _whole.Count + _nameWords.Count; } }

    public void Add(PhiKind kind, string? raw)
    {
        var v = raw?.Trim();
        if (string.IsNullOrEmpty(v) || v.Length < 4 && kind != PhiKind.Name) return;
        if (kind is PhiKind.None or PhiKind.Npi or PhiKind.Age) return;
        lock (_lock)
        {
            if (_whole.Count > 400_000) return;
            if (kind == PhiKind.FreeText) return;
            if (kind == PhiKind.Name)
            {
                foreach (var w in Detect.NameWords(v))
                    if (w.Length >= 3 && !Lists.IsCommon(w) && !Lists.PseudoWords.Contains(w)) _nameWords.Add(w);
                if (v.Length < 4) return;
            }
            if (Lists.IsCommon(v)) return;
            _whole.TryAdd(v, kind);
            var tokens = TokenRx().Matches(v).Select(m => m.Value).ToList();
            if (tokens.Count == 1) _tokens.TryAdd(tokens[0], kind);
            else if (tokens.Count > 1)
            {
                if (!_byFirstToken.TryGetValue(tokens[0], out var list)) _byFirstToken[tokens[0]] = list = [];
                if (list.Count < 50) list.Add(v);
            }
        }
    }

    /// <summary>Takes in another set's values (a later scan's), keeping its own.</summary>
    public void Merge(SensitiveValues other)
    {
        if (ReferenceEquals(this, other)) return;
        List<KeyValuePair<string, PhiKind>> whole;
        List<string> words;
        lock (other._lock)
        {
            whole = [.. other._whole];
            words = [.. other._nameWords];
        }
        foreach (var (v, k) in whole) Add(k, v);
        lock (_lock) foreach (var w in words) _nameWords.Add(w);
    }

    /// <summary>Whether a cell holds a value (or a name word) the scan saw as sensitive; the kind it had.</summary>
    public PhiKind? Holds(string text, bool directOnly = true)
    {
        lock (_lock)
        {
            if (_whole.TryGetValue(text.Trim(), out var whole) && (!directOnly || Kinds.Info(whole).Category == KindCategory.Direct)) return whole;
            foreach (Match m in TokenRx().Matches(text))
            {
                if (_tokens.TryGetValue(m.Value, out var k) && (!directOnly || Kinds.Info(k).Category == KindCategory.Direct)) return k;
                if (_byFirstToken.TryGetValue(m.Value, out var longer))
                    foreach (var l in longer)
                        if (text.Contains(l, StringComparison.Ordinal) && _whole.TryGetValue(l, out var lk) && (!directOnly || Kinds.Info(lk).Category == KindCategory.Direct)) return lk;
            }
            foreach (Match m in WordRx().Matches(text))
                if (_nameWords.Contains(m.Value) && char.IsUpper(m.Value[0]) && !Lists.PseudoWords.Contains(m.Value)) return PhiKind.Name;
            return null;
        }
    }

    /// <summary>
    /// <paramref name="text"/> with every sensitive value in it masked, and anything shaped like an SSN, an email
    /// address, a phone number or a full date masked too: the last guard on everything an agent is sent.
    /// </summary>
    public string Redact(string text)
    {
        lock (_lock)
        {
            if (_whole.Count + _nameWords.Count > 0)
            {
                text = TokenRx().Replace(text, m =>
                {
                    if (_tokens.TryGetValue(m.Value, out var k)) return Mask.Value(k, m.Value);
                    return m.Value;
                });
                foreach (var first in TokenRx().Matches(text).Select(m => m.Value).Distinct().ToList())
                    if (_byFirstToken.TryGetValue(first, out var longer))
                        foreach (var l in longer)
                            if (text.Contains(l, StringComparison.Ordinal)) text = text.Replace(l, Mask.Value(_whole[l], l));
                text = WordRx().Replace(text, m => _nameWords.Contains(m.Value) && !Lists.PseudoWords.Contains(m.Value) && char.IsUpper(m.Value[0])
                    ? m.Value[0] + new string('*', m.Length - 1) : m.Value);
            }
        }
        text = SsnShapeRx().Replace(text, m => Mask.Value(PhiKind.Ssn, m.Value));
        text = Detect.EmailRx().Replace(text, m => Mask.Value(PhiKind.Email, m.Value));
        text = EmailInlineRx().Replace(text, m => Mask.Value(PhiKind.Email, m.Value));
        text = PhoneShapeRx().Replace(text, m => Mask.Value(PhiKind.Phone, m.Value));
        text = FullDateRx().Replace(text, m => Detect.TryDate(m.Value, out var d) ? $"{d.Value.Year}-**-**" : m.Value);
        return text;
    }

    [GeneratedRegex(@"[A-Za-z0-9][A-Za-z0-9@._%+'-]*[A-Za-z0-9]|[A-Za-z0-9]")]
    private static partial Regex TokenRx();

    [GeneratedRegex(@"[A-Za-z][A-Za-z'-]{2,}")]
    private static partial Regex WordRx();

    [GeneratedRegex(@"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")]
    private static partial Regex SsnShapeRx();

    [GeneratedRegex(@"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")]
    private static partial Regex EmailInlineRx();

    [GeneratedRegex(@"(?<![\d*#-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?!\d)")]
    private static partial Regex PhoneShapeRx();

    [GeneratedRegex(@"\b(?:\d{4}-\d{2}-\d{2}|\d{4}/\d{2}/\d{2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2}-\d{1,2}-\d{4})\b")]
    private static partial Regex FullDateRx();
}

/// <summary>Decides what a column holds from its header and a sample of its values.</summary>
public static class Classifier
{
    public sealed record Result(PhiKind Kind, double Confidence, string Reason, int Count, Dictionary<PhiKind, int> Counts, bool TextLike);

    /// <summary>Kinds whose look is specific enough to overrule a header that says otherwise.</summary>
    private static bool Specific(PhiKind k) => k is PhiKind.Email or PhiKind.Url or PhiKind.IpAddress or PhiKind.Ssn or PhiKind.Phone
        or PhiKind.Date or PhiKind.StreetAddress or PhiKind.MemberId;

    /// <summary>Whether values that look like <paramref name="content"/> fit a header that names <paramref name="header"/>.</summary>
    private static bool Fits(PhiKind header, PhiKind content) =>
        header == content
        || header == PhiKind.Fax && content == PhiKind.Phone
        || header == PhiKind.BirthDate && content == PhiKind.Date
        || Kinds.IsIdentifier(header) && content is PhiKind.OtherId or PhiKind.Ssn or PhiKind.Npi or PhiKind.AccountNumber or PhiKind.DeviceId or PhiKind.Zip or PhiKind.Age or PhiKind.MemberId or PhiKind.VehicleId or PhiKind.License
        || header == PhiKind.Npi && content is PhiKind.Phone or PhiKind.OtherId
        || header == PhiKind.Name && content == PhiKind.City
        || header == PhiKind.City && content == PhiKind.Name
        || header == PhiKind.Age && content == PhiKind.Zip;

    public static Result Classify(string header, IReadOnlyList<string> values)
    {
        var n = values.Count;
        var hint = HeaderHints.Of(header);
        var counts = new Dictionary<PhiKind, int>();
        var strengths = new Dictionary<PhiKind, double>();
        double length = 0, words = 0;
        foreach (var v in values)
        {
            length += v.Length;
            words += v.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;
            foreach (var hit in Detect.Value(v))
            {
                counts[hit.Kind] = counts.GetValueOrDefault(hit.Kind) + 1;
                strengths[hit.Kind] = strengths.GetValueOrDefault(hit.Kind) + hit.Strength;
            }
        }
        var textLike = n > 0 && length / n >= 25 && words / n >= 4 || hint?.Kind == PhiKind.FreeText && n > 0 && length / n >= 8;
        if (textLike)
            return new Result(PhiKind.FreeText, hint?.Kind == PhiKind.FreeText ? 0.9 : 0.6, hint?.Kind == PhiKind.FreeText ? $"free text ({hint.Value.Why})" : "free text (long values of several words)", 0, counts, true);

        (PhiKind Kind, double Score) best = (PhiKind.None, 0);
        foreach (var (k, c) in counts)
        {
            var score = n == 0 ? 0 : (double)c / n * (strengths[k] / c);
            if (score > best.Score) best = (k, score);
        }
        string Share(PhiKind k) => $"{counts.GetValueOrDefault(k)} of {n} values look like {Kinds.Label(k).ToLowerInvariant()}s";

        if (hint is { NotPhi: true } notPhi)
        {
            if (best.Score >= 0.75 && Specific(best.Kind))
                return new Result(best.Kind, Math.Round(best.Score * 0.9, 2), $"{Share(best.Kind)}, though {notPhi.Why}", counts.GetValueOrDefault(best.Kind), counts, false);
            return new Result(PhiKind.None, notPhi.Confidence, notPhi.Why, 0, counts, false);
        }
        if (hint is { } h)
        {
            if (best.Kind == PhiKind.None || best.Score < 0.3)
            {
                var conf = n == 0 ? h.Confidence * 0.7 : h.Confidence * (best.Kind == PhiKind.None ? 0.85 : 0.8);
                if (h.Kind == PhiKind.Date && n > 0 && counts.GetValueOrDefault(PhiKind.Date) == 0) conf *= 0.6;
                return new Result(h.Kind, Math.Round(conf, 2), $"{h.Why}{(n == 0 ? " (no values to check)" : "")}", n, counts, false);
            }
            if (Fits(h.Kind, best.Kind))
                return new Result(h.Kind, Math.Round(1 - (1 - h.Confidence) * (1 - best.Score), 2), $"{h.Why}, and {Share(best.Kind)}", n, counts, false);
            if (best.Score >= 0.7 && Specific(best.Kind))
                return new Result(best.Kind, Math.Round(best.Score * 0.9, 2), $"{Share(best.Kind)} (the header suggested {Kinds.Label(h.Kind).ToLowerInvariant()})", counts[best.Kind], counts, false);
            return new Result(h.Kind, Math.Round(h.Confidence * 0.8, 2), $"{h.Why} ({Share(best.Kind)})", n, counts, false);
        }
        if (best.Score >= 0.3)
            return new Result(best.Kind, Math.Round(best.Score, 2), Share(best.Kind), counts[best.Kind], counts, false);
        return new Result(PhiKind.None, Math.Round(n == 0 ? 0.5 : 1 - best.Score, 2), n == 0 ? "empty in the sample" : "nothing identifying in the header or the values", 0, counts, false);
    }
}

/// <summary>
/// Scans a project's sources: reads each dataset (up to its sample limit), classifies every column, finds identifiers
/// inside free text (using the names and identifiers found in the structured columns), and keeps masked examples.
/// </summary>
public static class Scanner
{
    /// <summary>How many values of a column are looked at to classify it.</summary>
    public const int ValuesPerColumn = 2000;

    /// <summary>How many findings are kept per free-text column.</summary>
    public const int FindingsPerColumn = 200;

    public static Inventory Scan(Project project, string root, Func<string, Sources.ConnectionInfo?>? connections = null, IProgress<string>? progress = null, CancellationToken cancel = default, string? skip = null)
    {
        var inventory = new Inventory();
        var tables = new List<TableData>();
        foreach (var source in project.Sources)
        {
            List<Dataset> datasets;
            try
            {
                datasets = Sources.Expand(source, root, connections, skip ?? (project.Output is { Length: > 0 } o ? Sources.Full(root, o) : null));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.Data.Common.DbException)
            {
                inventory.Problems.Add($"Source {source.Id}: {Safe(e)}");
                continue;
            }
            foreach (var d in datasets)
            {
                cancel.ThrowIfCancellationRequested();
                progress?.Report($"Reading {Mask.Label(d.Display)}…");
                try
                {
                    tables.Add(Sources.Read(d, Math.Max(1, project.SampleRows)));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or FormatException or System.Text.Json.JsonException or System.Data.Common.DbException or InvalidDataException)
                {
                    inventory.Problems.Add($"{Mask.Label(d.Display)}: {Safe(e)}");
                }
            }
        }
        inventory.Datasets = tables.Count;
        inventory.RowsRead = tables.Sum(t => (long)t.Rows.Count);

        // First the structured columns, so free text can be checked for the names and identifiers found in them.
        var pending = new List<(ColumnReport Report, TableData Table, int Index)>();
        foreach (var t in tables)
        {
            for (var c = 0; c < t.Columns.Count; c++)
            {
                cancel.ThrowIfCancellationRequested();
                var d = t.Dataset;
                var report = new ColumnReport
                {
                    Key = ColumnReport.MakeKey(d.Source.Id, d.Location, d.Table, t.Columns[c]),
                    SourceId = d.Source.Id, Location = d.Location, Table = d.Table, Column = t.Columns[c], Format = d.Format,
                    RowsRead = t.Rows.Count, RowsTotal = t.TotalRows, Sampled = t.Sampled,
                };
                var values = Values(t, c, ValuesPerColumn);
                var r = Classifier.Classify(t.Columns[c], values);
                report.Detected = r.Kind;
                report.Confidence = r.Confidence;
                report.Reason = r.Reason;
                report.Values = values.Count;
                report.Count = r.Count;
                foreach (var (k, v) in r.Counts) report.ContentCounts[k] = v;
                inventory.Columns.Add(report);
                pending.Add((report, t, c));
            }
        }
        foreach (var (report, t, c) in pending)
        {
            var kind = project.EffectiveKind(report.Key, report.Detected);
            if (kind == PhiKind.Name) foreach (var v in Values(t, c, int.MaxValue)) inventory.Known.AddName(v);
            else if (Kinds.IsIdentifier(kind)) foreach (var v in Values(t, c, int.MaxValue)) inventory.Known.AddId(v, kind);
        }
        foreach (var (report, t, c) in pending)
        {
            cancel.ThrowIfCancellationRequested();
            var kind = project.EffectiveKind(report.Key, report.Detected);
            var values = Values(t, c, int.MaxValue);
            if (report.Detected == PhiKind.FreeText || kind == PhiKind.FreeText)
                ScanText(report, t, c, inventory);
            else if (report.Detected == PhiKind.None && kind == PhiKind.None && values.Any(v => v.Contains(' ') && v.Any(char.IsLetter)))
            {
                // Short text that isn't classified: identifiers stray into comment-like columns.
                ScanText(report, t, c, inventory);
                if (report.Count > 0)
                {
                    report.Detected = PhiKind.FreeText;
                    report.Confidence = Math.Round(Math.Min(0.9, 0.3 + (double)report.Count / Math.Max(1, report.Values)), 2);
                    report.Reason = $"short text, {report.Count} of {report.Values} values with identifiers in them";
                }
                else report.Findings.Clear();
            }
            if (report.Detected != PhiKind.FreeText)
            {
                foreach (var v in values.Distinct().Take(3)) report.Examples.Add(Mask.Value(kind, v));
                if (kind is PhiKind.Age) report.Over89 = values.Count(v => int.TryParse(v, out var a) && a > 89);
                if (kind is PhiKind.BirthDate) report.Over89 = values.Count(v => Detect.TryDate(v, out var d) && Ages.Years(d.Value, DateTime.Today) > 89);
            }
            if (Kinds.IsPhi(kind) || Kinds.IsPhi(report.Detected))
                foreach (var v in values) inventory.Sensitive.Add(kind == PhiKind.None ? report.Detected : kind, v);
        }
        for (var i = 0; i < inventory.Columns.Count; i++) inventory.Columns[i].Id = $"c{i + 1}";
        return inventory;
    }

    private static void ScanText(ColumnReport report, TableData t, int c, Inventory inventory)
    {
        var withFindings = 0;
        for (var r = 0; r < t.Rows.Count; r++)
        {
            if (t.Rows[r][c] is not { Length: > 0 } text) continue;
            var findings = TextScan.Find(text, inventory.Known);
            if (findings.Count == 0) continue;
            withFindings++;
            if (report.Examples.Count < 2) report.Examples.Add(Mask.Text(text, inventory.Known, 160));
            foreach (var f in findings)
            {
                report.TextCounts[f.Kind] = report.TextCounts.GetValueOrDefault(f.Kind) + 1;
                if (report.Findings.Count < FindingsPerColumn) report.Findings.Add(new CellFinding((t.Records.Count > r ? t.Records[r] : r) + 1, f.Kind, Mask.Value(f.Kind, f.Value)));
                if (f.Kind != PhiKind.Npi) inventory.Sensitive.Add(f.Kind, f.Value);
                if (f.Kind == PhiKind.Name) inventory.Known.AddName(f.Value);
            }
        }
        report.Count = withFindings;
        if (report.Detected == PhiKind.FreeText)
        {
            report.Reason += withFindings > 0
                ? $"; {withFindings} of {report.Values} values hold identifiers ({string.Join(", ", report.TextCounts.OrderByDescending(x => x.Value).Select(x => $"{x.Value} {Kinds.Label(x.Key).ToLowerInvariant()}"))})"
                : "; no identifiers found in the sample";
            if (withFindings > 0 && report.Confidence < 0.9) report.Confidence = Math.Round(Math.Min(0.9, report.Confidence + 0.2), 2);
        }
    }

    private static List<string> Values(TableData t, int c, int limit)
    {
        var list = new List<string>();
        foreach (var row in t.Rows)
        {
            if (c < row.Length && row[c] is { Length: > 0 } v) list.Add(v);
            if (list.Count >= limit) break;
        }
        return list;
    }

    /// <summary>An error's message with anything that looks like a value masked.</summary>
    public static string Safe(Exception e) => Safe(e.Message);

    public static string Safe(string message)
    {
        var s = new SensitiveValues().Redact(message);
        return Regex.Replace(s, @"'[^']{1,80}'|""[^""]{1,80}""", m => m.Value[0] + Mask.Label(m.Value[1..^1]) + m.Value[^1]);
    }
}

/// <summary>Working out ages.</summary>
public static class Ages
{
    public static int Years(DateTime born, DateTime on)
    {
        var years = on.Year - born.Year;
        if (on.Month < born.Month || on.Month == born.Month && on.Day < born.Day) years--;
        return years;
    }
}
