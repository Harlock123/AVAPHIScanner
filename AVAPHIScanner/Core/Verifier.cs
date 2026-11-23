namespace AVAPHIScanner;

/// <summary>Something left in a de-identified copy that the policy says shouldn't be there.</summary>
public sealed record Leftover(string Where, PhiKind Kind, int Count, List<string> Examples, string Why);

/// <summary>What re-scanning a de-identified copy found.</summary>
public sealed class VerifyResult
{
    public List<Leftover> Leftovers { get; } = [];
    /// <summary>What the source scan found, by kind (columns' values, and identifiers inside free text).</summary>
    public Dictionary<PhiKind, int> Before { get; } = [];
    /// <summary>What's left in the copy, by kind.</summary>
    public Dictionary<PhiKind, int> After { get; } = [];
    /// <summary>Values the policy keeps on purpose (shifted dates, a limited data set's ZIP codes…), by kind.</summary>
    public Dictionary<PhiKind, int> Expected { get; } = [];
    /// <summary>Values the copy has that the source scan saw as sensitive: originals that got through.</summary>
    public int Originals { get; set; }
    public int Datasets { get; set; }
    public long Rows { get; set; }
    public List<string> Problems { get; } = [];
    public string Policy { get; set; } = "";

    public bool Clean => Leftovers.Count == 0 && Problems.Count == 0;

    public string Summary => Clean
        ? $"Clean: nothing the policy removes was found in {Datasets} dataset{(Datasets == 1 ? "" : "s")} ({Rows} rows read)." +
          (Expected.Count > 0 ? " Kept by the policy: " + string.Join(", ", Expected.Select(e => $"{e.Value} {Kinds.Label(e.Key).ToLowerInvariant()}")) + "." : "")
        : $"{Leftovers.Sum(l => l.Count)} value{(Leftovers.Sum(l => l.Count) == 1 ? "" : "s")} left in {Leftovers.Select(l => l.Where).Distinct().Count()} place{(Leftovers.Select(l => l.Where).Distinct().Count() == 1 ? "" : "s")}" +
          (Originals > 0 ? $", {Originals} of them original values from the source" : "") + (Problems.Count > 0 ? $"; {Problems.Count} problem{(Problems.Count == 1 ? "" : "s")} reading the copy" : "") + ".";
}

/// <summary>
/// Checks a de-identified copy: scans it as a new source, then looks at every value the scan calls PHI and asks
/// whether it is a stand-in (a token, a made-up name, a marker, a three-digit ZIP, 90+, a year) or something the
/// policy keeps (shifted dates, a limited data set's dates, city and ZIP); anything else is left over. Every value is
/// also checked against the originals the source scan saw, which catches what the detectors alone would miss.
/// </summary>
public static class Verifier
{
    public static VerifyResult Verify(string output, Policy policy, Inventory? source = null, Func<string, Sources.ConnectionInfo?>? connections = null, CancellationToken cancel = default)
    {
        var project = new Project { Policy = policy, SampleRows = 1_000_000 };
        project.AddSource(new SourceSpec { Kind = Directory.Exists(output) ? "folder" : "file", Path = Path.GetFullPath(output) });
        var scan = Scanner.Scan(project, Path.GetDirectoryName(Path.GetFullPath(output)) ?? ".", connections, cancel: cancel);
        var result = new VerifyResult { Datasets = scan.Datasets, Rows = scan.RowsRead, Policy = policy.Describe() };
        result.Problems.AddRange(scan.Problems);
        if (source != null)
            foreach (var c in source.Columns)
            {
                if (c.Detected == PhiKind.FreeText)
                    foreach (var (k, n) in c.TextCounts) result.Before[k] = result.Before.GetValueOrDefault(k) + n;
                else if (Kinds.IsPhi(c.Detected)) result.Before[c.Detected] = result.Before.GetValueOrDefault(c.Detected) + c.Count;
            }

        // The values are read again here (the scan keeps masked examples only).
        foreach (var dataset in project.Sources.SelectMany(s => Sources.Expand(s, ".", connections)))
        {
            cancel.ThrowIfCancellationRequested();
            TableData t;
            try { t = Sources.Read(dataset, 1_000_000); }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException or System.Data.Common.DbException or InvalidOperationException)
            {
                result.Problems.Add($"{Mask.Label(dataset.Display)}: {Scanner.Safe(e)}");
                continue;
            }
            for (var c = 0; c < t.Columns.Count; c++)
            {
                var report = scan.Columns.FirstOrDefault(r => r.Location == dataset.Location && r.Table == dataset.Table && r.Column == t.Columns[c]);
                var kind = report?.Detected ?? PhiKind.None;
                var where = string.Join(" › ", new[] { dataset.Location, dataset.Table, t.Columns[c] }.Where(p => p.Length > 0));
                var left = new Dictionary<PhiKind, (int Count, List<string> Examples, string Why)>();
                void Note(PhiKind k, string value, string why)
                {
                    (int Count, List<string> Examples, string Why) e = left.TryGetValue(k, out var had) ? had : (0, new List<string>(), why);
                    if (e.Examples.Count < 3) e.Examples.Add(value.Length > 40 && value.Contains(' ') ? Mask.Text(value, source?.Known, 120) : Mask.Value(k, value));
                    left[k] = (e.Count + 1, e.Examples, e.Why);
                }
                foreach (var row in t.Rows)
                {
                    if (c >= row.Length || row[c] is not { Length: > 0 } v) continue;
                    if (source?.Sensitive.Holds(v) is { } original && !(original == PhiKind.Name && Detect.NameWords(v) is { Count: > 0 } nw && nw.All(w => Lists.PseudoWords.Contains(w) || Deidentifier.Keep.Contains(w))))
                    {
                        // Whole values and words: a name inside text is reported by the text check below too, so once is enough.
                        Note(original, v, "an original value from the source");
                        result.Originals++;
                        continue;
                    }
                    if (kind == PhiKind.FreeText || kind == PhiKind.None && v.Contains(' '))
                    {
                        foreach (var f in TextScan.Find(v, source?.Known))
                            switch (Judge(f.Kind, f.Value, policy))
                            {
                                case Verdict.Left: Note(f.Kind, f.Value, "an identifier inside text"); break;
                                case Verdict.Kept: result.Expected[f.Kind] = result.Expected.GetValueOrDefault(f.Kind) + 1; break;
                            }
                        continue;
                    }
                    if (kind == PhiKind.None) continue;
                    switch (Judge(kind, v, policy))
                    {
                        case Verdict.Left: Note(kind, v, $"a {Kinds.Label(kind).ToLowerInvariant()} the policy removes"); break;
                        case Verdict.Kept: result.Expected[kind] = result.Expected.GetValueOrDefault(kind) + 1; break;
                    }
                }
                foreach (var (k, (count, examples, why)) in left)
                {
                    result.Leftovers.Add(new Leftover(Mask.Label(where), k, count, examples, why));
                    result.After[k] = result.After.GetValueOrDefault(k) + count;
                }
            }
        }
        return result;
    }

    public enum Verdict { Replaced, Kept, Left }

    /// <summary>Whether a value the scan calls <paramref name="kind"/> is a stand-in, kept by the policy, or left over.</summary>
    public static Verdict Judge(PhiKind kind, string value, Policy policy)
    {
        var v = value.Trim();
        if (Deidentifier.Markers.Contains(v) || Tokens.IsToken(v)) return Verdict.Replaced;
        var lds = policy.Kind == PolicyKind.LimitedDataSet;
        switch (kind)
        {
            case PhiKind.None or PhiKind.Npi or PhiKind.FreeText:
                return Verdict.Replaced;
            case PhiKind.Name:
                var words = Detect.NameWords(v).Where(w => !Deidentifier.Keep.Contains(w)).ToList();
                return words.Count > 0 && words.All(w => Lists.PseudoWords.Contains(w)) ? Verdict.Replaced : Verdict.Left;
            case PhiKind.Zip:
                if (v.Length == 3 && v.All(char.IsAsciiDigit)) return Verdict.Replaced;
                return lds ? Verdict.Kept : Verdict.Left;
            case PhiKind.City:
                return lds ? Verdict.Kept : Verdict.Left;
            case PhiKind.Age:
                if (v == "90+") return Verdict.Replaced;
                return int.TryParse(v, out var age) && age > 89 && !lds ? Verdict.Left : Verdict.Replaced;
            case PhiKind.BirthDate or PhiKind.Date:
                if (v.Length == 4 && v.All(char.IsAsciiDigit)) return Verdict.Replaced;
                if (!Detect.TryDate(v, out _)) return Verdict.Replaced;
                return lds || policy.DateMode == DateMode.Shift ? Verdict.Kept : Verdict.Left;
            default:
                return Verdict.Left;
        }
    }
}
