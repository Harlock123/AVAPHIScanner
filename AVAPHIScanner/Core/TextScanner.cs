using System.Text.RegularExpressions;

namespace AVAPHIScanner;

/// <summary>An identifier found inside free text: where it is, what kind, and the text itself (never shown to agents).</summary>
public sealed record TextFinding(int Start, int Length, PhiKind Kind, string Value)
{
    public int End => Start + Length;
}

/// <summary>
/// Values the scan found in structured columns, so free text can be checked for them too: the words of names in name
/// columns ("a note mentions Lopez") and identifiers in ID columns ("member M10023 called").
/// </summary>
public sealed class KnownValues
{
    public HashSet<string> NameWords { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, PhiKind> Ids { get; } = new(StringComparer.Ordinal);

    /// <summary>Notes the words of a name found in a name column.</summary>
    public void AddName(string name)
    {
        foreach (var w in Detect.NameWords(name))
            if (w.Length >= 3 && !Lists.IsCommon(w) && NameWords.Count < 200_000) NameWords.Add(w);
    }

    public void AddId(string id, PhiKind kind)
    {
        var n = Tokens.Normalise(id);
        if (n.Length >= 4 && Ids.Count < 500_000) Ids.TryAdd(n, kind);
    }

    public static readonly KnownValues Empty = new();
}

/// <summary>
/// Finds identifiers inside free text (clinical notes, comments): SSNs, phone and fax numbers, email and web addresses,
/// IP addresses, dates (birth dates by what's written before them), ages over 89, ZIP codes after a state, street
/// addresses and the city after them, identifiers after a label ("MRN: …", "Member ID …") or known from the scan, and
/// names: after a title ("Mr.", "Dr.", "Patient"), a first and last name together, "Last, First", or a name word the
/// scan found in a name column. Detection is an aid: a name nobody has written down anywhere else may be missed.
/// </summary>
public static partial class TextScan
{
    public static List<TextFinding> Find(string text, KnownValues? known = null)
    {
        known ??= KnownValues.Empty;
        var found = new List<(TextFinding F, int Priority)>();
        void Add(int start, int length, PhiKind kind, int priority)
        {
            if (length <= 0) return;
            found.Add((new TextFinding(start, length, kind, text.Substring(start, length)), priority));
        }

        foreach (Match m in EmailRx().Matches(text)) Add(m.Index, m.Length, PhiKind.Email, 9);
        foreach (Match m in UrlRx().Matches(text)) Add(m.Index, m.Length, PhiKind.Url, 9);
        foreach (Match m in Ipv4Rx().Matches(text))
            if (Detect.IsIp(m.Value)) Add(m.Index, m.Length, PhiKind.IpAddress, 8);
        foreach (Match m in SsnRx().Matches(text))
            if (Detect.ValidSsn(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value)) Add(m.Index, m.Length, PhiKind.Ssn, 9);
        foreach (Match m in SsnLabelRx().Matches(text))
            if (Detect.Ssn(m.Groups[1].Value)) Add(m.Groups[1].Index, m.Groups[1].Length, PhiKind.Ssn, 9);
        foreach (Match m in PhoneRx().Matches(text))
        {
            var before = text[Math.Max(0, m.Index - 14)..m.Index];
            Add(m.Index, m.Length, before.Contains("fax", StringComparison.OrdinalIgnoreCase) ? PhiKind.Fax : PhiKind.Phone, 8);
        }
        foreach (Match m in DateRx().Matches(text))
        {
            if (!Detect.TryDate(m.Value, out _)) continue;
            var before = text[Math.Max(0, m.Index - 28)..m.Index];
            Add(m.Index, m.Length, BirthRx().IsMatch(before) ? PhiKind.BirthDate : PhiKind.Date, 7);
        }
        foreach (Regex rx in new[] { AgeYearsRx(), AgeLabelRx(), AgeYoRx() })
            foreach (Match m in rx.Matches(text))
                if (int.TryParse(m.Groups[1].Value, out var age) && age is > 89 and < 130)
                    Add(m.Groups[1].Index, m.Groups[1].Length, PhiKind.Age, 6);
        foreach (Match m in ZipAfterStateRx().Matches(text)) Add(m.Groups[1].Index, m.Groups[1].Length, PhiKind.Zip, 6);
        foreach (Match m in ZipLabelRx().Matches(text)) Add(m.Groups[1].Index, m.Groups[1].Length, PhiKind.Zip, 6);
        foreach (Match m in AddressRx().Matches(text))
        {
            Add(m.Index, m.Length, PhiKind.StreetAddress, 8);
            if (CityAfterRx().Match(text, m.Index + m.Length) is { Success: true } c && c.Index == m.Index + m.Length)
                Add(c.Groups[1].Index, c.Groups[1].Length, PhiKind.City, 6);
        }
        foreach (Match m in PoBoxRx().Matches(text)) Add(m.Index, m.Length, PhiKind.StreetAddress, 8);
        foreach (Match m in CityContextRx().Matches(text))
            if (Lists.Cities.Contains(m.Groups[1].Value.ToUpperInvariant())) Add(m.Groups[1].Index, m.Groups[1].Length, PhiKind.City, 4);
        foreach (Match m in LabelledIdRx().Matches(text))
        {
            var kind = LabelKind(m.Groups[1].Value);
            var v = m.Groups[2];
            if (kind == PhiKind.Npi && !Detect.Npi(v.Value)) continue;
            if (v.Value.Any(char.IsAsciiDigit)) Add(v.Index, v.Length, kind, 9);
        }
        foreach (Match m in TokenRx().Matches(text))
        {
            var t = m.Value;
            if (known.Ids.TryGetValue(Tokens.Normalise(t), out var kind)) Add(m.Index, m.Length, kind, 9);
            else if (t.Length == 11 && Detect.Mbi(t)) Add(m.Index, m.Length, PhiKind.MemberId, 8);
            else if (t.Length == 17 && Detect.Vin(t) == true) Add(m.Index, m.Length, PhiKind.VehicleId, 8);
        }
        foreach (Match m in NameLabelRx().Matches(text)) AddName(m.Groups[1], 9);
        foreach (Match m in TitleNameRx().Matches(text)) AddName(m.Groups[1], 8);
        foreach (Match m in FirstLastRx().Matches(text))
        {
            var first = m.Groups[1].Value.ToUpperInvariant();
            var last = m.Groups[2].Value.ToUpperInvariant();
            if (Lists.IsFirst(first) && !Lists.IsCommon(first) && (Lists.IsLast(last) || known.NameWords.Contains(last)) && !Lists.IsCommon(last))
                Add(m.Index, m.Length, PhiKind.Name, 7);
        }
        foreach (Match m in LastCommaFirstRx().Matches(text))
        {
            var last = m.Groups[1].Value.ToUpperInvariant();
            var first = m.Groups[2].Value.ToUpperInvariant();
            if ((Lists.IsLast(last) || known.NameWords.Contains(last)) && Lists.IsFirst(first) && !Lists.IsCommon(last))
                Add(m.Index, m.Length, PhiKind.Name, 7);
        }
        if (known.NameWords.Count > 0)
            foreach (Match m in CapitalisedRx().Matches(text))
            {
                var w = new string(m.Value.Where(char.IsLetter).ToArray()).ToUpperInvariant();
                if (w.Length >= 3 && known.NameWords.Contains(w) && !Lists.IsCommon(w)) Add(m.Index, m.Length, PhiKind.Name, 5);
            }

        // Where findings overlap, the more certain (then the longer) wins.
        var kept = new List<TextFinding>();
        foreach (var (f, _) in found.OrderByDescending(x => x.Priority).ThenByDescending(x => x.F.Length).ThenBy(x => x.F.Start))
            if (!kept.Any(k => f.Start < k.End && k.Start < f.End)) kept.Add(f);
        return [.. kept.OrderBy(k => k.Start)];

        void AddName(Group g, int priority)
        {
            // A title's name runs on to the first ordinary word ("Mr. Smith reports…" stops before "reports").
            var words = WordRx().Matches(g.Value).Cast<Match>().ToList();
            var take = 0;
            foreach (var w in words)
            {
                if (Lists.IsCommon(w.Value.TrimEnd('.')) && w.Value.Length > 2) break;
                take++;
            }
            if (take == 0) return;
            var end = words[take - 1].Index + words[take - 1].Length;
            Add(g.Index, end, PhiKind.Name, priority);
        }
    }

    private static PhiKind LabelKind(string label)
    {
        var l = label.ToLowerInvariant();
        if (l.StartsWith("mrn") || l.StartsWith("medical") || l.StartsWith("patient") || l.StartsWith("chart")) return PhiKind.Mrn;
        if (l.StartsWith("member") || l.StartsWith("subscriber") || l.StartsWith("mbi") || l.StartsWith("medicaid") || l.StartsWith("medicare") || l.StartsWith("policy")) return PhiKind.MemberId;
        if (l.StartsWith("acct") || l.StartsWith("account")) return PhiKind.AccountNumber;
        if (l.StartsWith("claim") || l.StartsWith("encounter")) return PhiKind.ClaimNumber;
        if (l.StartsWith("npi")) return PhiKind.Npi;
        if (l.StartsWith("dea") || l.StartsWith("licen")) return PhiKind.License;
        if (l.StartsWith("vin")) return PhiKind.VehicleId;
        if (l.StartsWith("serial") || l.StartsWith("device")) return PhiKind.DeviceId;
        return PhiKind.OtherId;
    }

    [GeneratedRegex(@"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")]
    private static partial Regex EmailRx();

    [GeneratedRegex(@"\b(?:https?://|www\.)[^\s<>""')\]]+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRx();

    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")]
    private static partial Regex Ipv4Rx();

    [GeneratedRegex(@"(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)")]
    private static partial Regex SsnRx();

    [GeneratedRegex(@"\b(?:SSN|SS#|Social Security(?: No\.?| Number| #)?)\s*[:#]?\s*(\d{9}|\d{3}[- ]\d{2}[- ]\d{4})\b", RegexOptions.IgnoreCase)]
    private static partial Regex SsnLabelRx();

    [GeneratedRegex(@"(?<![\d-])(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)\s?|[2-9]\d{2}[\s.-])[2-9]\d{2}[\s.-]\d{4}(?!\d)")]
    private static partial Regex PhoneRx();

    [GeneratedRegex(@"\b(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?|\d{1,2}/\d{1,2}/(?:\d{4}|\d{2})|\d{1,2}-\d{1,2}-\d{4}|\d{1,2}[- ](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[- ]\d{4}|(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4})\b")]
    private static partial Regex DateRx();

    [GeneratedRegex(@"(?:\bDOB|\bD\.O\.B\.?|\bborn|\bbirth(?:date|day)?|\bdate of birth)\W*(?:on\W*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex BirthRx();

    [GeneratedRegex(@"\b(\d{1,3})[- ]?(?:year|yr)s?[- ]old\b", RegexOptions.IgnoreCase)]
    private static partial Regex AgeYearsRx();

    [GeneratedRegex(@"\b(?:age|aged)\s*:?\s*(\d{1,3})\b", RegexOptions.IgnoreCase)]
    private static partial Regex AgeLabelRx();

    [GeneratedRegex(@"\b(\d{2,3})\s?(?:y/o|yo|y\.o\.)", RegexOptions.IgnoreCase)]
    private static partial Regex AgeYoRx();

    [GeneratedRegex(@"\b(?:A[LKZR]|C[AOT]|D[EC]|FL|GA|HI|I[DLNA]|K[SY]|LA|M[EDAINSOT]|N[EVHJMYCD]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[TA]|W[AVIY]|PR)\s+(\d{5}(?:-\d{4})?)\b")]
    private static partial Regex ZipAfterStateRx();

    [GeneratedRegex(@"\bZIP(?:\s*code)?\s*[:#]?\s*(\d{5}(?:-\d{4})?)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ZipLabelRx();

    [GeneratedRegex(@"\b\d{1,6}[A-Za-z]?\s+(?:[NSEW]\.?\s+)?(?:[A-Z][A-Za-z'.-]*\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Trail|Trl)\b\.?(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9-]+)?")]
    private static partial Regex AddressRx();

    [GeneratedRegex(@"\G,\s*([A-Z][a-z]+(?:[ -][A-Z][a-z]+)?),\s*[A-Z]{2}\b")]
    private static partial Regex CityAfterRx();

    [GeneratedRegex(@"\bP\.?\s*O\.?\s*Box\s+\d+\b", RegexOptions.IgnoreCase)]
    private static partial Regex PoBoxRx();

    [GeneratedRegex(@"\b(?:in|from|near|to|at|of)\s+([A-Z][a-z]+(?: [A-Z][a-z]+)?)\b")]
    private static partial Regex CityContextRx();

    [GeneratedRegex(@"\b((?i:MRN|Medical Record(?: No\.?| Number| #)?|Chart(?: No\.?| Number| #)?|Patient ID|Member(?: ID| No\.?| Number| #)|Subscriber(?: ID| No\.?| Number)?|MBI|Medicaid(?: ID| No\.?)?|Medicare(?: ID| No\.?)?|Policy(?: ID| No\.?| Number| #)|Acct\.?(?: No\.?| Number| #)?|Account(?: No\.?| Number| #)|Claim(?: ID| No\.?| Number| #)|Encounter(?: ID| No\.?)|NPI|DEA(?: No\.?| #)?|Licen[cs]e(?: No\.?| Number| #)|VIN|Serial(?: No\.?| Number| #)|Device ID))\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9-]{3,})")]
    private static partial Regex LabelledIdRx();

    [GeneratedRegex(@"(?<![A-Za-z0-9-])[A-Za-z0-9][A-Za-z0-9-]{3,}(?![A-Za-z0-9-])")]
    private static partial Regex TokenRx();

    [GeneratedRegex(@"\b(?:Patient Name|Member Name|Name)\s*:\s*([A-Z][A-Za-z'-]+(?:,?\s+[A-Z][A-Za-z'.-]*){0,3})")]
    private static partial Regex NameLabelRx();

    [GeneratedRegex(@"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Doctor|Nurse|Patient|Pt)\.?\s+((?:[A-Z][a-zA-Z'-]+|[A-Z]\.)(?:\s+(?:[A-Z][a-zA-Z'-]+|[A-Z]\.)){0,2})")]
    private static partial Regex TitleNameRx();

    [GeneratedRegex(@"\b([A-Z][a-z'-]+|[A-Z]{2,})(?:\s+[A-Z]\.?)?\s+([A-Z][a-z'-]+|[A-Z]{2,})\b")]
    private static partial Regex FirstLastRx();

    [GeneratedRegex(@"\b([A-Z][a-z'-]+|[A-Z]{2,}),\s+([A-Z][a-z'-]+|[A-Z]{2,})\b")]
    private static partial Regex LastCommaFirstRx();

    [GeneratedRegex(@"\b[A-Z][a-zA-Z'-]{2,}\b")]
    private static partial Regex CapitalisedRx();

    [GeneratedRegex(@"[A-Za-z][A-Za-z'.-]*")]
    private static partial Regex WordRx();
}
