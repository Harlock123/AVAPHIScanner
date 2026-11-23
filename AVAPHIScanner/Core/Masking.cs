using System.Text;
using System.Text.RegularExpressions;

namespace AVAPHIScanner;

/// <summary>
/// The only way a value leaves the program towards an AI agent, a picture or the report: masked. Names keep their
/// initials ("J*** S****"), identifiers their last few characters where the kind allows ("***-**-1234"), dates their
/// year ("1957-**-**"), and values that aren't PHI only their shape ("999.99", "Aaaaaa"). Free text is masked where
/// identifiers were found, and then every digit and every capitalised word that isn't an ordinary word is masked as
/// well, so a name the detectors missed still doesn't get through.
/// </summary>
public static partial class Mask
{
    /// <summary><paramref name="raw"/> masked as a value of <paramref name="kind"/>.</summary>
    public static string Value(PhiKind kind, string? raw)
    {
        if (raw is null) return "";
        var v = raw.Trim();
        if (v.Length == 0) return "";
        switch (kind)
        {
            case PhiKind.None:
                return Shape(v);
            case PhiKind.Name or PhiKind.City:
                return Initials(DigitRx().Replace(v, m => new string('#', m.Length)));
            case PhiKind.StreetAddress:
                return Initials(DigitRx().Replace(v, m => new string('#', m.Length)), keep: StreetWords);
            case PhiKind.Zip:
                var zip = new string(v.Where(char.IsAsciiDigit).ToArray());
                return zip.Length >= 5 ? zip[..3] + "**" : new string('*', v.Length);
            case PhiKind.BirthDate or PhiKind.Date:
                return Detect.TryDate(v, out var d) ? $"{d.Value.Year}-**-**" : Digits(v, 0, '*');
            case PhiKind.Age:
                return int.TryParse(v, out var age) && age > 89 ? "90+" : "**";
            case PhiKind.Phone or PhiKind.Fax:
                return Digits(v, 2, '*');
            case PhiKind.Ssn:
                return Digits(v, 4, '*');
            case PhiKind.Email:
                var at = v.IndexOf('@');
                var dot = v.LastIndexOf('.');
                return at > 0 && dot > at ? $"{v[0]}***@***{v[dot..]}" : "***@***";
            case PhiKind.Url:
                var scheme = v.IndexOf("://", StringComparison.Ordinal);
                return (scheme > 0 ? v[..(scheme + 3)] : "") + "***";
            case PhiKind.IpAddress:
                return v.Contains(':') ? "****:****:…" : "***.***.***.***";
            case PhiKind.Biometric:
                var ext = Path.GetExtension(v);
                return "*****" + (ext.Length is > 1 and < 6 ? ext : "");
            case PhiKind.FreeText:
                return Text(v);
            default:
                // Identifiers: their last two characters, when that leaves most of them hidden.
                return Chars(v, v.Length >= 6 ? 2 : 0);
        }
    }

    /// <summary>A value's shape: digits 9, capitals A, small letters a, everything else as it is. Long values are cut.</summary>
    public static string Shape(string v)
    {
        var s = new StringBuilder(Math.Min(v.Length, 40));
        foreach (var c in v.Take(40))
            s.Append(char.IsDigit(c) ? '9' : char.IsUpper(c) ? 'A' : char.IsLetter(c) ? 'a' : c);
        if (v.Length > 40) s.Append('…');
        return s.ToString();
    }

    /// <summary>
    /// Free text masked for an agent: each finding as its kind masks it, then every remaining digit and every capitalised
    /// or upper-case word that isn't on the ordinary-words list. Long text is cut to <paramref name="max"/> characters.
    /// </summary>
    public static string Text(string text, KnownValues? known = null, int max = 400)
    {
        if (text.Length > max * 2) text = text[..(max * 2)];
        var findings = TextScan.Find(text, known);
        var s = new StringBuilder(text.Length);
        var at = 0;
        foreach (var f in findings)
        {
            s.Append(Loose(text[at..f.Start]));
            s.Append('[').Append(Kinds.Id(f.Kind)).Append(": ").Append(Value(f.Kind, f.Value)).Append(']');
            at = f.End;
        }
        s.Append(Loose(text[at..]));
        var masked = s.ToString();
        return masked.Length > max ? masked[..max] + "…" : masked;
    }

    /// <summary>
    /// Text between findings: digits to #; capitalised words that aren't ordinary words, and words on the name lists in
    /// the middle of a sentence or in lower case, to their initial. <paramref name="pseudonyms"/> keeps the made-up names.
    /// </summary>
    private static string Loose(string text, bool pseudonyms = false)
    {
        var t = DigitRx().Replace(text, m => new string('#', m.Length));
        return AnyWordRx().Replace(t, m =>
        {
            var w = m.Value;
            if (w.Length < 2) return w;
            var upper = w.ToUpperInvariant();
            if (pseudonyms && Lists.PseudoWords.Contains(upper)) return w;
            var common = Lists.IsCommon(w);
            var onList = Lists.IsFirst(upper) || Lists.IsLast(upper);
            var capital = char.IsUpper(w[0]);
            var start = m.Index == 0 || SentenceStartRx().IsMatch(t[..m.Index]);
            var hide = capital ? !common || onList && !start : onList && !common;
            return hide ? w[0] + new string('*', w.Length - 1) : w;
        });
    }

    /// <summary>
    /// A de-identified text as an agent may see it: tokens, markers and made-up names as they are, dates by their year,
    /// every other digit and unusual word masked.
    /// </summary>
    public static string AfterText(string text, int max = 400)
    {
        if (text.Length > max * 2) text = text[..(max * 2)];
        var kept = new List<(int Start, int End, string Shown)>();
        void Keep(Regex rx, Func<Match, string> shown)
        {
            foreach (Match m in rx.Matches(text))
                if (!kept.Any(k => m.Index < k.End && k.Start < m.Index + m.Length)) kept.Add((m.Index, m.Index + m.Length, shown(m)));
        }
        Keep(Tokens.InlineRx(), m => m.Value);
        Keep(MarkerRx(), m => m.Value);
        Keep(TextDateRx(), m => Detect.TryDate(m.Value, out var d) ? $"{d.Value.Year}-**-**" : new string('#', m.Length));
        var s = new StringBuilder(text.Length);
        var at = 0;
        foreach (var (start, end, shown) in kept.OrderBy(k => k.Start))
        {
            s.Append(Loose(text[at..start], pseudonyms: true)).Append(shown);
            at = end;
        }
        s.Append(Loose(text[at..], pseudonyms: true));
        var t = s.ToString();
        return t.Length > max ? t[..max] + "…" : t;
    }

    /// <summary>
    /// A file, table, sheet or column name as an agent may see it: words that are names on the lists (and not
    /// ordinary words) and runs of five or more digits are masked. "john_smith_2024.csv" → "j***_s****_2024.csv".
    /// </summary>
    public static string Label(string name)
    {
        var s = LabelWordRx().Replace(name, m =>
        {
            var w = m.Value;
            if (w.All(char.IsAsciiDigit)) return w.Length >= 5 ? new string('#', w.Length) : w;
            var upper = w.ToUpperInvariant();
            if (w.Length < 3 || Lists.IsCommon(w) || HeaderWords.Contains(w.ToLowerInvariant())) return w;
            return Lists.IsFirst(upper) || Lists.IsLast(upper) ? w[0] + new string('*', w.Length - 1) : w;
        });
        return s;
    }

    /// <summary>Whether <see cref="Label"/> would change the name (so the agent is given a reference to use instead).</summary>
    public static bool LabelHides(string name) => Label(name) != name;

    private static readonly HashSet<string> HeaderWords = new(StringComparer.Ordinal)
    {
        "members", "member", "claims", "claim", "notes", "note", "clinic", "patients", "patient", "providers", "provider",
        "visits", "visit", "samples", "sample", "feed", "data", "export", "exports", "report", "reports", "csv", "xlsx",
        "json", "jsonl", "txt", "tsv", "db", "sqlite", "sheet", "table", "first", "last", "name", "date", "city", "state",
        "zip", "phone", "email", "address", "street", "birth", "dob", "ssn", "mrn", "npi", "amount", "paid", "charge",
        "status", "plan", "type", "code", "id", "deidentified", "output", "out", "main", "dbo", "public", "lab", "labs",
        "encounters", "encounter", "eligibility", "enrollment", "pharmacy", "rx", "dental", "vision", "medical",
    };

    private static readonly HashSet<string> StreetWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "street", "st", "avenue", "ave", "road", "rd", "boulevard", "blvd", "lane", "ln", "drive", "dr", "court", "ct",
        "way", "place", "pl", "terrace", "ter", "circle", "cir", "parkway", "pkwy", "highway", "hwy", "trail", "apt",
        "suite", "ste", "unit", "po", "box", "n", "s", "e", "w", "north", "south", "east", "west",
    };

    /// <summary>Each word as its initial and asterisks, keeping <paramref name="keep"/> words as they are.</summary>
    private static string Initials(string v, HashSet<string>? keep = null) =>
        LetterWordRx().Replace(v, m => keep != null && keep.Contains(m.Value.TrimEnd('.')) || m.Length == 1 ? m.Value : m.Value[0] + new string('*', m.Length - 1));

    /// <summary>Every digit but the last <paramref name="last"/> replaced with <paramref name="with"/>; letters too, if any.</summary>
    private static string Digits(string v, int last, char with)
    {
        var total = v.Count(char.IsLetterOrDigit);
        var seen = 0;
        var s = new StringBuilder(v.Length);
        foreach (var c in v)
        {
            if (char.IsLetterOrDigit(c))
            {
                seen++;
                s.Append(seen > total - last && char.IsDigit(c) ? c : with);
            }
            else s.Append(c);
        }
        return s.ToString();
    }

    /// <summary>Every letter and digit but the last <paramref name="last"/> as an asterisk.</summary>
    private static string Chars(string v, int last)
    {
        var total = v.Count(char.IsLetterOrDigit);
        var seen = 0;
        var s = new StringBuilder(v.Length);
        foreach (var c in v)
        {
            if (char.IsLetterOrDigit(c)) s.Append(++seen > total - last ? c : '*');
            else s.Append(c);
        }
        return s.ToString();
    }

    [GeneratedRegex(@"\d+")]
    private static partial Regex DigitRx();

    [GeneratedRegex(@"[A-Za-z][A-Za-z'-]*")]
    private static partial Regex AnyWordRx();

    [GeneratedRegex(@"(?:^|[.!?:\n]\s*|\[[a-z_]+:\s*)$")]
    private static partial Regex SentenceStartRx();

    [GeneratedRegex(@"\[(?:PHONE|FAX|EMAIL|URL|IP|ADDRESS|CITY|FILE|NAME|DATE|REDACTED)\]")]
    private static partial Regex MarkerRx();

    [GeneratedRegex(@"\b(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?|\d{1,2}/\d{1,2}/(?:\d{4}|\d{2})|\d{1,2}-\d{1,2}-\d{4}|(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4})\b")]
    private static partial Regex TextDateRx();




    [GeneratedRegex(@"\b[A-Z][A-Za-z'-]*")]
    private static partial Regex CapitalRx();

    [GeneratedRegex(@"[A-Za-z][A-Za-z'-]*")]
    private static partial Regex LetterWordRx();

    [GeneratedRegex(@"[A-Za-z]+|\d+")]
    private static partial Regex LabelWordRx();
}
