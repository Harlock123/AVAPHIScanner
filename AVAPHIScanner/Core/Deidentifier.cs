using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AVAPHIScanner;

/// <summary>Identifier tokens: what they look like, and the form a value is reduced to before it's hashed.</summary>
public static partial class Tokens
{
    public const string Prefix = "ID-";

    /// <summary>A value as it's hashed: upper case, without spaces, dashes, dots and slashes ("123-45-6789" and "123456789" match).</summary>
    public static string Normalise(string v)
    {
        var s = new StringBuilder(v.Length);
        foreach (var c in v.Trim())
            if (char.IsLetterOrDigit(c)) s.Append(char.ToUpperInvariant(c));
        return s.ToString();
    }

    public static bool IsToken(string v) => TokenRx().IsMatch(v.Trim());

    [GeneratedRegex(@"^ID-[A-Z2-7]{10}$")]
    private static partial Regex TokenRx();

    [GeneratedRegex(@"\bID-[A-Z2-7]{10}\b")]
    public static partial Regex InlineRx();
}

/// <summary>
/// The key tokens, pseudonyms and date shifts are made with: 32 random bytes, kept as base64 in a file the person keeps
/// (and never gives to whoever receives the copy). The same key makes the same stand-ins, across files, tables and runs.
/// </summary>
public static class KeyFile
{
    public static byte[] Load(string path)
    {
        var text = File.ReadAllText(path).Trim();
        try
        {
            var key = Convert.FromBase64String(text);
            if (key.Length < 16) throw new InvalidDataException("The key file holds a key shorter than 16 bytes.");
            return key;
        }
        catch (FormatException)
        {
            throw new InvalidDataException("The key file doesn't hold a key (base64 text, as AVA PHI Scanner writes it).");
        }
    }

    /// <summary>Makes a new random key in <paramref name="path"/> (never over an existing file), readable by its owner only where the system allows.</summary>
    public static byte[] Create(string path)
    {
        if (File.Exists(path)) throw new IOException("The key file already exists: use it, or choose another name.");
        if (Path.GetDirectoryName(Path.GetFullPath(path)) is { } dir) Directory.CreateDirectory(dir);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(key) + Environment.NewLine);
        if (!OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch (IOException) { }
        return key;
    }

    public static byte[] LoadOrCreate(string path, out bool created)
    {
        created = !File.Exists(path);
        return created ? Create(path) : Load(path);
    }
}

/// <summary>
/// Makes the stand-ins: keyed tokens for identifiers, made-up names for names, dates moved by a per-person number of
/// days (or cut to the year), ZIP codes to their first three digits (000 for the small areas), ages over 89 to 90+,
/// markers for contact details, and free text with its identifiers replaced where they stand. Everything comes from
/// one keyed hash (HMAC-SHA256), so the same input gives the same output everywhere this key is used.
/// </summary>
public sealed partial class Deidentifier(byte[] key, Policy policy, KnownValues? known = null, DateOnly? today = null)
{
    private readonly DateOnly _today = today ?? DateOnly.FromDateTime(DateTime.Today);

    public KnownValues Known { get; } = known ?? KnownValues.Empty;

    public Policy Policy { get; } = policy;

    /// <summary>How many values were replaced, by kind.</summary>
    public Dictionary<PhiKind, int> Replaced { get; } = [];

    private void Count(PhiKind kind) => Replaced[kind] = Replaced.GetValueOrDefault(kind) + 1;

    // ───────────────────────────── stand-ins ─────────────────────────────

    public string Token(string value)
    {
        var hash = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("id:" + Tokens.Normalise(value)));
        return Tokens.Prefix + Base32(hash)[..10];
    }

    /// <summary>A made-up name for <paramref name="name"/>, word by word, keeping its shape: "Lopez, Maria" → "Talbot, Quinn".</summary>
    public string Pseudonym(string name) => NameWordRx().Replace(name, m =>
    {
        var w = m.Value;
        var dot = w.EndsWith('.') ? "." : "";
        var core = w.TrimEnd('.');
        if (Keep.Contains(core)) return w;
        if (core.Length == 1)
        {
            var letter = (char)('A' + (int)(Hash("initial:" + char.ToUpperInvariant(core[0])) % 26));
            return (char.IsLower(core[0]) ? char.ToLowerInvariant(letter) : letter) + dot;
        }
        return string.Join('-', core.Split('-').Select(part => part.Length == 0 ? part : Shape(part, PseudoWord(part)))) + dot;
    });

    /// <summary>Titles and suffixes a pseudonym keeps as they are ("Dr.", "Jr.").</summary>
    public static readonly IReadOnlySet<string> Keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Jr", "Sr", "II", "III", "IV", "MD", "RN", "PhD", "DO", "NP", "PA", "Mr", "Mrs", "Ms", "Dr", "Miss", "Mx" };

    private string PseudoWord(string word)
    {
        var upper = new string(word.Where(char.IsLetter).ToArray()).ToUpperInvariant();
        var first = Lists.FirstNames.TryGetValue(upper, out var fr);
        var last = Lists.LastNames.TryGetValue(upper, out var lr);
        var asFirst = first && (!last || fr < lr);
        var list = asFirst ? Lists.PseudoFirst : Lists.PseudoLast;
        return list[Hash((asFirst ? "first:" : "last:") + upper) % (ulong)list.Length];
    }

    private static string Shape(string original, string upper)
    {
        var letters = original.Where(char.IsLetter).ToList();
        if (letters.Count > 0 && letters.All(char.IsUpper)) return upper;
        if (letters.Count > 0 && letters.All(char.IsLower)) return upper.ToLowerInvariant();
        return upper[0] + upper[1..].ToLowerInvariant();
    }

    /// <summary>The days every date of <paramref name="person"/> moves by (back 1 to 365); one number for all when there's no person.</summary>
    public int ShiftDays(string? person) =>
        -(1 + (int)(Hash("shift:" + (string.IsNullOrWhiteSpace(person) ? "" : Tokens.Normalise(person))) % 365));

    /// <summary>A date moved for <paramref name="person"/>; a birth date of someone over 89 becomes 1 January of the year 90 years ago.</summary>
    public DateTime Shift(DateTime d, string? person, bool birth)
    {
        if (birth && Ages.Years(d, _today.ToDateTime(TimeOnly.MinValue)) > 89) return new DateTime(_today.Year - 90, 1, 1);
        return d.AddDays(ShiftDays(person));
    }

    /// <summary>A date's year; for a birth date over 89 years ago, the year 90 years ago.</summary>
    public int Year(DateTime d, bool birth) => birth && Ages.Years(d, _today.ToDateTime(TimeOnly.MinValue)) > 89 ? _today.Year - 90 : d.Year;

    /// <summary>A ZIP code's first three digits, or 000 for the areas of 20,000 people or fewer.</summary>
    public static string Zip3(string zip)
    {
        var digits = new string(zip.Where(char.IsAsciiDigit).ToArray());
        if (digits.Length < 3) return "000";
        return Lists.RestrictedZip3.Contains(digits[..3]) ? "000" : digits[..3];
    }

    public static string Marker(PhiKind kind) => kind switch
    {
        PhiKind.Phone => "[PHONE]",
        PhiKind.Fax => "[FAX]",
        PhiKind.Email => "[EMAIL]",
        PhiKind.Url => "[URL]",
        PhiKind.IpAddress => "[IP]",
        PhiKind.StreetAddress => "[ADDRESS]",
        PhiKind.City => "[CITY]",
        PhiKind.Biometric => "[FILE]",
        PhiKind.Name => "[NAME]",
        PhiKind.BirthDate or PhiKind.Date => "[DATE]",
        _ => "[REDACTED]",
    };

    public static readonly IReadOnlySet<string> Markers = new HashSet<string>(
        Kinds.All.Select(k => Marker(k.Kind)).Append("[REDACTED]"), StringComparer.Ordinal);

    // ───────────────────────────── applying actions ─────────────────────────────

    /// <summary>
    /// What <paramref name="action"/> makes of a value of <paramref name="kind"/> in <paramref name="person"/>'s row.
    /// Null stays null. (Drop is the writer's to do: here it gives null.)
    /// </summary>
    public string? Apply(ColumnAction action, PhiKind kind, string? value, string? person)
    {
        if (value is null || value.Trim().Length == 0) return value;
        string? result;
        switch (action)
        {
            case ColumnAction.Keep:
                return value;
            case ColumnAction.Drop:
                return null;
            case ColumnAction.Pseudonymise:
                result = kind is PhiKind.Name or PhiKind.None or PhiKind.FreeText ? Pseudonym(value) : Token(value);
                break;
            case ColumnAction.Tokenise:
                result = Token(value);
                break;
            case ColumnAction.ShiftDate:
                if (Detect.TryDate(value, out var d)) result = Detect.FormatDate(Shift(d.Value, person, kind == PhiKind.BirthDate), d.Format);
                else result = value.Any(char.IsAsciiDigit) ? Marker(PhiKind.Date) : value;
                break;
            case ColumnAction.Generalise:
                result = Generalise(kind, value);
                break;
            case ColumnAction.Redact:
                result = Marker(kind);
                break;
            case ColumnAction.ScrubText:
                return Scrub(value, person);
            default:
                return value;
        }
        if (result != value) Count(kind);
        return result;
    }

    private string Generalise(PhiKind kind, string value)
    {
        switch (kind)
        {
            case PhiKind.Zip:
                return Zip3(value);
            case PhiKind.Age:
                var digits = AgeRx().Match(value);
                return digits.Success && int.TryParse(digits.Value, out var age) && age > 89 ? "90+" : value;
            case PhiKind.BirthDate or PhiKind.Date:
                return Detect.TryDate(value, out var d) ? Year(d.Value, kind == PhiKind.BirthDate).ToString(CultureInfo.InvariantCulture)
                    : value.Any(char.IsAsciiDigit) ? Marker(PhiKind.Date) : value;
            case PhiKind.Name:
                return Pseudonym(value);
            default:
                return Kinds.IsIdentifier(kind) ? Token(value) : Marker(kind);
        }
    }

    /// <summary>What the policy does with an identifier of <paramref name="kind"/> found inside free text.</summary>
    private ColumnAction InlineAction(PhiKind kind) => kind switch
    {
        PhiKind.Name => ColumnAction.Pseudonymise,
        PhiKind.Npi => ColumnAction.Keep,
        _ => new Policy { Kind = Policy.Kind == PolicyKind.LimitedDataSet ? PolicyKind.LimitedDataSet : PolicyKind.SafeHarbor, DateMode = Policy.DateMode }.ActionFor("", kind),
    };

    /// <summary>Free text with each identifier the scanner finds in it replaced where it stands.</summary>
    public string Scrub(string text, string? person)
    {
        var findings = TextScan.Find(text, Known);
        if (findings.Count == 0) return text;
        var s = new StringBuilder(text.Length);
        var at = 0;
        foreach (var f in findings)
        {
            s.Append(text, at, f.Start - at);
            var action = InlineAction(f.Kind);
            var replacement = f.Kind == PhiKind.Age && action == ColumnAction.Generalise ? "90+" : Apply(action, f.Kind, f.Value, person) ?? "";
            s.Append(replacement);
            at = f.End;
        }
        s.Append(text, at, text.Length - at);
        return s.ToString();
    }

    /// <summary>Whose text this is: the first member ID in it (else MRN, else SSN), labelled or known from the scan.</summary>
    public string? PersonOf(string text)
    {
        var ids = TextScan.Find(text, Known).Where(f => f.Kind is PhiKind.MemberId or PhiKind.Mrn or PhiKind.Ssn).ToList();
        return ids.OrderBy(f => f.Kind switch { PhiKind.MemberId => 0, PhiKind.Mrn => 1, _ => 2 }).ThenBy(f => f.Start).FirstOrDefault()?.Value;
    }

    private ulong Hash(string value) => BitConverter.ToUInt64(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));

    private static string Base32(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var s = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                s.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        return s.ToString();
    }

    [GeneratedRegex(@"[A-Za-z][A-Za-z'’-]*\.?")]
    private static partial Regex NameWordRx();

    [GeneratedRegex(@"\d+")]
    private static partial Regex AgeRx();
}
