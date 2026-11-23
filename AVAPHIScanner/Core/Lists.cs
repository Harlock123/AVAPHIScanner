using System.Reflection;

namespace AVAPHIScanner;

/// <summary>
/// The word lists the detectors use, bundled with the program (Core/Resources): common first and last names in rough
/// order of frequency, US cities, the three-digit ZIP areas Safe Harbor says to write as 000, and ordinary words that
/// free text capitalises. Also the made-up names pseudonyms are drawn from.
/// </summary>
public static class Lists
{
    public static readonly IReadOnlyDictionary<string, int> FirstNames = Ranked("first-names.txt");
    public static readonly IReadOnlyDictionary<string, int> LastNames = Ranked("last-names.txt");
    public static readonly IReadOnlySet<string> Cities = Words("us-cities.txt");
    public static readonly IReadOnlySet<string> RestrictedZip3 = Words("restricted-zip3.txt");
    public static readonly IReadOnlySet<string> CommonWords = Words("common-words.txt", upper: false);

    /// <summary>Last names pseudonyms are made from.</summary>
    public static readonly string[] PseudoLast =
    [
        "ASHFORD", "BELLAMY", "CARVER", "DALTON", "ELLERY", "FAIRBANK", "GARLAND", "HADLEY", "IVERSON", "JARRETT",
        "KENDRICK", "LANGLEY", "MERCER", "NORWOOD", "OAKLEY", "PRESCOTT", "QUINLAN", "RADCLIFF", "SUTTON", "TALBOT",
        "UPTON", "VANCE", "WHITLOCK", "YARDLEY", "ABERNATHY", "BRADDOCK", "CHANDLER", "DRUMMOND", "EASTON", "FENWICK",
        "GRAYSON", "HOLLOWAY", "ALDRIDGE", "BRAMLEY", "CALLOWAY", "DUNMORE", "ELSWORTH", "FARNHAM", "GATSBY", "HARCOURT",
        "INGLEBY", "KESTREL", "LOCKWOOD", "MARLOWE", "NETHERTON", "ORMSBY", "PEMBERTON", "REDMAYNE", "SELWYN", "THORNBURY",
        "VALENTINO", "WINSLOW", "ASHCROFT", "BLACKMORE", "CROMWELL", "DEVEREUX", "EVERLEIGH", "FOXWORTH", "GLADSTONE", "HAWTHORNE",
    ];

    /// <summary>First names pseudonyms are made from.</summary>
    public static readonly string[] PseudoFirst =
    [
        "ALEX", "BLAIR", "CAMERON", "DANA", "ELLIS", "FRANCIS", "GALE", "HAYDEN", "JORDAN", "KENDALL", "LANE", "MORGAN",
        "NOEL", "PARKER", "QUINN", "REESE", "SAWYER", "TAYLOR", "AVERY", "BAILEY", "CASEY", "DREW", "EMERSON", "FINLEY",
        "HARPER", "JESSIE", "KAI", "LOGAN", "MARLOW", "PEYTON", "RILEY", "SKYLER", "ARDEN", "BRYCE", "CORIN", "DARCY",
        "EDEN", "FLYNN", "GRAY", "HOLLIS", "INDIGO", "JULES", "KIT", "LEE", "MICAH", "NICO", "OAKLEY", "PAXTON",
        "REMY", "ROWAN", "SAGE", "TATUM", "WREN", "ZION", "ASPEN", "BRIAR", "CALLAN", "DALLAS", "ELLERY", "FALLON",
    ];

    /// <summary>Every word a pseudonym can be made of, to tell a pseudonym from a name left behind.</summary>
    public static readonly IReadOnlySet<string> PseudoWords = new HashSet<string>(PseudoLast.Concat(PseudoFirst), StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether an upper-case word is a first name (in the list).</summary>
    public static bool IsFirst(string upper) => FirstNames.ContainsKey(upper);

    public static bool IsLast(string upper) => LastNames.ContainsKey(upper);

    public static bool IsCommon(string word) => CommonWords.Contains(word.ToLowerInvariant());

    private static IEnumerable<string> Lines(string resource)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"The list {resource} isn't in the program.");
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            var t = line.Trim();
            if (t.Length > 0 && !t.StartsWith('#')) yield return t;
        }
    }

    private static Dictionary<string, int> Ranked(string resource)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var w in Lines(resource)) map.TryAdd(w.ToUpperInvariant(), map.Count);
        return map;
    }

    private static HashSet<string> Words(string resource, bool upper = true) =>
        new(Lines(resource).Select(w => upper ? w.ToUpperInvariant() : w.ToLowerInvariant()), StringComparer.Ordinal);
}
