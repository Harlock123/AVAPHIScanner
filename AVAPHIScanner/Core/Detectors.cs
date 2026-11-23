using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace AVAPHIScanner;

/// <summary>A date read from text, with the format it was written in (so a shifted date is written the same way).</summary>
public readonly record struct ParsedDate(DateTime Value, string Format);

/// <summary>
/// The value detectors: what one value on its own looks like (an SSN, a phone number, a date, a name…) and how sure
/// that look is (<c>Strength</c>, 0 to 1: a dashed SSN that passes the SSA's rules is very likely one; nine bare digits
/// much less so). Column classification (<see cref="Classifier"/>) weighs these over a sample, with the column's header.
/// </summary>
public static partial class Detect
{
    public readonly record struct Hit(PhiKind Kind, double Strength);

    /// <summary>Every kind <paramref name="raw"/> may be, with how sure each is. Empty: nothing recognisable.</summary>
    public static List<Hit> Value(string raw)
    {
        var hits = new List<Hit>(2);
        var v = raw.Trim();
        if (v.Length == 0 || v.Length > 200) return hits;

        if (EmailRx().IsMatch(v)) { hits.Add(new(PhiKind.Email, 0.98)); return hits; }
        if (UrlRx().IsMatch(v)) { hits.Add(new(PhiKind.Url, 0.95)); return hits; }
        if (IsIp(v)) { hits.Add(new(PhiKind.IpAddress, 0.9)); return hits; }
        if (SsnDashedRx().Match(v) is { Success: true } sd)
        {
            if (ValidSsn(sd.Groups[1].Value, sd.Groups[2].Value, sd.Groups[3].Value)) hits.Add(new(PhiKind.Ssn, 0.95));
            else if (TaxpayerShaped(sd.Groups[1].Value, sd.Groups[2].Value, sd.Groups[3].Value)) hits.Add(new(PhiKind.Ssn, 0.9));
            return hits;
        }
        if (Mbi(v)) { hits.Add(new(PhiKind.MemberId, 0.95)); return hits; }
        if (TryDate(v, out var date))
        {
            // Eight bare digits may be a date or just a number.
            hits.Add(new(PhiKind.Date, date.Format == "yyyyMMdd" ? 0.5 : 0.92));
            return hits;
        }
        if (PhoneRx().Match(v) is { Success: true } ph)
        {
            var formatted = v.Any(c => c is '-' or '.' or ' ' or '(' or '+');
            hits.Add(new(PhiKind.Phone, formatted ? 0.9 : 0.35));
        }
        var digits = v.All(char.IsAsciiDigit);
        if (digits && v.Length == 9 && ValidSsn(v[..3], v[3..5], v[5..])) hits.Add(new(PhiKind.Ssn, 0.35));
        if (digits && v.Length == 10 && Npi(v)) hits.Add(new(PhiKind.Npi, 0.6));
        if (CardRx().IsMatch(v) && Card(new string(v.Where(char.IsAsciiDigit).ToArray())))
            hits.Add(new(PhiKind.AccountNumber, digits ? 0.5 : 0.85));
        if (digits && v.Length == 15 && Luhn(v)) hits.Add(new(PhiKind.DeviceId, 0.5));
        if (Vin(v) is { } vin) hits.Add(new(PhiKind.VehicleId, vin ? 0.9 : 0.4));
        if (Dea(v)) hits.Add(new(PhiKind.License, 0.85));
        if (ZipPlus4Rx().IsMatch(v)) hits.Add(new(PhiKind.Zip, 0.85));
        else if (digits && v.Length == 5) hits.Add(new(PhiKind.Zip, 0.25));
        if (digits && v.Length <= 3 && int.TryParse(v, out var age) && age <= 125) hits.Add(new(PhiKind.Age, 0.05));
        if (AddressRx().IsMatch(v) || PoBoxRx().IsMatch(v)) hits.Add(new(PhiKind.StreetAddress, 0.85));
        if (FileRefRx().IsMatch(v)) hits.Add(new(PhiKind.Biometric, 0.6));
        if (hits.Count == 0 && IdLikeRx().IsMatch(v) && v.Any(char.IsAsciiDigit) && v.Any(char.IsAsciiLetter)) hits.Add(new(PhiKind.OtherId, 0.3));
        if (hits.Count == 0 && NameStrength(v) is > 0 and var name) hits.Add(new(PhiKind.Name, name));
        if (Lists.Cities.Contains(v.ToUpperInvariant())) hits.Add(new(PhiKind.City, 0.6));
        return hits;
    }

    // ───────────────────────────── names ─────────────────────────────

    /// <summary>
    /// How much <paramref name="v"/> looks like a person's name: "Maria Lopez" or "LOPEZ, MARIA" (both words on the
    /// lists) strongly, a single first or last name less so. 0 when it doesn't.
    /// </summary>
    public static double NameStrength(string v)
    {
        if (v.Length > 60 || !NameShapeRx().IsMatch(v)) return 0;
        var words = NameWords(v);
        if (words.Count is 0 or > 4) return 0;
        if (words.Count == 1)
        {
            var w = words[0];
            if (w.Length < 2) return 0;
            return Lists.IsFirst(w) || Lists.IsLast(w) ? 0.5 : 0;
        }
        var comma = v.Contains(',');
        var (first, last) = comma ? (words[1], words[0]) : (words[0], words[^1]);
        var f = Lists.IsFirst(first);
        var l = Lists.IsLast(last);
        if (f && l) return 0.85;
        if (f || l) return 0.55;
        return words.Count(w => Lists.IsFirst(w) || Lists.IsLast(w)) > 0 ? 0.4 : 0;
    }

    /// <summary>A name's words in upper case, without punctuation (O'Brien → OBRIEN), initials left out.</summary>
    public static List<string> NameWords(string v) =>
        NameSplitRx().Split(v).Select(w => new string(w.Where(char.IsLetter).ToArray()).ToUpperInvariant()).Where(w => w.Length > 1).ToList();

    // ───────────────────────────── numbers with rules ─────────────────────────────

    /// <summary>The SSA's rules: no area 000, 666 or 900-999, no group 00, no serial 0000, and not the famous invalid ones.</summary>
    public static bool ValidSsn(string area, string group, string serial)
    {
        if (area is "000" or "666" || area[0] == '9') return false;
        if (group == "00" || serial == "0000") return false;
        var all = area + group + serial;
        return all is not ("078051120" or "219099999" or "123456789" or "111111111" or "333333333");
    }

    /// <summary>
    /// Area 900-999, written like an SSN: never an SSN, but an ITIN (a taxpayer number, personal data too) or an
    /// example number standing in for an SSN, as in test data. Counted only when written with dashes or spaces, so
    /// nine bare digits (claim numbers and the like) still have to pass <see cref="ValidSsn"/>.
    /// </summary>
    public static bool TaxpayerShaped(string area, string group, string serial) =>
        area[0] == '9' && group != "00" && serial != "0000";

    /// <summary>
    /// An SSN written with dashes or spaces that passes <see cref="ValidSsn"/> or is <see cref="TaxpayerShaped"/>, or
    /// nine digits that pass <see cref="ValidSsn"/>.
    /// </summary>
    public static bool Ssn(string v)
    {
        v = v.Trim();
        if (SsnDashedRx().Match(v) is { Success: true } m)
            return ValidSsn(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value)
                || TaxpayerShaped(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value);
        return v.Length == 9 && v.All(char.IsAsciiDigit) && ValidSsn(v[..3], v[3..5], v[5..]);
    }

    /// <summary>The Luhn check digit test (cards, IMEIs, NPIs with their prefix).</summary>
    public static bool Luhn(string digits)
    {
        if (digits.Length < 2 || !digits.All(char.IsAsciiDigit)) return false;
        var sum = 0;
        var doubled = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (doubled) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubled = !doubled;
        }
        return sum % 10 == 0;
    }

    /// <summary>A payment card number: a known issuer's prefix and length (Visa, Mastercard, Amex, Discover) and the Luhn check.</summary>
    public static bool Card(string d) => Luhn(d) && (
        d[0] == '4' && d.Length is 13 or 16 or 19
        || d.Length == 16 && (d[..2] is "51" or "52" or "53" or "54" or "55" || int.TryParse(d[..4], out var mc) && mc is >= 2221 and <= 2720)
        || d.Length == 15 && d[..2] is "34" or "37"
        || d.Length == 16 && (d.StartsWith("6011", StringComparison.Ordinal) || d.StartsWith("65", StringComparison.Ordinal)));

    /// <summary>A National Provider Identifier: ten digits starting 1 or 2, whose check digit passes Luhn with the 80840 prefix.</summary>
    public static bool Npi(string v) => v.Length == 10 && v.All(char.IsAsciiDigit) && v[0] is '1' or '2' && Luhn("80840" + v);

    /// <summary>The check digit an NPI's first nine digits need (for making sample NPIs).</summary>
    public static char NpiCheckDigit(string nine)
    {
        for (var d = '0'; d <= '9'; d++)
            if (Luhn("80840" + nine + d)) return d;
        throw new ArgumentException("No check digit fits.");
    }

    /// <summary>A Medicare Beneficiary Identifier (MBI): 11 characters in the CMS pattern, with or without dashes.</summary>
    public static bool Mbi(string v) => MbiRx().IsMatch(v.Replace("-", "").ToUpperInvariant());

    /// <summary>A DEA registration number: two letters and seven digits whose last digit is the DEA checksum.</summary>
    public static bool Dea(string v)
    {
        if (!DeaRx().IsMatch(v)) return false;
        var d = v[2..].Select(c => c - '0').ToArray();
        return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6];
    }

    /// <summary>A vehicle identification number: true when its check digit is right, false when only its shape is, null when neither.</summary>
    public static bool? Vin(string v)
    {
        if (!VinRx().IsMatch(v)) return null;
        if (!v.Any(char.IsAsciiDigit) || !v.Any(char.IsAsciiLetter)) return null;
        const string weights = "8765432X098765432";
        var sum = 0;
        for (var i = 0; i < 17; i++)
        {
            var c = v[i];
            var value = char.IsAsciiDigit(c) ? c - '0' : "0123456789.ABCDEFGH..JKLMN.P.R..STUVWXYZ".IndexOf(c) % 10;
            if (char.IsAsciiLetter(c)) value = VinLetter(c);
            var w = weights[i] == 'X' ? 10 : weights[i] - '0';
            sum += value * w;
        }
        var check = sum % 11;
        return (check == 10 ? 'X' : (char)('0' + check)) == v[8];
    }

    private static int VinLetter(char c) => c switch
    {
        'A' or 'J' => 1, 'B' or 'K' or 'S' => 2, 'C' or 'L' or 'T' => 3, 'D' or 'M' or 'U' => 4, 'E' or 'N' or 'V' => 5,
        'F' or 'W' => 6, 'G' or 'P' or 'X' => 7, 'H' or 'Y' => 8, 'R' or 'Z' => 9, _ => 0,
    };

    public static bool IsIp(string v)
    {
        if (Ipv4Rx().IsMatch(v)) return v.Split('.').All(p => int.TryParse(p, out var n) && n <= 255);
        return v.Count(c => c == ':') >= 2 && v.All(c => Uri.IsHexDigit(c) || c is ':' or '.') && IPAddress.TryParse(v, out _);
    }

    // ───────────────────────────── dates ─────────────────────────────

    /// <summary>The date formats recognised, most specific first. A shifted date is written back in the format it was read in.</summary>
    public static readonly string[] DateFormats =
    [
        "yyyy-MM-ddTHH:mm:ss.fffZ", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm",
        "yyyy-MM-dd", "yyyy/MM/dd", "MM/dd/yyyy HH:mm", "M/d/yyyy h:mm tt", "MM/dd/yyyy", "M/d/yyyy", "MM-dd-yyyy", "M-d-yyyy",
        "MM/dd/yy", "M/d/yy", "dd-MMMM-yyyy", "dd-MMM-yyyy", "d-MMM-yyyy", "dd MMMM yyyy", "d MMMM yyyy", "dd MMM yyyy", "d MMM yyyy",
        "MMMM d, yyyy", "MMMM dd, yyyy", "MMM d, yyyy", "MMM dd, yyyy", "dd.MM.yyyy", "yyyyMMdd",
    ];

    /// <summary>A date in one of <see cref="DateFormats"/>, between 1880 and 2100.</summary>
    public static bool TryDate(string v, out ParsedDate date)
    {
        date = default;
        v = v.Trim();
        if (v.Length is < 6 or > 30 || !(char.IsAsciiDigit(v[^1]) || v[^1] is 'Z' or 'M')) return false;
        foreach (var f in DateFormats)
        {
            if (DateTime.TryParseExact(v, f, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var d) && d.Year is >= 1880 and <= 2100)
            {
                date = new ParsedDate(DateTime.SpecifyKind(d, DateTimeKind.Unspecified), f);
                return true;
            }
        }
        return false;
    }

    public static string FormatDate(DateTime d, string format) => d.ToString(format, CultureInfo.InvariantCulture);

    // ───────────────────────────── patterns ─────────────────────────────

    [GeneratedRegex(@"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")]
    public static partial Regex EmailRx();

    [GeneratedRegex(@"^(?:https?://|ftp://|www\.)\S+$", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRx();

    [GeneratedRegex(@"^(\d{3})[- ](\d{2})[- ](\d{4})$")]
    private static partial Regex SsnDashedRx();

    [GeneratedRegex(@"^(?:\+?1[\s.-]?)?\(?([2-9]\d{2})\)?[\s.-]?([2-9]\d{2})[\s.-]?(\d{4})(?:\s*(?:x|ext\.?)\s*\d{1,5})?$", RegexOptions.IgnoreCase)]
    private static partial Regex PhoneRx();

    [GeneratedRegex(@"^(?:\d[ -]?){12,18}\d$")]
    private static partial Regex CardRx();

    [GeneratedRegex(@"^\d{5}-\d{4}$")]
    private static partial Regex ZipPlus4Rx();

    [GeneratedRegex(@"^\d{1,6}[A-Za-z]?\s+(?:[NSEW]\.?\s+|North\s+|South\s+|East\s+|West\s+)?(?:[A-Za-z0-9'.-]+\s+){0,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Trail|Trl|Square|Sq|Loop|Run|Pike|Row)\.?(?:\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9-]+)?$", RegexOptions.IgnoreCase)]
    public static partial Regex AddressRx();

    [GeneratedRegex(@"^P\.?\s*O\.?\s*Box\s+\d+$", RegexOptions.IgnoreCase)]
    private static partial Regex PoBoxRx();

    [GeneratedRegex(@"^[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9][0-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9][0-9][AC-HJKMNP-RT-Y]{2}[0-9]{2}$")]
    private static partial Regex MbiRx();

    [GeneratedRegex(@"^[A-Z][A-Z9][0-9]{7}$")]
    private static partial Regex DeaRx();

    [GeneratedRegex(@"^[A-HJ-NPR-Z0-9]{17}$")]
    private static partial Regex VinRx();

    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}$")]
    private static partial Regex Ipv4Rx();

    [GeneratedRegex(@"\.(?:jpe?g|png|gif|bmp|tiff?|heic|webp|dcm|wav|mp3|wsq|fmr|bio)$", RegexOptions.IgnoreCase)]
    private static partial Regex FileRefRx();

    [GeneratedRegex(@"^[A-Za-z]{0,5}[-_]?[A-Za-z0-9]{0,4}[-_]?\d{3,14}[A-Za-z0-9-]{0,6}$")]
    private static partial Regex IdLikeRx();

    [GeneratedRegex(@"^[A-Za-z][A-Za-z'.\- ,]*[A-Za-z.]$")]
    private static partial Regex NameShapeRx();

    [GeneratedRegex(@"[\s,]+")]
    private static partial Regex NameSplitRx();
}

/// <summary>What a column's header says it holds, before a value is read.</summary>
public static partial class HeaderHints
{
    /// <summary>A header's verdict: the kind it names and how sure that is; <c>NotPhi</c> when it names something that isn't (an amount, a code).</summary>
    public readonly record struct Hint(PhiKind Kind, double Confidence, bool NotPhi = false, string Why = "");

    private static readonly (Regex Pattern, PhiKind Kind, double Confidence)[] Rules =
    [
        (R(@"(^|_)(ssn|ss_?num|ss_?no|social_?security(_number|_no)?|social|itin|tin)($|_)"), PhiKind.Ssn, 0.9),
        (R(@"(^|_)(mrn|medical_?record(_number|_no)?|med_?rec(_no)?|chart(_number|_no)?|patient_?(id|number|no)|pat_?id|emr_?id|ehr_?id|person_?id)($|_)"), PhiKind.Mrn, 0.85),
        (R(@"(^|_)(member|mbr|subscriber|beneficiary|bene|enrollee|insured)(_?(id|number|no|num))?($|_)|(^|_)(hicn|mbi|medicaid(_id)?|medicare(_id)?|policy_?(id|number|no)|insurance_?(id|number)|health_?plan_?id|cin)($|_)"), PhiKind.MemberId, 0.85),
        (R(@"(^|_)(claim|clm|icn|dcn|encounter|enc|visit|admission|invoice|case)_?(id|number|no|num|nbr)($|_)|(^|_)(claim_?id|icn|dcn)($|_)"), PhiKind.ClaimNumber, 0.75),
        (R(@"(^|_)(account|acct|acc)(_?(id|number|no|num))?($|_)|(^|_)(bank_?account|card_?number|credit_?card|iban|routing)($|_)"), PhiKind.AccountNumber, 0.8),
        (R(@"(^|_)(npi|provider_?npi|rendering_?npi|billing_?npi|attending_?npi|referring_?npi)($|_)"), PhiKind.Npi, 0.9),
        (R(@"(^|_)(licen[cs]e|dl|drivers?_?licen[cs]e|dea|certificate|cert_?(no|number)|permit)(_?(id|number|no))?($|_)"), PhiKind.License, 0.8),
        (R(@"(^|_)(vin|vehicle(_?(id|number))?|licen[cs]e_?plate|plate(_number)?)($|_)"), PhiKind.VehicleId, 0.8),
        (R(@"(^|_)(device(_?(id|serial))?|serial(_?(number|no))?|udi|imei|implant(_id)?)($|_)"), PhiKind.DeviceId, 0.75),
        (R(@"(^|_)(fax)(_?(number|no))?($|_)"), PhiKind.Fax, 0.9),
        (R(@"(^|_)(phone|telephone|tel|mobile|cell|cellphone|contact_?number|home_?phone|work_?phone|phone_?number)($|_)"), PhiKind.Phone, 0.9),
        (R(@"(^|_)(e_?mail|email_?address|mail)($|_)"), PhiKind.Email, 0.9),
        (R(@"(^|_)(url|website|web_?site|homepage|link|uri)($|_)"), PhiKind.Url, 0.8),
        (R(@"(^|_)(ip|ip_?address|ipaddr|client_?ip|remote_?addr)($|_)"), PhiKind.IpAddress, 0.85),
        (R(@"(^|_)(photo|picture|image|img|headshot|fingerprint|retina|iris|voiceprint|voice_?sample|face|biometric|signature_?image)(_?(file|path|ref|url))?($|_)"), PhiKind.Biometric, 0.75),
        (R(@"(^|_)(dob|birth|birthdate|birth_?date|date_?of_?birth|bdate|born)($|_)"), PhiKind.BirthDate, 0.95),
        (R(@"(^|_)(age|age_?years|patient_?age|age_?at_?\w+)($|_)"), PhiKind.Age, 0.85),
        (R(@"(^|_)(zip|zipcode|zip_?code|postal|postcode|postal_?code|zip5)($|_)"), PhiKind.Zip, 0.9),
        (R(@"(^|_)(city|town|municipality)($|_)"), PhiKind.City, 0.85),
        (R(@"(^|_)(address|addr|street|address_?\d|address_?line_?\d?|line_?1|mailing_?address|residence|home_?address)($|_)"), PhiKind.StreetAddress, 0.85),
        (R(@"(^|_)(note|notes|comment|comments|narrative|memo|remarks|observation|hpi|message|body|transcript|free_?text|clinical_?text|description)($|_)"), PhiKind.FreeText, 0.8),
        (R(@"(^|_)(first|last|middle|given|family|sur|full|maiden|patient|member|subscriber|guardian|spouse|mother|father|contact|emergency_?contact|provider|physician|doctor|nurse)_?name($|_)|(^|_)(fname|lname|mname|surname|forename|first|last|lastname|firstname|middlename|name)($|_)"), PhiKind.Name, 0.8),
        (R(@"(^|_)(date|dt|dos|admit|admitted|discharge|discharged|death|dod|deceased|service|visit|encounter|procedure|appointment|appt|timestamp|time_?stamp)($|_)|_(date|dt|on|at)$"), PhiKind.Date, 0.75),
        (R(@"(^|_)(id|key|identifier|guid|uuid|number|no)$"), PhiKind.OtherId, 0.45),
    ];

    /// <summary>Headers that name things which aren't about a person.</summary>
    private static readonly Regex NotPhi = R(@"(^|_)(amount|amt|paid|payment|charge|charges|billed|allowed|balance|cost|price|total|sum|qty|quantity|units?|count|cpt|hcpcs|icd(_?\d+)?|dx(_?code)?|diagnosis(_?code)?|procedure_?code|proc_?code|revenue_?code|rev_?code|drg|ndc|pos|place_?of_?service|status|type|gender|sex|state|flag|result|value|lab_?value|specialty|taxonomy|plan_?(name|type|code)|drug(_?name)?|medication|facility_?name|payer(_?name)?|company|organization|org_?name|race|ethnicity|language|weight|height|bmi|systolic|diastolic|pulse|temp|temperature|glucose|a1c|score|rating|units|dose|rate|copay|coinsurance|deductible|code)($|_)");

    private static Regex R(string pattern) => new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>A header as the rules read it: lower case, words joined by underscores ("DateOfBirth" → "date_of_birth").</summary>
    public static string Normalise(string header)
    {
        var s = CamelRx().Replace(header.Trim(), "$1_$2");
        s = NonWordRx().Replace(s.ToLowerInvariant(), "_").Trim('_');
        return s;
    }

    /// <summary>The header's verdict, or null when it says nothing either way.</summary>
    public static Hint? Of(string header)
    {
        var h = Normalise(header);
        if (h.Length == 0) return null;
        // JSON paths: the last part says the most ("member.address.zip" is a ZIP code).
        var leaf = h.Contains('_') && header.Contains('.') ? Normalise(header[(header.LastIndexOf('.') + 1)..].Replace("[]", "")) : h;
        foreach (var candidate in leaf == h ? [h] : new[] { leaf, h })
        {
            var notPhi = NotPhi.IsMatch(candidate);
            foreach (var (pattern, kind, confidence) in Rules)
            {
                if (!pattern.IsMatch(candidate)) continue;
                // "plan_name", "drug_name", "claim_amount": the not-PHI word decides, unless it's the whole header.
                if (notPhi && kind is PhiKind.Name or PhiKind.OtherId or PhiKind.Date or PhiKind.FreeText or PhiKind.ClaimNumber && !IdentifierWord(candidate))
                    return new Hint(PhiKind.None, 0.7, true, $"the header \"{header}\" names something that isn't about a person");
                return new Hint(kind, confidence, false, $"the header \"{header}\"");
            }
            if (notPhi) return new Hint(PhiKind.None, 0.7, true, $"the header \"{header}\" names something that isn't about a person");
        }
        return null;
    }

    private static bool IdentifierWord(string h) => h.EndsWith("_id", StringComparison.Ordinal) || h.EndsWith("_number", StringComparison.Ordinal) || h.EndsWith("_no", StringComparison.Ordinal);

    [GeneratedRegex(@"([a-z0-9])([A-Z])")]
    private static partial Regex CamelRx();

    [GeneratedRegex(@"[^a-z0-9]+")]
    private static partial Regex NonWordRx();
}
