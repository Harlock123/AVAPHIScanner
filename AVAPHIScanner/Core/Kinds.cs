using System.Text.Json.Serialization;

namespace AVAPHIScanner;

/// <summary>
/// What a column or a piece of text holds: one of HIPAA Safe Harbor's 18 identifiers (§164.514(b)(2)), a provider's
/// NPI, free text that may have identifiers inside it, or nothing to protect.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<PhiKind>))]
public enum PhiKind
{
    None,
    Name,
    StreetAddress,
    City,
    Zip,
    BirthDate,
    Date,
    Age,
    Phone,
    Fax,
    Email,
    Ssn,
    Mrn,
    MemberId,
    AccountNumber,
    ClaimNumber,
    License,
    VehicleId,
    DeviceId,
    Url,
    IpAddress,
    Biometric,
    OtherId,
    Npi,
    FreeText,
}

/// <summary>How much a kind says about a person on its own.</summary>
public enum KindCategory
{
    /// <summary>Not about a person (amounts, codes, clinical values).</summary>
    None,
    /// <summary>Names a person on its own: a name, SSN, MRN, phone number…</summary>
    Direct,
    /// <summary>Narrows down who someone is in combination: dates, ZIP, city, age.</summary>
    Quasi,
    /// <summary>A provider's identifier (NPI): public, and not the patient's.</summary>
    Provider,
    /// <summary>Free text, which may name anyone.</summary>
    Text,
}

/// <summary>What de-identification does to a column's values.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ColumnAction>))]
public enum ColumnAction
{
    /// <summary>Left as it is.</summary>
    Keep,
    /// <summary>The column is left out of the copy.</summary>
    Drop,
    /// <summary>Names become made-up names, the same name always the same stand-in.</summary>
    Pseudonymise,
    /// <summary>Identifiers become keyed tokens (ID-XXXXXXXXXX), the same value always the same token, so joins still work.</summary>
    Tokenise,
    /// <summary>Dates move back by a number of days that is the same for each person, so intervals stay true.</summary>
    ShiftDate,
    /// <summary>Made less precise: a date to its year, a ZIP code to its first three digits, an age over 89 to 90+.</summary>
    Generalise,
    /// <summary>Replaced by a marker such as [PHONE].</summary>
    Redact,
    /// <summary>Free text: the identifiers inside it are replaced where they stand.</summary>
    ScrubText,
}

/// <summary>Which rules a de-identified copy is made by.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<PolicyKind>))]
public enum PolicyKind
{
    /// <summary>HIPAA Safe Harbor: every one of the 18 identifiers removed or replaced.</summary>
    SafeHarbor,
    /// <summary>A limited data set (§164.514(e)): direct identifiers removed; dates, city, state, ZIP code and ages kept.</summary>
    LimitedDataSet,
    /// <summary>Safe Harbor's choices, with the person's own action for chosen columns.</summary>
    Custom,
}

/// <summary>What Safe Harbor does with dates (a new project's policy keeps only the year).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<DateMode>))]
public enum DateMode
{
    /// <summary>Moved by a per-person number of days: intervals kept (strictly, beyond Safe Harbor: see the README).</summary>
    Shift,
    /// <summary>Only the year kept: Safe Harbor's own rule.</summary>
    Year,
}

/// <summary>A kind's description and what each policy does with it.</summary>
public sealed record KindInfo(PhiKind Kind, string Id, string Label, string SafeHarborItem, KindCategory Category, ColumnAction SafeHarbor, ColumnAction LimitedDataSet);

/// <summary>The kinds, their names as agents and files write them, and the policies' defaults.</summary>
public static class Kinds
{
    public static readonly IReadOnlyList<KindInfo> All =
    [
        new(PhiKind.None, "none", "Not PHI", "", KindCategory.None, ColumnAction.Keep, ColumnAction.Keep),
        new(PhiKind.Name, "name", "Person name", "1. Names", KindCategory.Direct, ColumnAction.Pseudonymise, ColumnAction.Pseudonymise),
        new(PhiKind.StreetAddress, "street_address", "Street address", "2. Geographic subdivisions smaller than a state", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.City, "city", "City", "2. Geographic subdivisions smaller than a state", KindCategory.Quasi, ColumnAction.Redact, ColumnAction.Keep),
        new(PhiKind.Zip, "zip", "ZIP code", "2. Geographic subdivisions (ZIP: first 3 digits allowed)", KindCategory.Quasi, ColumnAction.Generalise, ColumnAction.Keep),
        new(PhiKind.BirthDate, "birth_date", "Birth date", "3. Dates (except year)", KindCategory.Quasi, ColumnAction.ShiftDate, ColumnAction.Keep),
        new(PhiKind.Date, "date", "Date (service, event)", "3. Dates (except year)", KindCategory.Quasi, ColumnAction.ShiftDate, ColumnAction.Keep),
        new(PhiKind.Age, "age", "Age", "3. Ages over 89", KindCategory.Quasi, ColumnAction.Generalise, ColumnAction.Keep),
        new(PhiKind.Phone, "phone", "Phone number", "4. Telephone numbers", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.Fax, "fax", "Fax number", "5. Fax numbers", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.Email, "email", "Email address", "6. Email addresses", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.Ssn, "ssn", "Social Security number", "7. Social Security numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.Mrn, "mrn", "Medical record number", "8. Medical record numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.MemberId, "member_id", "Member / beneficiary number", "9. Health plan beneficiary numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.AccountNumber, "account_number", "Account number", "10. Account numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.ClaimNumber, "claim_number", "Claim / encounter number", "18. Other unique identifying numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.License, "license", "Licence / certificate number", "11. Certificate/license numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.VehicleId, "vehicle_id", "Vehicle identifier", "12. Vehicle identifiers and serial numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.DeviceId, "device_id", "Device identifier", "13. Device identifiers and serial numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.Url, "url", "Web address", "14. Web URLs", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.IpAddress, "ip_address", "IP address", "15. IP addresses", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.Biometric, "biometric", "Biometric / photo reference", "16-17. Biometrics, full-face photographs", KindCategory.Direct, ColumnAction.Redact, ColumnAction.Redact),
        new(PhiKind.OtherId, "other_id", "Other identifying number", "18. Other unique identifying numbers", KindCategory.Direct, ColumnAction.Tokenise, ColumnAction.Tokenise),
        new(PhiKind.Npi, "npi", "Provider NPI", "(a provider's, not the patient's)", KindCategory.Provider, ColumnAction.Keep, ColumnAction.Keep),
        new(PhiKind.FreeText, "free_text", "Free text", "Any of the 18, inside the text", KindCategory.Text, ColumnAction.ScrubText, ColumnAction.ScrubText),
    ];

    private static readonly Dictionary<PhiKind, KindInfo> ByKind = All.ToDictionary(k => k.Kind);

    public static KindInfo Info(PhiKind kind) => ByKind[kind];

    public static string Id(PhiKind kind) => ByKind[kind].Id;

    public static string Label(PhiKind kind) => ByKind[kind].Label;

    public static bool IsPhi(PhiKind kind) => ByKind[kind].Category is KindCategory.Direct or KindCategory.Quasi or KindCategory.Text;

    public static bool IsDate(PhiKind kind) => kind is PhiKind.BirthDate or PhiKind.Date;

    /// <summary>Identifiers tokens stand in for: the same value gets the same token whichever of these columns it is in.</summary>
    public static bool IsIdentifier(PhiKind kind) => kind is PhiKind.Ssn or PhiKind.Mrn or PhiKind.MemberId or PhiKind.AccountNumber
        or PhiKind.ClaimNumber or PhiKind.License or PhiKind.VehicleId or PhiKind.DeviceId or PhiKind.OtherId;

    /// <summary>A kind from what people and agents write: "ssn", "Member ID", "birth_date", "NPI"…</summary>
    public static PhiKind Parse(string text)
    {
        var n = new string(text.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        foreach (var k in All)
            if (new string(k.Id.Where(char.IsLetterOrDigit).ToArray()) == n || k.Kind.ToString().ToLowerInvariant() == n) return k.Kind;
        return n switch
        {
            "notphi" or "nothing" or "safe" => PhiKind.None,
            "address" or "street" => PhiKind.StreetAddress,
            "zipcode" or "postal" or "postcode" => PhiKind.Zip,
            "dob" or "dateofbirth" or "birthdate" => PhiKind.BirthDate,
            "telephone" or "phonenumber" => PhiKind.Phone,
            "medicalrecordnumber" or "medicalrecord" => PhiKind.Mrn,
            "member" or "memberid" or "beneficiary" or "subscriber" or "memberno" => PhiKind.MemberId,
            "account" => PhiKind.AccountNumber,
            "claim" or "claimid" or "encounter" => PhiKind.ClaimNumber,
            "licence" or "certificate" => PhiKind.License,
            "vehicle" or "vin" => PhiKind.VehicleId,
            "device" or "serial" => PhiKind.DeviceId,
            "ip" => PhiKind.IpAddress,
            "photo" or "image" => PhiKind.Biometric,
            "id" or "identifier" => PhiKind.OtherId,
            "text" or "notes" or "note" => PhiKind.FreeText,
            _ => throw new ArgumentException($"\"{text}\" isn't a kind. The kinds: {string.Join(", ", All.Select(k => k.Id))}."),
        };
    }

    public static readonly IReadOnlyList<(ColumnAction Action, string Id)> Actions =
    [
        (ColumnAction.Keep, "keep"), (ColumnAction.Drop, "drop"), (ColumnAction.Pseudonymise, "pseudonymise"),
        (ColumnAction.Tokenise, "tokenise"), (ColumnAction.ShiftDate, "shift_date"), (ColumnAction.Generalise, "generalise"),
        (ColumnAction.Redact, "redact"), (ColumnAction.ScrubText, "scrub_text"),
    ];

    public static string Id(ColumnAction action) => Actions.First(a => a.Action == action).Id;

    /// <summary>An action from its name ("tokenize" and the other American spellings too).</summary>
    public static ColumnAction ParseAction(string text)
    {
        var n = new string(text.Where(char.IsLetter).ToArray()).ToLowerInvariant().Replace('z', 's');
        foreach (var (a, id) in Actions)
            if (id.Replace("_", "") == n) return a;
        return n switch
        {
            "remove" or "omit" or "delete" => ColumnAction.Drop,
            "pseudonym" or "fakename" => ColumnAction.Pseudonymise,
            "token" or "hash" => ColumnAction.Tokenise,
            "shift" or "dateshift" => ColumnAction.ShiftDate,
            "year" or "yearonly" or "generalize" => ColumnAction.Generalise,
            "mask" or "blank" => ColumnAction.Redact,
            "scrub" or "scrubtext" => ColumnAction.ScrubText,
            _ => throw new ArgumentException($"\"{text}\" isn't an action. The actions: {string.Join(", ", Actions.Select(a => a.Id))}."),
        };
    }

    public static string Id(PolicyKind kind) => kind switch
    {
        PolicyKind.LimitedDataSet => "limited_data_set",
        PolicyKind.Custom => "custom",
        _ => "safe_harbor",
    };

    public static string Label(PolicyKind kind) => kind switch
    {
        PolicyKind.LimitedDataSet => "Limited Data Set",
        PolicyKind.Custom => "Custom",
        _ => "Safe Harbor",
    };

    public static PolicyKind ParsePolicy(string text) => new string(text.Where(char.IsLetter).ToArray()).ToLowerInvariant() switch
    {
        "safeharbor" or "sh" or "hipaa" => PolicyKind.SafeHarbor,
        "limiteddataset" or "lds" or "limited" or "research" => PolicyKind.LimitedDataSet,
        "custom" => PolicyKind.Custom,
        _ => throw new ArgumentException($"\"{text}\" isn't a policy: safe_harbor, limited_data_set or custom."),
    };
}
