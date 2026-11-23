#:package ClosedXML@0.104.2
#:package Microsoft.Data.Sqlite@10.0.14
#:property JsonSerializerIsReflectionEnabledByDefault=true
#:property PublishAot=false
// Makes the sample data in this folder: run `dotnet run make-samples.cs` here. Every person, number and note is made
// up (a fixed seed, so the files come out the same each time). Phone numbers are in the 555-0100 to 555-0199 range kept for
// fiction, emails at example.com and example.org, IP addresses in 192.0.2.0/24 (TEST-NET-1); SSNs in the never-issued 9xx-01…49 range; MRNs, NPIs and the
// rest are random numbers in the right shape. The same members (member_id M10001…) appear in every file, so the
// de-identified copies can be joined again.
using System.Globalization;
using System.Text;
using System.Text.Json;
using ClosedXML.Excel;
using Microsoft.Data.Sqlite;

var rng = new Random(20261123);
var here = Directory.GetCurrentDirectory();
string[] first = ["Maria", "James", "Linda", "Robert", "Patricia", "Michael", "Jennifer", "David", "Elizabeth", "William", "Susan", "Richard", "Jessica", "Joseph", "Sarah", "Thomas", "Karen", "Charles", "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Sandra", "Mark", "Ashley", "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth", "Carol", "Kevin", "Amanda", "Brian"];
string[] last = ["Lopez", "Okafor", "Brennan", "Nguyen", "Whitfield", "Castillo", "Haddad", "Kowalski", "Fitzgerald", "Delgado", "Lindqvist", "Ibarra", "Moreau", "Tanaka", "Ramirez", "Sullivan", "Petrov", "Mendoza", "Gallagher", "Hoffman", "Rasmussen", "Pacheco", "Underwood", "Novotny", "Novak", "Esposito", "Barrett", "Kimura", "Osei", "Fontaine", "Herrera", "McAllister", "Lindgren", "Batista", "Brandt", "Sandoval", "Quintero", "Valdez", "Kaplan", "Whitaker"];
string[] streets = ["Maple St", "Oak Ave", "Cedar Ln", "Elm St", "Pine Rd", "Birch Dr", "Willow Way", "Aspen Ct", "Chestnut St", "Spruce Ave", "Laurel Ln", "Hawthorn Rd"];
(string City, string State, string Zip, string Area)[] places = [("Springfield", "IL", "62704", "217"), ("Columbus", "OH", "43215", "614"), ("Madison", "WI", "53703", "608"), ("Albany", "NY", "12207", "518"), ("Tucson", "AZ", "85701", "520"), ("Boise", "ID", "83702", "208"), ("Claremont", "NH", "03601", "603"), ("Rawlins", "WY", "82301", "307"), ("Savannah", "GA", "31401", "912"), ("Eugene", "OR", "97401", "541")];
string[] plans = ["Gold PPO", "Silver HMO", "Bronze EPO", "Medicare Advantage"];

string Digits(int n) => string.Concat(Enumerable.Range(0, n).Select(_ => (char)('0' + rng.Next(10))));
// SSNs in area 900-999 with group 01-49: never issued, as an SSN or as an ITIN (whose groups are 50-65, 70-88,
// 90-92 and 94-99), so no sample number can be anyone's. The scanner counts them as taxpayer-shaped numbers.
string Ssn() => $"{rng.Next(900, 1000):000}-{rng.Next(1, 50):00}-{rng.Next(1, 10000):0000}";
bool Luhn(string d) { var s = 0; var dbl = false; for (var i = d.Length - 1; i >= 0; i--) { var x = d[i] - '0'; if (dbl) { x *= 2; if (x > 9) x -= 9; } s += x; dbl = !dbl; } return s % 10 == 0; }
string Npi() { var nine = "1" + Digits(8); for (var c = '0'; c <= '9'; c++) if (Luhn("80840" + nine + c)) return nine + c; throw new(); }

var members = new List<Member>();
for (var i = 0; i < 40; i++)
{
    // Three members are over 89; the rest born 1940 to 2005.
    var dob = i is 6 or 19 or 33 ? new DateTime(1931 + i % 4, 1 + rng.Next(12), 1 + rng.Next(28)) : new DateTime(1940 + rng.Next(66), 1 + rng.Next(12), 1 + rng.Next(28));
    var p = places[rng.Next(places.Length)];
    var f = first[i];
    var l = last[i];
    members.Add(new Member($"M{10001 + i}", "MRN" + Digits(7), f, l, dob, Ssn(), i % 2 == 0 ? "F" : "M",
        $"{100 + rng.Next(9800)} {streets[rng.Next(streets.Length)]}", p.City, p.State, p.Zip, $"({p.Area}) 555-{100 + i:0000}", $"{f.ToLowerInvariant()}.{l.ToLowerInvariant()}@example.com",
        plans[rng.Next(plans.Length)], new DateTime(2019 + rng.Next(7), 1 + rng.Next(12), 1)));
}

var providers = new List<(string Npi, string Name, string Specialty)>
{
    (Npi(), "Dr. Alan Brooks", "Internal Medicine"), (Npi(), "Dr. Priya Raman", "Cardiology"), (Npi(), "Dr. Samuel Ortiz", "Family Medicine"),
    (Npi(), "Dr. Grace Whitman", "Endocrinology"), (Npi(), "Dr. Omar Haddad", "Pulmonology"), (Npi(), "Dr. Helen Park", "Orthopedics"),
};

// members.csv
var csv = new StringBuilder("member_id,mrn,first_name,last_name,dob,ssn,gender,street,city,state,zip,phone,email,plan,enrolled_on\n");
foreach (var m in members)
    csv.AppendLine(string.Join(',', m.Id, m.Mrn, m.First, m.Last, m.Dob.ToString("yyyy-MM-dd"), m.Ssn, m.Gender, m.Street, m.City, m.State, m.Zip, $"\"{m.Phone}\"", m.Email, m.Plan, m.Enrolled.ToString("MM/dd/yyyy", CultureInfo.InvariantCulture)));
File.WriteAllText(Path.Combine(here, "members.csv"), csv.ToString());

// claims.xlsx: claims with typed dates and amounts, and the providers.
string[] cpts = ["99213", "99214", "99203", "93000", "80053", "83036", "71046", "97110"];
string[] icds = ["E11.9", "I10", "J45.909", "M54.5", "E78.5", "R07.9", "Z00.00", "J44.9"];
var claims = new List<(string Id, string Member, DateTime Service, string Npi, string Cpt, string Icd, decimal Billed, decimal Paid)>();
for (var i = 0; i < 120; i++)
{
    var m = members[rng.Next(members.Count)];
    var billed = Math.Round((decimal)(60 + rng.Next(900)) + rng.Next(100) / 100m, 2);
    claims.Add(($"CLM-2026-{i + 1:00000}", m.Id, new DateTime(2026, 1, 1).AddDays(rng.Next(300)), providers[rng.Next(providers.Count)].Npi, cpts[rng.Next(cpts.Length)], icds[rng.Next(icds.Length)], billed, Math.Round(billed * (0.5m + rng.Next(40) / 100m), 2)));
}
using (var book = new XLWorkbook())
{
    var s = book.Worksheets.Add("Claims");
    string[] head = ["claim_id", "member_id", "service_date", "provider_npi", "cpt", "icd10", "billed", "paid"];
    for (var c = 0; c < head.Length; c++) s.Cell(1, c + 1).Value = head[c];
    for (var r = 0; r < claims.Count; r++)
    {
        var x = claims[r];
        s.Cell(r + 2, 1).Value = x.Id;
        s.Cell(r + 2, 2).Value = x.Member;
        s.Cell(r + 2, 3).Value = x.Service;
        s.Cell(r + 2, 3).Style.DateFormat.Format = "yyyy-mm-dd";
        s.Cell(r + 2, 4).Value = x.Npi;
        s.Cell(r + 2, 5).Value = x.Cpt;
        s.Cell(r + 2, 6).Value = x.Icd;
        s.Cell(r + 2, 7).Value = x.Billed;
        s.Cell(r + 2, 8).Value = x.Paid;
    }
    var p = book.Worksheets.Add("Providers");
    p.Cell(1, 1).Value = "npi";
    p.Cell(1, 2).Value = "provider_name";
    p.Cell(1, 3).Value = "specialty";
    for (var r = 0; r < providers.Count; r++)
    {
        p.Cell(r + 2, 1).Value = providers[r].Npi;
        p.Cell(r + 2, 2).Value = providers[r].Name;
        p.Cell(r + 2, 3).Value = providers[r].Specialty;
    }
    book.SaveAs(Path.Combine(here, "claims.xlsx"));
}

// notes/: free-text clinical notes, one a visit.
Directory.CreateDirectory(Path.Combine(here, "notes"));
foreach (var f in Directory.GetFiles(Path.Combine(here, "notes"))) File.Delete(f);
string[] complaints = ["follow-up of type 2 diabetes", "a cough for two weeks", "high blood pressure", "low back pain after a fall", "chest pain on exertion", "a medication review"];
for (var i = 0; i < 12; i++)
{
    var m = members[i * 3 % members.Count];
    var prov = providers[i % providers.Count];
    var visit = new DateTime(2026, 2, 1).AddDays(i * 17);
    var age = (int)((visit - m.Dob).TotalDays / 365.25);
    var title = m.Gender == "F" ? "Ms." : "Mr.";
    var they = m.Gender == "F" ? "She" : "He";
    var note = $"""
        Clinical note
        Member ID: {m.Id}    MRN: {m.Mrn}
        Patient: {m.First} {m.Last}    DOB: {m.Dob:MM/dd/yyyy}
        Visit date: {visit:yyyy-MM-dd}
        Provider: {prov.Name} (NPI {prov.Npi})

        {title} {m.Last} is a {age}-year-old seen for {complaints[i % complaints.Length]}. {they} lives at {m.Street}, {m.City}, {m.State} {m.Zip} and can be reached at {m.Phone} or {m.Email}. Blood pressure 132/84, pulse 76. {(i % 4 == 0 ? $"{they} was referred by {members[(i * 3 + 5) % members.Count].First} {members[(i * 3 + 5) % members.Count].Last}, a neighbour." : "")}

        Assessment: stable. Plan: recheck labs in 3 months; follow-up on {visit.AddDays(90):MMMM d, yyyy}. Called the pharmacy at 312-555-0199 to confirm the prescription.
        """;
    File.WriteAllText(Path.Combine(here, "notes", $"note-{i + 1:000}.txt"), note.Replace("\r\n", "\n") + "\n");
}

// feed.jsonl: an eligibility and contact feed, one event a line.
var feed = new StringBuilder();
string[] events = ["eligibility_check", "card_requested", "address_change", "portal_login", "call_center"];
for (var i = 0; i < 60; i++)
{
    var m = members[rng.Next(members.Count)];
    var o = new
    {
        event_id = $"EV{900000 + i}",
        member_id = m.Id,
        @event = events[rng.Next(events.Length)],
        at = new DateTime(2026, 3, 1, 8, 0, 0).AddMinutes(rng.Next(60 * 24 * 90)).ToString("yyyy-MM-ddTHH:mm:ss"),
        member = new { name = $"{m.Last}, {m.First}", birth_date = m.Dob.ToString("yyyy-MM-dd"), zip = m.Zip },
        contact = new { phone = m.Phone, email = m.Email },
        client_ip = $"192.0.2.{10 + rng.Next(200)}",
        comment = i % 5 == 0 ? $"Member asked to update the mailing address to {100 + rng.Next(800)} {streets[rng.Next(streets.Length)]}, {m.City}, {m.State} {m.Zip}." : "Routine event.",
        premium = Math.Round(80 + rng.Next(400) + rng.Next(100) / 100.0, 2),
    };
    feed.AppendLine(JsonSerializer.Serialize(o));
}
File.WriteAllText(Path.Combine(here, "feed.jsonl"), feed.ToString());

// clinic.db: patients and their visits.
var db = Path.Combine(here, "clinic.db");
SqliteConnection.ClearAllPools();
if (File.Exists(db)) File.Delete(db);
using (var conn = new SqliteConnection($"Data Source={db};Pooling=False"))
{
    conn.Open();
    using var tx = conn.BeginTransaction();
    void Exec(string sql, params (string, object?)[] ps)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
    Exec("CREATE TABLE patients (member_id TEXT PRIMARY KEY, mrn TEXT NOT NULL, first_name TEXT, last_name TEXT, birth_date TEXT, zip TEXT, phone TEXT)");
    Exec("CREATE TABLE visits (visit_id INTEGER PRIMARY KEY, member_id TEXT NOT NULL REFERENCES patients(member_id), visit_date TEXT, provider_npi TEXT, reason TEXT, charge REAL, notes TEXT)");
    foreach (var m in members.Take(30))
        Exec("INSERT INTO patients VALUES ($a, $b, $c, $d, $e, $f, $g)", ("$a", m.Id), ("$b", m.Mrn), ("$c", m.First), ("$d", m.Last), ("$e", m.Dob.ToString("yyyy-MM-dd")), ("$f", m.Zip), ("$g", m.Phone));
    for (var i = 0; i < 90; i++)
    {
        var m = members[rng.Next(30)];
        var prov = providers[rng.Next(providers.Count)];
        var notes = i % 6 == 0 ? $"{m.First} {m.Last} called from {m.Phone} to reschedule." : i % 6 == 3 ? $"Seen with {complaints[rng.Next(complaints.Length)]}; next visit in 6 weeks." : "";
        Exec("INSERT INTO visits VALUES ($a, $b, $c, $d, $e, $f, $g)", ("$a", 5000 + i), ("$b", m.Id), ("$c", new DateTime(2026, 1, 5).AddDays(rng.Next(300)).ToString("yyyy-MM-dd")),
            ("$d", prov.Npi), ("$e", complaints[rng.Next(complaints.Length)]), ("$f", Math.Round(75 + rng.Next(500) + rng.Next(100) / 100.0, 2)), ("$g", notes.Length == 0 ? null : notes));
    }
    tx.Commit();
}
Console.WriteLine($"Wrote members.csv ({members.Count}), claims.xlsx ({claims.Count} claims), notes/ (12), feed.jsonl (60), clinic.db (30 patients, 90 visits).");

record Member(string Id, string Mrn, string First, string Last, DateTime Dob, string Ssn, string Gender, string Street, string City, string State, string Zip, string Phone, string Email, string Plan, DateTime Enrolled);
