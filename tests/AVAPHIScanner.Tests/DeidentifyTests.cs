using System.Globalization;
using System.Text.Json.Nodes;
using ClosedXML.Excel;
using Microsoft.Data.Sqlite;

namespace AVAPHIScanner.Tests;

/// <summary>
/// Scanning the samples, every policy action, and the de-identified copy: tokens that match across files and tables
/// (so joins still work), dates shifted by the same days per person (so intervals stay true), the ZIP and age rules,
/// totals that still balance, and free text with nothing left in it.
/// </summary>
public sealed class DeidentifyTests
{
    private static (Project Project, Inventory Inventory, string Root) Scanned(Action<Project>? set = null)
    {
        var root = Samples.WorkingCopy();
        var p = new Project();
        p.AddSource(new SourceSpec { Kind = "folder", Path = Path.Combine(root, "samples") });
        set?.Invoke(p);
        return (p, Scanner.Scan(p, root), root);
    }

    private static string Write(Project p, Inventory inv, string root, string name = "out")
    {
        var output = Path.Combine(root, name);
        var r = DeidentifyRun.Run(p, inv, root, output, Samples.Key, today: Samples.Today);
        Assert.Empty(r.Problems);
        return output;
    }

    private static ColumnReport Column(Inventory inv, string display) => inv.Find(display);

    [Fact]
    public void The_scan_finds_every_kind_in_the_samples_and_where()
    {
        var (p, inv, _) = Scanned();
        Assert.Empty(inv.Problems);
        Assert.Equal(18, inv.Datasets);
        void Is(string where, PhiKind kind) => Assert.Equal(kind, p.EffectiveKind(Column(inv, where).Key, Column(inv, where).Detected));
        Is("members.csv › member_id", PhiKind.MemberId);
        Is("members.csv › mrn", PhiKind.Mrn);
        Is("members.csv › first_name", PhiKind.Name);
        Is("members.csv › last_name", PhiKind.Name);
        Is("members.csv › dob", PhiKind.BirthDate);
        Is("members.csv › ssn", PhiKind.Ssn);
        Is("members.csv › street", PhiKind.StreetAddress);
        Is("members.csv › city", PhiKind.City);
        Is("members.csv › zip", PhiKind.Zip);
        Is("members.csv › phone", PhiKind.Phone);
        Is("members.csv › email", PhiKind.Email);
        Is("members.csv › enrolled_on", PhiKind.Date);
        Is("members.csv › gender", PhiKind.None);
        Is("members.csv › state", PhiKind.None);
        Is("members.csv › plan", PhiKind.None);
        Is("claims.xlsx › Claims › claim_id", PhiKind.ClaimNumber);
        Is("claims.xlsx › Claims › service_date", PhiKind.Date);
        Is("claims.xlsx › Claims › provider_npi", PhiKind.Npi);
        Is("claims.xlsx › Claims › billed", PhiKind.None);
        Is("claims.xlsx › Claims › icd10", PhiKind.None);
        Is("feed.jsonl › contact.email", PhiKind.Email);
        Is("feed.jsonl › client_ip", PhiKind.IpAddress);
        Is("feed.jsonl › member.name", PhiKind.Name);
        Is("feed.jsonl › member.birth_date", PhiKind.BirthDate);
        Is("feed.jsonl › comment", PhiKind.FreeText);
        Is("feed.jsonl › premium", PhiKind.None);
        Is("clinic.db › main.patients › birth_date", PhiKind.BirthDate);
        Is("clinic.db › main.visits › notes", PhiKind.FreeText);
        Is("clinic.db › main.visits › charge", PhiKind.None);
        Is("notes/note-001.txt › (text)", PhiKind.FreeText);
        // Every confident column says how sure it is and why; examples are masked.
        var ssn = Column(inv, "members.csv › ssn");
        Assert.True(ssn.Confidence >= 0.9);
        Assert.All(ssn.Examples, e => Assert.StartsWith("***-**-", e));
        Assert.Equal(40, ssn.Count);
        // The people over 89 are counted.
        Assert.Equal(3, Column(inv, "members.csv › dob").Over89);
        // Free text has cell-level findings.
        var note = Column(inv, "notes/note-001.txt › (text)");
        Assert.Contains(note.Findings, f => f.Kind == PhiKind.Name);
        Assert.Contains(note.Findings, f => f.Kind == PhiKind.Phone);
        Assert.Equal("High", RiskSummary.Of(inv, p).Overall);
    }

    [Fact]
    public void Sampling_reads_only_the_first_rows_and_says_so()
    {
        var (p, inv, _) = Scanned(p => p.SampleRows = 10);
        var c = Column(inv, "claims.xlsx › Claims › member_id");
        Assert.True(c.Sampled);
        Assert.Equal(10, c.RowsRead);
        Assert.Equal(120, c.RowsTotal);
        Assert.Contains(RiskSummary.Of(inv, p).Notes, n => n.Contains("sampled"));
    }

    [Fact]
    public void Every_policy_action_on_a_value()
    {
        var d = new Deidentifier(Samples.Key, new Policy(), today: Samples.Today);
        Assert.Equal("x", d.Apply(ColumnAction.Keep, PhiKind.Name, "x", null));
        Assert.Null(d.Apply(ColumnAction.Drop, PhiKind.Name, "Maria Lopez", null));
        var pseudo = d.Apply(ColumnAction.Pseudonymise, PhiKind.Name, "Lopez, Maria", null)!;
        Assert.Matches(@"^[A-Z][a-z]+, [A-Z][a-z]+$", pseudo);
        Assert.All(Detect.NameWords(pseudo), w => Assert.Contains(w, Lists.PseudoWords));
        Assert.Equal("Dr. " + d.Pseudonym("Alan Brooks"), d.Apply(ColumnAction.Pseudonymise, PhiKind.Name, "Dr. Alan Brooks", null));
        Assert.Matches(@"^ID-[A-Z2-7]{10}$", d.Apply(ColumnAction.Tokenise, PhiKind.Ssn, "512-44-1093", null)!);
        var shifted = d.Apply(ColumnAction.ShiftDate, PhiKind.Date, "2026-02-01", "M10001")!;
        Assert.Equal(new DateTime(2026, 2, 1).AddDays(d.ShiftDays("M10001")).ToString("yyyy-MM-dd"), shifted);
        Assert.Equal("1957", d.Apply(ColumnAction.Generalise, PhiKind.BirthDate, "03/14/1957", null));
        Assert.Equal("627", d.Apply(ColumnAction.Generalise, PhiKind.Zip, "62704", null));
        Assert.Equal("90+", d.Apply(ColumnAction.Generalise, PhiKind.Age, "93", null));
        Assert.Equal("45", d.Apply(ColumnAction.Generalise, PhiKind.Age, "45", null));
        Assert.Equal("[PHONE]", d.Apply(ColumnAction.Redact, PhiKind.Phone, "(217) 555-0100", null));
        Assert.Equal("[EMAIL]", d.Apply(ColumnAction.Redact, PhiKind.Email, "a@example.com", null));
        var scrubbed = d.Apply(ColumnAction.ScrubText, PhiKind.FreeText, "Maria Lopez called from (217) 555-0100 on 2026-02-01.", "M10001")!;
        Assert.DoesNotContain("Lopez", scrubbed);
        Assert.DoesNotContain("555-0100", scrubbed);
        Assert.DoesNotContain("2026-02-01", scrubbed);
        Assert.Contains("[PHONE]", scrubbed);
        Assert.Null(d.Apply(ColumnAction.Tokenise, PhiKind.Mrn, null, null));
    }

    [Fact]
    public void Tokens_and_pseudonyms_are_the_same_wherever_the_value_is_and_differ_with_the_key()
    {
        var d = new Deidentifier(Samples.Key, new Policy());
        Assert.Equal(d.Token("123-45-6789"), d.Token("123456789"));
        Assert.Equal(d.Token("m10001"), d.Token("M10001"));
        Assert.NotEqual(d.Token("M10001"), d.Token("M10002"));
        Assert.Equal(d.Pseudonym("LOPEZ"), d.Pseudonym("LOPEZ"));
        Assert.Equal(d.Pseudonym("Lopez").ToUpperInvariant(), d.Pseudonym("LOPEZ"));
        var other = new Deidentifier(Enumerable.Repeat((byte)7, 32).ToArray(), new Policy());
        Assert.NotEqual(d.Token("M10001"), other.Token("M10001"));
    }

    [Fact]
    public void Zip_codes_keep_three_digits_except_the_small_areas()
    {
        Assert.Equal("627", Deidentifier.Zip3("62704"));
        Assert.Equal("627", Deidentifier.Zip3("62704-1234"));
        Assert.Equal("000", Deidentifier.Zip3("03601"));   // 036: New Hampshire, under 20,000 people
        Assert.Equal("000", Deidentifier.Zip3("82301"));   // 823: Wyoming
        Assert.Equal("000", Deidentifier.Zip3("89301"));   // 893: Nevada
        Assert.Equal(17, Lists.RestrictedZip3.Count);
    }

    [Fact]
    public void Dates_shift_by_the_same_days_for_one_person_so_intervals_stay_and_birth_dates_over_89_go_to_90_years_ago()
    {
        var d = new Deidentifier(Samples.Key, new Policy(), today: Samples.Today);
        var a = d.Shift(new DateTime(2026, 1, 10), "M10001", false);
        var b = d.Shift(new DateTime(2026, 3, 1), "M10001", false);
        Assert.Equal(new DateTime(2026, 3, 1) - new DateTime(2026, 1, 10), b - a);
        Assert.InRange(d.ShiftDays("M10001"), -365, -1);
        Assert.Contains(Enumerable.Range(10002, 20).Select(i => d.ShiftDays($"M{i}")), s => s != d.ShiftDays("M10001"));
        Assert.Equal(new DateTime(1936, 1, 1), d.Shift(new DateTime(1931, 6, 2), "M10007", birth: true));
        Assert.Equal(1936, d.Year(new DateTime(1931, 6, 2), birth: true));
    }

    [Fact]
    public void A_safe_harbor_copy_keeps_joins_intervals_and_totals_across_every_file_and_table()
    {
        var (p, inv, root) = Scanned();
        var output = Write(p, inv, root);
        var d = new Deidentifier(Samples.Key, p.Policy, inv.Known, Samples.Today);
        var source = Samples.Members(Path.Combine(root, "samples"));
        var copy = Samples.Members(output);
        Assert.Equal(source.Count, copy.Count);

        // Every member's token is the same in the members file, the workbook, the database, the feed and the notes.
        var tokens = copy.Select(m => m["member_id"]).ToHashSet();
        Assert.All(copy, m => Assert.Matches(@"^ID-[A-Z2-7]{10}$", m["member_id"]));
        using (var book = new XLWorkbook(Path.Combine(output, "claims.xlsx")))
        {
            var claims = book.Worksheet("Claims");
            foreach (var r in Enumerable.Range(2, 120)) Assert.Contains(claims.Cell(r, 2).GetString(), tokens);
        }
        using (var c = new SqliteConnection($"Data Source={Path.Combine(output, "clinic.db")};Pooling=False"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM visits v JOIN patients p ON p.member_id = v.member_id";
            Assert.Equal(90L, (long)cmd.ExecuteScalar()!);
        }
        foreach (var line in File.ReadLines(Path.Combine(output, "feed.jsonl")))
            Assert.Contains((string?)JsonNode.Parse(line)!["member_id"], tokens);
        var note = File.ReadAllText(Path.Combine(output, "notes", "note-001.txt"));
        Assert.Contains($"Member ID: {d.Token(source[0]["member_id"])}", note);

        // Dates move by the member's own days: the interval between enrolment and each claim is what it was.
        var byToken = copy.ToDictionary(m => m["member_id"]);
        using (var before = new XLWorkbook(Path.Combine(root, "samples", "claims.xlsx")))
        using (var after = new XLWorkbook(Path.Combine(output, "claims.xlsx")))
        {
            var (bs, as_) = (before.Worksheet("Claims"), after.Worksheet("Claims"));
            for (var r = 2; r <= 121; r++)
            {
                var member = source.First(m => m["member_id"] == bs.Cell(r, 2).GetString());
                var copied = byToken[as_.Cell(r, 2).GetString()];
                var enrolledBefore = DateTime.ParseExact(member["enrolled_on"], "MM/dd/yyyy", CultureInfo.InvariantCulture);
                var enrolledAfter = DateTime.ParseExact(copied["enrolled_on"], "MM/dd/yyyy", CultureInfo.InvariantCulture);
                Assert.Equal(bs.Cell(r, 3).GetDateTime() - enrolledBefore, as_.Cell(r, 3).GetDateTime() - enrolledAfter);
                Assert.NotEqual(bs.Cell(r, 3).GetDateTime(), as_.Cell(r, 3).GetDateTime());
            }
            // Totals balance.
            double Sum(IXLWorksheet s, int col) => Enumerable.Range(2, 120).Sum(r => s.Cell(r, col).GetDouble());
            Assert.Equal(Sum(bs, 7), Sum(as_, 7), 6);
            Assert.Equal(Sum(bs, 8), Sum(as_, 8), 6);
            Assert.Equal(bs.Cell(5, 5).GetString(), as_.Cell(5, 5).GetString());   // CPT codes as they were
        }
        // A birth date is shifted the same in the members file and the database.
        using (var c = new SqliteConnection($"Data Source={Path.Combine(output, "clinic.db")};Pooling=False"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT birth_date FROM patients WHERE member_id = $m";
            cmd.Parameters.AddWithValue("$m", copy[0]["member_id"]);
            Assert.Equal(copy[0]["dob"], (string)cmd.ExecuteScalar()!);
            cmd.CommandText = "SELECT ROUND(SUM(charge), 2) FROM visits";
            var after = (double)cmd.ExecuteScalar()!;
            using var src = new SqliteConnection($"Data Source={Path.Combine(root, "samples", "clinic.db")};Pooling=False");
            src.Open();
            using var cmd2 = src.CreateCommand();
            cmd2.CommandText = "SELECT ROUND(SUM(charge), 2) FROM visits";
            Assert.Equal((double)cmd2.ExecuteScalar()!, after);
        }
        // The over-89s show the year 90 years ago; ZIP codes keep three digits (000 for small areas); nothing raw is left.
        Assert.Equal(3, copy.Count(m => m["dob"] == "1936-01-01"));
        Assert.All(copy, m => Assert.Matches(@"^\d{3}$", m["zip"]));
        Assert.Contains(copy, m => m["zip"] == "000");
        var all = string.Join("\n", Directory.GetFiles(output, "*", SearchOption.AllDirectories).Where(f => !f.EndsWith(".xlsx") && !f.EndsWith(".db")).Select(File.ReadAllText));
        Assert.Empty(Samples.Leaks(all, Samples.Secrets(Path.Combine(root, "samples"))));
        SqliteConnection.ClearAllPools();
    }

    [Fact]
    public void A_limited_data_set_keeps_dates_zip_and_city_and_still_removes_direct_identifiers()
    {
        var (p, inv, root) = Scanned(p => p.Policy.Kind = PolicyKind.LimitedDataSet);
        var output = Write(p, inv, root);
        var source = Samples.Members(Path.Combine(root, "samples"));
        var copy = Samples.Members(output);
        Assert.Equal(source.Select(m => m["dob"]), copy.Select(m => m["dob"]));
        Assert.Equal(source.Select(m => m["zip"]), copy.Select(m => m["zip"]));
        Assert.Equal(source.Select(m => m["city"]), copy.Select(m => m["city"]));
        Assert.All(copy, m => Assert.Equal("[ADDRESS]", m["street"]));
        Assert.All(copy, m => Assert.StartsWith("ID-", m["ssn"]));
        Assert.DoesNotContain(copy, m => source.Any(s => s["last_name"] == m["last_name"]));
        Assert.True(Verifier.Verify(output, p.Policy, inv).Clean);
    }

    [Fact]
    public void Custom_actions_drop_keep_and_generalise_columns_in_every_format()
    {
        var (p, inv, root) = Scanned();
        p.Policy.Kind = PolicyKind.Custom;
        p.Policy.Actions[inv.Find("members.csv › ssn").Key] = ColumnAction.Drop;
        p.Policy.Actions[inv.Find("members.csv › city").Key] = ColumnAction.Keep;
        p.Policy.Actions[inv.Find("members.csv › dob").Key] = ColumnAction.Generalise;
        p.Policy.Actions[inv.Find("claims.xlsx › Claims › provider_npi").Key] = ColumnAction.Drop;
        p.Policy.Actions[inv.Find("feed.jsonl › client_ip").Key] = ColumnAction.Drop;
        p.Policy.Actions[inv.Find("clinic.db › main.patients › phone").Key] = ColumnAction.Drop;
        p.Policy.Actions[inv.Find("clinic.db › main.visits › reason").Key] = ColumnAction.Redact;
        var output = Write(p, inv, root);
        var copy = Samples.Members(output);
        Assert.DoesNotContain("ssn", copy[0].Keys);
        Assert.Equal(Samples.Members(Path.Combine(root, "samples")).Select(m => m["city"]), copy.Select(m => m["city"]));
        Assert.All(copy, m => Assert.Matches(@"^\d{4}$", m["dob"]));
        using (var book = new XLWorkbook(Path.Combine(output, "claims.xlsx")))
            Assert.DoesNotContain("provider_npi", book.Worksheet("Claims").Row(1).CellsUsed().Select(c => c.GetString()));
        Assert.DoesNotContain("client_ip", File.ReadAllText(Path.Combine(output, "feed.jsonl")));
        using var c = new SqliteConnection($"Data Source={Path.Combine(output, "clinic.db")};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('patients') WHERE name = 'phone'";
        Assert.Equal(0L, (long)cmd.ExecuteScalar()!);
        cmd.CommandText = "SELECT DISTINCT reason FROM visits";
        Assert.Equal("[REDACTED]", (string)cmd.ExecuteScalar()!);
        SqliteConnection.ClearAllPools();
    }

    [Fact]
    public void Year_mode_keeps_only_years_and_verify_is_clean()
    {
        var (p, inv, root) = Scanned(p => p.Policy.DateMode = DateMode.Year);
        var output = Write(p, inv, root);
        Assert.All(Samples.Members(output), m => Assert.Matches(@"^\d{4}$", m["dob"]));
        Assert.All(Samples.Members(output), m => Assert.Matches(@"^\d{4}$", m["enrolled_on"]));
        var note = File.ReadAllText(Path.Combine(output, "notes", "note-002.txt"));
        Assert.DoesNotMatch(@"\d{4}-\d{2}-\d{2}", note);
        var v = Verifier.Verify(output, p.Policy, inv);
        Assert.True(v.Clean, v.Summary + string.Join("; ", v.Leftovers.Select(l => $"{l.Where} {l.Kind} {l.Count}")));
        Assert.Empty(v.Expected.Where(e => Kinds.IsDate(e.Key)));
    }

    [Fact]
    public void Verify_is_clean_after_safe_harbor_and_reports_what_a_wrong_decision_leaves()
    {
        var (p, inv, root) = Scanned();
        var output = Write(p, inv, root);
        var clean = Verifier.Verify(output, p.Policy, inv);
        Assert.True(clean.Clean, clean.Summary + string.Join("; ", clean.Leftovers.Select(l => $"{l.Where} {l.Kind} {l.Count}")));
        Assert.True(clean.Before[PhiKind.Ssn] >= 40);
        Assert.True(clean.Expected.GetValueOrDefault(PhiKind.Date) > 0);   // shifted dates: kept by the policy

        // The person (wrongly) says the last names aren't PHI: the copy keeps them, and verify finds them.
        p.Overrides[inv.Find("members.csv › last_name").Key] = new ColumnOverride { IsPhi = false };
        var leaky = Write(p, inv, root, "leaky");
        var v = Verifier.Verify(leaky, p.Policy, inv);
        Assert.False(v.Clean);
        Assert.Contains(v.Leftovers, l => l.Where == "members.csv › last_name" && l.Kind == PhiKind.Name && l.Why.Contains("original"));
        Assert.All(v.Leftovers.SelectMany(l => l.Examples), e => Assert.Contains("*", e));

        // Checked against Safe Harbor's own date rule, shifted dates count as left.
        var strict = Verifier.Verify(output, new Policy { DateMode = DateMode.Year }, inv);
        Assert.Contains(strict.Leftovers, l => Kinds.IsDate(l.Kind));
    }

    [Fact]
    public void The_copy_never_goes_into_a_source_folder_or_over_a_file()
    {
        var (p, inv, root) = Scanned();
        Assert.Throws<IOException>(() => DeidentifyRun.Run(p, inv, root, Path.Combine(root, "samples"), Samples.Key));
        Assert.Throws<IOException>(() => DeidentifyRun.Run(p, inv, root, Path.Combine(root, "samples", "out"), Samples.Key));
        var output = Write(p, inv, root);
        var again = DeidentifyRun.Run(p, inv, root, output, Samples.Key);
        Assert.NotEmpty(again.Problems);
        Assert.Contains(again.Problems, x => x.Contains("exists"));
        // The sources are as they were.
        Assert.Equal(File.ReadAllText(Path.Combine(Samples.Folder, "members.csv")), File.ReadAllText(Path.Combine(root, "samples", "members.csv")));
    }

    [Fact]
    public void Projects_save_and_load_with_relative_paths()
    {
        var root = Samples.WorkingCopy();
        var p = new Project();
        p.AddSource(new SourceSpec { Kind = "folder", Path = Path.Combine(root, "samples") });
        p.Overrides["s1|members.csv||plan"] = new ColumnOverride { IsPhi = true, Kind = PhiKind.OtherId, Note = "plan codes are per-person here" };
        p.Policy.Kind = PolicyKind.Custom;
        p.Policy.Actions["s1|members.csv||city"] = ColumnAction.Keep;
        var file = Path.Combine(root, "p.phiscan");
        ProjectFiles.Save(p, file);
        Assert.Contains("\"path\": \"samples\"", File.ReadAllText(file));
        Assert.Contains("\"kind\": \"Custom\"", File.ReadAllText(file));
        var back = ProjectFiles.Load(file);
        Assert.Equal(Path.Combine(root, "samples"), back.Sources[0].Path);
        Assert.Equal(PhiKind.OtherId, back.EffectiveKind("s1|members.csv||plan", PhiKind.None));
        Assert.Equal(ColumnAction.Keep, back.ActionFor("s1|members.csv||city", PhiKind.City));
        Assert.Throws<InvalidDataException>(() => Project.FromJson("{\"format\": \"something else\"}"));
    }

    [Fact]
    public void Reports_export_as_a_workbook_and_a_page_with_every_value_masked()
    {
        var (p, inv, root) = Scanned();
        var xlsx = Path.Combine(root, "r.xlsx");
        var html = Path.Combine(root, "r.html");
        ReportWriter.Write(xlsx, inv, p);
        ReportWriter.Write(html, inv, p);
        using (var book = new XLWorkbook(xlsx))
        {
            Assert.Equal(["Summary", "Inventory", "Free-text findings"], book.Worksheets.Select(w => w.Name));
            var text = string.Join("\n", book.Worksheets.SelectMany(w => w.CellsUsed()).Select(c => c.GetString()));
            Assert.Empty(Samples.Leaks(text, Samples.Secrets(Path.Combine(root, "samples"))));
            Assert.Contains("Social Security number", text);
        }
        var page = File.ReadAllText(html);
        Assert.Contains("<title>PHI Scan Report</title>", page);
        Assert.Contains("prefers-color-scheme: dark", page);
        Assert.Contains("actual knowledge", page);
        Assert.Empty(Samples.Leaks(page, Samples.Secrets(Path.Combine(root, "samples"))));
    }
}
