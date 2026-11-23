namespace AVAPHIScanner.Tests;

/// <summary>Each detector with values it should and shouldn't take: the look of one value, a header, and text.</summary>
public sealed class DetectorTests
{
    private static PhiKind? Best(string v) => Detect.Value(v).OrderByDescending(h => h.Strength).Select(h => (PhiKind?)h.Kind).FirstOrDefault();

    private static double Strength(string v, PhiKind kind) => Detect.Value(v).Where(h => h.Kind == kind).Select(h => h.Strength).DefaultIfEmpty(0).Max();

    [Theory]
    [InlineData("512-44-1093", true)]
    [InlineData("512 44 1093", true)]
    [InlineData("900-12-3456", false)]   // area 900-999: not issued (ITINs live there)
    [InlineData("000-12-3456", false)]
    [InlineData("666-12-3456", false)]
    [InlineData("512-00-1093", false)]   // group 00
    [InlineData("512-44-0000", false)]   // serial 0000
    [InlineData("078-05-1120", false)]   // the Woolworth wallet card
    [InlineData("12-345-6789", false)]
    public void Ssns_follow_the_ssas_rules(string value, bool ssn)
    {
        Assert.Equal(ssn, Detect.Ssn(value));
        Assert.Equal(ssn, Strength(value, PhiKind.Ssn) >= 0.9);
    }

    [Fact]
    public void Nine_bare_digits_are_only_weakly_an_ssn_and_not_at_all_when_invalid()
    {
        Assert.InRange(Strength("512441093", PhiKind.Ssn), 0.1, 0.5);
        Assert.Equal(0, Strength("912345678", PhiKind.Ssn));
        // A column of nine-digit claim numbers is claim numbers, not SSNs, even where some would pass as SSNs.
        var values = new[] { "512441093", "634112087", "201998877", "455120934", "377201456" };
        var r = Classifier.Classify("claim_number", values);
        Assert.Equal(PhiKind.ClaimNumber, r.Kind);
        // And with no header to go on, invalid nine-digit numbers are nothing.
        Assert.Equal(PhiKind.None, Classifier.Classify("x", ["912345678", "987654321", "900000001", "999112222"]).Kind);
    }

    [Theory]
    [InlineData("(217) 555-0100", true)]
    [InlineData("217-555-0100", true)]
    [InlineData("217.555.0100", true)]
    [InlineData("+1 217 555 0100", true)]
    [InlineData("555-010-0100", false)]   // an exchange can't start with 0
    [InlineData("117-555-0100", false)]   // nor an area code with 1
    [InlineData("12345", false)]
    public void Phone_numbers_are_north_american(string value, bool phone) =>
        Assert.Equal(phone, Strength(value, PhiKind.Phone) >= 0.9);

    [Theory]
    [InlineData("maria.lopez@example.com", true)]
    [InlineData("o'neil+x@mail.example.org", true)]
    [InlineData("not an email@", false)]
    [InlineData("a@b", false)]
    public void Emails(string value, bool email) => Assert.Equal(email, Best(value) == PhiKind.Email);

    [Fact]
    public void Npis_pass_luhn_with_the_80840_prefix()
    {
        Assert.True(Detect.Npi("1234567893"));
        Assert.False(Detect.Npi("1234567890"));
        Assert.False(Detect.Npi("3234567893"));
        Assert.Equal('3', Detect.NpiCheckDigit("123456789"));
        Assert.Equal(PhiKind.Npi, Classifier.Classify("rendering_npi", ["1234567893", "1245319599"]).Kind);
    }

    [Theory]
    [InlineData("1957-03-14", "yyyy-MM-dd")]
    [InlineData("03/14/1957", "MM/dd/yyyy")]
    [InlineData("3/4/1957", "M/d/yyyy")]
    [InlineData("14-Mar-1957", "dd-MMM-yyyy")]
    [InlineData("March 14, 1957", "MMMM d, yyyy")]
    [InlineData("Mar 14, 1957", "MMM d, yyyy")]
    [InlineData("2026-04-13T14:44:00", "yyyy-MM-ddTHH:mm:ss")]
    [InlineData("19570314", "yyyyMMdd")]
    public void Dates_in_many_formats_keep_their_format(string value, string format)
    {
        Assert.True(Detect.TryDate(value, out var d));
        Assert.Equal(format, d.Format);
        Assert.Equal(value, Detect.FormatDate(d.Value, d.Format));
    }

    [Theory]
    [InlineData("2020-02-30")]
    [InlineData("13/45/2020")]
    [InlineData("1850-01-01")]
    [InlineData("125.00")]
    [InlineData("12345678")]
    public void Things_that_arent_dates(string value) => Assert.False(Detect.TryDate(value, out _));

    [Fact]
    public void A_service_date_is_a_date_and_a_birth_date_is_a_birth_date()
    {
        string[] dates = ["2026-01-04", "2026-02-11", "2026-03-30"];
        Assert.Equal(PhiKind.Date, Classifier.Classify("service_date", dates).Kind);
        Assert.Equal(PhiKind.Date, Classifier.Classify("DateOfService", dates).Kind);
        Assert.Equal(PhiKind.BirthDate, Classifier.Classify("dob", ["1957-03-14", "1990-11-02"]).Kind);
        Assert.Equal(PhiKind.BirthDate, Classifier.Classify("DateOfBirth", ["1957-03-14"]).Kind);
        Assert.Equal(PhiKind.Date, Classifier.Classify("x", dates).Kind);
    }

    [Fact]
    public void Ages_over_89_are_found_in_text_and_younger_ages_are_not()
    {
        Assert.Contains(TextScan.Find("Ms. Lopez is a 92-year-old seen today."), f => f.Kind == PhiKind.Age && f.Value == "92");
        Assert.Contains(TextScan.Find("Patient, aged 96, lives alone."), f => f.Kind == PhiKind.Age);
        Assert.DoesNotContain(TextScan.Find("A 45-year-old seen today."), f => f.Kind == PhiKind.Age);
        var c = Classifier.Classify("age", ["45", "92", "33"]);
        Assert.Equal(PhiKind.Age, c.Kind);
    }

    [Fact]
    public void Zip_codes_need_a_header_or_a_plus_four()
    {
        Assert.Equal(PhiKind.Zip, Classifier.Classify("zip", ["62704", "03601"]).Kind);
        Assert.Equal(PhiKind.Zip, Classifier.Classify("x", ["62704-1234", "03601-0001"]).Kind);
        // Five-digit amounts aren't ZIP codes.
        Assert.Equal(PhiKind.None, Classifier.Classify("x", ["12500", "33000", "10400"]).Kind);
        Assert.Equal(PhiKind.None, Classifier.Classify("amount", ["62704", "03601"]).Kind);
    }

    [Fact]
    public void Member_numbers_device_vehicle_and_licence_identifiers_by_their_check_digits()
    {
        Assert.True(Detect.Mbi("1EG4-TE5-MK73"));
        Assert.Equal(PhiKind.MemberId, Best("1EG4TE5MK73"));
        Assert.True(Detect.Vin("1HGCM82633A004352"));
        Assert.False(Detect.Vin("1HGCM82637A004352"));
        Assert.Null(Detect.Vin("ABCDEFGHJKLMNPRST"));
        Assert.True(Detect.Dea("AB1234563"));
        Assert.False(Detect.Dea("AB1234567"));
        Assert.Equal(PhiKind.License, Best("AB1234563"));
        Assert.Equal(PhiKind.DeviceId, Best("490154203237518"));
        Assert.Equal(PhiKind.AccountNumber, Best("4111 1111 1111 1111"));
    }

    [Theory]
    [InlineData("192.0.2.15", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("999.1.1.1", false)]
    [InlineData("1.2.3", false)]
    public void Ip_addresses(string value, bool ip) => Assert.Equal(ip, Detect.IsIp(value));

    [Fact]
    public void Urls_addresses_photos_and_names()
    {
        Assert.Equal(PhiKind.Url, Best("https://portal.example.org/member/10001"));
        Assert.Equal(PhiKind.StreetAddress, Best("412 Maple St"));
        Assert.Equal(PhiKind.StreetAddress, Best("88 N. Oak Avenue Apt 4B"));
        Assert.NotEqual(PhiKind.StreetAddress, Best("Maple St"));
        Assert.Equal(PhiKind.Biometric, Best("photos/member_10001.jpg"));
        Assert.True(Detect.NameStrength("Maria Lopez") >= 0.8);
        Assert.True(Detect.NameStrength("LOPEZ, MARIA") >= 0.8);
        Assert.Equal(0, Detect.NameStrength("Cardiology"));
        Assert.Equal(0, Detect.NameStrength("Office visit 2"));
    }

    [Theory]
    [InlineData("DateOfBirth", PhiKind.BirthDate)]
    [InlineData("member_id", PhiKind.MemberId)]
    [InlineData("SubscriberNumber", PhiKind.MemberId)]
    [InlineData("patient_id", PhiKind.Mrn)]
    [InlineData("MRN", PhiKind.Mrn)]
    [InlineData("claim_id", PhiKind.ClaimNumber)]
    [InlineData("acct_no", PhiKind.AccountNumber)]
    [InlineData("home_phone", PhiKind.Phone)]
    [InlineData("fax_number", PhiKind.Fax)]
    [InlineData("e_mail", PhiKind.Email)]
    [InlineData("last_name", PhiKind.Name)]
    [InlineData("zip_code", PhiKind.Zip)]
    [InlineData("vin", PhiKind.VehicleId)]
    [InlineData("device_serial", PhiKind.DeviceId)]
    [InlineData("drivers_license", PhiKind.License)]
    [InlineData("photo_file", PhiKind.Biometric)]
    [InlineData("ip_address", PhiKind.IpAddress)]
    [InlineData("clinical_notes", PhiKind.FreeText)]
    [InlineData("member.address.zip", PhiKind.Zip)]
    public void Headers_name_their_kind(string header, PhiKind kind) => Assert.Equal(kind, HeaderHints.Of(header)?.Kind);

    [Theory]
    [InlineData("plan_name")]
    [InlineData("claim_amount")]
    [InlineData("billed")]
    [InlineData("gender")]
    [InlineData("state")]
    [InlineData("icd10")]
    [InlineData("cpt")]
    public void Headers_that_say_not_phi(string header) => Assert.True(HeaderHints.Of(header) is { NotPhi: true });

    [Fact]
    public void Free_text_findings_with_their_kinds()
    {
        const string note = "Member ID: M10001  MRN: MRN3578261\nPatient: Maria Lopez  DOB: 07/12/1958\nMs. Lopez lives at 591 Chestnut St, Springfield, IL 62704, phone (217) 555-0100, email maria.lopez@example.com. SSN 591-10-4714. Seen at https://portal.example.org from 192.0.2.84. Dr. Alan Brooks (NPI 1234567893).";
        var f = TextScan.Find(note);
        var kinds = f.Select(x => x.Kind).ToHashSet();
        foreach (var k in new[] { PhiKind.MemberId, PhiKind.Mrn, PhiKind.Name, PhiKind.BirthDate, PhiKind.StreetAddress, PhiKind.City, PhiKind.Zip, PhiKind.Phone, PhiKind.Email, PhiKind.Ssn, PhiKind.Url, PhiKind.IpAddress, PhiKind.Npi })
            Assert.Contains(k, kinds);
        Assert.Contains(f, x => x.Kind == PhiKind.Name && x.Value == "Maria Lopez");
        Assert.Contains(f, x => x.Kind == PhiKind.Name && x.Value == "Lopez");
        Assert.Contains(f, x => x.Kind == PhiKind.BirthDate && x.Value == "07/12/1958");
        // Ordinary words with capitals aren't names.
        Assert.Empty(TextScan.Find("Blood Pressure stable. Plan: Follow up in May. Will recheck."));
    }

    [Fact]
    public void Names_known_from_the_scan_are_found_alone_in_text()
    {
        var known = new KnownValues();
        known.AddName("Okafor");
        known.AddId("M10002", PhiKind.MemberId);
        var f = TextScan.Find("Called Okafor back about member M10002.", known);
        Assert.Contains(f, x => x.Kind == PhiKind.Name && x.Value == "Okafor");
        Assert.Contains(f, x => x.Kind == PhiKind.MemberId && x.Value == "M10002");
    }

    [Fact]
    public void Masks_keep_initials_last_digits_and_years_only()
    {
        Assert.Equal("J*** S****", Mask.Value(PhiKind.Name, "John Smith"));
        Assert.Equal("***-**-1093", Mask.Value(PhiKind.Ssn, "512-44-1093"));
        Assert.Equal("1957-**-**", Mask.Value(PhiKind.BirthDate, "03/14/1957"));
        Assert.Equal("(***) ***-**00", Mask.Value(PhiKind.Phone, "(217) 555-0100"));
        Assert.Equal("m***@***.com", Mask.Value(PhiKind.Email, "maria.lopez@example.com"));
        Assert.Equal("****01", Mask.Value(PhiKind.MemberId, "M10001"));
        Assert.Equal("627**", Mask.Value(PhiKind.Zip, "62704"));
        Assert.Equal("90+", Mask.Value(PhiKind.Age, "93"));
        Assert.Equal("### C******* St", Mask.Value(PhiKind.StreetAddress, "591 Chestnut St"));
        Assert.Equal("999.99", Mask.Value(PhiKind.None, "125.00"));
        var text = Mask.Text("Seen with Maria Lopez on 2026-02-01; call (217) 555-0100. Her neighbour Okonkwo drove her.");
        foreach (var raw in new[] { "Maria", "Lopez", "2026-02-01", "555-0100", "Okonkwo" }) Assert.DoesNotContain(raw, text);
        Assert.Equal("j***_s****_#####.csv", Mask.Label("john_smith_20260.csv"));
        Assert.Equal("members.csv", Mask.Label("members.csv"));
    }
}
