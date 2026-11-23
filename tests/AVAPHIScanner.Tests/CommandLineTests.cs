namespace AVAPHIScanner.Tests;

/// <summary>The command line: --scan writes a report, --deidentify a verified copy with a kept key, --verify checks one.</summary>
public sealed class CommandLineTests
{
    private static (int Code, string Out, string Err) Run(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var code = CommandLine.Run(args, o, e, Samples.Today);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public void Scan_prints_the_inventory_masked_and_writes_a_report()
    {
        var root = Samples.WorkingCopy();
        var report = Path.Combine(root, "inventory.xlsx");
        var (code, output, _) = Run("--scan", Path.Combine(root, "samples"), "--report", report);
        Assert.Equal(0, code);
        Assert.Contains("Risk: High", output);
        Assert.Contains("Social Security number", output);
        Assert.True(File.Exists(report));
        Assert.Empty(Samples.Leaks(output, Samples.Secrets(Path.Combine(root, "samples"))));
        var (dbCode, dbOut, _) = Run("--scan", "sqlite:" + Path.Combine(root, "samples", "clinic.db"), "--report", Path.Combine(root, "db.html"));
        Assert.Equal(0, dbCode);
        Assert.Contains("main.patients", dbOut);
        Assert.True(File.Exists(Path.Combine(root, "db.html")));
    }

    [Fact]
    public void Deidentify_makes_a_key_writes_a_clean_copy_and_the_same_key_gives_the_same_tokens()
    {
        var root = Samples.WorkingCopy();
        var key = Path.Combine(root, "keys", "k.key");
        var (code, output, errors) = Run("--deidentify", Path.Combine(root, "samples"), "--policy", "safe-harbor", "--key-file", key, "--out", Path.Combine(root, "out1"));
        Assert.True(code == 0, output + errors);
        Assert.Contains("Made a new key", output);
        Assert.Contains("Verify: Clean", output);
        Assert.True(File.Exists(key));
        Assert.DoesNotContain(File.ReadAllText(key).Trim(), output);
        var (again, _, _) = Run("--deidentify", Path.Combine(root, "samples"), "--key-file", key, "--out", Path.Combine(root, "out2"));
        Assert.Equal(0, again);
        Assert.Equal(File.ReadAllText(Path.Combine(root, "out1", "members.csv")), File.ReadAllText(Path.Combine(root, "out2", "members.csv")));
        // Writing into an existing copy fails without --overwrite.
        var (third, _, err3) = Run("--deidentify", Path.Combine(root, "samples"), "--key-file", key, "--out", Path.Combine(root, "out2"));
        Assert.Equal(1, third);
        Assert.Contains("exists", err3);
        Assert.Equal(0, Run("--deidentify", Path.Combine(root, "samples"), "--key-file", key, "--out", Path.Combine(root, "out2"), "--overwrite").Code);
    }

    [Fact]
    public void Verify_tells_a_clean_copy_from_the_original()
    {
        var root = Samples.WorkingCopy();
        Run("--deidentify", Path.Combine(root, "samples"), "--key-file", Path.Combine(root, "k.key"), "--out", Path.Combine(root, "out"), "--dates", "year");
        var (clean, cleanOut, _) = Run("--verify", Path.Combine(root, "out"), "--against", Path.Combine(root, "samples"), "--dates", "year");
        Assert.True(clean == 0, cleanOut);
        Assert.StartsWith("Clean", cleanOut);
        var (dirty, dirtyOut, _) = Run("--verify", Path.Combine(root, "samples"));
        Assert.Equal(1, dirty);
        Assert.Contains("left in", dirtyOut);
        Assert.Empty(Samples.Leaks(dirtyOut, Samples.Secrets(Path.Combine(root, "samples"))));
    }

    [Fact]
    public void A_project_file_carries_its_decisions_and_policy()
    {
        var root = Samples.WorkingCopy();
        var p = new Project();
        p.AddSource(new SourceSpec { Kind = "file", Path = Path.Combine(root, "samples", "members.csv") });
        p.Policy.Kind = PolicyKind.LimitedDataSet;
        ProjectFiles.Save(p, Path.Combine(root, "members.phiscan"));
        var (code, output, _) = Run("--deidentify", Path.Combine(root, "members.phiscan"), "--key-file", Path.Combine(root, "k.key"), "--out", Path.Combine(root, "lds"));
        Assert.Equal(0, code);
        Assert.Contains("Limited Data Set", output);
        Assert.Equal(Samples.Members(Path.Combine(root, "samples")).Select(m => m["dob"]), Samples.Members(Path.Combine(root, "lds")).Select(m => m["dob"]));
    }

    [Fact]
    public void Bad_arguments_exit_2_with_the_usage()
    {
        Assert.Equal(2, Run("--scan").Code);
        Assert.Equal(2, Run("--deidentify", Samples.Folder).Code);
        Assert.Equal(2, Run("--scan", "/no/such/place").Code);
        var (code, _, err) = Run("--scan", Samples.Folder, "--frobnicate");
        Assert.Equal(2, code);
        Assert.Contains("--deidentify", err);
        Assert.True(CommandLine.Wanted(["--scan", "x"]));
        Assert.False(CommandLine.Wanted(["--mcp"]));
    }
}
