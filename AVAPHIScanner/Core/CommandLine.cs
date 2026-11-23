namespace AVAPHIScanner;

/// <summary>
/// The command line, for scripts and scheduled jobs (no window): <c>--scan</c> writes a report, <c>--deidentify</c>
/// writes a de-identified copy and verifies it, <c>--verify</c> checks a copy. Nothing here prints a raw value.
/// </summary>
public static class CommandLine
{
    public const string Usage = """
        AVAPHIScanner --scan SOURCE [--report FILE.xlsx|FILE.html] [--project FILE.phiscan] [--sample-rows N]
        AVAPHIScanner --deidentify SOURCE --out FOLDER --key-file FILE [--policy safe-harbor|limited-data-set|custom]
                      [--dates shift|year] [--project FILE.phiscan] [--db-output csv|sqlite] [--overwrite] [--report FILE]
        AVAPHIScanner --verify COPY [--against SOURCE] [--policy …] [--dates shift|year] [--report FILE]

          SOURCE is a file, a folder (read through sub-folders), a project (.phiscan, with its sources, decisions and
          policy), or a database: sqlite:PATH, sqlserver:"CONNECTION STRING" or postgres:"CONNECTION STRING".
          --key-file  The key tokens and date shifts are made with. A new one is made if the file doesn't exist: keep
                      it, and never send it with the copy. The same key gives the same tokens next time.
          Exit codes: 0 done (and, for --deidentify and --verify, the copy is clean); 1 something was left in the
          copy or a file failed; 2 bad arguments.
        """;

    public static bool Wanted(IReadOnlyList<string> args) =>
        args.Any(a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase) || a.Equals("--deidentify", StringComparison.OrdinalIgnoreCase) || a.Equals("--verify", StringComparison.OrdinalIgnoreCase));

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter errors, DateOnly? today = null)
    {
        string? mode = null, source = null, report = null, projectFile = null, outFolder = null, keyFile = null, policy = null, dates = null, dbOutput = null, against = null;
        var sampleRows = 0;
        var overwrite = false;
        for (var i = 0; i < args.Count; i++)
        {
            string Next() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
            try
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--scan" or "--deidentify" or "--verify":
                        mode = args[i][2..].ToLowerInvariant();
                        source = Next();
                        break;
                    case "--report": report = Next(); break;
                    case "--project": projectFile = Next(); break;
                    case "--out": outFolder = Next(); break;
                    case "--key-file": keyFile = Next(); break;
                    case "--policy": policy = Next(); break;
                    case "--dates": dates = Next(); break;
                    case "--db-output": dbOutput = Next(); break;
                    case "--against": against = Next(); break;
                    case "--sample-rows": sampleRows = int.Parse(Next()); break;
                    case "--overwrite": overwrite = true; break;
                    case "--help" or "-h": output.WriteLine(Usage); return 0;
                    default: throw new ArgumentException($"Unknown option {args[i]}.");
                }
            }
            catch (Exception e) when (e is ArgumentException or FormatException)
            {
                errors.WriteLine($"{e.Message}\n\n{Usage}");
                return 2;
            }
        }
        if (mode is null || source is null)
        {
            errors.WriteLine(Usage);
            return 2;
        }
        try
        {
            var root = Environment.CurrentDirectory;
            var project = Load(mode == "verify" ? against : source, projectFile, ref root);
            if (policy != null) project.Policy.Kind = Kinds.ParsePolicy(policy);
            if (dates != null) project.Policy.DateMode = dates.ToLowerInvariant() is "year" or "year-only" ? DateMode.Year : dates.ToLowerInvariant() is "shift" ? DateMode.Shift : throw new ArgumentException("--dates is shift or year.");
            if (dbOutput != null) project.Policy.DatabaseOutput = dbOutput.ToLowerInvariant() is "sqlite" ? "sqlite" : dbOutput.ToLowerInvariant() is "csv" ? "csv" : throw new ArgumentException("--db-output is csv or sqlite.");
            if (sampleRows > 0) project.SampleRows = sampleRows;
            switch (mode)
            {
                case "scan":
                {
                    var inventory = Scanner.Scan(project, root);
                    Print(inventory, project, output, errors);
                    if (report != null) Report(report, inventory, project, null, output);
                    return 0;
                }
                case "deidentify":
                {
                    if (outFolder is null || keyFile is null) throw new ArgumentException("--deidentify needs --out FOLDER and --key-file FILE.");
                    var key = KeyFile.LoadOrCreate(keyFile, out var made);
                    if (made) output.WriteLine($"Made a new key in {keyFile}. Keep it to make the same tokens next time, and never send it with the copy.");
                    var inventory = Scanner.Scan(project, root, skip: Path.GetFullPath(outFolder));
                    foreach (var p in inventory.Problems) errors.WriteLine(p);
                    var result = DeidentifyRun.Run(project, inventory, root, outFolder, key, overwrite: overwrite, today: today);
                    output.WriteLine($"Wrote {Path.GetFullPath(outFolder)} ({project.Policy.Describe()}): {result.Summary}.");
                    foreach (var p in result.Problems) errors.WriteLine(p);
                    var verify = Verifier.Verify(outFolder, project.Policy, inventory);
                    output.WriteLine("Verify: " + verify.Summary);
                    foreach (var l in verify.Leftovers) output.WriteLine($"  {l.Where}: {l.Count} {Kinds.Label(l.Kind).ToLowerInvariant()} ({l.Why}), e.g. {string.Join(", ", l.Examples)}");
                    if (report != null) Report(report, inventory, project, verify, output);
                    output.WriteLine("Detection is an aid, not a guarantee: check the copy before sharing it.");
                    return result.Problems.Count == 0 && verify.Clean ? 0 : 1;
                }
                default:
                {
                    Inventory? before = null;
                    if (against != null)
                    {
                        before = Scanner.Scan(project, root, skip: Path.GetFullPath(source));
                    }
                    var verify = Verifier.Verify(source, project.Policy, before);
                    output.WriteLine(verify.Summary);
                    foreach (var l in verify.Leftovers) output.WriteLine($"  {l.Where}: {l.Count} {Kinds.Label(l.Kind).ToLowerInvariant()} ({l.Why}), e.g. {string.Join(", ", l.Examples)}");
                    foreach (var p in verify.Problems) errors.WriteLine(p);
                    if (report != null && before != null) Report(report, before, project, verify, output);
                    return verify.Clean ? 0 : 1;
                }
            }
        }
        catch (Exception e) when (e is ArgumentException or IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or System.Data.Common.DbException or NotSupportedException)
        {
            errors.WriteLine(Scanner.Safe(e));
            return e is ArgumentException ? 2 : 1;
        }
    }

    /// <summary>A project for a source: a .phiscan file as it is, or a new one with the file, folder or database as its source.</summary>
    private static Project Load(string? source, string? projectFile, ref string root)
    {
        Project project;
        if (projectFile != null)
        {
            project = Project.FromJson(File.ReadAllText(projectFile));
            root = Path.GetDirectoryName(Path.GetFullPath(projectFile))!;
            if (source is null || source.EndsWith(Project.Extension, StringComparison.OrdinalIgnoreCase)) return project;
            project.Sources.Clear();
        }
        else if (source != null && source.EndsWith(Project.Extension, StringComparison.OrdinalIgnoreCase))
        {
            root = Path.GetDirectoryName(Path.GetFullPath(source))!;
            return Project.FromJson(File.ReadAllText(source));
        }
        else project = new Project();
        if (source is null) return project;
        project.AddSource(Source(source));
        return project;
    }

    /// <summary>A source from the command line: a path, or ENGINE:CONNECTION.</summary>
    public static SourceSpec Source(string text)
    {
        var colon = text.IndexOf(':');
        if (colon > 1 && text[..colon].ToLowerInvariant() is "sqlite" or "sqlserver" or "mssql" or "postgres" or "postgresql" or "pg")
        {
            var engine = Db.ParseEngine(text[..colon]);
            var rest = text[(colon + 1)..];
            return engine == DbEngine.Sqlite
                ? new SourceSpec { Kind = "database", Engine = "SQLite", Connection = $"Data Source={Path.GetFullPath(rest)};Pooling=False" }
                : new SourceSpec { Kind = "database", Engine = Db.DisplayName(engine), Connection = rest };
        }
        var full = Path.GetFullPath(text);
        if (Directory.Exists(full)) return new SourceSpec { Kind = "folder", Path = full };
        if (File.Exists(full))
            return Sources.FormatOf(full) == SourceFormat.Database
                ? new SourceSpec { Kind = "database", Engine = "SQLite", Connection = $"Data Source={full};Pooling=False" }
                : new SourceSpec { Kind = "file", Path = full };
        throw new ArgumentException("There's no file or folder there.");
    }

    private static void Print(Inventory inventory, Project project, TextWriter output, TextWriter errors)
    {
        var risk = RiskSummary.Of(inventory, project);
        output.WriteLine($"Scanned {inventory.Datasets} datasets, {inventory.Columns.Count} columns, {inventory.RowsRead} rows. Risk: {risk.Overall}.");
        foreach (var c in inventory.Columns.Where(c => Kinds.IsPhi(project.EffectiveKind(c.Key, c.Detected)) || project.EffectiveKind(c.Key, c.Detected) == PhiKind.Npi))
        {
            var kind = project.EffectiveKind(c.Key, c.Detected);
            output.WriteLine($"  {c.Id,-5} {c.SafeDisplay}: {Kinds.Label(kind)} ({c.Confidence:P0}), {c.Count} · {string.Join(", ", c.Examples.Take(2))}");
        }
        foreach (var p in inventory.Problems) errors.WriteLine(p);
    }

    private static void Report(string path, Inventory inventory, Project project, VerifyResult? verify, TextWriter output)
    {
        ReportWriter.Write(path, inventory, project, verify);
        output.WriteLine($"Report: {Path.GetFullPath(path)}");
    }
}
