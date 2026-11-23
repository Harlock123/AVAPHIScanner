using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AVAPHIScanner.Agents.Mcp;

/// <summary>
/// The MCP tools: what an agent can do with AVA PHI Scanner. Each handler reaches the project only through
/// <see cref="IScanHost.RunAsync{T}"/>, and reads data (scanning, de-identifying, verifying) off that thread. Every
/// change to the project is one undo step, a call that fails leaves the project as it was, and failures come back as
/// MCP tool errors that say what to do instead. Agents never receive a raw value: every value in an answer is masked
/// here, and the server checks each answer again before it leaves (<see cref="ScanServer.Guard"/>).
/// </summary>
/// <remarks>The parameter names are the JSON names agents see, hence snake_case.</remarks>
public sealed partial class ScanTools(IScanHost host)
{
    private readonly Workspace _files = new(host.Root);

    /// <summary>Files list_files showed under a reference because their names may hold a name ("f3").</summary>
    private readonly Dictionary<string, string> _refs = new(StringComparer.OrdinalIgnoreCase);

    private const string ColumnHelp = "The column's id from get_inventory (\"c7\"), or its path (\"members.csv › ssn\").";

    // ───────────────────────────── the project ─────────────────────────────

    [McpServerTool(Name = "get_project", ReadOnly = true, Idempotent = true)]
    [Description("The open project: its file, its sources (files, folders, databases; never a password), the policy and the column actions, the person's decisions about columns, the last scan (how many datasets, columns and PHI columns, and the risk), the last de-identified copy and its check. Start here.")]
    public Task<string> GetProject(CancellationToken cancel = default) =>
        Read("read the project", s => ProjectInfo(s), cancel);

    [McpServerTool(Name = "new_project")]
    [Description("Starts a new, empty project (no sources, Safe Harbor). Fails if the open project has unsaved changes, unless discard_changes is true.")]
    public Task<string> NewProject(
        [Description("Throw away unsaved changes to the open project. Default false.")] bool discard_changes = false,
        CancellationToken cancel = default) =>
        Read("started a new project", s =>
        {
            Discardable(s, discard_changes);
            s.Replace(new Project(), null);
            s.Refresh();
            return ProjectInfo(s);
        }, cancel);

    [McpServerTool(Name = "open_project")]
    [Description("Opens a saved project (.phiscan) from the working folder, replacing the open one. Scan it to see its results. Fails if the open project has unsaved changes, unless discard_changes is true.")]
    public Task<string> OpenProject(
        [Description("The .phiscan file, relative to the working folder.")] string path,
        [Description("Throw away unsaved changes to the open project. Default false.")] bool discard_changes = false,
        CancellationToken cancel = default) =>
        Read("opened a project", s =>
        {
            var full = _files.Resolve(path, "A project", Project.Extension);
            if (!File.Exists(full)) throw new FileNotFoundException($"There's no {Mask.Label(path)} in the working folder. list_files shows what is there.");
            var project = ProjectFiles.Load(full);
            Discardable(s, discard_changes);
            s.Replace(project, full);
            s.Refresh();
            return ProjectInfo(s);
        }, cancel);

    [McpServerTool(Name = "save_project")]
    [Description("Saves the project as a .phiscan file in the working folder: its sources (database connection strings included, with any password: keep project files private), decisions and policy. Scan results aren't kept in it. Won't write over a file it didn't write unless overwrite is true.")]
    public Task<string> SaveProject(
        [Description("The file, relative to the working folder (.phiscan is added if missing). Default: the file it was opened from or last saved to.")] string? path = null,
        [Description("Write over an existing file. Default false.")] bool overwrite = false,
        CancellationToken cancel = default) =>
        Read("saved the project", s =>
        {
            var target = path is { Length: > 0 } p ? _files.Resolve(p.EndsWith(Project.Extension, StringComparison.OrdinalIgnoreCase) ? p : p + Project.Extension)
                : s.FilePath ?? throw new ArgumentException("The project has no file yet: give a path such as \"projects/vendor-extract.phiscan\".");
            _files.Resolve(Relative(target));
            if (target != s.FilePath) _files.CheckWritable(target, overwrite);
            ProjectFiles.Save(s.Document, target);
            _files.Wrote(target);
            s.Saved(target);
            return new JsonObject { ["saved"] = Relative(target), ["sources"] = s.Document.Sources.Count };
        }, cancel);

    // ───────────────────────────── sources ─────────────────────────────

    [McpServerTool(Name = "list_files", ReadOnly = true, Idempotent = true)]
    [Description("Lists files in the working folder (or a folder inside it) that can be scanned or used: .csv, .tsv, .xlsx, .json, .jsonl, .txt, SQLite databases, projects (.phiscan) and steps files. A name that may hold a person's name is masked and given a ref (\"f3\") to use as the path instead.")]
    public Task<string> ListFiles(
        [Description("A folder inside the working folder. Default: the working folder.")] string folder = ".",
        [Description("Look through sub-folders too. Default false.")] bool recursive = false,
        CancellationToken cancel = default) =>
        Read("listed files", session =>
        {
            var full = folder is "." or "" ? _files.Root : PathOf(folder);
            if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"There's no folder {Mask.Label(folder)} in the working folder.");
            var skip = new[] { "bin", "obj", "node_modules", ".git", ".vs", ".idea" };
            var files = Directory.EnumerateFiles(full, "*", new EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true })
                .Where(f => !Path.GetRelativePath(full, f).Split(Path.DirectorySeparatorChar).Any(part => skip.Contains(part, StringComparer.OrdinalIgnoreCase)))
                .Where(f => Sources.FormatOf(f) != null || f.EndsWith(Project.Extension, StringComparison.OrdinalIgnoreCase) || f.EndsWith(".avasteps.json", StringComparison.OrdinalIgnoreCase))
                .Take(501).ToList();
            var folders = recursive ? [] : Directory.EnumerateDirectories(full).Select(Path.GetFileName).Where(n => n is not null && !skip.Contains(n, StringComparer.OrdinalIgnoreCase)).Take(200).ToList();
            return new JsonObject
            {
                ["folder"] = Mask.Label(Path.GetRelativePath(_files.Root, full)),
                ["folders"] = new JsonArray(folders.Select(f => (JsonNode)Listed(Path.Combine(full, f!), out _)).ToArray()),
                ["files"] = new JsonArray(files.Take(500).Select(f =>
                {
                    var shown = Listed(f, out var reference);
                    return (JsonNode)new JsonObject { ["path"] = shown, ["ref"] = reference, ["kind"] = Sources.FormatOf(f)?.ToString().ToLowerInvariant() ?? (f.EndsWith(Project.Extension) ? "project" : "steps"), ["bytes"] = new FileInfo(f).Length };
                }).ToArray()),
                ["more"] = files.Count > 500 ? "More than 500: narrow it with a folder." : null,
            };
        }, cancel);

    /// <summary>A path as list_files shows it, masked where it may hold a name; then <paramref name="reference"/> is what to give instead.</summary>
    private string Listed(string full, out string? reference)
    {
        var rel = Path.GetRelativePath(_files.Root, full).Replace('\\', '/');
        reference = null;
        if (!Mask.LabelHides(rel)) return rel;
        lock (_refs)
        {
            reference = _refs.FirstOrDefault(r => r.Value == full).Key ?? $"f{_refs.Count + 1}";
            _refs[reference] = full;
        }
        return Mask.Label(rel);
    }

    /// <summary>A path in the working folder, or a list_files ref.</summary>
    private string PathOf(string path)
    {
        lock (_refs) if (_refs.TryGetValue(path.Trim(), out var full)) return full;
        return _files.Resolve(path);
    }

    [McpServerTool(Name = "list_connections", ReadOnly = true, Idempotent = true)]
    [Description("The database connections the person has saved, by name: engine and server, never passwords. add_source takes one by name.")]
    public Task<string> ListConnections(CancellationToken cancel = default) =>
        Task.FromResult(new JsonObject
        {
            ["saved"] = new JsonArray(host.Connections.All.Select(c => (JsonNode)new JsonObject
            {
                ["name"] = c.Name, ["engine"] = Db.DisplayName(c.Engine), ["connection"] = c.Redacted, ["note"] = c.Note,
            }).ToArray()),
        }.ToJsonString(Json.Options));

    [McpServerTool(Name = "add_connection")]
    [Description("Adds a database connection by name for this session (save keeps it for next time too), tested first; then add_source takes it by name. Its connection string is never shown again, only the server and database.")]
    public async Task<string> AddConnection(
        [Description("A name for it: \"claims-warehouse\".")] string name,
        [Description("SQL Server, PostgreSQL or SQLite.")] string engine,
        [Description("The ADO.NET connection string: \"Server=db1;Database=Claims;Integrated Security=true;TrustServerCertificate=true\", \"Host=db1;Database=claims;Username=reader;Password=…\", \"Data Source=clinic.db\".")] string connection_string,
        [Description("Keep it in the person's connections for next time. Default false.")] bool save = false,
        [Description("A note on what it is. Optional.")] string? note = null,
        CancellationToken cancel = default)
    {
        var e = Wrap(() => Db.ParseEngine(engine));
        await TestConnection(e, connection_string, cancel).ConfigureAwait(false);
        var c = new DataConnection { Name = name, Provider = e.ToString(), ConnectionString = connection_string, Note = note };
        Wrap(() => { host.Connections.Put(c, save); return true; });
        return new JsonObject { ["added"] = c.Name, ["engine"] = Db.DisplayName(e), ["connection"] = c.Redacted, ["saved"] = save }.ToJsonString(Json.Options);
    }

    [McpServerTool(Name = "add_source")]
    [Description("Adds a source to scan: a file or folder in the working folder (path; a folder is read through its sub-folders, SQLite files in it included), a saved database connection (connection_name), or a SQLite file as a database (sqlite_file). For a database, tables limits it to some tables (\"main.patients\", or just \"patients\"). Sources are only ever read.")]
    public async Task<string> AddSource(
        [Description("A file or folder, relative to the working folder, or a list_files ref (\"f3\").")] string? path = null,
        [Description("A saved connection's name (list_connections).")] string? connection_name = null,
        [Description("A SQLite database file, relative to the working folder.")] string? sqlite_file = null,
        [Description("For a database: only these tables. Default: all of them.")] List<string>? tables = null,
        CancellationToken cancel = default)
    {
        if (new[] { path, connection_name, sqlite_file }.Count(x => !string.IsNullOrWhiteSpace(x)) != 1)
            throw new McpException("Give one of path (a file or folder), connection_name (a saved database) or sqlite_file.");
        SourceSpec spec;
        if (path is { Length: > 0 })
        {
            var full = Wrap(() => PathOf(path));
            if (Directory.Exists(full)) spec = new SourceSpec { Kind = "folder", Path = full };
            else if (File.Exists(full))
                spec = Sources.FormatOf(full) switch
                {
                    null => throw new McpException($"{Mask.Label(path)} isn't a kind of file the scanner reads (.csv, .tsv, .xlsx, .json, .jsonl, .txt, .db/.sqlite)."),
                    SourceFormat.Database => new SourceSpec { Kind = "database", Engine = "SQLite", Connection = $"Data Source={full};Pooling=False", Tables = tables },
                    _ => new SourceSpec { Kind = "file", Path = full },
                };
            else throw new McpException($"There's no {Mask.Label(path)} in the working folder. list_files shows what is there.");
        }
        else if (sqlite_file is { Length: > 0 })
        {
            var full = Wrap(() => PathOf(sqlite_file));
            if (!File.Exists(full)) throw new McpException($"There's no {Mask.Label(sqlite_file)} in the working folder.");
            spec = new SourceSpec { Kind = "database", Engine = "SQLite", Connection = $"Data Source={full};Pooling=False", Tables = tables };
        }
        else
        {
            var c = Wrap(() => host.Connections.Get(connection_name!));
            await TestConnection(c.Engine, c.ConnectionString, cancel).ConfigureAwait(false);
            spec = new SourceSpec { Kind = "database", Engine = Db.DisplayName(c.Engine), ConnectionName = c.Name, Tables = tables };
        }
        var datasets = await Task.Run(() =>
        {
            try { return Sources.Expand(spec, host.Root, Lookup); }
            catch (Exception e) when (e is not OperationCanceledException) { throw new McpException(Explain(e), e); }
        }, cancel).ConfigureAwait(false);
        if (spec.Tables is { Count: > 0 } && datasets.Count == 0) throw new McpException("None of those tables is in the database.");
        return await Edit("added a source", (s, p) =>
        {
            var added = p.AddSource(spec);
            return new JsonObject { ["added"] = added.Id, ["kind"] = added.Kind, ["source"] = SourceLabel(added), ["datasets"] = datasets.Count, ["next"] = "scan reads it." };
        }, cancel).ConfigureAwait(false);
    }

    [McpServerTool(Name = "remove_source", Destructive = true)]
    [Description("Removes a source from the project (its files and tables stay as they are), with the person's decisions about its columns. In the open window the person is asked first.")]
    public async Task<string> RemoveSource(
        McpServer server,
        [Description("The source's id from get_project (\"s2\").")] string id,
        CancellationToken cancel = default)
    {
        var label = await Run("read the project", s => s.Document.Sources.FirstOrDefault(x => x.Id.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase)) is { } x ? SourceLabel(x) : null, cancel).ConfigureAwait(false);
        if (label is null) throw new McpException($"There's no source \"{id}\". get_project lists them.");
        if (host.Live) await Confirm(server, $"Remove source {id} ({label}) from the project? Go ahead?", cancel).ConfigureAwait(false);
        return await Edit("removed a source", (s, p) =>
        {
            var source = p.Sources.First(x => x.Id.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase));
            p.Sources.Remove(source);
            foreach (var k in p.Overrides.Keys.Where(k => k.StartsWith(source.Id + "|", StringComparison.Ordinal)).ToList()) p.Overrides.Remove(k);
            foreach (var k in p.Policy.Actions.Keys.Where(k => k.StartsWith(source.Id + "|", StringComparison.Ordinal)).ToList()) p.Policy.Actions.Remove(k);
            return new JsonObject { ["removed"] = source.Id, ["sources"] = p.Sources.Count };
        }, cancel).ConfigureAwait(false);
    }

    [McpServerTool(Name = "set_sampling")]
    [Description("How many rows of each table (records of a JSON file, paragraphs of a text file) a scan reads: fewer for a quick look at a big database, more to count everything. De-identification always reads every row.")]
    public Task<string> SetSampling(
        [Description("Rows per table, from 10 to 10,000,000. The default is 10,000.")] int rows,
        CancellationToken cancel = default)
    {
        if (rows is < 10 or > 10_000_000) throw new McpException("rows is from 10 to 10,000,000.");
        return Edit("set the sample size", (s, p) =>
        {
            p.SampleRows = rows;
            return new JsonObject { ["sample_rows"] = rows, ["next"] = "scan again to use it." };
        }, cancel);
    }

    // ───────────────────────────── scanning ─────────────────────────────

    [McpServerTool(Name = "scan")]
    [Description("Scans every source: reads each table's first sample_rows rows, classifies each column (kind and confidence, from its header and its values), and finds identifiers inside free text. Answers with a summary: datasets, columns, PHI columns by kind, the risk, and any problems. get_inventory lists the columns.")]
    public async Task<string> Scan(CancellationToken cancel = default)
    {
        var project = await Run("read the project", s => s.Document, cancel).ConfigureAwait(false);
        if (project.Sources.Count == 0) throw new McpException("The project has no sources: add_source first.");
        var inventory = await Task.Run(() => Scanner.Scan(project, host.Root, Lookup, cancel: cancel), cancel).ConfigureAwait(false);
        return await Read("scanned the sources", s =>
        {
            s.Scanned(inventory);
            s.Refresh();
            return ScanSummary(s.Document, inventory);
        }, cancel).ConfigureAwait(false);
    }

    [McpServerTool(Name = "get_inventory", ReadOnly = true, Idempotent = true)]
    [Description("Where the PHI is: each column with its id, where it is (source › table or sheet › column), kind, confidence, count, masked examples and what de-identification will do with it. By default only columns holding PHI (or a provider's NPI); all of them with phi_only false.")]
    public Task<string> GetInventory(
        [Description("Only columns that hold PHI. Default true.")] bool phi_only = true,
        [Description("Only this kind (\"ssn\", \"name\", \"free_text\"…). Optional.")] string? kind = null,
        [Description("Only columns of this source (\"s1\"). Optional.")] string? source = null,
        [Description("Only columns whose confidence is below this (0 to 1), to find the doubtful ones. Optional.")] double? below_confidence = null,
        [Description("At most this many columns, 1 to 500. Default 200.")] int max = 200,
        CancellationToken cancel = default) =>
        Read("read the inventory", s =>
        {
            var inv = Scanned(s);
            var p = s.Document;
            PhiKind? k = kind is { Length: > 0 } ? Kinds.Parse(kind) : null;
            var rows = inv.Columns.Where(c =>
            {
                var ek = p.EffectiveKind(c.Key, c.Detected);
                return (!phi_only || Kinds.IsPhi(ek) || ek == PhiKind.Npi)
                    && (k is null || ek == k)
                    && (source is null || c.SourceId.Equals(source, StringComparison.OrdinalIgnoreCase))
                    && (below_confidence is null || c.Confidence < below_confidence);
            }).ToList();
            return new JsonObject
            {
                ["columns"] = new JsonArray(rows.Take(Math.Clamp(max, 1, 500)).Select(c => (JsonNode)ColumnRow(c, p)).ToArray()),
                ["shown"] = Math.Min(rows.Count, Math.Clamp(max, 1, 500)),
                ["matching"] = rows.Count,
                ["all_columns"] = inv.Columns.Count,
                ["policy"] = p.Policy.Describe(),
            };
        }, cancel);

    [McpServerTool(Name = "get_column", ReadOnly = true, Idempotent = true)]
    [Description("One column in detail: why the scan thinks what it does (its header, how many values looked like each kind), masked examples, how many rows were read, how many people are over 89, the person's decision if any, the action, and for free text the identifiers found inside it, cell by cell (row, kind, masked).")]
    public Task<string> GetColumn(
        [Description(ColumnHelp)] string column,
        [Description("At most this many free-text findings, 0 to 200. Default 40.")] int max_findings = 40,
        CancellationToken cancel = default) =>
        Read("read a column", s =>
        {
            var inv = Scanned(s);
            var c = inv.Find(column);
            var p = s.Document;
            var o = ColumnRow(c, p);
            o["reason"] = c.Reason;
            o["values_read"] = c.Values;
            o["rows_read"] = c.RowsRead;
            o["rows_total"] = c.RowsTotal;
            o["sampled"] = c.Sampled ? true : null;
            o["over_89"] = c.Over89 > 0 ? c.Over89 : null;
            o["looked_like"] = new JsonObject(c.ContentCounts.OrderByDescending(x => x.Value).Select(x => KeyValuePair.Create(Kinds.Id(x.Key), (JsonNode?)x.Value)));
            if (p.Overrides.TryGetValue(c.Key, out var ov)) o["decision"] = new JsonObject { ["is_phi"] = ov.IsPhi, ["kind"] = ov.Kind is { } ok ? Kinds.Id(ok) : null, ["note"] = ov.Note };
            if (c.TextCounts.Count > 0)
            {
                o["in_text"] = new JsonObject(c.TextCounts.OrderByDescending(x => x.Value).Select(x => KeyValuePair.Create(Kinds.Id(x.Key), (JsonNode?)x.Value)));
                o["findings"] = new JsonArray(c.Findings.Take(Math.Clamp(max_findings, 0, 200)).Select(f => (JsonNode)new JsonObject { ["row"] = f.Row, ["kind"] = Kinds.Id(f.Kind), ["found"] = f.Masked }).ToArray());
            }
            return o;
        }, cancel);

    [McpServerTool(Name = "get_risk", ReadOnly = true, Idempotent = true)]
    [Description("The risk summary: each table's level (High: direct identifiers or identifiers in free text; Medium: two or more quasi-identifiers such as a birth date and a ZIP code; Low: one), which identifiers it holds, and why, with notes (people over 89, sampled tables, low-confidence columns).")]
    public Task<string> GetRisk(
        [Description("Only tables whose name contains this. Optional.")] string? table = null,
        CancellationToken cancel = default) =>
        Read("read the risk", s =>
        {
            var risk = RiskSummary.Of(Scanned(s), s.Document);
            var tables = risk.Tables.Where(t => table is null || t.Where.Contains(table, StringComparison.OrdinalIgnoreCase)).ToList();
            return new JsonObject
            {
                ["overall"] = risk.Overall,
                ["columns"] = risk.Columns,
                ["direct_identifier_columns"] = risk.DirectColumns,
                ["quasi_identifier_columns"] = risk.QuasiColumns,
                ["free_text_columns"] = risk.TextColumns,
                ["tables"] = new JsonArray(tables.Select(t => (JsonNode)new JsonObject
                {
                    ["where"] = t.Where, ["risk"] = t.Level, ["rows"] = t.Rows,
                    ["direct"] = new JsonArray(t.Direct.Select(k => (JsonNode)Kinds.Id(k)).ToArray()),
                    ["quasi"] = new JsonArray(t.Quasi.Select(k => (JsonNode)Kinds.Id(k)).ToArray()),
                    ["in_free_text"] = t.TextFindings, ["why"] = t.Explanation,
                }).ToArray()),
                ["notes"] = new JsonArray(risk.Notes.Select(n => (JsonNode)n).ToArray()),
                ["caveats"] = new JsonArray(ReportWriter.Caveats.Select(n => (JsonNode)n).ToArray()),
            };
        }, cancel);

    // ───────────────────────────── decisions and policy ─────────────────────────────

    [McpServerTool(Name = "set_classification")]
    [Description("Overrides what the scan decided about a column: is_phi true (with the kind it is, or the scan's kind) or false (not PHI: kept as it is). The decision is the person's to make: say why, and ask them when unsure. It stays with the project across scans.")]
    public Task<string> SetClassification(
        [Description(ColumnHelp)] string column,
        [Description("Whether the column holds PHI.")] bool is_phi,
        [Description("The kind, when it is PHI (\"name\", \"mrn\", \"free_text\"…). Default: the scan's kind.")] string? kind = null,
        [Description("Why, in a few words (kept with the decision). Optional.")] string? note = null,
        CancellationToken cancel = default) =>
        Edit("classified a column", (s, p) =>
        {
            var c = Scanned(s).Find(column);
            PhiKind? k = kind is { Length: > 0 } ? Kinds.Parse(kind) : null;
            if (is_phi && k == PhiKind.None) throw new ArgumentException("kind \"none\" isn't PHI: give is_phi false instead.");
            p.Overrides[c.Key] = new ColumnOverride { IsPhi = is_phi, Kind = is_phi ? k : null, Note = note };
            return ColumnRow(c, p);
        }, cancel);

    [McpServerTool(Name = "clear_classification")]
    [Description("Takes back the decision about a column, so the scan's classification applies again.")]
    public Task<string> ClearClassification(
        [Description(ColumnHelp)] string column,
        CancellationToken cancel = default) =>
        Edit("cleared a decision", (s, p) =>
        {
            var c = Scanned(s).Find(column);
            if (!p.Overrides.Remove(c.Key)) throw new ArgumentException($"{c.Id} has no decision to clear.");
            return ColumnRow(c, p);
        }, cancel);

    [McpServerTool(Name = "set_policy")]
    [Description("Sets how the copy is made: policy safe_harbor, limited_data_set or custom; date_mode year (only the year kept, Safe Harbor's own rule, and the default) or shift (each person's dates moved by the same number of days, intervals kept, which goes beyond Safe Harbor's rule); person_key, the column that says whose row it is (default: member ID, else MRN, else SSN); database_output csv or sqlite for database tables. Leave out what stays as it is.")]
    public Task<string> SetPolicy(
        [Description("safe_harbor, limited_data_set or custom. Optional.")] string? policy = null,
        [Description("year (the default) or shift. Optional.")] string? date_mode = null,
        [Description("A column name that identifies the person in each table, for date shifting (\"member_id\"). Give \"\" for the default. Optional.")] string? person_key = null,
        [Description("csv (a file per table) or sqlite (one database), for database sources. Optional.")] string? database_output = null,
        CancellationToken cancel = default) =>
        Edit("set the policy", (s, p) =>
        {
            if (policy is { Length: > 0 }) p.Policy.Kind = Kinds.ParsePolicy(policy);
            if (date_mode is { Length: > 0 })
                p.Policy.DateMode = date_mode.Trim().ToLowerInvariant() switch { "shift" or "shifted" => DateMode.Shift, "year" or "year_only" or "yearonly" => DateMode.Year, _ => throw new ArgumentException("date_mode is shift or year.") };
            if (person_key != null) p.Policy.PersonKey = person_key.Trim().Length == 0 ? null : person_key.Trim();
            if (database_output is { Length: > 0 })
                p.Policy.DatabaseOutput = database_output.Trim().ToLowerInvariant() is "csv" or "sqlite" ? database_output.Trim().ToLowerInvariant() : throw new ArgumentException("database_output is csv or sqlite.");
            return PolicyInfo(p, s.Inventory);
        }, cancel);

    [McpServerTool(Name = "set_column_action")]
    [Description("Chooses what de-identification does with one column, making the policy custom (Safe Harbor's choices for every other column): keep, drop, pseudonymise, tokenise, shift_date, generalise, redact or scrub_text; or \"default\" to go back to the policy's choice.")]
    public Task<string> SetColumnAction(
        [Description(ColumnHelp)] string column,
        [Description("keep, drop, pseudonymise, tokenise, shift_date, generalise, redact, scrub_text, or default.")] string action,
        CancellationToken cancel = default) =>
        Edit("set a column's action", (s, p) =>
        {
            var c = Scanned(s).Find(column);
            var kind = p.EffectiveKind(c.Key, c.Detected);
            string? warning = null;
            if (action.Trim().Equals("default", StringComparison.OrdinalIgnoreCase)) p.Policy.Actions.Remove(c.Key);
            else
            {
                var a = Kinds.ParseAction(action);
                if (p.Policy.Kind != PolicyKind.Custom)
                {
                    // Custom starts from Safe Harbor: the limited data set's choices are carried over as column actions.
                    if (p.Policy.Kind == PolicyKind.LimitedDataSet)
                        foreach (var other in Scanned(s).Columns)
                            if (other.Key != c.Key && !p.Policy.Actions.ContainsKey(other.Key))
                            {
                                var ok = p.EffectiveKind(other.Key, other.Detected);
                                if (Kinds.Info(ok).LimitedDataSet != Kinds.Info(ok).SafeHarbor) p.Policy.Actions[other.Key] = Kinds.Info(ok).LimitedDataSet;
                            }
                    p.Policy.Kind = PolicyKind.Custom;
                }
                p.Policy.Actions[c.Key] = a;
                if (a == ColumnAction.ShiftDate && !Kinds.IsDate(kind)) warning = "shift_date only changes values that are dates; others become [DATE].";
                if (a == ColumnAction.Keep && Kinds.Info(kind).Category == KindCategory.Direct) warning = $"Keeping a {Kinds.Label(kind).ToLowerInvariant()} column leaves a direct identifier in the copy: the copy is then not de-identified.";
            }
            var row = ColumnRow(c, p);
            row["warning"] = warning;
            row["policy"] = p.Policy.Describe();
            return row;
        }, cancel);

    // ───────────────────────────── de-identifying ─────────────────────────────

    [McpServerTool(Name = "preview_deidentification", ReadOnly = true)]
    [Description("What de-identification would do to a column, on a few of its values: each value before (masked) and after. Made-up names and tokens are shown as they are; dates after shifting only by their year. Uses the key file if it exists (else a throwaway key, so the tokens will differ).")]
    public async Task<string> PreviewDeidentification(
        [Description(ColumnHelp)] string column,
        [Description("How many values, 1 to 20. Default 5.")] int max = 5,
        [Description("The key file, relative to the working folder. Default: the project's, else phi.key.")] string? key_file = null,
        CancellationToken cancel = default)
    {
        var (project, inventory, report) = await Run("read the project", s =>
        {
            var inv = Scanned(s);
            return (s.Document, inv, inv.Find(column));
        }, cancel).ConfigureAwait(false);
        var keyPath = _files.Resolve(key_file ?? project.KeyFile ?? "phi.key");
        var key = File.Exists(keyPath) ? Wrap(() => KeyFile.Load(keyPath)) : System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var samples = await Task.Run(() =>
        {
            var dataset = Sources.Expand(project.Sources.First(x => x.Id == report.SourceId), host.Root, Lookup)
                .FirstOrDefault(d => d.Location == report.Location && d.Table == report.Table) ?? throw new McpException("The column's source can't be read just now: scan again.");
            var t = Sources.Read(dataset, 500);
            var plans = DeidentifyRun.Plans(project, inventory, dataset);
            var personCol = DeidentifyRun.PersonColumn(project, plans) is { } pc ? t.Columns.IndexOf(pc) : -1;
            var ci = t.Columns.IndexOf(report.Column);
            var d = new Deidentifier(key, project.Policy, inventory.Known);
            var kind = project.EffectiveKind(report.Key, report.Detected);
            var action = project.ActionFor(report.Key, report.Detected);
            var list = new List<(string Before, string After)>();
            var seen = new HashSet<string>();
            foreach (var row in t.Rows)
            {
                if (ci < 0 || row[ci] is not { Length: > 0 } v || !seen.Add(v)) continue;
                var who = personCol >= 0 ? row[personCol] : null;
                var after = action == ColumnAction.ScrubText ? d.Scrub(v, who ?? d.PersonOf(v)) : d.Apply(action, kind, v, who);
                list.Add((Mask.Value(kind == PhiKind.None ? PhiKind.None : kind, v), After(kind, action, after)));
                if (list.Count >= Math.Clamp(max, 1, 20)) break;
            }
            return (list, kind, action);
        }, cancel).ConfigureAwait(false);
        return new JsonObject
        {
            ["column"] = report.Id,
            ["where"] = report.SafeDisplay,
            ["kind"] = Kinds.Id(samples.kind),
            ["action"] = Kinds.Id(samples.action),
            ["key"] = File.Exists(keyPath) ? "the key file" : "a throwaway key (no key file yet): tokens will differ in the real run",
            ["samples"] = new JsonArray(samples.list.Select(x => (JsonNode)new JsonObject { ["before"] = x.Before, ["after"] = x.After }).ToArray()),
        }.ToJsonString(Json.Options);
    }

    /// <summary>A de-identified value as an agent may see it: stand-ins as they are, dates by their year, text masked but for stand-ins.</summary>
    private static string After(PhiKind kind, ColumnAction action, string? after)
    {
        if (after is null) return action == ColumnAction.Drop ? "(column left out)" : "";
        return action switch
        {
            ColumnAction.Keep => Mask.Value(kind, after),
            ColumnAction.ShiftDate => Detect.TryDate(after, out var d) ? $"{d.Value.Year}-**-** (shifted)" : after,
            ColumnAction.ScrubText => Mask.AfterText(after),
            ColumnAction.Generalise when Kinds.IsDate(kind) || kind is PhiKind.Zip or PhiKind.Age => after,
            ColumnAction.Pseudonymise or ColumnAction.Tokenise or ColumnAction.Redact or ColumnAction.Generalise => after,
            _ => Mask.Value(kind, after),
        };
    }

    [McpServerTool(Name = "deidentify")]
    [Description("Writes the de-identified copy of every source into a folder in the working folder (never inside a source folder): files as the same kind of file, SQLite databases as SQLite, a server's tables as CSV or SQLite (set_policy database_output). Tokens and date shifts come from the key file, which is made if it doesn't exist; the key is never shown. Scans first if there's no scan yet. Then run verify.")]
    public async Task<string> Deidentify(
        [Description("The output folder, relative to the working folder. Default: the project's, else \"deidentified\".")] string? output = null,
        [Description("The key file, relative to the working folder. Default: the project's, else \"phi.key\". Keep it out of the output folder.")] string? key_file = null,
        [Description("Make the key file if it doesn't exist. Default true.")] bool create_key = true,
        [Description("Write over files already in the output folder. Default false.")] bool overwrite = false,
        CancellationToken cancel = default)
    {
        var (project, inventory) = await Run("read the project", s => (s.Document, s.Inventory), cancel).ConfigureAwait(false);
        if (project.Sources.Count == 0) throw new McpException("The project has no sources: add_source first.");
        var outRel = output ?? project.Output ?? "deidentified";
        var keyRel = key_file ?? project.KeyFile ?? "phi.key";
        var outFull = Wrap(() => _files.Resolve(outRel));
        var keyFull = Wrap(() => _files.Resolve(keyRel));
        var outSlash = Path.TrimEndingDirectorySeparator(outFull) + Path.DirectorySeparatorChar;
        if (keyFull.StartsWith(outSlash, StringComparison.Ordinal)) throw new McpException("The key file must not be inside the output folder: whoever gets the copy must not get the key.");
        Wrap(() => { DeidentifyRun.CheckOutput(project, host.Root, outFull); return true; });
        if (!overwrite && Directory.Exists(outFull) && Directory.EnumerateFileSystemEntries(outFull).Any())
            throw new McpException($"{Mask.Label(Relative(outFull))} already has files in it. Give overwrite true to write over them, or another output folder.");
        if (!File.Exists(keyFull) && !create_key) throw new McpException($"There's no key file {Mask.Label(keyRel)}. Give create_key true to make one, or another key_file.");
        byte[] key;
        bool made;
        try { key = KeyFile.LoadOrCreate(keyFull, out made); }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException) { throw new McpException(Explain(e), e); }
        inventory ??= await Task.Run(() => Scanner.Scan(project, host.Root, Lookup, cancel: cancel, skip: outFull), cancel).ConfigureAwait(false);
        var scanned = inventory;
        var result = await Task.Run(() =>
        {
            try { return DeidentifyRun.Run(project, scanned, host.Root, outFull, key, Lookup, overwrite, cancel: cancel); }
            catch (Exception e) when (e is IOException or InvalidOperationException or ArgumentException) { throw new McpException(Explain(e), e); }
        }, cancel).ConfigureAwait(false);
        _files.Wrote(keyFull);
        return await Run("de-identified the sources", s =>
        {
            if (s.Inventory != scanned) s.Scanned(scanned);
            s.Deidentified(result);
            var p = s.Document;
            if (p.Output != outFull || p.KeyFile != keyFull)
            {
                p.Output = outFull;
                p.KeyFile = keyFull;
                s.Apply(p, "AI: set the output folder and key file");
            }
            s.Refresh();
            return new JsonObject
            {
                ["output"] = Mask.Label(Relative(outFull)),
                ["policy"] = result.Policy,
                ["summary"] = result.Summary,
                ["files"] = new JsonArray(result.Files.Take(100).Select(f => (JsonNode)Mask.Label(f)).ToArray()),
                ["replaced"] = new JsonObject(result.Replaced.OrderByDescending(x => x.Value).Select(x => KeyValuePair.Create(Kinds.Id(x.Key), (JsonNode?)x.Value))),
                ["problems"] = result.Problems.Count > 0 ? new JsonArray(result.Problems.Select(x => (JsonNode)x).ToArray()) : null,
                ["key"] = made ? $"A new key was made in {Mask.Label(Relative(keyFull))}: the person keeps it, and never sends it with the copy." : $"Made with the key in {Mask.Label(Relative(keyFull))}.",
                ["next"] = "verify checks the copy.",
            }.ToJsonString(Json.Options);
        }, cancel).ConfigureAwait(false);
    }

    [McpServerTool(Name = "verify")]
    [Description("Checks a de-identified copy: scans it again and reports anything the policy removes that is still there (masked, by place), any original value from the sources found in it, and a before/after summary by kind. Default: the last copy made.")]
    public async Task<string> Verify(
        [Description("The copy's folder or file, relative to the working folder. Default: the last output.")] string? output = null,
        CancellationToken cancel = default)
    {
        var (project, inventory, last) = await Run("read the project", s => (s.Document, s.Inventory, s.LastRun?.Output), cancel).ConfigureAwait(false);
        var target = output is { Length: > 0 } o ? Wrap(() => PathOf(o)) : last ?? (project.Output is { } po ? Wrap(() => _files.Resolve(po)) : throw new McpException("There's no copy yet: deidentify first, or give output."));
        if (!Directory.Exists(target) && !File.Exists(target)) throw new McpException($"There's no {Mask.Label(Relative(target))} in the working folder.");
        var result = await Task.Run(() => Verifier.Verify(target, project.Policy, inventory, Lookup, cancel), cancel).ConfigureAwait(false);
        return await Read("verified the copy", s =>
        {
            s.Verified(result);
            return VerifyInfo(result);
        }, cancel).ConfigureAwait(false);
    }

    [McpServerTool(Name = "export_report")]
    [Description("Writes the scan report to a file in the working folder: .xlsx (summary, inventory, free-text findings, and the last verification) or .html (one page). Every value in it is masked. Won't write over a file it didn't write unless overwrite is true.")]
    public Task<string> ExportReport(
        [Description("The file, relative to the working folder: \"reports/phi-inventory.xlsx\" or \".html\".")] string path,
        [Description("Write over an existing file. Default false.")] bool overwrite = false,
        CancellationToken cancel = default) =>
        Read("exported the report", s =>
        {
            var full = _files.Resolve(path, "A report", ".xlsx", ".html", ".htm");
            _files.CheckWritable(full, overwrite);
            var inv = Scanned(s);
            ReportWriter.Write(full, inv, s.Document, s.LastVerify);
            _files.Wrote(full);
            return new JsonObject { ["exported"] = Mask.Label(Relative(full)), ["columns"] = inv.Columns.Count, ["verification"] = s.LastVerify != null };
        }, cancel);

    [McpServerTool(Name = "render_view", ReadOnly = true, Idempotent = true)]
    [Description("A picture of the inventory as the window shows it (masked): the risk, then each PHI column with its kind, confidence, count, examples and action. Look at it to check the scan and the policy, or to show the person.")]
    public async Task<CallToolResult> RenderView(
        [Description("Scale, from 0.3 to 2. Default 1.")] double scale = 1,
        CancellationToken cancel = default)
    {
        if (scale is < 0.3 or > 2) throw new McpException("scale is from 0.3 to 2.");
        var (png, text) = await Run("looked at the inventory", s =>
        {
            var inv = s.Inventory;
            var info = inv is null ? "(no scan yet)" : $"{inv.Columns.Count(c => Kinds.IsPhi(s.Document.EffectiveKind(c.Key, c.Detected)))} PHI columns of {inv.Columns.Count}; risk {RiskSummary.Of(inv, s.Document).Overall}; policy {s.Document.Policy.Describe()}.";
            return (host.Library.Picture(s.Document, inv, scale), info);
        }, cancel).ConfigureAwait(false);
        return new CallToolResult { Content = [ImageContentBlock.FromBytes(png, "image/png"), new TextContentBlock { Text = text }] };
    }

    // ───────────────────────────── history ─────────────────────────────

    [McpServerTool(Name = "undo")]
    [Description("Takes back the last change to the project (anyone's: the person's or an agent's), as Ctrl+Z does.")]
    public Task<string> Undo(CancellationToken cancel = default) =>
        Read("undid a change", s =>
        {
            if (!s.History.CanUndo) throw new InvalidOperationException("There's nothing to undo.");
            var what = s.History.UndoLabel;
            s.History.Undo();
            s.Refresh();
            return new JsonObject { ["undone"] = what, ["policy"] = s.Document.Policy.Describe(), ["sources"] = s.Document.Sources.Count, ["decisions"] = s.Document.Overrides.Count };
        }, cancel);

    [McpServerTool(Name = "redo")]
    [Description("Puts back the change undo last took back.")]
    public Task<string> Redo(CancellationToken cancel = default) =>
        Read("redid a change", s =>
        {
            if (!s.History.CanRedo) throw new InvalidOperationException("There's nothing to redo.");
            var what = s.History.RedoLabel;
            s.History.Redo();
            s.Refresh();
            return new JsonObject { ["redone"] = what, ["policy"] = s.Document.Policy.Describe(), ["sources"] = s.Document.Sources.Count, ["decisions"] = s.Document.Overrides.Count };
        }, cancel);

    // ───────────────────────────── helpers ─────────────────────────────

    private Sources.ConnectionInfo? Lookup(string name)
    {
        try
        {
            var c = host.Connections.Get(name);
            return new Sources.ConnectionInfo(c.Engine, c.ConnectionString);
        }
        catch (ArgumentException) { return null; }
    }

    private string Relative(string full) => Path.GetRelativePath(host.Root, full).Replace('\\', '/');

    /// <summary>A source as an agent sees it: its kind and path (masked where it may hold a name), or its engine and database.</summary>
    private string SourceLabel(SourceSpec s) => s.Kind switch
    {
        "database" when s.ConnectionName is { } n => $"{s.Engine} database \"{n}\"" + (s.Tables is { Count: > 0 } t ? $" ({t.Count} tables)" : ""),
        "database" => $"{s.Engine} database {Mask.Label(DbRead.DisplayName(Db.ParseEngine(s.Engine ?? "sqlite"), s.Connection ?? ""))}" + (s.Tables is { Count: > 0 } t2 ? $" ({t2.Count} tables)" : ""),
        _ => $"{s.Kind} {Mask.Label(s.Path is { } p ? (Path.IsPathRooted(p) && p.StartsWith(host.Root, StringComparison.Ordinal) ? Relative(p) : Path.IsPathRooted(p) ? Path.GetFileName(Path.TrimEndingDirectorySeparator(p)) : p) : "")}",
    };

    private JsonObject ProjectInfo(IScanSession s)
    {
        var p = s.Document;
        var info = new JsonObject
        {
            ["file"] = s.FilePath is { } f ? Mask.Label(Relative(f)) : null,
            ["changed"] = s.History.IsDirty,
            ["sources"] = new JsonArray(p.Sources.Select(x => (JsonNode)new JsonObject { ["id"] = x.Id, ["kind"] = x.Kind, ["source"] = SourceLabel(x) }).ToArray()),
            ["policy"] = PolicyInfo(p, s.Inventory),
            ["decisions"] = new JsonArray(p.Overrides.Select(o => (JsonNode)new JsonObject
            {
                ["column"] = ColumnName(o.Key, s.Inventory), ["is_phi"] = o.Value.IsPhi, ["kind"] = o.Value.Kind is { } k ? Kinds.Id(k) : null, ["note"] = o.Value.Note,
            }).ToArray()),
            ["sample_rows"] = p.SampleRows,
            ["output"] = p.Output is { } po ? Mask.Label(Relative(Sources.Full(host.Root, po))) : null,
            ["key_file"] = p.KeyFile is { } kf ? Mask.Label(Relative(Sources.Full(host.Root, kf))) : null,
            ["scan"] = s.Inventory is { } inv ? ScanSummary(p, inv) : null,
            ["last_copy"] = s.LastRun is { } r ? r.Summary : null,
            ["last_check"] = s.LastVerify is { } v ? v.Summary : null,
            ["values"] = "masked: agents never see a raw value",
        };
        return info;
    }

    private static JsonObject PolicyInfo(Project p, Inventory? inventory) => new()
    {
        ["policy"] = Kinds.Id(p.Policy.Kind),
        ["date_mode"] = p.Policy.DateMode == DateMode.Year ? "year" : "shift",
        ["describe"] = p.Policy.Describe(),
        ["person_key"] = p.Policy.PersonKey,
        ["database_output"] = p.Policy.DatabaseOutput,
        ["column_actions"] = new JsonArray(p.Policy.Actions.Select(a => (JsonNode)new JsonObject { ["column"] = ColumnName(a.Key, inventory), ["action"] = Kinds.Id(a.Value) }).ToArray()),
    };

    /// <summary>A column key as an agent sees it: "c7 members.csv › ssn" when the scan has it, else its parts masked.</summary>
    internal static string ColumnName(string key, Inventory? inventory)
    {
        if (inventory?.Columns.FirstOrDefault(c => c.Key == key) is { } c) return $"{c.Id} {c.SafeDisplay}";
        var parts = key.Split('|');
        return string.Join(" › ", parts.Skip(1).Where(x => x.Length > 0).Select(Mask.Label));
    }

    private static JsonObject ScanSummary(Project p, Inventory inv)
    {
        var risk = RiskSummary.Of(inv, p);
        var phi = inv.Columns.Where(c => Kinds.IsPhi(p.EffectiveKind(c.Key, c.Detected))).ToList();
        return new JsonObject
        {
            ["datasets"] = inv.Datasets,
            ["columns"] = inv.Columns.Count,
            ["rows_read"] = inv.RowsRead,
            ["phi_columns"] = phi.Count,
            ["by_kind"] = new JsonObject(phi.GroupBy(c => p.EffectiveKind(c.Key, c.Detected)).OrderByDescending(g => g.Count()).Select(g => KeyValuePair.Create(Kinds.Id(g.Key), (JsonNode?)g.Count()))),
            ["free_text_findings"] = inv.Columns.Sum(c => c.TextCounts.Where(t => t.Key != PhiKind.Npi).Sum(t => t.Value)),
            ["low_confidence"] = inv.Columns.Count(c => Kinds.IsPhi(c.Detected) && c.Confidence < 0.6),
            ["risk"] = risk.Overall,
            ["problems"] = inv.Problems.Count > 0 ? new JsonArray(inv.Problems.Take(20).Select(x => (JsonNode)x).ToArray()) : null,
        };
    }

    private static JsonObject ColumnRow(ColumnReport c, Project p)
    {
        var kind = p.EffectiveKind(c.Key, c.Detected);
        return new JsonObject
        {
            ["id"] = c.Id,
            ["where"] = c.SafeDisplay,
            ["kind"] = Kinds.Id(kind),
            ["detected"] = kind != c.Detected ? Kinds.Id(c.Detected) : null,
            ["set_by_person"] = p.Overrides.ContainsKey(c.Key) ? true : null,
            ["confidence"] = Math.Round(c.Confidence, 2),
            ["count"] = c.Count,
            ["values"] = c.Values,
            ["examples"] = new JsonArray(c.Examples.Select(e => (JsonNode)e).ToArray()),
            ["action"] = Kinds.Id(p.ActionFor(c.Key, c.Detected)),
        };
    }

    private static JsonObject VerifyInfo(VerifyResult r) => new()
    {
        ["clean"] = r.Clean,
        ["summary"] = r.Summary,
        ["policy"] = r.Policy,
        ["left"] = new JsonArray(r.Leftovers.Take(100).Select(l => (JsonNode)new JsonObject
        {
            ["where"] = l.Where, ["kind"] = Kinds.Id(l.Kind), ["count"] = l.Count, ["why"] = l.Why,
            ["examples"] = new JsonArray(l.Examples.Select(e => (JsonNode)e).ToArray()),
        }).ToArray()),
        ["originals_found"] = r.Originals,
        ["before_after"] = new JsonArray(r.Before.Keys.Union(r.After.Keys).Union(r.Expected.Keys).Distinct().Select(k => (JsonNode)new JsonObject
        {
            ["kind"] = Kinds.Id(k), ["before"] = r.Before.GetValueOrDefault(k), ["left"] = r.After.GetValueOrDefault(k), ["kept_by_policy"] = r.Expected.GetValueOrDefault(k),
        }).ToArray()),
        ["problems"] = r.Problems.Count > 0 ? new JsonArray(r.Problems.Select(x => (JsonNode)x).ToArray()) : null,
        ["datasets"] = r.Datasets,
        ["rows_read"] = r.Rows,
    };

    private static Inventory Scanned(IScanSession s) =>
        s.Inventory ?? throw new InvalidOperationException(s.Document.Sources.Count == 0 ? "There's no scan yet, and no sources: add_source, then scan." : "There's no scan yet: scan first.");

    private static void Discardable(IScanSession s, bool discard)
    {
        if (s.History.IsDirty && !discard)
            throw new InvalidOperationException("The open project has changes that haven't been saved. Save it first (save_project), or call again with discard_changes true to throw them away.");
    }

    private static async Task TestConnection(DbEngine engine, string cs, CancellationToken cancel)
    {
        try
        {
            await Task.Run(() => Db.Test(engine, cs), cancel).ConfigureAwait(false);
        }
        catch (Exception e) when (e is System.Data.Common.DbException or ArgumentException or InvalidOperationException)
        {
            throw new McpException($"Couldn't connect to the {Db.DisplayName(engine)} database: {Scanner.Safe(e)}");
        }
    }

    private static T Wrap<T>(Func<T> work)
    {
        try
        {
            return work();
        }
        catch (Exception e) when (e is not McpException and not OperationCanceledException)
        {
            throw new McpException(Explain(e), e);
        }
    }

    /// <summary>Runs a call that changes nothing (or replaces the project wholesale) and answers in JSON.</summary>
    private Task<string> Read(string action, Func<IScanSession, JsonObject> work, CancellationToken cancel) =>
        Run(action, s => work(s).ToJsonString(Json.Options), cancel);

    /// <summary>
    /// Runs a change as one undo step: the work changes a copy of the project, and only if it succeeds (and changed
    /// something) does the copy become the project. A call that fails leaves the project as it was.
    /// </summary>
    private Task<string> Edit(string label, Func<IScanSession, Project, JsonObject> work, CancellationToken cancel) =>
        Run(label, s =>
        {
            var before = s.Document.ToJson();
            var doc = s.Document;
            var result = work(s, doc);
            if (doc.ToJson() == before)
            {
                result["unchanged"] = true;
                return result.ToJsonString(Json.Options);
            }
            s.Apply(doc, "AI: " + label);
            s.Refresh();
            return result.ToJsonString(Json.Options);
        }, cancel);

    private async Task<T> Run<T>(string action, Func<IScanSession, T> work, CancellationToken cancel)
    {
        try
        {
            return await host.RunAsync(action, work, cancel).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not McpException and not OperationCanceledException)
        {
            throw new McpException(Explain(e), e);
        }
    }

    /// <summary>Asks the person (MCP elicitation; the in-app chat shows buttons). Throws if they say no or can't be asked.</summary>
    private static async Task Confirm(McpServer server, string question, CancellationToken cancel)
    {
        ElicitResult answer;
        try
        {
            answer = await server.ElicitAsync(new ElicitRequestParams
            {
                Message = question,
                RequestedSchema = new ElicitRequestParams.RequestSchema { Properties = { } },
            }, cancel).ConfigureAwait(false);
        }
        catch (Exception e) when (e is McpException or InvalidOperationException or NotSupportedException)
        {
            throw new McpException($"{question} The person couldn't be asked ({e.Message}), so nothing was changed.");
        }
        if (answer.Action != "accept")
            throw new McpException($"The person said no: {question.Replace(" Go ahead?", "", StringComparison.Ordinal)}. Nothing was changed. Ask them what they want.");
    }

    internal static string Explain(Exception e) => Scanner.Safe(e switch
    {
        ArgumentException or InvalidOperationException or FormatException or NotSupportedException or IOException
            or UnauthorizedAccessException or ScanBusyException or JsonException or InvalidDataException or KeyNotFoundException => e.Message,
        System.Data.Common.DbException => $"The database said: {e.Message}",
        _ => $"Something went wrong ({e.GetType().Name}): {e.Message}",
    });
}
