using System.ComponentModel;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace AVAPHIScanner.Agents.Mcp;

/// <summary>
/// Saved recipes, served as MCP prompts: short step-by-step plans for the jobs agents are asked to do, written with the
/// real tool names and arguments. Each step that calls a tool shows the call on a line of its own, "→ tool {arguments}",
/// so an agent can follow it as it is or adapt it (the tests run every recipe through the server, call by call, on a
/// working folder holding the samples, so a recipe that stops working fails the build). The defaults name the sample
/// data (a "samples" folder in the working folder: members.csv, claims.xlsx, notes/, feed.jsonl, clinic.db).
/// </summary>
[McpServerPromptType]
public static class Recipes
{
    /// <summary>The marker that starts a step's tool call in a recipe's text.</summary>
    public const string CallMarker = "→ ";

    [McpServerPrompt(Name = "find_phi_in_folder", Title = "Find the PHI in a folder")]
    [Description("Scans a folder of files (CSV, Excel, JSON, text notes, SQLite) and reports where the PHI is: which files and columns, what kind, how sure, and the risk; then looks closer at free text and doubtful columns.")]
    public static string FindPhiInFolder(
        [Description("The folder, relative to the working folder (default \"samples\").")] string? folder = null)
    {
        var f = Pick(folder, "samples");
        var r = new Recipe($"Find the PHI in the folder {f}.");
        r.Step("See what's open.", "get_project", new { });
        r.Step("Add the folder as a source (it's read through its sub-folders).", "add_source", new { path = f });
        r.Step("Scan it.", "scan", new { });
        r.Step("The risk, table by table.", "get_risk", new { });
        r.Step("Where the PHI is: each column with its kind, confidence, count and masked examples.", "get_inventory", new { });
        r.Step("The columns the scan is least sure of: check these with the person.", "get_inventory", new { phi_only = false, below_confidence = 0.7 });
        r.Step("A free-text column in detail: the identifiers found inside it, cell by cell. Use a free_text column's id from the inventory.", "get_column", new { column = "notes/note-001.txt › (text)", max_findings = 20 });
        r.Step("Show the inventory.", "render_view", new { });
        return r.Text("Report to the person: how many files and columns hold PHI, of which kinds, the riskiest tables and why, and the columns to check by hand (low confidence, free text). Say that detection is an aid, not a guarantee. Offer to export the report (export_report) or make a de-identified copy (the deidentify_for_vendor recipe).");
    }

    [McpServerPrompt(Name = "inventory_database", Title = "Inventory a database")]
    [Description("Scans a database's tables (SQL Server, PostgreSQL or SQLite) on a sample of rows, lists every column with what it holds, and exports the inventory as a workbook.")]
    public static string InventoryDatabase(
        [Description("A SQLite file in the working folder (default \"samples/clinic.db\"); for a server, add_source with connection_name instead.")] string? sqlite_file = null,
        [Description("Rows to read per table (default 1000).")] int? rows = null)
    {
        var db = Pick(sqlite_file, "samples/clinic.db");
        var r = new Recipe($"Inventory the database {db}.");
        r.Step("A saved server connection can be used instead (add_source connection_name).", "list_connections", new { });
        r.Step("Add the database as a source.", "add_source", new { sqlite_file = db });
        r.Step("Read a sample of each table: enough to classify, quick on a big database.", "set_sampling", new { rows = rows ?? 1000 });
        r.Step("Scan.", "scan", new { });
        r.Step("Every column, PHI or not.", "get_inventory", new { phi_only = false });
        r.Step("The risk per table.", "get_risk", new { });
        r.Step("Keep the inventory as a workbook for the data owner.", "export_report", new { path = "reports/database-inventory.xlsx", overwrite = true });
        return r.Text("Summarise table by table: which hold direct identifiers, which only quasi-identifiers, which nothing, and which have free text. Mention that tables were sampled, and that a column the person knows better than the scan can be overridden (set_classification).");
    }

    [McpServerPrompt(Name = "deidentify_for_vendor", Title = "De-identify for a vendor (Safe Harbor)")]
    [Description("Makes a Safe Harbor copy of a folder to send to a vendor: scans, checks doubtful columns, previews the changes, writes the copy with a key kept back, verifies it and writes a report to send with it.")]
    public static string DeidentifyForVendor(
        [Description("The folder to copy (default \"samples\").")] string? folder = null,
        [Description("The output folder (default \"vendor-extract\").")] string? output = null)
    {
        var f = Pick(folder, "samples");
        var o = Pick(output, "vendor-extract");
        var r = new Recipe($"Make a Safe Harbor copy of {f} in {o}, for a vendor.");
        r.Step("Add the folder and scan it.", "add_source", new { path = f });
        r.Step(null, "scan", new { });
        r.Step("Doubtful columns first: ask the person about any you can't settle, and record their decision with set_classification.", "get_inventory", new { phi_only = false, below_confidence = 0.7 });
        r.Step("Safe Harbor, with each person's dates shifted by the same number of days (intervals kept). For the strict Safe Harbor rule use date_mode year.", "set_policy", new { policy = "safe_harbor", date_mode = "shift" });
        r.Step("Look at what happens to names…", "preview_deidentification", new { column = "members.csv › last_name", max = 3 });
        r.Step("…to identifiers (tokens keep joins: the same member ID gets the same token in every file)…", "preview_deidentification", new { column = "members.csv › member_id", max = 3 });
        r.Step("…and to free text.", "preview_deidentification", new { column = "notes/note-001.txt › (text)", max = 2 });
        r.Step("Write the copy. The key file stays with the person, outside the copy.", "deidentify", new { output = o, key_file = "keys/vendor.key", overwrite = true });
        r.Step("Check the copy.", "verify", new { output = o });
        r.Step("A report to keep (and to send, if the vendor wants to see what was done).", "export_report", new { path = $"reports/{o}.html", overwrite = true });
        return r.Text($"Tell the person: the copy is in {o}, what was replaced (by kind), whether verify found anything left, and that the key file must never go with the copy. Remind them that Safe Harbor also needs them to have no actual knowledge that what's left could identify someone, and that shifted dates go beyond Safe Harbor's own rule (date_mode year keeps only the year).");
    }

    [McpServerPrompt(Name = "limited_data_set_for_research", Title = "A limited data set for research")]
    [Description("Makes a limited data set (HIPAA §164.514(e)): direct identifiers removed, dates, city, state, ZIP codes and ages kept, for research under a data use agreement.")]
    public static string LimitedDataSetForResearch(
        [Description("The folder to copy (default \"samples\").")] string? folder = null,
        [Description("The output folder (default \"research-lds\").")] string? output = null)
    {
        var f = Pick(folder, "samples");
        var o = Pick(output, "research-lds");
        var r = new Recipe($"Make a limited data set of {f} in {o}.");
        r.Step("Add the folder and scan it.", "add_source", new { path = f });
        r.Step(null, "scan", new { });
        r.Step("A limited data set keeps dates, city, state, ZIP code and ages; names, contact details and identifiers still go.", "set_policy", new { policy = "limited_data_set" });
        r.Step("What stays and what goes, column by column.", "get_inventory", new { });
        r.Step("Dates are kept as they are.", "preview_deidentification", new { column = "members.csv › dob", max = 3 });
        r.Step("Write the copy.", "deidentify", new { output = o, key_file = "keys/research.key", overwrite = true });
        r.Step("Check it: dates, cities and ZIP codes are reported as kept by the policy, anything else as left.", "verify", new { output = o });
        return r.Text("Tell the person what the limited data set keeps and what it removed, and that it may only be shared under a data use agreement: it is not de-identified data.");
    }

    [McpServerPrompt(Name = "check_export_is_clean", Title = "Check that an export is clean")]
    [Description("Checks a folder of exported data before it leaves: scans the original data so its values are known, then verifies the export and reports anything left in it.")]
    public static string CheckExportIsClean(
        [Description("The export to check (default \"vendor-extract\").")] string? export = null,
        [Description("The data it was made from (default \"samples\").")] string? source = null)
    {
        var e = Pick(export, "vendor-extract");
        var s = Pick(source, "samples");
        var r = new Recipe($"Check that {e} is clean.");
        r.Step("Find the export.", "list_files", new { });
        r.Step("Add the data it was made from and scan it, so verify can also look for the original values.", "add_source", new { path = s });
        r.Step(null, "scan", new { });
        r.Step("The policy the export should meet.", "set_policy", new { policy = "safe_harbor" });
        r.Step("Check the export.", "verify", new { output = e });
        r.Step("A report with the verification in it.", "export_report", new { path = "reports/export-check.html", overwrite = true });
        return r.Text("Say plainly whether the export is clean. If not, list where something was left (masked), whether any were original values, and what to change (a column's classification or action) before making the export again. Shifted dates are reported as kept by the policy; with date_mode year they would count as left.");
    }

    [McpServerPrompt(Name = "explain_table_risk", Title = "Explain the risk in a table")]
    [Description("Explains, for a non-specialist, why a table is risky: which columns identify people on their own, which only in combination, what is in its free text, and what de-identification will do about each.")]
    public static string ExplainTableRisk(
        [Description("The folder or file that holds the table (default \"samples\").")] string? source = null,
        [Description("The table, sheet or file name (default \"members.csv\").")] string? table = null)
    {
        var s = Pick(source, "samples");
        var t = Pick(table, "members.csv");
        var r = new Recipe($"Explain the risk in {t}.");
        r.Step("Add and scan the data.", "add_source", new { path = s });
        r.Step(null, "scan", new { });
        r.Step("The table's risk and why.", "get_risk", new { table = t });
        r.Step("Its columns.", "get_inventory", new { phi_only = false, source = "s1" });
        r.Step("The column that matters most for re-identification in combination: the birth date (ages over 89 are counted here).", "get_column", new { column = $"{t} › dob" });
        r.Step("Show it.", "render_view", new { });
        return r.Text("Explain in plain words: direct identifiers (name, SSN, member ID…) name a person on their own; quasi-identifiers (birth date, ZIP code, sex) identify most people in combination; then say what the policy does with each, and what would be left.");
    }

    [McpServerPrompt(Name = "review_free_text", Title = "Review free-text notes")]
    [Description("Looks at what is hidden in free text (clinical notes, comments): the identifiers found in each note, how the scrubbing would replace them, and which notes need a person's eye.")]
    public static string ReviewFreeText(
        [Description("The folder of notes (default \"samples/notes\").")] string? folder = null)
    {
        var f = Pick(folder, "samples/notes");
        var r = new Recipe($"Review the free text in {f}.");
        r.Step("Add the notes and scan them.", "add_source", new { path = f });
        r.Step(null, "scan", new { });
        r.Step("The free-text columns (a text file is one).", "get_inventory", new { kind = "free_text" });
        r.Step("One note's findings, cell by cell.", "get_column", new { column = "note-001.txt › (text)" });
        r.Step("How scrubbing would replace them where they stand.", "preview_deidentification", new { column = "note-001.txt › (text)", max = 3 });
        return r.Text("Summarise what kinds of identifiers the notes hold and how many, and point out that names nobody wrote down anywhere else (a neighbour, a relative) are the likeliest to be missed: suggest the person reads a few scrubbed notes before the copy leaves.");
    }

    [McpServerPrompt(Name = "monthly_deidentification", Title = "A repeatable monthly de-identification")]
    [Description("Keeps the project's set-up (a source folder and the policy) as a steps file with the folder as a parameter, then runs it for this month and makes the copy, so next month is one call.")]
    public static string MonthlyDeidentification(
        [Description("This month's folder (default \"samples\").")] string? folder = null,
        [Description("The output folder (default \"monthly/2026-11\").")] string? output = null)
    {
        var f = Pick(folder, "samples");
        var o = Pick(output, "monthly/2026-11");
        var r = new Recipe($"Set up a monthly de-identification, and run it for {f}.");
        r.Step("Keep the set-up as steps, with the folder as a parameter.", "save_steps", new
        {
            path = "steps/monthly-deidentification",
            overwrite = true,
            description = "Adds a month's folder and sets Safe Harbor with shifted dates",
            steps = new object[]
            {
                new { tool = "add_source", args = new { path = "${folder}" } },
                new { tool = "set_policy", args = new { policy = "safe_harbor", date_mode = "shift" } },
            },
            parameters = new Dictionary<string, string> { ["folder"] = f },
        });
        r.Step("Run it for this month.", "run_steps", new { path = "steps/monthly-deidentification.avasteps.json", values = new Dictionary<string, string> { ["folder"] = f } });
        r.Step("Scan, write the copy with the same key as every month (so tokens match from month to month), and check it.", "scan", new { });
        r.Step(null, "deidentify", new { output = o, key_file = "keys/monthly.key", overwrite = true });
        r.Step(null, "verify", new { output = o });
        return r.Text("Tell the person that next month, run_steps with path \"steps/monthly-deidentification.avasteps.json\" and the new folder, then scan, deidentify and verify, makes the same kind of copy; and that keeping the same key file keeps the same tokens across months, so the months can be joined.");
    }

    private static string Pick(string? given, string fallback) => string.IsNullOrWhiteSpace(given) ? fallback : given.Trim();

    private sealed class Recipe(string intro)
    {
        private readonly StringBuilder _text = new(intro + "\n\nFollow these steps in order. A line starting with \"" + CallMarker.Trim() + "\" is one tool call, with its arguments as JSON. If a step fails, read the error, fix the cause and carry on. Paths and column names in these calls are the sample data's: use the person's own. Every value you see is masked; never ask for raw values.\n");
        private int _number;

        public void Step(string? says, string tool, object args)
        {
            _number++;
            _text.Append('\n').Append(_number).Append('.').Append(says != null ? " " : "");
            if (says != null) _text.Append(says);
            _text.Append("\n   ");
            _text.Append(CallMarker).Append(tool).Append(' ').Append(JsonSerializer.Serialize(args, Json.Options));
        }

        public string Text(string closing) => _text.Append("\n\n").Append(closing).ToString();
    }
}
