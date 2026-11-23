using System.Reflection;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Threading;
using AVAPHIScanner.Agents;
using AVAPHIScanner.Agents.Chat;
using AVAPHIScanner.Agents.Mcp;
using Microsoft.Data.Sqlite;
using ModelContextProtocol.Server;
using static AVAPHIScanner.Tests.Agents.FakeModelServer;

namespace AVAPHIScanner.Tests.Agents;

internal sealed class AvaloniaThread : IUiThread
{
    public Task<T> InvokeAsync<T>(Func<Task<T>> work) => Dispatcher.UIThread.InvokeAsync(work);
}

/// <summary>
/// The MCP server and the AI Chat, driven as agents drive them: through an in-process MCP client over the real server,
/// on Avalonia's headless platform, in a working folder holding a copy of the samples. Every answer any tool gives in
/// these tests is checked for the samples' raw values (<see cref="Rig.Call"/>). The chat's models are scripted fakes of
/// both APIs; no real model, key or database server is used.
/// </summary>
public sealed class AgentTests
{
    /// <summary>Every tool the server offers. A new tool goes here, with descriptions on it and its arguments.</summary>
    internal static readonly string[] ToolNames =
    [
        "get_project", "new_project", "open_project", "save_project", "list_files", "list_connections", "add_connection",
        "add_source", "remove_source", "set_sampling", "scan", "get_inventory", "get_column", "get_risk", "set_classification",
        "clear_classification", "set_policy", "set_column_action", "preview_deidentification", "deidentify", "verify",
        "export_report", "render_view", "undo", "redo", "batch", "get_recording", "save_steps", "run_steps", "checkpoint",
        "diff", "render_checkpoint", "restore_checkpoint",
    ];

    /// <summary>A server on a project of its own, in a temporary working folder holding a copy of the samples.</summary>
    internal sealed class Rig : IDisposable
    {
        private readonly Window _window;

        public HeadlessDesk Desk { get; } = new();
        public string Root { get; } = Samples.WorkingCopy("aps-agent-");
        public ConnectionStore Connections { get; } = new(null);
        public McpToolBridge Bridge { get; }
        public HeadlessSession Session => (HeadlessSession)Desk.Session;
        public List<string> Secrets { get; }
        /// <summary>Every answer the tools gave, for the no-leak checks.</summary>
        public List<string> Answers { get; } = [];

        public Rig(bool scan = false)
        {
            Secrets = Samples.Secrets(Path.Combine(Root, "samples"));
            var stage = new Panel();
            _window = new Window { Width = 20, Height = 20, Content = stage };
            _window.Show();
            Bridge = Wait(McpToolBridge.StartAsync(new ScanHost(new AvaloniaThread(), Desk, new ScanLibrary(stage), Root, Connections)));
            if (scan)
            {
                Ok("add_source", new { path = "samples" });
                Ok("scan");
            }
        }

        /// <summary>Calls a tool, and checks its answer holds none of the samples' raw values.</summary>
        public ToolOutcome Call(string tool, object? args = null)
        {
            var o = Wait(Bridge.CallAsync(tool, JsonSerializer.SerializeToElement(args ?? new { }).EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())), 60);
            Answers.Add(o.Text);
            var leaks = Samples.Leaks(o.Text, Secrets);
            Assert.True(leaks.Count == 0, $"{tool} gave raw values: {string.Join(", ", leaks.Take(5).Select(l => l.Length > 3 ? l[..3] + "…" : l))}");
            return o;
        }

        public JsonElement Ok(string tool, object? args = null)
        {
            var o = Call(tool, args);
            Assert.False(o.IsError, $"{tool} failed: {o.Text}");
            return o.Text.StartsWith('{') ? JsonDocument.Parse(o.Text).RootElement.Clone() : default;
        }

        public string Error(string tool, object? args = null)
        {
            var o = Call(tool, args);
            Assert.True(o.IsError, $"{tool} should have failed: {o.Text}");
            return o.Text;
        }

        /// <summary>A column's id from the scan.</summary>
        public string Id(string display) => Session.Inventory!.Find(display).Id;

        public void Dispose()
        {
            Wait(Bridge.DisposeAsync().AsTask().ContinueWith(_ => true));
            _window.Close();
            SqliteConnection.ClearAllPools();
        }
    }

    internal static T Wait<T>(Task<T> task, int seconds = 30)
    {
        for (var i = 0; i < seconds * 500 && !task.IsCompleted; i++)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(2);
        }
        Assert.True(task.IsCompleted, "It didn't finish in time.");
        Dispatcher.UIThread.RunJobs();
        return task.GetAwaiter().GetResult();
    }

    private static void WithRig(Action<Rig> test, bool scan = false) => HeadlessApp.Run(() =>
    {
        using var rig = new Rig(scan);
        test(rig);
    });

    [Fact]
    public void The_tools_are_the_ones_listed_and_each_says_what_it_and_its_arguments_are() => WithRig(rig =>
    {
        var tools = Wait(rig.Bridge.ListToolsAsync());
        Assert.Equal(ToolNames.Order(), tools.Select(t => t.Name).Order());
        foreach (var t in tools)
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Description), $"{t.Name} has no description");
            if (t.InputSchema.TryGetProperty("properties", out var props))
                foreach (var p in props.EnumerateObject())
                {
                    Assert.True(p.Value.TryGetProperty("description", out _), $"{t.Name}.{p.Name} has no description");
                    Assert.Matches("^[a-z][a-z0-9_]*$", p.Name);
                }
        }
        foreach (var name in ChatTools.Core) Assert.Contains(name, ToolNames);
        Assert.Contains("never see a raw value", rig.Bridge.ServerInstructions);
    });

    [Fact]
    public void An_agent_adds_a_folder_scans_it_and_reads_the_inventory_masked() => WithRig(rig =>
    {
        Assert.Equal(0, rig.Ok("get_project").GetProperty("sources").GetArrayLength());
        Assert.Contains("no sources", rig.Error("scan"));
        var added = rig.Ok("add_source", new { path = "samples" });
        Assert.Equal("s1", added.GetProperty("added").GetString());
        Assert.Equal(18, added.GetProperty("datasets").GetInt32());
        Assert.Contains("no scan yet", rig.Error("get_inventory"));
        var scan = rig.Ok("scan");
        Assert.Equal(18, scan.GetProperty("datasets").GetInt32());
        Assert.Equal("High", scan.GetProperty("risk").GetString());
        Assert.True(scan.GetProperty("by_kind").GetProperty("ssn").GetInt32() >= 1);

        var inv = rig.Ok("get_inventory");
        var ssn = inv.GetProperty("columns").EnumerateArray().First(c => c.GetProperty("where").GetString() == "members.csv › ssn");
        Assert.Equal("ssn", ssn.GetProperty("kind").GetString());
        Assert.Equal("tokenise", ssn.GetProperty("action").GetString());
        Assert.All(ssn.GetProperty("examples").EnumerateArray(), e => Assert.StartsWith("***-**-", e.GetString()));
        Assert.DoesNotContain(inv.GetProperty("columns").EnumerateArray(), c => c.GetProperty("where").GetString()!.EndsWith("› plan"));
        Assert.Contains(rig.Ok("get_inventory", new { phi_only = false }).GetProperty("columns").EnumerateArray(), c => c.GetProperty("where").GetString()!.EndsWith("members.csv › plan"));
        Assert.True(rig.Ok("get_inventory", new { kind = "free_text" }).GetProperty("matching").GetInt32() >= 14);

        var note = rig.Ok("get_column", new { column = "notes/note-001.txt › (text)" });
        Assert.Equal("free_text", note.GetProperty("kind").GetString());
        Assert.True(note.GetProperty("findings").GetArrayLength() > 5);
        Assert.Contains(note.GetProperty("findings").EnumerateArray(), f => f.GetProperty("kind").GetString() == "name");
        var dob = rig.Ok("get_column", new { column = rig.Id("members.csv › dob") });
        Assert.Equal(3, dob.GetProperty("over_89").GetInt32());

        var risk = rig.Ok("get_risk", new { table = "members.csv" });
        Assert.Equal("High", risk.GetProperty("tables")[0].GetProperty("risk").GetString());
        Assert.Contains("more than one column", rig.Error("get_column", new { column = "member_id" }));
    });

    [Fact]
    public void Decisions_and_policy_are_undo_steps_and_survive_a_rescan() => WithRig(rig =>
    {
        var plan = rig.Id("members.csv › plan");
        var set = rig.Ok("set_classification", new { column = plan, is_phi = true, kind = "other_id", note = "plan codes identify people here" });
        Assert.Equal("other_id", set.GetProperty("kind").GetString());
        Assert.Equal("tokenise", set.GetProperty("action").GetString());
        Assert.Contains("is_phi false", rig.Error("set_classification", new { column = plan, is_phi = true, kind = "none" }));
        var provider = rig.Id("claims.xlsx › Providers › provider_name");
        Assert.Equal("none", rig.Ok("set_classification", new { column = provider, is_phi = false }).GetProperty("kind").GetString());
        rig.Ok("scan");
        Assert.Equal("other_id", rig.Ok("get_column", new { column = plan }).GetProperty("kind").GetString());
        Assert.Equal(2, rig.Ok("get_project").GetProperty("decisions").GetArrayLength());

        rig.Ok("set_policy", new { policy = "limited_data_set" });
        Assert.Equal("keep", rig.Ok("get_column", new { column = rig.Id("members.csv › zip") }).GetProperty("action").GetString());
        rig.Ok("set_policy", new { policy = "safe_harbor", date_mode = "year" });
        Assert.Equal("generalise", rig.Ok("get_column", new { column = rig.Id("members.csv › dob") }).GetProperty("action").GetString());
        var act = rig.Ok("set_column_action", new { column = rig.Id("members.csv › city"), action = "keep" });
        Assert.Equal("keep", act.GetProperty("action").GetString());
        Assert.StartsWith("Custom", act.GetProperty("policy").GetString());
        Assert.Contains("direct identifier", rig.Ok("set_column_action", new { column = rig.Id("members.csv › email"), action = "keep" }).GetProperty("warning").GetString());
        Assert.Equal("redact", rig.Ok("set_column_action", new { column = rig.Id("members.csv › email"), action = "default" }).GetProperty("action").GetString());
        Assert.Contains("isn't an action", rig.Error("set_column_action", new { column = rig.Id("members.csv › email"), action = "obliterate" }));

        Assert.Equal("AI: set a column's action", rig.Session.History.UndoLabel);
        rig.Ok("undo");
        Assert.Equal("keep", rig.Ok("get_column", new { column = rig.Id("members.csv › email") }).GetProperty("action").GetString());
        rig.Ok("undo");
        Assert.Equal("redact", rig.Ok("get_column", new { column = rig.Id("members.csv › email") }).GetProperty("action").GetString());
        rig.Ok("redo");
        Assert.Equal("keep", rig.Ok("get_column", new { column = rig.Id("members.csv › email") }).GetProperty("action").GetString());
        rig.Ok("clear_classification", new { column = plan });
        Assert.Contains("no decision", rig.Error("clear_classification", new { column = plan }));
        rig.Ok("set_sampling", new { rows = 50 });
        Assert.Equal(50, rig.Session.Document.SampleRows);
        Assert.Contains("10 to", rig.Error("set_sampling", new { rows = 1 }));
    }, scan: true);

    [Fact]
    public void Previews_show_values_before_masked_and_after_as_stand_ins() => WithRig(rig =>
    {
        var names = rig.Ok("preview_deidentification", new { column = rig.Id("members.csv › last_name"), max = 3 });
        Assert.Equal("pseudonymise", names.GetProperty("action").GetString());
        Assert.Contains("throwaway", names.GetProperty("key").GetString());
        foreach (var s in names.GetProperty("samples").EnumerateArray())
        {
            Assert.Contains("*", s.GetProperty("before").GetString());
            Assert.Contains(s.GetProperty("after").GetString()!.ToUpperInvariant(), Lists.PseudoWords);
        }
        var ids = rig.Ok("preview_deidentification", new { column = rig.Id("members.csv › member_id") });
        Assert.All(ids.GetProperty("samples").EnumerateArray(), s => Assert.Matches(@"^ID-[A-Z2-7]{10}$", s.GetProperty("after").GetString()));
        var dates = rig.Ok("preview_deidentification", new { column = rig.Id("members.csv › dob") });
        Assert.All(dates.GetProperty("samples").EnumerateArray(), s => Assert.Matches(@"^\d{4}-\*\*-\*\*", s.GetProperty("after").GetString()));
        var text = rig.Ok("preview_deidentification", new { column = "notes/note-001.txt › (text)", max = 3 });
        Assert.Contains(text.GetProperty("samples").EnumerateArray(), s => s.GetProperty("after").GetString()!.Contains("ID-"));
    }, scan: true);

    [Fact]
    public void A_copy_is_made_with_a_kept_key_and_verified_clean() => WithRig(rig =>
    {
        Assert.Contains("must not be inside the output folder", rig.Error("deidentify", new { output = "copy", key_file = "copy/k.key" }));
        Assert.Contains("inside a source folder", rig.Error("deidentify", new { output = "samples/copy" }));
        Assert.Contains("no key file", rig.Error("deidentify", new { output = "copy", key_file = "none.key", create_key = false }));
        var made = rig.Ok("deidentify", new { output = "copy", key_file = "keys/k.key" });
        Assert.Contains("new key", made.GetProperty("key").GetString());
        Assert.True(made.GetProperty("replaced").GetProperty("name").GetInt32() > 0);
        var key = File.ReadAllText(Path.Combine(rig.Root, "keys", "k.key")).Trim();
        Assert.DoesNotContain(rig.Answers, a => a.Contains(key));
        var v = rig.Ok("verify");
        Assert.True(v.GetProperty("clean").GetBoolean(), v.ToString());
        Assert.Contains(v.GetProperty("before_after").EnumerateArray(), x => x.GetProperty("kind").GetString() == "ssn" && x.GetProperty("left").GetInt32() == 0);
        // Verifying the sources themselves finds everything, masked.
        var raw = rig.Ok("verify", new { output = "samples" });
        Assert.False(raw.GetProperty("clean").GetBoolean());
        Assert.True(raw.GetProperty("originals_found").GetInt32() > 100);
        Assert.Equal(Path.Combine(rig.Root, "copy"), rig.Session.Document.Output);
        Assert.Contains("already has files", rig.Error("deidentify"));
        rig.Ok("deidentify", new { overwrite = true });
        rig.Ok("export_report", new { path = "reports/scan.xlsx" });
        rig.Ok("export_report", new { path = "reports/scan.html" });
        Assert.Contains("is one of", rig.Error("export_report", new { path = "reports/scan.pdf" }));
        Assert.Contains("Verification", File.ReadAllText(Path.Combine(rig.Root, "reports", "scan.html")));
    }, scan: true);

    [Fact]
    public void The_inventory_is_drawn_for_the_agent() => WithRig(rig =>
    {
        var before = rig.Call("render_view");
        Assert.False(before.IsError, before.Text);
        Assert.Single(before.Images);
        Assert.Contains("no scan", before.Text);
        rig.Ok("add_source", new { path = "samples" });
        rig.Ok("scan");
        var picture = rig.Call("render_view", new { scale = 0.5 });
        Assert.Equal("image/png", picture.Images[0].MediaType);
        Assert.True(picture.Images[0].Data.Length > 2000);
        Assert.Contains("risk High", picture.Text);
    });

    [Fact]
    public void Projects_save_open_and_start_new() => WithRig(rig =>
    {
        Assert.Contains("discard_changes", rig.Error("new_project"));
        rig.Ok("save_project", new { path = "projects/vendor" });
        Assert.True(File.Exists(Path.Combine(rig.Root, "projects", "vendor.phiscan")));
        Assert.Contains("\"path\": \"../samples\"", File.ReadAllText(Path.Combine(rig.Root, "projects", "vendor.phiscan")));
        rig.Ok("new_project");
        Assert.Empty(rig.Session.Document.Sources);
        rig.Ok("open_project", new { path = "projects/vendor.phiscan" });
        Assert.Equal(Path.Combine(rig.Root, "samples"), rig.Session.Document.Sources[0].Path);
        Assert.Null(rig.Session.Inventory);
        Assert.Contains("outside the working folder", rig.Error("open_project", new { path = "../../etc/x.phiscan" }));
    }, scan: true);

    [Fact]
    public void Files_whose_names_may_be_names_are_listed_masked_with_a_reference() => WithRig(rig =>
    {
        Directory.CreateDirectory(Path.Combine(rig.Root, "intake"));
        File.Copy(Path.Combine(rig.Root, "samples", "members.csv"), Path.Combine(rig.Root, "intake", "maria_lopez_records.csv"));
        var files = rig.Ok("list_files", new { folder = "intake" });
        var f = files.GetProperty("files")[0];
        Assert.Equal("intake/m****_l****_records.csv", f.GetProperty("path").GetString());
        var reference = f.GetProperty("ref").GetString()!;
        Assert.Equal("intake", rig.Ok("list_files").GetProperty("folders").EnumerateArray().Select(x => x.GetString()).First(x => x == "intake"));
        rig.Ok("add_source", new { path = reference });
        rig.Ok("scan");
        Assert.Contains("m****_l****_records.csv", rig.Ok("get_inventory").GetProperty("columns")[0].GetProperty("where").GetString());
        Assert.DoesNotContain(rig.Answers, a => a.Contains("lopez", StringComparison.OrdinalIgnoreCase));
        File.WriteAllText(Path.Combine(rig.Root, "intake", "scan.pdf"), "x");
        Assert.Contains("isn't a kind of file", rig.Error("add_source", new { path = "intake/scan.pdf" }));
        Assert.Contains("There's no", rig.Error("add_source", new { path = "intake/missing.csv" }));
    });

    [Fact]
    public void Databases_come_in_by_name_or_file_and_passwords_never_show() => WithRig(rig =>
    {
        var db = Path.Combine(rig.Root, "samples", "clinic.db");
        rig.Ok("add_connection", new { name = "clinic", engine = "sqlite", connection_string = $"Data Source={db};Pooling=False" });
        var list = rig.Ok("list_connections");
        Assert.Equal("clinic", list.GetProperty("saved")[0].GetProperty("name").GetString());
        rig.Ok("add_source", new { connection_name = "clinic", tables = new[] { "patients" } });
        rig.Ok("add_source", new { sqlite_file = "samples/clinic.db", tables = new[] { "visits" } });
        Assert.Contains("None of those tables", rig.Error("add_source", new { sqlite_file = "samples/clinic.db", tables = new[] { "nothing" } }));
        Assert.Contains("one of path", rig.Error("add_source", new { path = "samples", sqlite_file = "samples/clinic.db" }));
        var scan = rig.Ok("scan");
        Assert.Equal(2, scan.GetProperty("datasets").GetInt32());
        Assert.DoesNotContain("secret", ConnectionStore.Redact("Server=db1;Database=x;User ID=u;Password=secret"));
        rig.Ok("set_policy", new { database_output = "sqlite" });
        rig.Ok("deidentify", new { output = "dbcopy" });
        Assert.True(File.Exists(Path.Combine(rig.Root, "dbcopy", "s1-clinic.sqlite")));
        Assert.True(File.Exists(Path.Combine(rig.Root, "dbcopy", "s2-clinic.sqlite")));
        Assert.True(rig.Ok("verify").GetProperty("clean").GetBoolean());
        rig.Ok("remove_source", new { id = "s2" });
        Assert.Single(rig.Session.Document.Sources);
        Assert.Contains("no source", rig.Error("remove_source", new { id = "s9" }));
    });

    [Fact]
    public void Batches_are_one_step_or_nothing_and_checkpoints_compare_and_restore() => WithRig(rig =>
    {
        rig.Ok("checkpoint", new { name = "start" });
        var depth = rig.Session.History.Index;
        var dry = rig.Ok("batch", new
        {
            dry_run = true,
            steps = new object[]
            {
                new { tool = "set_policy", args = new { policy = "limited_data_set" } },
                new { tool = "set_classification", args = new { column = rig.Id("members.csv › plan"), is_phi = true, kind = "other_id" } },
            },
        });
        Assert.True(dry.GetProperty("would_change").GetProperty("changed").GetBoolean());
        Assert.Equal(depth, rig.Session.History.Index);
        rig.Ok("batch", new
        {
            steps = new object[]
            {
                new { tool = "set_policy", args = new { policy = "limited_data_set" } },
                new { tool = "set_classification", args = new { column = rig.Id("members.csv › plan"), is_phi = true, kind = "other_id" } },
            },
        });
        Assert.Equal(depth + 1, rig.Session.History.Index);
        var failed = rig.Error("batch", new
        {
            steps = new object[]
            {
                new { tool = "set_policy", args = new { policy = "safe_harbor" } },
                new { tool = "set_classification", args = new { column = "c9999", is_phi = true } },
            },
        });
        Assert.Contains("Step 2", failed);
        Assert.Equal(PolicyKind.LimitedDataSet, rig.Session.Document.Policy.Kind);
        Assert.Contains("can't be in a batch", rig.Error("batch", new { steps = new object[] { new { tool = "scan" } } }));

        var diff = rig.Ok("diff", new { since = "start" });
        Assert.True(diff.GetProperty("changed").GetBoolean());
        Assert.Contains(diff.GetProperty("added").EnumerateArray(), x => x.GetString()!.Contains("members.csv › plan"));
        Assert.Contains("Limited", diff.GetProperty("policy_now").GetString());
        var pic = rig.Call("render_checkpoint", new { name = "start", width = 300, height = 200 });
        Assert.False(pic.IsError, pic.Text);
        Assert.Single(pic.Images);
        Assert.True(rig.Ok("restore_checkpoint", new { name = "start" }).GetProperty("changed").GetBoolean());
        Assert.Equal(PolicyKind.SafeHarbor, rig.Session.Document.Policy.Kind);
        Assert.Empty(rig.Session.Document.Overrides);
        rig.Ok("undo");
        Assert.Equal(PolicyKind.LimitedDataSet, rig.Session.Document.Policy.Kind);
        Assert.Equal(2, rig.Ok("checkpoint").GetProperty("checkpoints").GetArrayLength() + 1);
    }, scan: true);

    [Fact]
    public void Steps_files_run_again_with_other_values() => WithRig(rig =>
    {
        rig.Ok("set_policy", new { policy = "limited_data_set" });
        var recording = rig.Ok("get_recording");
        Assert.Contains(recording.GetProperty("steps").EnumerateArray(), s => s.GetProperty("tool").GetString() == "add_source");
        rig.Ok("save_steps", new
        {
            path = "steps/setup",
            steps = new object[] { new { tool = "add_source", args = new { path = "${folder}" } }, new { tool = "set_policy", args = new { policy = "${policy}" } } },
            parameters = new Dictionary<string, string> { ["folder"] = "samples/notes", ["policy"] = "safe_harbor" },
        });
        Assert.Contains("Give a default", rig.Error("save_steps", new { path = "steps/bad", steps = new object[] { new { tool = "add_source", args = new { path = "${x}" } } } }));
        rig.Ok("run_steps", new { path = "steps/setup.avasteps.json", values = new Dictionary<string, string> { ["policy"] = "custom" } });
        Assert.Equal(2, rig.Session.Document.Sources.Count);
        Assert.Equal(PolicyKind.Custom, rig.Session.Document.Policy.Kind);
        Assert.Contains("has no parameter", rig.Error("run_steps", new { path = "steps/setup.avasteps.json", values = new Dictionary<string, string> { ["nope"] = "x" } }));
    }, scan: true);

    [Fact]
    public void Every_recipe_runs_call_by_call() => HeadlessApp.Run(() =>
    {
        var recipes = typeof(Recipes).GetMethods(BindingFlags.Public | BindingFlags.Static).Where(m => m.GetCustomAttribute<McpServerPromptAttribute>() != null).ToList();
        Assert.Equal(8, recipes.Count);
        foreach (var recipe in recipes)
        {
            using var rig = new Rig();
            // check_export_is_clean checks an export made earlier.
            rig.Ok("add_source", new { path = "samples" });
            rig.Ok("scan");
            rig.Ok("deidentify", new { output = "vendor-extract", key_file = "keys/vendor.key" });
            rig.Ok("new_project", new { discard_changes = true });
            var text = (string)recipe.Invoke(null, recipe.GetParameters().Select(_ => (object?)null).ToArray())!;
            var calls = text.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith(Recipes.CallMarker, StringComparison.Ordinal)).ToList();
            Assert.NotEmpty(calls);
            foreach (var call in calls)
            {
                var rest = call[Recipes.CallMarker.Length..];
                var space = rest.IndexOf(' ');
                var tool = rest[..space];
                var args = JsonDocument.Parse(rest[(space + 1)..]).RootElement;
                var outcome = Wait(rig.Bridge.CallAsync(tool, args.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())), 60);
                Assert.False(outcome.IsError, $"{recipe.Name}: {tool} failed: {outcome.Text}");
                Assert.Empty(Samples.Leaks(outcome.Text, rig.Secrets));
                if (tool == "verify") Assert.True(JsonDocument.Parse(outcome.Text).RootElement.GetProperty("clean").GetBoolean(), $"{recipe.Name}: {outcome.Text}");
            }
        }
    });

    /// <summary>
    /// The strictest rule: no tool, recipe or chat ever hands an agent a raw value. Every tool is called over the samples
    /// (and the copy), with the arguments that reach the most data, and every answer and the chat's whole transcript
    /// are searched for the samples' names, SSNs, MRNs, member IDs, phone numbers, emails, street addresses and birth dates.
    /// </summary>
    [Fact]
    public void No_tool_recipe_or_chat_ever_gives_an_agent_a_raw_value() => WithRig(rig =>
    {
        var called = new HashSet<string>();
        ToolOutcome Use(string tool, object? args = null)
        {
            called.Add(tool);
            return rig.Call(tool, args);   // Call checks the answer for raw values.
        }
        Use("get_project");
        Use("list_files", new { recursive = true });
        Use("list_connections");
        Use("add_connection", new { name = "clinic", engine = "sqlite", connection_string = $"Data Source={Path.Combine(rig.Root, "samples", "clinic.db")}" });
        Use("add_source", new { path = "samples" });
        Use("set_sampling", new { rows = 100000 });
        Use("scan");
        Use("get_inventory", new { phi_only = false, max = 500 });
        Use("get_risk");
        foreach (var c in rig.Session.Inventory!.Columns)
        {
            Use("get_column", new { column = c.Id, max_findings = 200 });
            Use("preview_deidentification", new { column = c.Id, max = 20 });
        }
        Use("set_classification", new { column = rig.Id("members.csv › last_name"), is_phi = false });
        Use("clear_classification", new { column = rig.Id("members.csv › last_name") });
        Use("set_policy", new { policy = "safe_harbor" });
        Use("set_column_action", new { column = rig.Id("members.csv › city"), action = "keep" });
        Use("checkpoint", new { name = "a" });
        Use("diff", new { since = "a" });
        Use("render_checkpoint", new { name = "a" });
        Use("restore_checkpoint", new { name = "a" });
        Use("batch", new { steps = new object[] { new { tool = "get_inventory", args = new { phi_only = false } } } });
        Use("get_recording");
        Use("save_steps", new { path = "steps/s" });
        Use("run_steps", new { path = "steps/s.avasteps.json", dry_run = true });
        Use("undo");
        Use("redo");
        Use("deidentify", new { output = "copy" });
        Use("verify");
        Use("verify", new { output = "samples" });   // the raw sources: everything is left, and all of it masked
        Use("export_report", new { path = "r.html" });
        Use("render_view");
        Use("save_project", new { path = "p" });
        Use("open_project", new { path = "p.phiscan" });
        Use("remove_source", new { id = "s1" });
        Use("new_project", new { discard_changes = true });
        Assert.Equal(ToolNames.Order(), called.Order());

        // The report the agent wrote is masked too (agents can't read files, but the person may share it).
        Assert.Empty(Samples.Leaks(File.ReadAllText(Path.Combine(rig.Root, "r.html")), rig.Secrets));

        // A chat that reads everything it can: its transcript (what the model saw and said) has no raw value in it.
        rig.Ok("add_source", new { path = "samples" });
        rig.Ok("scan");
        var server = new FakeModelServer("http://localhost:1234/v1")
            .Reply(Call("c1", "get_inventory", new { phi_only = false }))
            .Reply(Call("c2", "get_column", new { column = "notes/note-003.txt › (text)", max_findings = 200 }), Call("c3", "preview_deidentification", new { column = "feed.jsonl › comment", max = 20 }))
            .Reply(Call("c4", "verify", new { output = "samples" }))
            .Reply(Say("Done."));
        var chat = new ChatSession(rig.Bridge) { Provider = ChatProvider.OpenAICompatible, Server = server.Client(), ServerModel = "qwen3" };
        Wait(chat.SendAsync("Show me everything you can about the members.").ContinueWith(t => { t.GetAwaiter().GetResult(); return true; }), 60);
        Assert.All(chat.Entries.OfType<ToolEntry>(), t => Assert.False(t.IsError, t.Result));
        var transcript = ChatMarkdown.Write(chat.ToStored(_ => null));
        Assert.Contains("get_column", transcript);
        Assert.Empty(Samples.Leaks(transcript, rig.Secrets));
        // And what was sent to the model, request by request.
        foreach (var request in server.Requests) Assert.Empty(Samples.Leaks(request.ToJsonString(), rig.Secrets));

        // Every recipe's text too.
        foreach (var recipe in typeof(Recipes).GetMethods(BindingFlags.Public | BindingFlags.Static).Where(m => m.GetCustomAttribute<McpServerPromptAttribute>() != null))
            Assert.Empty(Samples.Leaks((string)recipe.Invoke(null, recipe.GetParameters().Select(_ => (object?)null).ToArray())!, rig.Secrets));
    });

    [Fact]
    public void The_guard_masks_a_raw_value_even_if_a_tool_let_one_slip()
    {
        var guard = new SensitiveValues();
        guard.Add(PhiKind.Name, "Maria Lopez");
        guard.Add(PhiKind.MemberId, "M10001");
        guard.Add(PhiKind.StreetAddress, "591 Chestnut St");
        var text = guard.Redact("{\"x\": \"Maria Lopez of 591 Chestnut St, member M10001, ssn 512-44-1093, mail maria.lopez@example.com, (217) 555-0100, born 1958-07-12\"}");
        foreach (var raw in new[] { "Maria", "Lopez", "591 Chestnut", "M10001", "512-44-1093", "maria.lopez@", "555-0100", "1958-07-12" })
            Assert.DoesNotContain(raw, text);
        Assert.Contains("1958-**-**", text);
        var result = ScanServer.Guard(new ModelContextProtocol.Protocol.CallToolResult { Content = [new ModelContextProtocol.Protocol.TextContentBlock { Text = "Lopez" }] }, guard);
        Assert.Equal("L****", ((ModelContextProtocol.Protocol.TextContentBlock)result.Content[0]).Text);
    }

    // ───────────────────────────── the chat ─────────────────────────────

    [Fact]
    public void A_chat_on_a_local_openai_compatible_model_scans_and_its_reply_can_be_undone() => WithRig(rig =>
    {
        var server = new FakeModelServer("http://localhost:1234/v1")
            .Reply(Say("I'll add the samples folder and scan it."), Call("c1", "add_source", new { path = "samples" }))
            .Reply(Call("c2", "scan", new { }))
            .Reply(Call("c3", "set_policy", new { policy = "limited_data_set" }))
            .Reply(Say("Done: 18 datasets scanned, risk High."));
        var chat = new ChatSession(rig.Bridge) { Provider = ChatProvider.OpenAICompatible, Server = server.Client(), ServerModel = "qwen/qwen3-8b" };
        Wait(chat.SendAsync("find the PHI in samples").ContinueWith(t => { t.GetAwaiter().GetResult(); return true; }), 60);

        Assert.Equal(["add_source", "scan", "set_policy"], chat.Entries.OfType<ToolEntry>().Select(t => t.Name));
        Assert.All(chat.Entries.OfType<ToolEntry>(), t => Assert.False(t.IsError, t.Result));
        Assert.Contains("AVA PHI Scanner", (string?)server.Requests[0]["messages"]![0]!["content"]);
        Assert.Contains("never see a raw value", (string?)server.Requests[0]["messages"]![0]!["content"]);
        Assert.NotNull(rig.Session.Inventory);

        var undo = Assert.Single(chat.Entries.OfType<ReplyUndoEntry>());
        Assert.Contains("+1 item", undo.Summary);
        Assert.True(Wait(chat.UndoReplyAsync(undo)));
        Assert.Empty(rig.Session.Document.Sources);
        Assert.Equal(PolicyKind.SafeHarbor, rig.Session.Document.Policy.Kind);
    });

    [Fact]
    public void A_chat_on_a_local_server_that_speaks_the_messages_api_uses_the_core_tools() => WithRig(rig =>
    {
        var claude = new FakeMessagesServer()
            .Reply(new FakeMessagesServer.ToolUse("t1", "get_inventory", new { kind = "ssn" }))
            .Reply(new FakeMessagesServer.Words("One SSN column, in members.csv."));
        var client = new Anthropic.AnthropicClient { ApiKey = "local", BaseUrl = "http://localhost:1234", HttpClient = new HttpClient(claude) };
        var chat = new ChatSession(rig.Bridge) { Provider = ChatProvider.Anthropic, Client = client, Model = "qwen/qwen3-8b", ClaudeServer = "localhost:1234", ClaudeCoreToolsOnly = true, ClaudeSeesPictures = false };
        Wait(chat.SendAsync("where are the SSNs?").ContinueWith(t => { t.GetAwaiter().GetResult(); return true; }), 60);

        Assert.Equal("http://localhost:1234/v1/messages", claude.Urls[0]);
        Assert.Equal("qwen/qwen3-8b", (string?)claude.Requests[0]["model"]);
        var offered = claude.Requests[0]["tools"]!.AsArray().Select(t => (string?)t!["name"]).ToList();
        Assert.Equal(ChatTools.Core.Order(), offered.Order());
        Assert.Contains("core set", (string?)claude.Requests[0]["system"]![0]!["text"]);
        var result = Assert.Single(chat.Entries.OfType<ToolEntry>());
        Assert.False(result.IsError, result.Result);
        Assert.Contains("members.csv › ssn", result.Result);
        Assert.Empty(Samples.Leaks(string.Join("\n", claude.Requests.Select(r => r.ToJsonString())), rig.Secrets));
        Assert.Equal("The model", chat.Who);
        Assert.Null(chat.Price);
    }, scan: true);
}
