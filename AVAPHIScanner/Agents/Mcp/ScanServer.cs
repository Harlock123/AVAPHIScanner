using System.Net.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AVAPHIScanner.Agents.Mcp;

/// <summary>
/// The MCP server: <see cref="ScanTools"/>' methods as MCP tools (the SDK's attribute model, read by reflection),
/// with instructions that tell an agent AVA PHI Scanner's conventions, and a filter that checks every answer for
/// sensitive values before it leaves (<see cref="Guard"/>). The same server runs over stdio headless, over a
/// pipe for agents attached to the open window, and in-process for the program's own AI Chat.
/// </summary>
public static class ScanServer
{
    public const string Name = "AVAPHIScanner";

    /// <summary>What every agent is told on connecting: the conventions the tools' descriptions build on.</summary>
    public const string Instructions = """
        AVA PHI Scanner finds protected health information (PHI) and other personal data in files and databases, reports where it is, and writes a de-identified copy in which joins and totals still work. It reads CSV and TSV files, Excel workbooks (every sheet), JSON and JSON lines, plain text (clinical notes) and folders of them, and tables in SQL Server, PostgreSQL and SQLite. It looks for HIPAA Safe Harbor's 18 identifiers (names, addresses, dates, ages over 89, phone and fax numbers, email, SSNs, medical record, member, account and claim numbers, licences, vehicle and device identifiers, URLs, IP addresses, biometrics and photos) and provider NPIs, both column by column and inside free text.

        Conventions (they matter):
        - You never see a raw value, and no setting changes that. Every value you are given is masked: names to initials ("J*** S****"), identifiers to their last characters ("***-**-1234", "****01"), dates to their year ("1957-**-**"), values that aren't PHI to their shape ("999.99"), free text with its identifiers and every unusual word masked. Don't ask the person to paste values; work from kinds, counts, confidence and masked examples, and ask the person what they see when it matters.
        - A project holds sources (files, folders, databases: add_source), the person's decisions about columns (set_classification), and the de-identification policy (set_policy, set_column_action). Every call that changes the project is one undo step (undo takes it back; in the program Ctrl+Z does too), and a call that fails changes nothing.
        - scan reads every source (the first sample_rows rows of each table) and classifies each column: get_inventory lists them with ids (c1, c2…), kinds, confidence, counts and masked examples; get_column explains one, with the identifiers found inside free text, cell by cell; get_risk summarises each table's risk. Tools take a column by its id.
        - Kinds: name, street_address, city, zip, birth_date, date, age, phone, fax, email, ssn, mrn, member_id, account_number, claim_number, license, vehicle_id, device_id, url, ip_address, biometric, other_id, npi (a provider's, kept), free_text, none.
        - Policies: safe_harbor (names to made-up names; identifiers to keyed tokens ID-XXXXXXXXXX, the same value always the same token, so joins still work; dates to the year only (the default, Safe Harbor's own rule), or with date_mode shift moved by a per-person number of days so intervals stay true; ZIP codes to three digits, 000 for small areas; ages over 89 to 90+; contact details redacted; free text scrubbed in place), limited_data_set (keeps dates, city, state, ZIP codes and ages), and custom (safe_harbor with your own action for chosen columns: keep, drop, pseudonymise, tokenise, shift_date, generalise, redact, scrub_text). Amounts and clinical values are never changed, so totals still balance.
        - Sources are only read. deidentify writes a copy into a folder of its own (never inside a source folder), with a key file the person keeps: never ask for the key or put it where the copy goes. verify re-scans the copy and reports anything left, with a before/after summary.
        - Detection is an aid, not a guarantee: say so when you report, point to low-confidence columns for the person to check, and remember that Safe Harbor also requires that no one has actual knowledge the rest could identify someone.

        A good way to work: get_project; add_source (list_files shows the working folder); scan; get_risk and get_inventory; get_column on doubtful or free-text columns; set_classification where the scan is wrong (ask the person when unsure); set_policy; preview_deidentification on a few columns; deidentify; verify; export_report (.xlsx or .html); render_view to show the inventory. batch runs several changes as one undo step (dry_run to preview), and save_steps keeps a sequence as a steps file with ${parameters} that run_steps runs again.

        The server's prompts are saved recipes (find the PHI in a folder, inventory a database, de-identify for a vendor, make a limited data set for research, check that an export is clean, explain the risk in a table, review free-text notes, set up a repeatable monthly de-identification): step-by-step plans with the exact tool calls, to follow or adapt.
        """;

    /// <summary>The MCP tools, bound to a host.</summary>
    public static IEnumerable<McpServerTool> Tools(IScanHost host) => Tools(new ScanTools(host));

    /// <summary>The MCP tools of one set of handlers (one session's: its checkpoints and its recording).</summary>
    public static IEnumerable<McpServerTool> Tools(ScanTools target)
    {
        foreach (var method in typeof(ScanTools).GetMethods(BindingFlags.Public | BindingFlags.Instance))
            if (method.GetCustomAttribute<McpServerToolAttribute>() != null)
                yield return McpServerTool.Create(method, target);
    }

    /// <summary>The saved recipes (<see cref="Recipes"/>) as MCP prompts.</summary>
    public static IEnumerable<McpServerPrompt> Prompts() =>
        typeof(Recipes).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.GetCustomAttribute<McpServerPromptAttribute>() != null)
            .Select(m => McpServerPrompt.Create(m, target: null));

    /// <summary>The tools' MCP definitions (names, descriptions, input schemas), without a host to run them.</summary>
    public static IList<Tool> Definitions() => [.. _definitions.Value];

    private static readonly Lazy<Tool[]> _definitions = new(() => Tools(new NoHost()).Select(t => t.ProtocolTool).ToArray());

    public static Implementation Info => new()
    {
        Name = Name,
        Title = "AVA PHI Scanner",
        Version = typeof(ScanServer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "1.0",
    };

    public static McpServerOptions Options(IScanHost host) => Configure(new McpServerOptions(), host);

    /// <summary>Fills a new session's options (ones the network door's HTTP handler made) as <see cref="Options"/> makes them.</summary>
    public static McpServerOptions Configure(McpServerOptions options, IScanHost host)
    {
        options.ServerInfo = Info;
        options.ServerInstructions = Instructions;
        options.ToolCollection = [];
        var target = new ScanTools(host);
        options.Filters.Request.CallToolFilters.Add(next => async (request, cancel) =>
        {
            // The last guard: whatever a tool answers (and whatever an error says) is checked for the values scans have
            // seen, and for anything shaped like an SSN, email address, phone number or full date, before it leaves.
            CallToolResult result;
            var tool = request.Params is { } p && options.ToolCollection.TryGetPrimitive(p.Name, out var t) ? t.ProtocolTool : null;
            if (tool != null && Arguments.Check(tool, request.Params!.Arguments) is { } problem) result = Arguments.Error(problem);
            else
            {
                try
                {
                    result = await next(request, cancel).ConfigureAwait(false);
                    // The session's changes, as steps save_steps can keep: every call that worked and may change something.
                    if (tool != null && result.IsError != true && tool.Annotations?.ReadOnlyHint != true)
                        target.Record(tool.Name, request.Params!.Arguments);
                }
                catch (McpException e)
                {
                    result = Arguments.Error(e.Message);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    // The SDK couldn't bind the arguments to the handler (a value of the wrong kind): say which, not just that it failed.
                    result = Arguments.Error(tool != null ? $"{tool.Name}: {Scanner.Safe(e)} Check the arguments against the tool's input schema." : Scanner.Safe(e));
                }
            }
            return Guard(result, host.Guard);
        });
        foreach (var tool in Tools(target)) options.ToolCollection.Add(tool);
        options.PromptCollection = [];
        foreach (var prompt in Prompts()) options.PromptCollection.Add(prompt);
        return options;
    }

    /// <summary>Every text block of <paramref name="result"/> through <see cref="SensitiveValues.Redact"/>.</summary>
    public static CallToolResult Guard(CallToolResult result, SensitiveValues guard)
    {
        foreach (var block in result.Content.OfType<TextContentBlock>()) block.Text = guard.Redact(block.Text);
        return result;
    }

    /// <summary>Serves one MCP session over a transport until the client goes away or <paramref name="cancel"/> fires.</summary>
    public static async Task RunAsync(ITransport transport, IScanHost host, CancellationToken cancel = default)
    {
        await using var server = McpServer.Create(transport, Options(host));
        await server.RunAsync(cancel).ConfigureAwait(false);
    }

    /// <summary>Checks a call's arguments against its tool's input schema before the SDK binds them.</summary>
    internal static class Arguments
    {
        public static CallToolResult Error(string message) => new() { IsError = true, Content = [new TextContentBlock { Text = message }] };

        /// <summary>What's wrong with the arguments (a name the tool doesn't take, a value of the wrong kind), or null.</summary>
        public static string? Check(Tool tool, IDictionary<string, JsonElement>? args)
        {
            if (!tool.InputSchema.TryGetProperty("properties", out var props)) return null;
            // A required argument that's missing: say which, and what it is (the SDK's own words are about dictionaries).
            if (tool.InputSchema.TryGetProperty("required", out var required) && required.ValueKind == JsonValueKind.Array)
            {
                var missing = required.EnumerateArray().Select(r => r.GetString() ?? "").Where(r => r.Length > 0 && args?.ContainsKey(r) != true).ToList();
                if (missing.Count > 0)
                    return $"{tool.Name} needs {string.Join(" and ", missing)}: " + string.Join(" ", missing.Select(m =>
                        props.TryGetProperty(m, out var p) && p.TryGetProperty("description", out var d) ? $"{m} is {d.GetString()?.TrimEnd('.')}." : $"{m}."));
            }
            if (args == null) return null;
            foreach (var (name, value) in args)
            {
                if (!props.TryGetProperty(name, out var schema))
                {
                    var names = props.EnumerateObject().Select(x => x.Name).ToList();
                    return $"{tool.Name} has no argument \"{name}\". It takes: {(names.Count == 0 ? "none" : string.Join(", ", names))}.";
                }
                if (Kinds(schema) is { Count: > 0 } kinds && !kinds.Any(k => Fits(k, value)))
                    return $"{tool.Name}: {name} must be {string.Join(" or ", kinds.Where(k => k != "null").Select(Describe))}, not {Describe(value)}.";
            }
            return null;
        }

        private static List<string> Kinds(JsonElement schema) =>
            schema.ValueKind != JsonValueKind.Object || !schema.TryGetProperty("type", out var type) ? []
            : type.ValueKind == JsonValueKind.String ? [type.GetString()!]
            : type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(x => x.GetString() ?? "").ToList() : [];

        private static bool Fits(string kind, JsonElement v) => kind switch
        {
            "string" => v.ValueKind == JsonValueKind.String,
            "number" => v.ValueKind == JsonValueKind.Number,
            "integer" => v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out _),
            "boolean" => v.ValueKind is JsonValueKind.True or JsonValueKind.False,
            "array" => v.ValueKind == JsonValueKind.Array,
            "object" => v.ValueKind == JsonValueKind.Object,
            "null" => v.ValueKind == JsonValueKind.Null,
            _ => true,
        };

        private static string Describe(string kind) => kind switch
        {
            "string" => "text", "number" => "a number", "integer" => "a whole number", "boolean" => "true or false",
            "array" => "a list", "object" => "an object", _ => kind,
        };

        private static string Describe(JsonElement v) => v.ValueKind switch
        {
            JsonValueKind.String => $"the text \"{v.GetString()}\"",
            JsonValueKind.Number => $"the number {v.GetRawText()}",
            JsonValueKind.True or JsonValueKind.False => v.GetRawText(),
            JsonValueKind.Array => "a list",
            JsonValueKind.Object => "an object",
            _ => "null",
        };
    }

    /// <summary>A host for reading the tools' definitions only.</summary>
    private sealed class NoHost : IScanHost
    {
        public string Root => Path.GetTempPath();
        public IScanLibrary Library => throw new InvalidOperationException("Not connected to a project.");
        public ConnectionStore Connections => new(null);
        public bool Live => false;
        public SensitiveValues Guard { get; } = new();
        public Task<T> RunAsync<T>(string action, Func<IScanSession, Task<T>> work, CancellationToken cancel = default) =>
            throw new InvalidOperationException("Not connected to a project.");
    }
}
