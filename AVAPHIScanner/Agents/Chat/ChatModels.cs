using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AVAPHIScanner.Agents.Mcp;
using McpTool = ModelContextProtocol.Protocol.Tool;

namespace AVAPHIScanner.Agents.Chat;

/// <summary>The Claude models the chat offers, by their API ids.</summary>
public static class ChatModels
{
    public const string Opus = "claude-opus-5-5";
    public const string Sonnet = "claude-sonnet-5-5";
    public const string Haiku = "claude-haiku-4-5-20251001";

    /// <summary>The model a new chat starts with.</summary>
    public const string Default = Opus;

    /// <summary>The choices, most capable first, with a name to show.</summary>
    public static readonly IReadOnlyList<(string Id, string Label)> All =
    [
        (Opus, "Claude Opus 5.5"),
        (Sonnet, "Claude Sonnet 5.5"),
        (Haiku, "Claude Haiku 4.5"),
    ];

    public static string Label(string id) => All.FirstOrDefault(m => m.Id == id).Label ?? id;
}

/// <summary>What the model is told: the MCP server's own instructions, and a few lines about working inside the program.</summary>
public static class ChatPrompt
{
    public const string InApp = """
        You are working inside AVA PHI Scanner itself, in its AI Chat panel, with the person watching. Your tool calls change the project in the window as you make them (sources, decisions about columns, the policy), and the person's Ctrl+Z undoes your calls one at a time. Talk to them briefly and plainly: say what you're about to do, do it, then say what you found or made. Keep it to a few sentences; the tool calls show in the panel on their own. Every value you see is masked, and that is on purpose: never ask the person to paste data into the chat, and never try to work out a masked value. Scan before you classify (get_inventory gives column ids), check doubtful columns with the person before overriding them, verify every copy you make, and say that detection is an aid, not a guarantee. If the person is busy in the program (a dialog open), calls wait for them. Sources, copies, keys and reports are in the working folder.
        """;

    /// <summary>The system prompt: the same instructions every MCP agent gets, then <see cref="InApp"/>.</summary>
    public static string System => ScanServer.Instructions.TrimEnd() + "\n\n" + InApp.TrimEnd();

    /// <summary>Added for a model given only <see cref="ChatTools.Core"/>.</summary>
    public const string CoreToolsNote =
        "In this chat you have a core set of the server's tools, not all of them: the instructions above may name tools you don't have, so work with the ones you're given.";

    /// <summary>Added for a model that can't see pictures (its tools' pictures become a line of text).</summary>
    public const string NoPicturesNote =
        "You can't see pictures in this chat: render_view still shows the person the inventory, but check your work yourself with get_inventory, get_column and get_risk.";
}

/// <summary>Which of the MCP server's tools the chat offers a model.</summary>
public static class ChatTools
{
    /// <summary>
    /// The core set for small local models, which choose better among fewer tools: the project and its sources, the
    /// scan and its inventory, decisions and the policy, previewing, de-identifying and verifying, the report, and undo.
    /// </summary>
    public static readonly IReadOnlyList<string> Core =
    [
        "get_project", "list_files", "add_source", "scan", "get_inventory", "get_column", "get_risk", "set_classification",
        "set_policy", "set_column_action", "preview_deidentification", "deidentify", "verify", "export_report", "render_view", "undo",
    ];

    /// <summary>The core tools among <paramref name="tools"/>, in the server's order.</summary>
    public static IReadOnlyList<McpTool> CoreOf(IReadOnlyList<McpTool> tools) => tools.Where(t => Core.Contains(t.Name)).ToList();
}
