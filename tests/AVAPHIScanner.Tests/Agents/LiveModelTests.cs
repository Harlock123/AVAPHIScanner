using AVAPHIScanner.Agents.Chat;

namespace AVAPHIScanner.Tests.Agents;

/// <summary>
/// The chat against a real model server, through each of its APIs: opt-in, with APS_LIVE_SERVER (Ollama's address, such as
/// http://localhost:11434, which speaks both the OpenAI and the Anthropic Messages API) and APS_LIVE_MODEL (a model there
/// that calls tools, such as qwen3:1.7b). Nothing runs without them. The model, like every agent, sees masked values only.
/// </summary>
public sealed class LiveModelTests
{
    private static (string Server, string Model)? Live =>
        Environment.GetEnvironmentVariable("APS_LIVE_SERVER") is { Length: > 0 } s && Environment.GetEnvironmentVariable("APS_LIVE_MODEL") is { Length: > 0 } m
            ? (s.TrimEnd('/'), m) : null;

    private const string Ask = "Add the folder \"samples\" as a source with add_source, then scan it with scan. Then stop.";

    [Fact]
    public void A_real_model_scans_through_the_openai_compatible_api()
    {
        if (Live is not { } live) return;
        Run(rig => new ChatSession(rig.Bridge)
        {
            Provider = ChatProvider.OpenAICompatible,
            Server = new OpenAICompatibleClient(new HttpClient { Timeout = TimeSpan.FromMinutes(5) }, live.Server + "/v1", null),
            ServerModel = live.Model,
        });
    }

    [Fact]
    public void A_real_model_scans_through_the_messages_api()
    {
        if (Live is not { } live) return;
        Run(rig => new ChatSession(rig.Bridge)
        {
            Provider = ChatProvider.Anthropic,
            Client = new Anthropic.AnthropicClient { ApiKey = "local", BaseUrl = live.Server, HttpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(5) } },
            Model = live.Model,
            ClaudeServer = "local",
            ClaudeCoreToolsOnly = true,
            ClaudeSeesPictures = false,
        });
    }

    private static void Run(Func<AgentTests.Rig, ChatSession> make) => HeadlessApp.Run(() =>
    {
        using var rig = new AgentTests.Rig();
        var chat = make(rig);
        AgentTests.Wait(chat.SendAsync(Ask).ContinueWith(t => { t.GetAwaiter().GetResult(); return true; }), 600);
        var calls = chat.Entries.OfType<ToolEntry>().Select(t => $"{t.Name}{(t.IsError ? " (error: " + t.Result + ")" : "")}").ToList();
        var notices = chat.Entries.OfType<NoticeEntry>().Select(n => n.Text).ToList();
        Assert.True(rig.Session.Inventory != null, $"The model didn't scan. Calls: {string.Join("; ", calls)}. Notices: {string.Join("; ", notices)}");
        Assert.Empty(Samples.Leaks(ChatMarkdown.Write(chat.ToStored(_ => null)), rig.Secrets));
    });
}
