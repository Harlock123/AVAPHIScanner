using System.IO.Pipelines;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.LogicalTree;
using Avalonia.Threading;
using AVAPHIScanner.Agents;
using AVAPHIScanner.Agents.Chat;
using AVAPHIScanner.Agents.Mcp;
using Microsoft.Data.Sqlite;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using static AVAPHIScanner.Tests.Agents.FakeModelServer;

namespace AVAPHIScanner.Tests.Agents;

/// <summary>The window's doors for outside agents: the pipe for <c>AVAPHIScanner --mcp --attach</c>, and the network door.</summary>
public sealed class LiveAgentTests
{
    private static MainWindow Open()
    {
        var window = new MainWindow { AgentPipe = "avaphiscanner-test-" + Guid.NewGuid().ToString("N") };
        window.Show();
        return window;
    }

    internal static void Close(MainWindow window)
    {
        window.History.MarkSaved();
        window.Close();
        SqliteConnection.ClearAllPools();
    }

    [Fact]
    public void An_outside_agent_attaches_through_the_pipe_and_scans_in_the_window() => HeadlessApp.Run(() =>
    {
        var w = Open();
        var root = Samples.WorkingCopy("aps-root-");
        Assert.StartsWith("AI agents may connect", w.SetAllowAgents(true));
        Assert.True(LiveListener.Answers(w.AgentPipe));
        var bridge = new LiveBridge(w.AgentPipe, root);
        Pipe up = new(), down = new();
        var server = McpServer.Create(new StreamServerTransport(up.Reader.AsStream(), down.Writer.AsStream(), "attach"), bridge.Options());
        using var stop = new CancellationTokenSource();
        var serving = Task.Run(() => server.RunAsync(stop.Token));
        var client = AgentTests.Wait(McpClient.CreateAsync(new StreamClientTransport(up.Writer.AsStream(), down.Reader.AsStream())));
        try
        {
            Assert.Contains("live app", client.ServerInstructions);
            string Text(CallToolResult r) => string.Join(" ", r.Content.OfType<TextContentBlock>().Select(t => t.Text));
            var added = AgentTests.Wait(client.CallToolAsync("add_source", new Dictionary<string, object?> { ["path"] = "samples" }).AsTask());
            Assert.False(added.IsError == true, Text(added));
            var scan = AgentTests.Wait(client.CallToolAsync("scan", new Dictionary<string, object?>()).AsTask(), 60);
            Assert.False(scan.IsError == true, Text(scan));
            Assert.NotNull(w.Inventory);
            Assert.Contains("datasets", w.txtSummary.Text);
            var inventory = AgentTests.Wait(client.CallToolAsync("get_inventory", new Dictionary<string, object?>()).AsTask());
            Assert.Empty(Samples.Leaks(Text(inventory), Samples.Secrets(Path.Combine(root, "samples"))));
            Assert.Single(w.History.Current.Sources);
        }
        finally
        {
            // Everything this test started ends with it: work left running would reach into the next test's app.
            AgentTests.Wait(client.DisposeAsync().AsTask().ContinueWith(_ => true));
            stop.Cancel();
            AgentTests.Wait(serving.ContinueWith(_ => true));
            AgentTests.Wait(bridge.DisposeAsync().AsTask().ContinueWith(_ => true));
            Assert.Equal("AI agents are shut out.", w.SetAllowAgents(false));
            AgentTests.Wait(w.Agents.StopAsync().ContinueWith(_ => true));
            Close(w);
        }
    });

    [Fact]
    public void The_network_door_opens_on_the_settings_and_wants_the_token() => HeadlessApp.Run(() =>
    {
        var w = Open();
        try
        {
            w.AgentSettings.AllowNetworkAgents = true;
            w.AgentSettings.NetworkAgentsAddress = "localhost";
            w.AgentSettings.NetworkAgentsPort = 0;
            w.AgentSettings.NetworkAgentsFolder = Directory.CreateTempSubdirectory("aps-net-").FullName;
            Assert.StartsWith("AI agents on other computers may connect", AgentTests.Wait(w.SyncNetworkAsync()));
            using var http = new HttpClient();
            var refused = AgentTests.Wait(http.PostAsync(w.Agents.NetworkUrls.First(), new StringContent("{}", System.Text.Encoding.UTF8, "application/json")));
            Assert.Equal(System.Net.HttpStatusCode.Unauthorized, refused.StatusCode);
            w.AgentSettings.Save();
            Assert.DoesNotContain(w.NetworkToken, File.ReadAllText(AgentSettings.Path));
            Assert.Equal(8775, new AgentSettings().NetworkAgentsPort);
        }
        finally
        {
            w.AgentSettings.AllowNetworkAgents = false;
            AgentTests.Wait(w.SyncNetworkAsync());
            Close(w);
        }
    });

    [Fact]
    public void The_names_are_this_apps_own() => HeadlessApp.Run(() =>
    {
        Assert.Equal("AVAPHISCANNER_MCP_TOKEN", McpCommandLine.TokenVariable);
        Assert.Equal(8775, McpCommandLine.NetworkPort);
        Assert.StartsWith("AVAPHIScanner-mcp-", LiveProtocol.PipeName);
        Assert.EndsWith("AVAPHIScanner", Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(AgentSettings.Path)!) is var d && AgentSettings.FolderOverride is null ? d : "AVAPHIScanner");
        Assert.Contains("AVAPHISCANNER_MCP_TOKEN", McpCommandLine.Usage);
        Assert.DoesNotContain("--rows", McpCommandLine.Usage);
    });
}

/// <summary>The window's own buttons and the agents in it, on the shared history.</summary>
public sealed class WindowFlowTests
{
    private static void Settle(int times = 30)
    {
        for (var i = 0; i < times; i++) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(5); }
    }

    private static void Click(Button b) => b.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));

    internal static MainWindow ScannedWindow(string root, int width = 1320, int height = 820)
    {
        var w = new MainWindow { Width = width, Height = height };
        w.ChatKeys = (new ApiKeyStore(null, null), new ApiKeyStore(null, null));
        w.AgentSettings.WorkingFolder = root;
        w.Show();
        w.AddSources([Path.Combine(root, "samples")]);
        AgentTests.Wait(w.ScanAsync().ContinueWith(_ => true), 60);
        Settle();
        return w;
    }

    [Fact]
    public void Add_a_folder_scan_decide_about_a_column_and_undo_it() => HeadlessApp.Run(() =>
    {
        var root = Samples.WorkingCopy("aps-flow-");
        var w = ScannedWindow(root);
        try
        {
            Assert.Single(w.History.Current.Sources);
            Assert.NotNull(w.Inventory);
            Assert.Contains("risk High", w.txtSummary.Text);
            Assert.Contains("Overall risk: High", w.txtRisk.Text);
            Assert.Empty(Samples.Leaks(w.txtRisk.Text ?? "", Samples.Secrets(Path.Combine(root, "samples"))));
            // Choose the plan column and say it's PHI; then not; then undo both.
            var plan = w.Inventory!.Find("members.csv › plan");
            w.cboColumn.SelectedItem = w.cboColumn.Items.OfType<ComboBoxItem>().First(i => (string?)i.Tag == plan.Key);
            Settle(2);
            Assert.Contains("Not PHI", w.txtColumn.Text);
            w.cboKind.SelectedItem = w.cboKind.Items.OfType<ComboBoxItem>().First(i => (PhiKind)i.Tag! == PhiKind.OtherId);
            Click(w.cmdMarkPhi);
            Assert.Equal(PhiKind.OtherId, w.History.Current.EffectiveKind(plan.Key, plan.Detected));
            Assert.Contains("You decided", w.txtColumn.Text);
            Click(w.cmdNotPhi);
            Assert.Equal(PhiKind.None, w.History.Current.EffectiveKind(plan.Key, plan.Detected));
            w.cboAction.SelectedIndex = 1 + Kinds.Actions.ToList().FindIndex(a => a.Action == ColumnAction.Drop);
            Assert.Equal(PolicyKind.Custom, w.History.Current.Policy.Kind);
            w.cboPolicy.SelectedIndex = 1;
            Assert.Equal(PolicyKind.LimitedDataSet, w.History.Current.Policy.Kind);
            for (var i = 0; i < 4; i++)
                w.RaiseEvent(new Avalonia.Input.KeyEventArgs { RoutedEvent = Avalonia.Input.InputElement.KeyDownEvent, Key = Avalonia.Input.Key.Z, KeyModifiers = Avalonia.Input.KeyModifiers.Control });
            Assert.Empty(w.History.Current.Overrides);
            Assert.Equal(PolicyKind.SafeHarbor, w.History.Current.Policy.Kind);
            Assert.EndsWith("*", w.Title!.Replace(" - AVA PHI Scanner", ""));

            // De-identify and verify from the window.
            Assert.Null(AgentTests.Wait(w.DeidentifyAsync(Path.Combine(root, "copy"), Path.Combine(root, "k.key"), false), 60));
            Assert.Contains("Verification: Clean", w.txtCopy.Text);
            Assert.Equal("The key file must not be inside the output folder: whoever gets the copy must not get the key.",
                AgentTests.Wait(w.DeidentifyAsync(Path.Combine(root, "copy2"), Path.Combine(root, "copy2", "k.key"), false)));
            w.SaveTo(Path.Combine(root, "p.phiscan"));
            Assert.True(File.Exists(Path.Combine(root, "p.phiscan")));
        }
        finally
        {
            LiveAgentTests.Close(w);
        }
    });

    [Fact]
    public void An_agent_works_in_the_open_window_and_the_person_undoes_its_steps() => HeadlessApp.Run(() =>
    {
        var root = Samples.WorkingCopy("aps-window-");
        var w = new MainWindow();
        w.Show();
        w.Agents.Connections = new ConnectionStore(null);
        var bridge = AgentTests.Wait(McpToolBridge.StartAsync(w.Agents.ChatHost(root, () => "Claude")));
        try
        {
            ToolOutcome Call(string tool, object args) =>
                AgentTests.Wait(bridge.CallAsync(tool, JsonSerializer.SerializeToElement(args).EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())), 60);
            Assert.False(Call("add_source", new { path = "samples" }).IsError);
            Assert.False(Call("scan", new { }).IsError);
            Assert.NotNull(w.Inventory);
            Assert.Contains("Claude", w.txtStatusBar.Text);
            var c = w.Inventory!.Find("members.csv › plan").Id;
            Assert.False(Call("set_classification", new { column = c, is_phi = true, kind = "other_id" }).IsError);
            Assert.Single(w.History.Current.Overrides);

            // The person's Ctrl+Z takes the agent's step back.
            var key = new Avalonia.Input.KeyEventArgs { RoutedEvent = Avalonia.Input.InputElement.KeyDownEvent, Key = Avalonia.Input.Key.Z, KeyModifiers = Avalonia.Input.KeyModifiers.Control };
            w.RaiseEvent(key);
            Assert.Empty(w.History.Current.Overrides);

            // Removing a source in the open window asks the person first: no, and nothing changes.
            bridge.Ask = (_, _) => Task.FromResult(false);
            var no = Call("remove_source", new { id = "s1" });
            Assert.True(no.IsError);
            Assert.Contains("said no", no.Text);
            Assert.Single(w.History.Current.Sources);
            bridge.Ask = (_, _) => Task.FromResult(true);
            Assert.False(Call("remove_source", new { id = "s1" }).IsError);
            Assert.Empty(w.History.Current.Sources);
        }
        finally
        {
            AgentTests.Wait(bridge.DisposeAsync().AsTask().ContinueWith(_ => true));
            LiveAgentTests.Close(w);
        }
    });

    [Fact]
    public void The_chat_intro_recommends_a_local_model() => HeadlessApp.Run(() =>
    {
        foreach (var local in new[] { false, true })
        {
            var w = new MainWindow();
            w.ChatKeys = (new ApiKeyStore(null, null), new ApiKeyStore(null, null));
            if (local)
            {
                w.AgentSettings.ChatProvider = "OpenAICompatible";
                w.AgentSettings.ChatServerUrl = "http://localhost:1234/v1";
                w.AgentSettings.ChatServerModel = "qwen3-8b";
            }
            w.Show();
            try
            {
                w.ToggleChat();
                Assert.True(w.ChatHolder.IsVisible);
                Assert.Contains(local ? "the set-up this app recommends" : "on your own computer is recommended", w.Chat!.IntroText);
                Assert.Contains("never sees a raw value", w.Chat.IntroText);
                w.ToggleChat();
                Assert.False(w.ChatHolder.IsVisible);
            }
            finally
            {
                LiveAgentTests.Close(w);
            }
        }
    });
}

/// <summary>
/// The README's pictures (APS_SHOTS=folder): the inventory after scanning the samples, and the AI Chat finding the
/// PHI on a scripted local model. Nothing runs without the variable.
/// </summary>
public sealed class Screenshots
{
    [Fact]
    public void Pictures() => HeadlessApp.Run(() =>
    {
        var dir = Environment.GetEnvironmentVariable("APS_SHOTS");
        if (string.IsNullOrEmpty(dir)) return;
        Directory.CreateDirectory(dir);
        var root = Samples.WorkingCopy("aps-shot-");

        var w = WindowFlowTests.ScannedWindow(root, 1500, 900);
        var dob = w.Inventory!.Find("members.csv › dob");
        w.cboColumn.SelectedItem = w.cboColumn.Items.OfType<ComboBoxItem>().First(i => (string?)i.Tag == dob.Key);
        for (var i = 0; i < 20; i++) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(10); }
        AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        w.CaptureRenderedFrame()!.Save(Path.Combine(dir, "inventory.png"));
        w.tabs.SelectedItem = w.tabRisk;
        for (var i = 0; i < 10; i++) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(10); }
        AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        w.CaptureRenderedFrame()!.Save(Path.Combine(dir, "risk.png"));
        LiveAgentTests.Close(w);

        var chat = new MainWindow { Width = 1500, Height = 900 };
        chat.ChatKeys = (new ApiKeyStore(null, null), new ApiKeyStore(null, null));
        chat.AgentSettings.ChatProvider = "OpenAICompatible";
        chat.AgentSettings.ChatServerUrl = "http://localhost:1234/v1";
        chat.AgentSettings.ChatServerModel = "qwen3-8b";
        chat.AgentSettings.WorkingFolder = root;
        chat.Show();
        if (!chat.ChatHolder.IsVisible) chat.ToggleChat();
        var server = new FakeModelServer("http://localhost:1234/v1")
            .Reply(Say("I'll add the samples folder and scan it."), Call("c1", "add_source", new { path = "samples" }))
            .Reply(Call("c2", "scan", new { }))
            .Reply(Say("Here's where the risk is."), Call("c3", "get_risk", new { }))
            .Reply(Call("c4", "get_inventory", new { below_confidence = 0.8 }))
            .Reply(Say("I scanned 18 datasets: 49 of 64 columns hold PHI and the risk is High. members.csv has names, SSNs, birth dates (3 people over 89), addresses, phones and emails; the 12 clinical notes and the visit notes have names, dates, addresses and phone numbers inside the text. The provider names in claims.xlsx › Providers are doctors, not patients: you may want to mark them Not PHI. I only ever see masked values. Shall I make a Safe Harbor copy?"));
        var panel = chat.Chat!;
        panel.ServerFactory = (_, key) => server.Client(key);
        panel.Input.Text = "Find the PHI in the samples folder and tell me where the risk is.";
        panel.Send();
        AgentTests.Wait(panel.Running.ContinueWith(_ => true), 60);
        for (var i = 0; i < 20; i++) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(10); }
        AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        chat.CaptureRenderedFrame()!.Save(Path.Combine(dir, "ai-chat.png"));
        LiveAgentTests.Close(chat);
    });
}
