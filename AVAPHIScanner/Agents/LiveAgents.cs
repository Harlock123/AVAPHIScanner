using Avalonia.Threading;
using AVAPHIScanner.Agents.Mcp;

namespace AVAPHIScanner.Agents;

/// <summary>The project open in the window, as an agent works on it: the person's own project, history and scan.</summary>
internal sealed class WindowSession(MainWindow window) : IScanSession
{
    public Project Document => window.History.Current;

    public ProjectHistory History => window.History;

    public string? FilePath => window.CurrentFilePath;

    public Inventory? Inventory => window.Inventory;

    public DeidentifyResult? LastRun => window.LastRun;

    public VerifyResult? LastVerify => window.LastVerify;

    public SensitiveValues Guard => window.Guard;

    public void Apply(Project project, string label) => window.Commit(project, label);

    public void Refresh() => window.ShowProject();

    public void Replace(Project project, string? path) => window.Adopt(project, path);

    public void Saved(string path) => window.AgentSaved(path);

    public void Scanned(Inventory inventory) => window.ShowScan(inventory);

    public void Deidentified(DeidentifyResult result) => window.ShowRun(result);

    public void Verified(VerifyResult result) => window.ShowVerify(result);
}

/// <summary>
/// AI agents in the open window: the session and host the chat and outside agents share, the door on this computer
/// (a pipe, for <c>AVAPHIScanner --mcp --attach</c>) and the network door (MCP over HTTP with a token).
/// </summary>
internal sealed class LiveAgents(MainWindow window) : IScanDesk, IUiThread, IAsyncDisposable
{
    private readonly WindowSession _session = new(window);
    private LiveListener? _listener;
    private NetworkListener? _network;

    public ScanLibrary Library { get; } = new(window.AgentStage);

    /// <summary>The person's database connections (connections.json beside the settings; tests give their own).</summary>
    public ConnectionStore Connections { get; set; } = new(Path.Combine(AgentSettings.Folder, ConnectionStore.FileName));

    public bool Running => _listener != null;

    public TimeSpan BusyWait { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>How many outside agents are connected (pipe and network together), when it changes.</summary>
    public event Action<int>? ConnectionsChanged;

    public IScanSession Session => _session;

    public string? Busy => window.OwnedWindows.Count > 0 || ChatLook.ModalsOpen > 0 ? "a dialog box is open in AVA PHI Scanner" : null;

    public void Report(string text) => window.Say(text);

    public Task<T> InvokeAsync<T>(Func<Task<T>> work) => Dispatcher.UIThread.InvokeAsync(work);

    /// <summary>The host outside agents work through, in <paramref name="root"/>.</summary>
    public ScanHost Host(string root) => new(this, this, Library, root, Connections) { BusyWait = BusyWait, Live = true };

    /// <summary>The host the AI Chat runs its in-process MCP server on; its status lines name the chat's model.</summary>
    public ScanHost ChatHost(string root, Func<string> who) => new(this, new ChatDesk(this, who), Library, root, Connections) { BusyWait = BusyWait, Live = true };

    private sealed class ChatDesk(LiveAgents agents, Func<string> who) : IScanDesk
    {
        public IScanSession Session => agents.Session;

        public string? Busy => agents.Busy;

        public void Report(string text) =>
            agents.Report(text.StartsWith("AI agent: ", StringComparison.Ordinal) ? who() + ": " + text["AI agent: ".Length..] : text);
    }

    /// <summary>Opens the door on a pipe; returns why it couldn't (another AVA PHI Scanner has it), or null.</summary>
    public string? Start(string pipeName, Func<string> root)
    {
        if (_listener != null) return null;
        var listener = new LiveListener(pipeName, asked => Host(Directory.Exists(asked) ? asked : root()));
        listener.ConnectionsChanged += n => Dispatcher.UIThread.Post(() => ConnectionsChanged?.Invoke(n));
        try
        {
            listener.Start();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _ = listener.DisposeAsync();
            return e.Message;
        }
        _listener = listener;
        return null;
    }

    public async Task StopAsync()
    {
        var listener = _listener;
        _listener = null;
        if (listener == null) return;
        listener.Stop();
        await listener.DisposeAsync();
    }

    public bool NetworkRunning => _network != null;

    public NetworkSettings? NetworkSettings { get; private set; }

    public string? NetworkRoot { get; private set; }

    public IReadOnlyList<string> NetworkUrls => _network?.Urls ?? [];

    public async Task<string?> StartNetworkAsync(NetworkSettings settings, string root)
    {
        if (_network != null) return null;
        if (!Directory.Exists(root)) return $"the working folder {root} doesn't exist.";
        var listener = new NetworkListener(settings, ScanServer.Name, o => ScanServer.Configure(o, Host(root)));
        listener.ConnectionsChanged += n => Dispatcher.UIThread.Post(() => ConnectionsChanged?.Invoke(n));
        try
        {
            await listener.StartAsync();
        }
        catch (IOException e)
        {
            return e.Message;
        }
        _network = listener;
        NetworkSettings = settings;
        NetworkRoot = root;
        return null;
    }

    public async Task StopNetworkAsync()
    {
        var listener = _network;
        _network = null;
        NetworkSettings = null;
        NetworkRoot = null;
        if (listener != null) await listener.DisposeAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        await StopNetworkAsync();
    }
}
