using System.Diagnostics;

namespace AVAPHIScanner.Agents.Mcp;

/// <summary>What the server needs from the program that it can't do itself: drawing the inventory, which needs Avalonia.</summary>
public interface IScanLibrary
{
    /// <summary>The inventory view (masked) drawn as a PNG, at <paramref name="scale"/>: the project's decisions over the scan's results.</summary>
    byte[] Picture(Project project, Inventory? inventory, double scale);
}

/// <summary>
/// The project an agent works on and what goes with it: its undo history, its file, the last scan, the last copy and
/// its check, and the sensitive values every answer is checked against. Used on the host's thread only
/// (<see cref="IScanHost.RunAsync{T}"/>), except <see cref="Guard"/>, which is safe from any thread.
/// </summary>
public interface IScanSession
{
    /// <summary>The project as it is now (a copy: change it, then <see cref="Apply"/> it).</summary>
    Project Document { get; }

    /// <summary>The project's undo history, the person's own (Ctrl+Z undoes an agent's steps too).</summary>
    ProjectHistory History { get; }

    /// <summary>The .phiscan file the project was opened from or saved to, or null.</summary>
    string? FilePath { get; }

    /// <summary>The last scan's results, or null before the first scan.</summary>
    Inventory? Inventory { get; }

    DeidentifyResult? LastRun { get; }

    VerifyResult? LastVerify { get; }

    /// <summary>Every sensitive value scans have seen: anything sent to an agent is checked against them.</summary>
    SensitiveValues Guard { get; }

    /// <summary>Makes <paramref name="project"/> the project, as one undo step named <paramref name="label"/>.</summary>
    void Apply(Project project, string label);

    /// <summary>Shows the history's current project (after undo, redo or a batch folded into one step).</summary>
    void Refresh();

    /// <summary>Adopts another project (new, open): a fresh history, not changed, no scan.</summary>
    void Replace(Project project, string? path);

    /// <summary>The project was written to <paramref name="path"/>, which becomes its file.</summary>
    void Saved(string path);

    /// <summary>A scan finished: shows its results.</summary>
    void Scanned(Inventory inventory);

    void Deidentified(DeidentifyResult result);

    void Verified(VerifyResult result);
}

/// <summary>
/// Where the MCP tools' work runs. The handlers (<see cref="ScanTools"/>) only touch the project through
/// <see cref="RunAsync{T}"/>, so the same handlers serve the headless server and the open window.
/// </summary>
public interface IScanHost
{
    /// <summary>The folder relative paths start from; sources, copies, keys and reports stay inside it.</summary>
    string Root { get; }

    IScanLibrary Library { get; }

    /// <summary>The database connections the person has set up, by name.</summary>
    ConnectionStore Connections { get; }

    /// <summary>Working in the open window, with the person watching (so removing a source asks them first).</summary>
    bool Live { get; }

    /// <summary>The session's sensitive values, for checking answers on any thread.</summary>
    SensitiveValues Guard { get; }

    /// <summary>
    /// Runs <paramref name="work"/> on the thread that owns the project, one call at a time, and returns what it returns
    /// (or throws what it throws). <paramref name="action"/> names it for the status bar. Reading data doesn't belong
    /// in it: it would hold up the window.
    /// </summary>
    Task<T> RunAsync<T>(string action, Func<IScanSession, Task<T>> work, CancellationToken cancel = default);
}

public static class ScanHostExtensions
{
    public static Task<T> RunAsync<T>(this IScanHost host, string action, Func<IScanSession, T> work, CancellationToken cancel = default) =>
        host.RunAsync(action, s => Task.FromResult(work(s)), cancel);
}

/// <summary>Runs work on a UI thread (the program's Avalonia dispatcher, or a test's).</summary>
public interface IUiThread
{
    Task<T> InvokeAsync<T>(Func<Task<T>> work);
}

/// <summary>The program as the host sees it: the project, whether it can take a call now, and the status bar.</summary>
public interface IScanDesk
{
    IScanSession Session { get; }

    /// <summary>Why the program can't take a call just now ("a dialog box is open"), or null. The call waits.</summary>
    string? Busy { get; }

    /// <summary>Tells the person what an agent just did.</summary>
    void Report(string text);
}

/// <summary>
/// The host: calls run against the desk's project on its UI thread, one at a time, so the window redraws and Ctrl+Z
/// undoes them like the person's own edits. While the person is busy a call waits up to <see cref="BusyWait"/>.
/// </summary>
public sealed class ScanHost(IUiThread ui, IScanDesk desk, IScanLibrary library, string root, ConnectionStore connections) : IScanHost
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string Root { get; } = Path.GetFullPath(root);

    public IScanLibrary Library { get; } = library;

    public ConnectionStore Connections { get; } = connections;

    public bool Live { get; init; }

    public SensitiveValues Guard => desk.Session.Guard;

    public TimeSpan BusyWait { get; init; } = TimeSpan.FromSeconds(20);

    public TimeSpan BusyPoll { get; init; } = TimeSpan.FromMilliseconds(200);

    public async Task<T> RunAsync<T>(string action, Func<IScanSession, Task<T>> work, CancellationToken cancel = default)
    {
        await _gate.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            var clock = Stopwatch.StartNew();
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                var (ran, result, busy) = await ui.InvokeAsync(async () =>
                {
                    if (desk.Busy is { } why) return (false, default(T), why);
                    try
                    {
                        var r = await work(desk.Session);
                        desk.Report($"AI agent: {action}.");
                        return (true, r, (string?)null);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        desk.Report($"AI agent: {action} failed: {Scanner.Safe(e)}");
                        throw;
                    }
                }).ConfigureAwait(false);
                if (ran) return result!;
                if (clock.Elapsed >= BusyWait)
                    throw new ScanBusyException($"AVA PHI Scanner is busy: {busy}. The call waited {BusyWait.TotalSeconds:0} seconds; ask the person to finish, then try again.");
                await Task.Delay(BusyPoll, cancel).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}

public sealed class ScanBusyException(string message) : Exception(message);

/// <summary>A project with no window round it, as <c>AVAPHIScanner --mcp</c> serves it.</summary>
public sealed class HeadlessSession : IScanSession
{
    public ProjectHistory History { get; } = new(new Project());

    public Project Document => History.Current;

    public string? FilePath { get; private set; }

    public Inventory? Inventory { get; private set; }

    public DeidentifyResult? LastRun { get; private set; }

    public VerifyResult? LastVerify { get; private set; }

    public SensitiveValues Guard { get; } = new();

    public void Apply(Project project, string label) => History.Commit(project, label);

    public void Refresh() { }

    public void Replace(Project project, string? path)
    {
        History.Reset(project);
        FilePath = path;
        Inventory = null;
        LastRun = null;
        LastVerify = null;
    }

    public void Saved(string path)
    {
        FilePath = path;
        History.MarkSaved();
    }

    public void Scanned(Inventory inventory)
    {
        Inventory = inventory;
        Guard.Merge(inventory.Sensitive);
    }

    public void Deidentified(DeidentifyResult result) => LastRun = result;

    public void Verified(VerifyResult result) => LastVerify = result;
}

public sealed class HeadlessDesk(TextWriter? log = null) : IScanDesk
{
    public IScanSession Session { get; } = new HeadlessSession();

    public string? Busy => null;

    public void Report(string text) => log?.WriteLine(text);
}
