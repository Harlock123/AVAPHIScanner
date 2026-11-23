using System.Data;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using AVAPHIScanner.Agents;

namespace AVAPHIScanner;

/// <summary>
/// The window: the project's sources and policy on the left; the inventory, the risk, the free-text findings and the
/// de-identified copy in tabs; the selected column and the person's decision about it underneath. Every change to the
/// project goes through <see cref="Commit"/> as one undo step (the person's and agents' alike), and the window is
/// drawn from the history's current project (<see cref="ShowProject"/>). Values are shown masked here too.
/// </summary>
public partial class MainWindow : Window
{
    /// <summary>The project's undo history: every step is the whole project after it.</summary>
    private readonly ProjectHistory _history = new(new Project());

    /// <summary>The .phiscan file the project was opened from or saved to, or null.</summary>
    private string? _filePath;

    /// <summary>The rows the inventory grid shows, in order (for clicks).</summary>
    private List<ColumnReport> _shownColumns = [];

    /// <summary>True while the window fills its own controls, so their change events don't make undo steps.</summary>
    private bool _filling;

    private bool _scanning;

    public MainWindow()
    {
        InitializeComponent();
        foreach (var k in Kinds.All.Where(k => k.Kind != PhiKind.None)) cboKind.Items.Add(new ComboBoxItem { Content = k.Label, Tag = k.Kind });
        cboKind.SelectedIndex = 0;
        cboAction.Items.Add(new ComboBoxItem { Content = "Action: policy's choice", Tag = null });
        foreach (var (a, id) in Kinds.Actions) cboAction.Items.Add(new ComboBoxItem { Content = "Action: " + id, Tag = a });
        InventoryGrid.GridItemClick += (_, item) => SelectRow(item.rowID);
        _history.Changed += UpdateHistoryState;
        KeyDown += OnWindowKeyDown;
        SetUpAgents();
        ShowProject();
    }

    // ───────────────────────────── state agents and tests read ─────────────────────────────

    internal ProjectHistory History => _history;

    internal string? CurrentFilePath => _filePath;

    /// <summary>The last scan's results, or null.</summary>
    internal Inventory? Inventory { get; private set; }

    internal DeidentifyResult? LastRun { get; private set; }

    internal VerifyResult? LastVerify { get; private set; }

    /// <summary>Every sensitive value the window's scans have seen, for checking what agents are sent.</summary>
    internal SensitiveValues Guard { get; } = new();

    /// <summary>The folder relative source paths start from: the working folder agents use.</summary>
    internal string SourceRoot => AgentRoot;

    // ───────────────────────────── the project and its history ─────────────────────────────

    /// <summary>Makes <paramref name="project"/> the project as one undo step, and shows it.</summary>
    internal void Commit(Project project, string label)
    {
        _history.Commit(project, label);
        ShowProject();
    }

    /// <summary>Adopts another project (new, open): a fresh history, no scan.</summary>
    internal void Adopt(Project project, string? path)
    {
        _history.Reset(project);
        _filePath = path;
        Inventory = null;
        LastRun = null;
        LastVerify = null;
        ShowProject();
    }

    internal void AgentSaved(string path)
    {
        _filePath = path;
        _history.MarkSaved();
        UpdateTitle();
    }

    internal void ShowScan(Inventory inventory)
    {
        Inventory = inventory;
        Guard.Merge(inventory.Sensitive);
        ShowProject();
        tabs.SelectedItem = tabInventory;
    }

    internal void ShowRun(DeidentifyResult result)
    {
        LastRun = result;
        ShowCopy();
    }

    internal void ShowVerify(VerifyResult result)
    {
        LastVerify = result;
        ShowCopy();
        tabs.SelectedItem = tabCopy;
    }

    private void Undo()
    {
        if (!_history.CanUndo) return;
        var what = _history.UndoLabel;
        _history.Undo();
        ShowProject();
        Say($"Undid {what}.");
    }

    private void Redo()
    {
        if (!_history.CanRedo) return;
        var what = _history.RedoLabel;
        _history.Redo();
        ShowProject();
        Say($"Redid {what}.");
    }

    private void UpdateHistoryState()
    {
        UndoMenuItem.IsEnabled = _history.CanUndo;
        RedoMenuItem.IsEnabled = _history.CanRedo;
        UndoMenuItem.Header = _history.UndoLabel is { } u ? $"_Undo {u}" : "_Undo";
        RedoMenuItem.Header = _history.RedoLabel is { } r ? $"_Redo {r}" : "_Redo";
        UpdateTitle();
    }

    private void UpdateTitle()
    {
        var name = _filePath is { } f ? Path.GetFileName(f) : "Untitled";
        Title = $"{name}{(_history.IsDirty ? " *" : "")} - AVA PHI Scanner";
    }

    /// <summary>A change to a copy of the project, committed as one step.</summary>
    private void Change(string label, Action<Project> change)
    {
        var p = _history.Current;
        change(p);
        Commit(p, label);
    }

    // ───────────────────────────── drawing the project ─────────────────────────────

    /// <summary>Draws everything from the history's current project and the last scan.</summary>
    internal void ShowProject()
    {
        _filling = true;
        try
        {
            var p = _history.Current;
            lstSources.ItemsSource = p.Sources.Select(s => $"{s.Id}  {SourceText(s)}").ToList();
            cboPolicy.SelectedIndex = (int)p.Policy.Kind;
            cboDates.SelectedIndex = p.Policy.DateMode == DateMode.Shift ? 1 : 0;
            cboDates.IsEnabled = p.Policy.Kind != PolicyKind.LimitedDataSet;
            txtPolicy.Text = p.Policy.Describe() + ".";
            ShowInventory(p);
            ShowRisk(p);
            ShowFindings();
            ShowColumnList(p);
            UpdateTitle();
        }
        finally
        {
            _filling = false;
        }
    }

    private static string SourceText(SourceSpec s) => s.Kind switch
    {
        "database" when s.ConnectionName is { } n => $"database \"{n}\"",
        "database" => $"{s.Engine} {DbRead.DisplayName(Db.ParseEngine(s.Engine ?? "sqlite"), s.Connection ?? "")}",
        _ => $"{s.Kind} {Path.GetFileName(Path.TrimEndingDirectorySeparator(s.Path ?? ""))}",
    };

    private void ShowInventory(Project p)
    {
        var table = new DataTable();
        foreach (var h in ReportWriter.Headings) table.Columns.Add(h, typeof(string));
        _shownColumns = [];
        if (Inventory is { } inv)
        {
            foreach (var c in inv.Columns)
            {
                var kind = p.EffectiveKind(c.Key, c.Detected);
                if (chkPhiOnly.IsChecked == true && !Kinds.IsPhi(kind) && kind != PhiKind.Npi) continue;
                table.Rows.Add(ReportWriter.Row(c, p).Select(v => v.Replace('\n', ' ')).Cast<object>().ToArray());
                _shownColumns.Add(c);
            }
            var phi = inv.Columns.Count(c => Kinds.IsPhi(p.EffectiveKind(c.Key, c.Detected)));
            txtSummary.Text = $"{inv.Datasets} datasets · {inv.Columns.Count} columns · {phi} with PHI · {inv.RowsRead} rows read · risk {RiskSummary.Of(inv, p).Overall}" +
                (inv.Problems.Count > 0 ? $" · {inv.Problems.Count} problem{(inv.Problems.Count == 1 ? "" : "s")} (see Risk)" : "");
        }
        else txtSummary.Text = p.Sources.Count == 0 ? "No sources yet." : "Not scanned yet: Scan (F5).";
        InventoryGrid.PopulateFromDataTable(table);
    }

    private void ShowRisk(Project p)
    {
        if (Inventory is not { } inv)
        {
            txtRisk.Text = "Scan to see the risk.";
            return;
        }
        var risk = RiskSummary.Of(inv, p);
        var s = new StringBuilder();
        s.AppendLine($"Overall risk: {risk.Overall}");
        s.AppendLine($"Columns with direct identifiers: {risk.DirectColumns}   quasi-identifiers: {risk.QuasiColumns}   free text: {risk.TextColumns}   of {risk.Columns}");
        s.AppendLine();
        foreach (var t in risk.Tables.OrderBy(t => t.Level switch { "High" => 0, "Medium" => 1, "Low" => 2, _ => 3 }))
            s.AppendLine($"{t.Level,-7} {t.Where} ({t.Rows} rows): {t.Explanation}");
        s.AppendLine();
        foreach (var n in risk.Notes) s.AppendLine("• " + n);
        foreach (var problem in inv.Problems) s.AppendLine("Problem: " + problem);
        s.AppendLine();
        foreach (var c in ReportWriter.Caveats) s.AppendLine("• " + c);
        txtRisk.Text = s.ToString();
    }

    private void ShowFindings()
    {
        var table = new DataTable();
        foreach (var h in new[] { "Column", "Where", "Row", "Kind", "Found (masked)" }) table.Columns.Add(h, typeof(string));
        if (Inventory is { } inv)
            foreach (var c in inv.Columns.Where(c => c.Findings.Count > 0))
                foreach (var f in c.Findings)
                    table.Rows.Add(c.Id, c.SafeDisplay, f.Row.ToString(), Kinds.Label(f.Kind), f.Masked);
        FindingsGrid.PopulateFromDataTable(table);
    }

    private void ShowCopy()
    {
        var s = new StringBuilder();
        if (LastRun is { } r)
        {
            s.AppendLine($"Copy in {r.Output}");
            s.AppendLine($"Policy: {r.Policy}");
            s.AppendLine(r.Summary + ".");
            foreach (var f in r.Files.Take(60)) s.AppendLine("  " + f);
            foreach (var p in r.Problems) s.AppendLine("Problem: " + p);
            s.AppendLine();
        }
        if (LastVerify is { } v)
        {
            s.AppendLine("Verification: " + v.Summary);
            if (v.Before.Count + v.After.Count + v.Expected.Count > 0)
            {
                s.AppendLine();
                s.AppendLine($"{"Kind",-40} {"Before",8} {"Left",8} {"Kept",8}");
                foreach (var k in v.Before.Keys.Union(v.After.Keys).Union(v.Expected.Keys).Distinct())
                    s.AppendLine($"{Kinds.Label(k),-40} {v.Before.GetValueOrDefault(k),8} {v.After.GetValueOrDefault(k),8} {v.Expected.GetValueOrDefault(k),8}");
            }
            foreach (var l in v.Leftovers) s.AppendLine($"  Left: {l.Where}: {l.Count} {Kinds.Label(l.Kind).ToLowerInvariant()} ({l.Why}), e.g. {string.Join(", ", l.Examples)}");
            s.AppendLine();
            s.AppendLine("Keep the key file; never send it with the copy. Detection is an aid, not a guarantee: read some of the copy before it leaves.");
        }
        txtCopy.Text = s.Length == 0 ? "No copy yet: De-identify... writes one, then checks it." : s.ToString();
    }

    private void ShowColumnList(Project p)
    {
        var selected = (cboColumn.SelectedItem as ComboBoxItem)?.Tag as string;
        cboColumn.Items.Clear();
        if (Inventory is { } inv)
            foreach (var c in inv.Columns)
                cboColumn.Items.Add(new ComboBoxItem { Content = $"{c.Id}  {c.SafeDisplay}  ({Kinds.Label(p.EffectiveKind(c.Key, c.Detected))})", Tag = c.Key });
        var again = cboColumn.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string?)i.Tag == selected);
        cboColumn.SelectedItem = again ?? cboColumn.Items.OfType<ComboBoxItem>().FirstOrDefault();
        ShowColumn(p);
    }

    private ColumnReport? SelectedColumn =>
        (cboColumn.SelectedItem as ComboBoxItem)?.Tag is string key ? Inventory?.Columns.FirstOrDefault(c => c.Key == key) : null;

    private void ShowColumn(Project p)
    {
        var c = SelectedColumn;
        var has = c != null;
        cmdMarkPhi.IsEnabled = cmdNotPhi.IsEnabled = cboKind.IsEnabled = cboAction.IsEnabled = has;
        cmdClearDecision.IsEnabled = has && p.Overrides.ContainsKey(c!.Key);
        if (c is null)
        {
            txtColumn.Text = Inventory is null ? "Scan to see each column's classification, and to correct it." : "";
            return;
        }
        var kind = p.EffectiveKind(c.Key, c.Detected);
        var decided = p.Overrides.TryGetValue(c.Key, out var o) ? $" You decided: {(o.IsPhi ? Kinds.Label(kind) : "not PHI")}{(o.Note is { } n ? $" ({n})" : "")}." : "";
        txtColumn.Text = $"{Kinds.Label(kind)} · {c.Confidence:P0} sure · {c.Reason}.{decided} " +
            $"{c.Values} values read{(c.Sampled ? $" (first {c.RowsRead} of {c.RowsTotal} rows)" : "")}" +
            (c.Over89 > 0 ? $" · {c.Over89} over 89" : "") +
            $" · de-identification: {Kinds.Id(p.ActionFor(c.Key, c.Detected))}" +
            (c.Examples.Count > 0 ? $" · e.g. {string.Join("  ·  ", c.Examples.Select(e => e.Replace('\n', ' ')))}" : "");
        cboKind.SelectedItem = cboKind.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (PhiKind)i.Tag! == (kind == PhiKind.None ? c.Detected == PhiKind.None ? PhiKind.Name : c.Detected : kind));
        var chosen = p.Policy.Kind == PolicyKind.Custom && p.Policy.Actions.TryGetValue(c.Key, out var a) ? (ColumnAction?)a : null;
        cboAction.SelectedItem = cboAction.Items.OfType<ComboBoxItem>().FirstOrDefault(i => Equals(i.Tag, chosen));
    }

    private void SelectRow(int row)
    {
        // LAWgrid counts the header row as row 0 on some versions: accept either.
        var index = row >= 0 && row < _shownColumns.Count ? row : row - 1;
        if (index < 0 || index >= _shownColumns.Count) return;
        var key = _shownColumns[index].Key;
        cboColumn.SelectedItem = cboColumn.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string?)i.Tag == key);
    }

    // ───────────────────────────── the person's decisions ─────────────────────────────

    private void OnColumnChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_filling) return;
        _filling = true;
        try { ShowColumn(_history.Current); }
        finally { _filling = false; }
    }

    private void OnPhiOnlyChanged(object? sender, RoutedEventArgs e)
    {
        if (!_filling) ShowInventory(_history.Current);
    }

    /// <summary>Marks the selected column as PHI of the chosen kind (the person's decision, one undo step).</summary>
    internal void MarkSelected(bool isPhi, PhiKind? kind = null)
    {
        if (SelectedColumn is not { } c) return;
        var k = kind ?? (cboKind.SelectedItem as ComboBoxItem)?.Tag as PhiKind?;
        Change(isPhi ? $"Mark {c.Column} as {Kinds.Label(k ?? PhiKind.OtherId)}" : $"Mark {c.Column} as not PHI",
            p => p.Overrides[c.Key] = new ColumnOverride { IsPhi = isPhi, Kind = isPhi ? k : null });
        Say(isPhi ? $"{c.Id} is {Kinds.Label(k ?? PhiKind.OtherId)} now." : $"{c.Id} is not PHI now: it will be kept as it is.");
    }

    private void OnMarkPhiClick(object? sender, RoutedEventArgs e) => MarkSelected(true);

    private void OnNotPhiClick(object? sender, RoutedEventArgs e) => MarkSelected(false);

    private void OnClearDecisionClick(object? sender, RoutedEventArgs e)
    {
        if (SelectedColumn is not { } c) return;
        Change($"Clear the decision on {c.Column}", p => p.Overrides.Remove(c.Key));
    }

    private void OnActionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_filling || SelectedColumn is not { } c) return;
        var action = (cboAction.SelectedItem as ComboBoxItem)?.Tag as ColumnAction?;
        Change(action is { } a ? $"Set {c.Column} to {Kinds.Id(a)}" : $"Use the policy's action for {c.Column}", p =>
        {
            if (action is { } a)
            {
                p.Policy.Kind = PolicyKind.Custom;
                p.Policy.Actions[c.Key] = a;
            }
            else p.Policy.Actions.Remove(c.Key);
        });
    }

    private void OnPolicyChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_filling || cboPolicy.SelectedIndex < 0 || cboDates.SelectedIndex < 0) return;
        var kind = (PolicyKind)cboPolicy.SelectedIndex;
        var dates = cboDates.SelectedIndex == 1 ? DateMode.Shift : DateMode.Year;
        var now = _history.Current.Policy;
        if (now.Kind == kind && now.DateMode == dates) return;
        Change($"Policy: {Kinds.Label(kind)}", p =>
        {
            p.Policy.Kind = kind;
            p.Policy.DateMode = dates;
        });
    }

    // ───────────────────────────── sources ─────────────────────────────

    private async void OnAddFileClick(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Files to scan", AllowMultiple = true,
            FileTypeFilter = [new FilePickerFileType("Data files") { Patterns = ["*.csv", "*.tsv", "*.xlsx", "*.json", "*.jsonl", "*.txt", "*.db", "*.sqlite"] }, FilePickerFileTypes.All],
        });
        var paths = files.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
        if (paths.Count > 0) AddSources(paths);
    }

    private async void OnAddFolderClick(object? sender, RoutedEventArgs e)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "A folder to scan (with its sub-folders)", AllowMultiple = false });
        if (folders.Count > 0 && folders[0].TryGetLocalPath() is { } path) AddSources([path]);
    }

    /// <summary>Adds files, folders or SQLite files as sources, as one undo step.</summary>
    internal void AddSources(IReadOnlyList<string> paths)
    {
        try
        {
            var specs = paths.Select(CommandLine.Source).ToList();
            Change(specs.Count == 1 ? "Add a source" : $"Add {specs.Count} sources", p => { foreach (var s in specs) p.AddSource(s); });
            Say($"Added {specs.Count} source{(specs.Count == 1 ? "" : "s")}. Scan (F5) to see what they hold.");
        }
        catch (ArgumentException ex)
        {
            Say(ex.Message);
        }
    }

    private void OnRemoveSourceClick(object? sender, RoutedEventArgs e)
    {
        var p = _history.Current;
        if (lstSources.SelectedIndex < 0 || lstSources.SelectedIndex >= p.Sources.Count) { Say("Choose a source to remove."); return; }
        var id = p.Sources[lstSources.SelectedIndex].Id;
        Change($"Remove source {id}", q =>
        {
            q.Sources.RemoveAll(s => s.Id == id);
            foreach (var k in q.Overrides.Keys.Where(k => k.StartsWith(id + "|", StringComparison.Ordinal)).ToList()) q.Overrides.Remove(k);
            foreach (var k in q.Policy.Actions.Keys.Where(k => k.StartsWith(id + "|", StringComparison.Ordinal)).ToList()) q.Policy.Actions.Remove(k);
        });
    }

    private async void OnAddDatabaseClick(object? sender, RoutedEventArgs e) => await ShowAddDatabase();

    /// <summary>Adds a database: a saved connection by name, a SQLite file, or a connection string; tables optional.</summary>
    public async Task ShowAddDatabase()
    {
        var engines = new[] { DbEngine.SqlServer, DbEngine.PostgreSql, DbEngine.Sqlite };
        var saved = new ComboBox { MinWidth = 300, ItemsSource = new[] { "(none)" }.Concat(Agents.Connections.All.Select(c => c.Name)).ToList(), SelectedIndex = 0 };
        var engine = new ComboBox { MinWidth = 300, ItemsSource = engines.Select(Db.DisplayName).ToList(), SelectedIndex = 2 };
        var conn = new TextBox { Watermark = "Data Source=clinic.db   or   Server=…;Database=…;…", MinWidth = 480, PasswordChar = '•' };
        var tables = new TextBox { Watermark = "All tables (or: main.patients, main.visits)", MinWidth = 480 };
        var result = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
        var pick = new Button { Content = "SQLite File…" };
        var dialog = new Window { Title = "Add a Database", Width = 640, SizeToContent = SizeToContent.Height, CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        pick.Click += async (_, _) =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "A SQLite database", AllowMultiple = false });
            if (files.Count > 0 && files[0].TryGetLocalPath() is { } f)
            {
                engine.SelectedIndex = 2;
                conn.Text = $"Data Source={f};Pooling=False";
                conn.PasswordChar = '\0';
            }
        };
        var ok = new Button { Content = "Add", MinWidth = 90, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", MinWidth = 90 };
        cancel.Click += (_, _) => dialog.Close();
        ok.Click += async (_, _) =>
        {
            var list = (tables.Text ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            SourceSpec spec;
            DbEngine eng;
            string cs;
            if (saved.SelectedIndex > 0)
            {
                var c = Agents.Connections.Get((string)saved.SelectedItem!);
                (eng, cs) = (c.Engine, c.ConnectionString);
                spec = new SourceSpec { Kind = "database", Engine = Db.DisplayName(c.Engine), ConnectionName = c.Name, Tables = list.Count > 0 ? list : null };
            }
            else
            {
                eng = engines[Math.Max(0, engine.SelectedIndex)];
                cs = conn.Text?.Trim() ?? "";
                spec = new SourceSpec { Kind = "database", Engine = Db.DisplayName(eng), Connection = cs, Tables = list.Count > 0 ? list : null };
            }
            result.Text = "Connecting…";
            try
            {
                await Task.Run(() => Db.Test(eng, cs));
                Change("Add a database", p => p.AddSource(spec));
                dialog.Close();
                Say("Added the database. Scan (F5) to see what it holds.");
            }
            catch (Exception ex) when (ex is System.Data.Common.DbException or ArgumentException or InvalidOperationException)
            {
                result.Text = "Couldn't connect: " + Scanner.Safe(ex);
            }
        };
        static TextBlock Words(string t) => new() { Text = t, VerticalAlignment = VerticalAlignment.Center };
        dialog.Content = new StackPanel
        {
            Margin = new Thickness(20), Spacing = 10,
            Children =
            {
                new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Text = "A database is only ever read: SQLite opens read-only, and every read is inside a transaction that is rolled back. Saved connections (AI › Database Connections) keep their passwords out of the project file." },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { Words("Saved connection"), saved } },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { Words("Or engine"), engine, pick } },
                conn,
                tables,
                result,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Children = { ok, cancel } },
            },
        };
        await ChatLook.ShowModal(dialog, this);
    }

    // ───────────────────────────── scanning ─────────────────────────────

    private async void OnScanClick(object? sender, RoutedEventArgs e) => await ScanAsync();

    /// <summary>Scans every source (off the window's thread) and shows the results.</summary>
    public async Task ScanAsync()
    {
        if (_scanning) return;
        var project = _history.Current;
        if (project.Sources.Count == 0) { Say("Add a file, a folder or a database first."); return; }
        _scanning = true;
        cmdScan.IsEnabled = false;
        Say("Scanning…");
        try
        {
            var progress = new Progress<string>(Say);
            var root = SourceRoot;
            var lookup = ConnectionLookup;
            var inventory = await Task.Run(() => Scanner.Scan(project, root, lookup, progress));
            ShowScan(inventory);
            var phi = inventory.Columns.Count(c => Kinds.IsPhi(_history.Current.EffectiveKind(c.Key, c.Detected)));
            Say($"Scanned {inventory.Datasets} datasets: {phi} of {inventory.Columns.Count} columns hold PHI. Risk: {RiskSummary.Of(inventory, _history.Current).Overall}." + (inventory.Problems.Count > 0 ? $" {inventory.Problems.Count} couldn't be read (see Risk)." : ""));
        }
        finally
        {
            _scanning = false;
            cmdScan.IsEnabled = true;
        }
    }

    internal Func<string, Sources.ConnectionInfo?> ConnectionLookup => name =>
    {
        try
        {
            var c = Agents.Connections.Get(name);
            return new Sources.ConnectionInfo(c.Engine, c.ConnectionString);
        }
        catch (ArgumentException) { return null; }
    };

    private async void OnSampleRowsClick(object? sender, RoutedEventArgs e)
    {
        var box = new NumericUpDown { Minimum = 10, Maximum = 10_000_000, Increment = 1000, Value = _history.Current.SampleRows, FormatString = "0", MinWidth = 200 };
        var ok = new Button { Content = "OK", MinWidth = 90, Classes = { "accent" } };
        var dialog = new Window { Title = "Sample Rows", SizeToContent = SizeToContent.WidthAndHeight, CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        ok.Click += (_, _) =>
        {
            var rows = (int)(box.Value ?? 10_000);
            if (rows != _history.Current.SampleRows) Change($"Sample {rows} rows", p => p.SampleRows = rows);
            dialog.Close();
        };
        dialog.Content = new StackPanel
        {
            Margin = new Thickness(20), Spacing = 10,
            Children = { new TextBlock { Text = "Rows a scan reads from each table (records of a JSON file, paragraphs of a text file).\nDe-identification always reads every row.", TextWrapping = TextWrapping.Wrap }, box, ok },
        };
        await ChatLook.ShowModal(dialog, this);
    }

    // ───────────────────────────── de-identifying ─────────────────────────────

    private async void OnDeidentifyClick(object? sender, RoutedEventArgs e) => await ShowDeidentify();

    /// <summary>Asks where the copy and the key go, then writes the copy and checks it.</summary>
    public async Task ShowDeidentify()
    {
        var p = _history.Current;
        if (p.Sources.Count == 0) { Say("Add a source and scan it first."); return; }
        var output = new TextBox { Text = p.Output ?? Path.Combine(SourceRoot, "deidentified"), MinWidth = 440 };
        var key = new TextBox { Text = p.KeyFile ?? Path.Combine(SourceRoot, "phi.key"), MinWidth = 440 };
        var overwrite = new CheckBox { Content = "Write over files already in the output folder" };
        var browseOut = new Button { Content = "Browse…" };
        browseOut.Click += async (_, _) =>
        {
            var f = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "The folder the copy goes in" });
            if (f.Count > 0 && f[0].TryGetLocalPath() is { } path) output.Text = path;
        };
        var browseKey = new Button { Content = "Browse…" };
        browseKey.Click += async (_, _) =>
        {
            var f = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "The key file (made if it doesn't exist)", SuggestedFileName = "phi.key", ShowOverwritePrompt = false });
            if (f?.TryGetLocalPath() is { } path) key.Text = path;
        };
        var note = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
        var go = new Button { Content = "De-identify", MinWidth = 110, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", MinWidth = 90 };
        var dialog = new Window { Title = "De-identify", Width = 660, SizeToContent = SizeToContent.Height, CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        cancel.Click += (_, _) => dialog.Close();
        go.Click += async (_, _) =>
        {
            go.IsEnabled = false;
            note.Text = "Writing the copy…";
            var error = await DeidentifyAsync(output.Text ?? "", key.Text ?? "", overwrite.IsChecked == true);
            if (error is null) dialog.Close();
            else { note.Text = error; go.IsEnabled = true; }
        };
        static TextBlock Words(string t) => new() { Text = t, VerticalAlignment = VerticalAlignment.Center, Width = 90 };
        dialog.Content = new StackPanel
        {
            Margin = new Thickness(20), Spacing = 10,
            Children =
            {
                new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Text = $"Policy: {p.Policy.Describe()}. The sources are only read; the copy goes into a folder of its own (not inside a source folder). Tokens and date shifts come from the key file: keep it, use it again to get the same tokens, and never send it with the copy." },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { Words("Output folder"), output, browseOut } },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { Words("Key file"), key, browseKey } },
                overwrite,
                note,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Children = { go, cancel } },
            },
        };
        await ChatLook.ShowModal(dialog, this);
    }

    /// <summary>Writes the copy and verifies it; returns why it couldn't, or null.</summary>
    internal async Task<string?> DeidentifyAsync(string output, string keyFile, bool overwrite)
    {
        var p = _history.Current;
        if (string.IsNullOrWhiteSpace(output) || string.IsNullOrWhiteSpace(keyFile)) return "Give an output folder and a key file.";
        var outFull = Path.GetFullPath(output);
        var keyFull = Path.GetFullPath(keyFile);
        if (keyFull.StartsWith(Path.TrimEndingDirectorySeparator(outFull) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            return "The key file must not be inside the output folder: whoever gets the copy must not get the key.";
        if (!overwrite && Directory.Exists(outFull) && Directory.EnumerateFileSystemEntries(outFull).Any())
            return "The output folder already has files in it: choose an empty folder, or tick Write over files.";
        try
        {
            DeidentifyRun.CheckOutput(p, SourceRoot, outFull);
            var key = KeyFile.LoadOrCreate(keyFull, out var made);
            var root = SourceRoot;
            var lookup = ConnectionLookup;
            var inventory = Inventory ?? await Task.Run(() => Scanner.Scan(p, root, lookup, skip: outFull));
            if (Inventory is null) ShowScan(inventory);
            Say("Writing the de-identified copy…");
            var result = await Task.Run(() => DeidentifyRun.Run(p, inventory, root, outFull, key, lookup, overwrite));
            ShowRun(result);
            if (p.Output != outFull || p.KeyFile != keyFull)
                Change("Set the output folder and key file", q => { q.Output = outFull; q.KeyFile = keyFull; });
            Say("Checking the copy…");
            var verify = await Task.Run(() => Verifier.Verify(outFull, p.Policy, inventory, lookup));
            ShowVerify(verify);
            Say((made ? "Made a new key file. " : "") + $"Wrote the copy: {result.Summary}. {verify.Summary}");
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            return Scanner.Safe(ex);
        }
    }

    private async void OnVerifyClick(object? sender, RoutedEventArgs e)
    {
        var f = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "A de-identified copy to check" });
        if (f.Count == 0 || f[0].TryGetLocalPath() is not { } path) return;
        Say("Checking the copy…");
        var p = _history.Current;
        var inventory = Inventory;
        var lookup = ConnectionLookup;
        var result = await Task.Run(() => Verifier.Verify(path, p.Policy, inventory, lookup));
        ShowVerify(result);
        Say(result.Summary + (inventory is null ? " (Scan the sources first to check for their original values too.)" : ""));
    }

    // ───────────────────────────── files ─────────────────────────────

    private static readonly FilePickerFileType ProjectType = new("AVA PHI Scanner project") { Patterns = ["*.phiscan"] };

    private void OnNewClick(object? sender, RoutedEventArgs e)
    {
        Adopt(new Project(), null);
        Say("A new project.");
    }

    private async void OnOpenClick(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Open a project", FileTypeFilter = [ProjectType] });
        if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
        try
        {
            Adopt(ProjectFiles.Load(path), path);
            Say($"Opened {Path.GetFileName(path)}. Scan (F5) to see its results.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Text.Json.JsonException)
        {
            Say("Couldn't open it: " + ex.Message);
        }
    }

    private async void OnSaveClick(object? sender, RoutedEventArgs e)
    {
        if (_filePath is null) await SaveAs();
        else SaveTo(_filePath);
    }

    private async void OnSaveAsClick(object? sender, RoutedEventArgs e) => await SaveAs();

    private async Task SaveAs()
    {
        var path = await ChatLook.Save(this, "Save the project", "project.phiscan", ProjectType);
        if (path != null) SaveTo(path);
    }

    internal void SaveTo(string path)
    {
        ProjectFiles.Save(_history.Current, path);
        _filePath = path;
        _history.MarkSaved();
        Say($"Saved {Path.GetFileName(path)}. It holds database connection strings (with any password): keep it private.");
    }

    private async void OnExportClick(object? sender, RoutedEventArgs e)
    {
        if (Inventory is null) { Say("Scan first: the report is the scan's."); return; }
        var path = await ChatLook.Save(this, "Export the report", "phi-report.xlsx",
            new FilePickerFileType("Excel workbook") { Patterns = ["*.xlsx"] }, new FilePickerFileType("Web page") { Patterns = ["*.html"] });
        if (path is null) return;
        try
        {
            ReportWriter.Write(path, Inventory, _history.Current, LastVerify);
            Say($"Exported the report to {Path.GetFileName(path)} (every value in it is masked).");
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or UnauthorizedAccessException)
        {
            Say("Couldn't export it: " + ex.Message);
        }
    }

    // ───────────────────────────── keys and menus ─────────────────────────────

    private void OnUndoClick(object? sender, RoutedEventArgs e) => Undo();

    private void OnRedoClick(object? sender, RoutedEventArgs e) => Redo();

    private void OnWindowKeyDown(object? sender, Avalonia.Input.KeyEventArgs e)
    {
        var ctrl = e.KeyModifiers.HasFlag(Avalonia.Input.KeyModifiers.Control) || e.KeyModifiers.HasFlag(Avalonia.Input.KeyModifiers.Meta);
        var shift = e.KeyModifiers.HasFlag(Avalonia.Input.KeyModifiers.Shift);
        // The chat's input box takes its own Ctrl+Z (its text); everywhere else Ctrl+Z undoes a change to the project.
        if (ChatHolder.IsKeyboardFocusWithin && e.Key is Avalonia.Input.Key.Z or Avalonia.Input.Key.Y) return;
        switch (e.Key)
        {
            case Avalonia.Input.Key.F12:
                ToggleChat();
                e.Handled = true;
                break;
            case Avalonia.Input.Key.F5:
                _ = ScanAsync();
                e.Handled = true;
                break;
            case Avalonia.Input.Key.Z when ctrl && !shift:
                Undo();
                e.Handled = true;
                break;
            case Avalonia.Input.Key.Y when ctrl:
            case Avalonia.Input.Key.Z when ctrl && shift:
                Redo();
                e.Handled = true;
                break;
            case Avalonia.Input.Key.N when ctrl:
                OnNewClick(null, new RoutedEventArgs());
                e.Handled = true;
                break;
            case Avalonia.Input.Key.O when ctrl:
                OnOpenClick(null, new RoutedEventArgs());
                e.Handled = true;
                break;
            case Avalonia.Input.Key.S when ctrl:
                OnSaveClick(null, new RoutedEventArgs());
                e.Handled = true;
                break;
        }
    }
}
