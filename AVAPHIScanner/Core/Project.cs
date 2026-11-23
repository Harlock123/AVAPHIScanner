using System.Text.Json;
using System.Text.Json.Serialization;

namespace AVAPHIScanner;

/// <summary>A person's decision about a column: it is PHI (and of which kind), or it isn't.</summary>
public sealed class ColumnOverride
{
    [JsonPropertyName("is_phi")] public bool IsPhi { get; set; }

    /// <summary>The kind, when <see cref="IsPhi"/>; the detected kind is kept when this is null.</summary>
    [JsonPropertyName("kind")] public PhiKind? Kind { get; set; }

    [JsonPropertyName("note")] public string? Note { get; set; }
}

/// <summary>
/// The rules a de-identified copy is made by: Safe Harbor, a limited data set, or custom (Safe Harbor with the person's
/// own action for chosen columns), and what Safe Harbor does with dates.
/// </summary>
public sealed class Policy
{
    [JsonPropertyName("kind")] public PolicyKind Kind { get; set; } = PolicyKind.SafeHarbor;

    [JsonPropertyName("date_mode")] public DateMode DateMode { get; set; } = DateMode.Year;

    /// <summary>Column actions by column key, for a custom policy.</summary>
    [JsonPropertyName("actions")] public Dictionary<string, ColumnAction> Actions { get; set; } = [];

    /// <summary>The column whose value says whose row it is (for date shifting); by default each table's member ID, else MRN, else SSN.</summary>
    [JsonPropertyName("person_key")] public string? PersonKey { get; set; }

    /// <summary>How database tables are written: "csv" (a file per table) or "sqlite" (one database).</summary>
    [JsonPropertyName("database_output")] public string DatabaseOutput { get; set; } = "csv";

    /// <summary>What the policy does with a column of <paramref name="kind"/> (its key: <paramref name="key"/>).</summary>
    public ColumnAction ActionFor(string key, PhiKind kind)
    {
        if (Kind == PolicyKind.Custom && Actions.TryGetValue(key, out var chosen)) return chosen;
        var info = Kinds.Info(kind);
        var action = Kind == PolicyKind.LimitedDataSet ? info.LimitedDataSet : info.SafeHarbor;
        if (action == ColumnAction.ShiftDate && DateMode == DateMode.Year && Kind != PolicyKind.LimitedDataSet) action = ColumnAction.Generalise;
        return action;
    }

    /// <summary>"Safe Harbor (dates to year only)", "Custom: 2 column actions"…</summary>
    public string Describe() => Kind switch
    {
        PolicyKind.LimitedDataSet => "Limited Data Set (dates, city, state, ZIP code and ages kept)",
        PolicyKind.Custom => $"Custom: Safe Harbor{(DateMode == DateMode.Year ? " (dates to year)" : " (dates shifted)")} with {Actions.Count} column action{(Actions.Count == 1 ? "" : "s")}",
        _ => DateMode == DateMode.Year ? "Safe Harbor (dates to year only)" : "Safe Harbor (dates shifted per person)",
    };
}

/// <summary>
/// A scanning project, saved as a .phiscan file (JSON): its sources, the person's decisions about columns, the
/// de-identification policy, and where the copy and the key go. Scan results aren't kept in it: they come from scanning.
/// </summary>
public sealed class Project
{
    public const string Extension = ".phiscan";

    [JsonPropertyName("format")] public string Format { get; set; } = "avaphiscanner.project";

    [JsonPropertyName("version")] public int Version { get; set; } = 1;

    [JsonPropertyName("sources")] public List<SourceSpec> Sources { get; set; } = [];

    /// <summary>The person's decisions, by column key.</summary>
    [JsonPropertyName("overrides")] public Dictionary<string, ColumnOverride> Overrides { get; set; } = [];

    [JsonPropertyName("policy")] public Policy Policy { get; set; } = new();

    /// <summary>How many rows of each table (records of a JSON file, paragraphs of a text file) a scan reads.</summary>
    [JsonPropertyName("sample_rows")] public int SampleRows { get; set; } = 10_000;

    /// <summary>The folder de-identified copies are written to.</summary>
    [JsonPropertyName("output")] public string? Output { get; set; }

    /// <summary>The key file tokens and date shifts are made with (never the key itself).</summary>
    [JsonPropertyName("key_file")] public string? KeyFile { get; set; }

    [JsonPropertyName("next_source")] public int NextSource { get; set; } = 1;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static Project FromJson(string json)
    {
        var p = JsonSerializer.Deserialize<Project>(json, JsonOptions) ?? throw new InvalidDataException("That isn't a project file.");
        if (p.Format != "avaphiscanner.project") throw new InvalidDataException("That isn't an AVA PHI Scanner project (.phiscan) file.");
        return p;
    }

    public Project Clone() => FromJson(ToJson());

    /// <summary>What a column is, with the person's decision over the scan's.</summary>
    public PhiKind EffectiveKind(string key, PhiKind detected) =>
        Overrides.TryGetValue(key, out var o) ? (o.IsPhi ? o.Kind ?? (detected == PhiKind.None ? PhiKind.OtherId : detected) : PhiKind.None) : detected;

    /// <summary>What de-identification does to a column.</summary>
    public ColumnAction ActionFor(string key, PhiKind detected) => Policy.ActionFor(key, EffectiveKind(key, detected));

    public SourceSpec AddSource(SourceSpec source)
    {
        source.Id = $"s{NextSource++}";
        Sources.Add(source);
        return source;
    }
}

/// <summary>
/// The project's undo history: every step is the whole project after it (sources, decisions, policy), whether the
/// person or an agent made it. A copy of AVA Query Builder's QueryHistory, on projects.
/// </summary>
public sealed class ProjectHistory
{
    private readonly List<(string Json, string Label)> _states = [];
    private int _index;
    private int _saved;

    public ProjectHistory(Project start) => Reset(start);

    /// <summary>Raised after every change to the history (a step, undo, redo, reset).</summary>
    public event Action? Changed;

    public int Index => _index;

    public bool CanUndo => _index > 0;

    public bool CanRedo => _index < _states.Count - 1;

    public string? UndoLabel => CanUndo ? _states[_index].Label : null;

    public string? RedoLabel => CanRedo ? _states[_index + 1].Label : null;

    public bool IsDirty => _index != _saved;

    /// <summary>The project now, as a fresh copy.</summary>
    public Project Current => Project.FromJson(_states[_index].Json);

    public string CurrentJson => _states[_index].Json;

    public void Reset(Project start)
    {
        _states.Clear();
        _states.Add((start.ToJson(), "Start"));
        _index = 0;
        _saved = 0;
        Changed?.Invoke();
    }

    /// <summary>Records <paramref name="after"/> as one step named <paramref name="label"/>; false if nothing changed.</summary>
    public bool Commit(Project after, string label)
    {
        var json = after.ToJson();
        if (json == _states[_index].Json) return false;
        _states.RemoveRange(_index + 1, _states.Count - _index - 1);
        if (_saved > _index) _saved = -1;
        _states.Add((json, label));
        _index++;
        Changed?.Invoke();
        return true;
    }

    public Project? Undo()
    {
        if (!CanUndo) return null;
        _index--;
        Changed?.Invoke();
        return Current;
    }

    public Project? Redo()
    {
        if (!CanRedo) return null;
        _index++;
        Changed?.Invoke();
        return Current;
    }

    /// <summary>Folds the last <paramref name="steps"/> steps into one named <paramref name="label"/> (a batch).</summary>
    public void Squash(int steps, string label)
    {
        if (steps < 1 || steps > _index) return;
        var last = _states[_index].Json;
        var start = _index - steps + 1;
        _states.RemoveRange(start, _states.Count - start);
        _states.Add((last, label));
        _index = start;
        if (_saved > _index) _saved = -1;
        Changed?.Invoke();
    }

    /// <summary>Drops the steps that could be redone (after a failed batch is undone).</summary>
    public void ForgetRedo()
    {
        _states.RemoveRange(_index + 1, _states.Count - _index - 1);
        if (_saved > _index) _saved = -1;
        Changed?.Invoke();
    }

    public void MarkSaved()
    {
        _saved = _index;
        Changed?.Invoke();
    }
}
