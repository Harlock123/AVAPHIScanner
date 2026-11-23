using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Headless;
using AVAPHIScanner.Agents;

[assembly: AvaloniaTestApplication(typeof(AVAPHIScanner.Tests.HeadlessApp))]
// One app for the whole run: resetting between tests leaves a render queued after its fonts are gone.
[assembly: AvaloniaTestIsolation(AvaloniaTestIsolationLevel.PerAssembly)]

namespace AVAPHIScanner.Tests;

/// <summary>The app, rendered by Skia off screen: windows and dialogs can be driven and pictured without a screen.</summary>
public static class HeadlessApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UseSkia()
        .WithInterFont()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });

    /// <summary>Runs <paramref name="action"/> on the headless UI thread.</summary>
    public static void Run(Action action) =>
        HeadlessUnitTestSession.GetOrStartForAssembly(typeof(HeadlessApp).Assembly)
            .Dispatch(action, CancellationToken.None).GetAwaiter().GetResult();
}

/// <summary>
/// Before any test runs: the AI side's settings, keys, token, connections and saved chats go to a temporary folder, so
/// no test reads or writes the person's own (and none ever finds a real API key).
/// </summary>
internal static class SettingsIsolation
{
    [ModuleInitializer]
    internal static void Isolate() =>
        AgentSettings.FolderOverride = Directory.CreateTempSubdirectory("avaphiscanner-agents-").FullName;
}

/// <summary>The sample data, and copies of it to work on.</summary>
public static class Samples
{
    /// <summary>The repository's samples folder.</summary>
    public static string Folder
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "samples", "members.csv"))) return Path.Combine(dir.FullName, "samples");
            throw new FileNotFoundException("samples/members.csv wasn't found above the test folder.");
        }
    }

    /// <summary>A temporary working folder holding a copy of the samples in "samples" (the generator script left out).</summary>
    public static string WorkingCopy(string prefix = "aps-")
    {
        var root = Directory.CreateTempSubdirectory(prefix).FullName;
        Copy(Folder, Path.Combine(root, "samples"));
        return root;
    }

    private static void Copy(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var f in Directory.GetFiles(from))
            if (!f.EndsWith(".cs", StringComparison.Ordinal)) File.Copy(f, Path.Combine(to, Path.GetFileName(f)));
        foreach (var d in Directory.GetDirectories(from)) Copy(d, Path.Combine(to, Path.GetFileName(d)));
    }

    /// <summary>A fixed key, so tokens are the same from run to run.</summary>
    public static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    public static readonly DateOnly Today = new(2026, 11, 23);

    /// <summary>The members file's rows, by header.</summary>
    public static List<Dictionary<string, string>> Members(string? folder = null) => Table(Path.Combine(folder ?? Folder, "members.csv"));

    public static List<Dictionary<string, string>> Table(string csv)
    {
        using var r = Sources.OpenText(csv);
        var rows = Csv.Read(r, ',').ToList();
        return rows.Skip(1).Select(x => rows[0].Select((h, i) => (h, v: i < x.Length ? x[i] : "")).ToDictionary(p => p.h, p => p.v)).ToList();
    }

    /// <summary>
    /// Every raw value of the samples that must never reach an agent: names, SSNs, MRNs, member IDs, phones, emails,
    /// street addresses and full birth dates, as they are written in the files.
    /// </summary>
    public static List<string> Secrets(string? folder = null)
    {
        var list = new List<string>();
        foreach (var m in Members(folder))
        {
            list.Add(m["first_name"] + " " + m["last_name"]);
            list.Add(m["last_name"]);
            list.Add(m["ssn"]);
            list.Add(m["mrn"]);
            list.Add(m["phone"]);
            list.Add(m["email"]);
            list.Add(m["street"]);
            list.Add(m["dob"]);
            list.Add(DateTime.Parse(m["dob"], System.Globalization.CultureInfo.InvariantCulture).ToString("MM/dd/yyyy", System.Globalization.CultureInfo.InvariantCulture));
            list.Add(m["member_id"]);
        }
        // Short last names (Osei, Novak) are kept: they must not appear either. First names alone are too common in
        // ordinary words to test as substrings, so they're tested with the last name.
        return list.Where(s => s.Length >= 4).Distinct().ToList();
    }

    /// <summary>The raw values found in <paramref name="text"/>, if any.</summary>
    public static List<string> Leaks(string text, IEnumerable<string> secrets) =>
        secrets.Where(s => text.Contains(s, StringComparison.OrdinalIgnoreCase)).ToList();
}
