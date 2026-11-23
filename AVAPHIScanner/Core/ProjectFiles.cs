namespace AVAPHIScanner;

/// <summary>Project files: paths inside the project's folder are kept relative to it, so the folder can move.</summary>
public static class ProjectFiles
{
    public static Project Load(string path)
    {
        var p = Project.FromJson(File.ReadAllText(path));
        var folder = Path.GetDirectoryName(Path.GetFullPath(path))!;
        foreach (var s in p.Sources)
        {
            if (s.Path is { Length: > 0 } sp && !Path.IsPathRooted(sp)) s.Path = Path.GetFullPath(Path.Combine(folder, sp));
            if (s.Kind == "database" && s.Connection is { } cs && (s.Engine ?? "").Equals("SQLite", StringComparison.OrdinalIgnoreCase))
            {
                var b = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(cs);
                if (!Path.IsPathRooted(b.DataSource)) b.DataSource = Path.GetFullPath(Path.Combine(folder, b.DataSource));
                s.Connection = b.ConnectionString;
            }
        }
        if (p.Output is { Length: > 0 } o && !Path.IsPathRooted(o)) p.Output = Path.GetFullPath(Path.Combine(folder, o));
        if (p.KeyFile is { Length: > 0 } k && !Path.IsPathRooted(k)) p.KeyFile = Path.GetFullPath(Path.Combine(folder, k));
        return p;
    }

    public static void Save(Project project, string path)
    {
        var p = project.Clone();
        var folder = Path.GetDirectoryName(Path.GetFullPath(path))!;
        // Relative to the project's folder (with .. where needed), so the folder and its data can move together; a path
        // on another drive stays absolute (GetRelativePath gives it back as it is).
        string Rel(string full) => Path.GetRelativePath(folder, full).Replace('\\', '/');
        foreach (var s in p.Sources)
        {
            if (s.Path is { Length: > 0 } sp && Path.IsPathRooted(sp)) s.Path = Rel(sp);
            if (s.Kind == "database" && s.Connection is { } cs && (s.Engine ?? "").Equals("SQLite", StringComparison.OrdinalIgnoreCase))
            {
                var b = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(cs);
                if (Path.IsPathRooted(b.DataSource)) b.DataSource = Rel(b.DataSource);
                s.Connection = b.ConnectionString;
            }
        }
        if (p.Output is { Length: > 0 } o && Path.IsPathRooted(o)) p.Output = Rel(o);
        if (p.KeyFile is { Length: > 0 } k && Path.IsPathRooted(k)) p.KeyFile = Rel(k);
        Directory.CreateDirectory(folder);
        File.WriteAllText(path, p.ToJson());
    }
}
