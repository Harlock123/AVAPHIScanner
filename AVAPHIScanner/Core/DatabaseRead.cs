using System.Data.Common;
using System.Globalization;
using Microsoft.Data.Sqlite;

namespace AVAPHIScanner;

/// <summary>
/// What this program adds to the copied <see cref="Db"/>: reading a whole table row by row, read-only, for scanning and
/// de-identifying. Nothing here writes to a source database: SQLite opens read-only, and every read is inside a
/// transaction that is rolled back (read-only on PostgreSQL too).
/// </summary>
public static class DbRead
{
    /// <summary>A table's name quoted for its engine: [dbo].[Patients], "public"."patients", "main"."patients".</summary>
    public static string Quote(DbEngine engine, string schemaAndTable)
    {
        var parts = schemaAndTable.Split('.', 2);
        string Q(string p) => engine == DbEngine.SqlServer ? $"[{p.Replace("]", "]]")}]" : $"\"{p.Replace("\"", "\"\"")}\"";
        return parts.Length == 2 ? $"{Q(parts[0])}.{Q(parts[1])}" : Q(parts[0]);
    }

    /// <summary>The first <paramref name="rows"/> rows of a table (all of them when null).</summary>
    public static string Select(DbEngine engine, string table, int? rows) => rows is { } n
        ? (engine == DbEngine.SqlServer ? $"SELECT TOP {n} * FROM {Quote(engine, table)}" : $"SELECT * FROM {Quote(engine, table)} LIMIT {n}")
        : $"SELECT * FROM {Quote(engine, table)}";

    public static long Count(DbEngine engine, string cs, string table)
    {
        long total = 0;
        Stream(engine, cs, $"SELECT COUNT(*) FROM {Quote(engine, table)}", _ => { }, r => { total = long.Parse(r[0] ?? "0", CultureInfo.InvariantCulture); return false; });
        return total;
    }

    /// <summary>
    /// Runs <paramref name="sql"/> read-only and hands each row to <paramref name="row"/> as text (null for NULL) until it
    /// returns false. <paramref name="columns"/> gets the column names first.
    /// </summary>
    public static void Stream(DbEngine engine, string cs, string sql, Action<IReadOnlyList<string>> columns, Func<string?[], bool> row)
    {
        if (engine == DbEngine.Sqlite)
            cs = new SqliteConnectionStringBuilder(cs) { Mode = SqliteOpenMode.ReadOnly }.ConnectionString;
        using var conn = Db.Open(engine, cs);
        using var tx = conn.BeginTransaction();
        try
        {
            if (engine == DbEngine.PostgreSql)
            {
                using var ro = conn.CreateCommand();
                ro.Transaction = tx;
                ro.CommandText = "SET TRANSACTION READ ONLY";
                ro.ExecuteNonQuery();
            }
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.CommandTimeout = 300;
            using var reader = cmd.ExecuteReader();
            var names = new List<string>();
            for (var i = 0; i < reader.FieldCount; i++)
                names.Add(string.IsNullOrEmpty(reader.GetName(i)) ? $"Column{i + 1}" : reader.GetName(i));
            columns(names);
            while (reader.Read())
            {
                var values = new string?[reader.FieldCount];
                for (var i = 0; i < reader.FieldCount; i++)
                    values[i] = reader.IsDBNull(i) ? null : Text(reader.GetValue(i));
                if (!row(values)) break;
            }
        }
        finally
        {
            try { tx.Rollback(); } catch (Exception e) when (e is InvalidOperationException or DbException) { }
        }
    }

    /// <summary>A database value as text: dates as ISO dates (with the time when there is one), numbers invariant.</summary>
    public static string Text(object value) => value switch
    {
        DateTime d => d.TimeOfDay == TimeSpan.Zero ? d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : d.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        DateTimeOffset o => o.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        DateOnly d => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        byte[] b => $"({b.Length} bytes)",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    /// <summary>A database's name for reports and output folders: the file's name for SQLite, else the database's.</summary>
    public static string DisplayName(DbEngine engine, string cs)
    {
        try
        {
            return engine switch
            {
                DbEngine.Sqlite => Path.GetFileName(new SqliteConnectionStringBuilder(cs).DataSource),
                DbEngine.PostgreSql => new Npgsql.NpgsqlConnectionStringBuilder(cs).Database ?? "postgres",
                _ => new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(cs).InitialCatalog is { Length: > 0 } c ? c : "sqlserver",
            };
        }
        catch (ArgumentException)
        {
            return Db.DisplayName(engine);
        }
    }
}
