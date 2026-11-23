using System.Collections.Generic;
using System.Linq;

namespace AVAPHIScanner;

/// <summary>
/// The parts of the SQL that differ between engines: row limits, alias quoting, casts and the derived-field
/// functions. AVA Query Builder's copy, cut to what the scanner needs (reading tables row by row is in <see cref="DbRead"/>).
/// </summary>
public static class Dialect
{
    /// <summary>A column alias, quoted: [alias] for SQL Server, "alias" for the others.</summary>
    public static string Alias(DbEngine engine, string alias) => engine == DbEngine.SqlServer
        ? $"[{alias.Replace("]", "]]")}]"
        : $"\"{alias.Replace("\"", "\"\"")}\"";

    /// <summary>" AS alias", or nothing when there is no alias.</summary>
    public static string As(DbEngine engine, string? alias) =>
        string.IsNullOrWhiteSpace(alias) ? string.Empty : $" AS {Alias(engine, alias)}";

    /// <summary>True when the row limit goes after SELECT (TOP n); false when it ends the query (LIMIT n).</summary>
    public static bool LimitsWithTop(DbEngine engine) => engine == DbEngine.SqlServer;

    /// <summary>The first <paramref name="rows"/> rows of a table, for the field browser.</summary>
    public static string Preview(DbEngine engine, string table, int rows) => LimitsWithTop(engine)
        ? $"SELECT TOP {rows} * FROM {table}"
        : $"SELECT * FROM {table} LIMIT {rows}";

    /// <summary>
    /// A filter's "cast as" choice (VARCHAR, INT, DATE, DATETIME, DECIMAL) applied to a field. SQLite has no
    /// date type, so dates go through its DATE() and DATETIME() functions instead of CAST.
    /// </summary>
    public static string Cast(DbEngine engine, string field, string castAs) => (engine, castAs) switch
    {
        (DbEngine.SqlServer, "VARCHAR") => $"CAST({field} AS VARCHAR(MAX))",
        (DbEngine.PostgreSql, "DATETIME") => $"CAST({field} AS TIMESTAMP)",
        (DbEngine.Sqlite, "VARCHAR") => $"CAST({field} AS TEXT)",
        (DbEngine.Sqlite, "INT") => $"CAST({field} AS INTEGER)",
        (DbEngine.Sqlite, "DECIMAL") => $"CAST({field} AS NUMERIC)",
        (DbEngine.Sqlite, "DATE") => $"DATE({field})",
        (DbEngine.Sqlite, "DATETIME") => $"DATETIME({field})",
        _ => $"CAST({field} AS {castAs})"
    };

    /// <summary>A table's name quoted for the engine: [dbo].[Patients], "public"."patients", "main"."patients".</summary>
    public static string Table(DbEngine engine, string schemaAndTable) => DbRead.Quote(engine, schemaAndTable);
}
