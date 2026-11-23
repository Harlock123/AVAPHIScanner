using System.Net;
using System.Text;
using ClosedXML.Excel;

namespace AVAPHIScanner;

/// <summary>How risky one table (or file, or sheet) is, and why.</summary>
public sealed record TableRisk(string Where, string Level, List<PhiKind> Direct, List<PhiKind> Quasi, int TextFindings, string Explanation, int Rows);

/// <summary>A scan's risk summary: each table's level, and the whole in a few lines.</summary>
public sealed class RiskSummary
{
    public List<TableRisk> Tables { get; } = [];
    public string Overall { get; set; } = "None";
    public int DirectColumns { get; set; }
    public int QuasiColumns { get; set; }
    public int TextColumns { get; set; }
    public int Columns { get; set; }
    public List<string> Notes { get; } = [];

    /// <summary>
    /// Direct identifiers (or identifiers inside free text) make a table High; two or more quasi-identifiers together
    /// (a birth date and a ZIP code) Medium; one Low. Names are masked.
    /// </summary>
    public static RiskSummary Of(Inventory inventory, Project project)
    {
        var risk = new RiskSummary { Columns = inventory.Columns.Count };
        foreach (var g in inventory.Columns.GroupBy(c => (c.Location, c.Table)))
        {
            var kinds = g.Select(c => (c, k: project.EffectiveKind(c.Key, c.Detected))).ToList();
            var direct = kinds.Where(x => Kinds.Info(x.k).Category == KindCategory.Direct).Select(x => x.k).Distinct().ToList();
            var quasi = kinds.Where(x => Kinds.Info(x.k).Category == KindCategory.Quasi).Select(x => x.k).Distinct().ToList();
            var text = kinds.Where(x => x.k == PhiKind.FreeText).Sum(x => x.c.TextCounts.Where(t => t.Key != PhiKind.Npi).Sum(t => t.Value));
            risk.DirectColumns += kinds.Count(x => Kinds.Info(x.k).Category == KindCategory.Direct);
            risk.QuasiColumns += kinds.Count(x => Kinds.Info(x.k).Category == KindCategory.Quasi);
            risk.TextColumns += kinds.Count(x => x.k == PhiKind.FreeText);
            var level = direct.Count > 0 || text > 0 ? "High" : quasi.Count >= 2 ? "Medium" : quasi.Count == 1 ? "Low" : "None";
            var why = new List<string>();
            if (direct.Count > 0) why.Add($"{Join(direct)} identif{(direct.Count == 1 ? "ies" : "y")} people on {(direct.Count == 1 ? "its" : "their")} own");
            if (text > 0) why.Add($"free text holds {text} identifier{(text == 1 ? "" : "s")}");
            if (quasi.Count >= 2) why.Add($"{Join(quasi)} together narrow people down (a birth date, ZIP code and sex identify most Americans)");
            else if (quasi.Count == 1) why.Add($"{Join(quasi)} alone narrows people down a little");
            if (why.Count == 0) why.Add("nothing found that identifies a person");
            var first = g.First();
            risk.Tables.Add(new TableRisk(Mask.Label(first.Table.Length == 0 ? first.Location : $"{first.Location} › {first.Table}"), level, direct, quasi, text,
                char.ToUpperInvariant(why[0][0]) + string.Join("; ", why)[1..] + ".", (int)Math.Min(int.MaxValue, first.RowsTotal ?? first.RowsRead)));
        }
        risk.Overall = risk.Tables.Any(t => t.Level == "High") ? "High" : risk.Tables.Any(t => t.Level == "Medium") ? "Medium" : risk.Tables.Any(t => t.Level == "Low") ? "Low" : "None";
        if (inventory.Columns.Where(c => c.Over89 > 0).ToList() is { Count: > 0 } old)
            risk.Notes.Add($"{old.Sum(c => c.Over89)} birth dates or ages over 89, in {old.Count} column{(old.Count == 1 ? "" : "s")} (the same person may be in several): Safe Harbor shows such ages as 90+ and their birth year as 90 years ago.");
        if (inventory.Columns.Any(c => c.Sampled)) risk.Notes.Add("Some tables were sampled (only their first rows were read): counts are for the rows read.");
        if (inventory.Columns.Any(c => c.Confidence < 0.6 && Kinds.IsPhi(c.Detected))) risk.Notes.Add("Some columns were classified with low confidence: check them, and override where the scan is wrong.");
        return risk;

        static string Join(List<PhiKind> kinds)
        {
            var labels = kinds.Select(k => Kinds.Label(k).ToLowerInvariant()).ToList();
            return labels.Count == 1 ? labels[0] : string.Join(", ", labels[..^1]) + " and " + labels[^1];
        }
    }
}

/// <summary>The scan report as an Excel workbook or a web page: the risk summary, the inventory and the free-text findings, all masked.</summary>
public static class ReportWriter
{
    public static void Write(string path, Inventory inventory, Project project, VerifyResult? verify = null)
    {
        if (Path.GetExtension(path).Equals(".xlsx", StringComparison.OrdinalIgnoreCase)) Xlsx(path, inventory, project, verify);
        else if (Path.GetExtension(path).ToLowerInvariant() is ".html" or ".htm") File.WriteAllText(path, Html(inventory, project, verify), new UTF8Encoding(false));
        else throw new NotSupportedException("A report is an .xlsx or .html file.");
    }

    /// <summary>One row of the inventory as the report and the window show it.</summary>
    public static string[] Row(ColumnReport c, Project project)
    {
        var kind = project.EffectiveKind(c.Key, c.Detected);
        var overridden = project.Overrides.ContainsKey(c.Key);
        return
        [
            c.Id, Mask.Label(c.Location), Mask.Label(c.Table), Mask.Label(c.Column), Kinds.Label(kind) + (overridden ? " (set by you)" : ""),
            $"{c.Confidence:P0}", c.Detected == PhiKind.FreeText ? $"{c.Count} with identifiers" : c.Count.ToString(),
            Kinds.Id(project.ActionFor(c.Key, c.Detected)), string.Join("  ·  ", c.Examples),
        ];
    }

    public static readonly string[] Headings = ["Id", "Source", "Table / sheet", "Column", "Kind", "Confidence", "Count", "Action", "Examples (masked)"];

    private static void Xlsx(string path, Inventory inventory, Project project, VerifyResult? verify)
    {
        using var book = new XLWorkbook();
        var risk = RiskSummary.Of(inventory, project);
        var summary = book.Worksheets.Add("Summary");
        var r = 1;
        summary.Cell(r++, 1).Value = "AVA PHI Scanner report";
        summary.Cell(1, 1).Style.Font.Bold = true;
        summary.Cell(1, 1).Style.Font.FontSize = 14;
        summary.Cell(r++, 1).Value = $"Scanned {inventory.When:yyyy-MM-dd HH:mm}: {inventory.Datasets} datasets, {inventory.Columns.Count} columns, {inventory.RowsRead} rows read.";
        summary.Cell(r++, 1).Value = $"Overall risk: {risk.Overall}. Columns with direct identifiers: {risk.DirectColumns}; quasi-identifiers: {risk.QuasiColumns}; free text: {risk.TextColumns}.";
        summary.Cell(r++, 1).Value = $"Policy: {project.Policy.Describe()}.";
        foreach (var n in risk.Notes) summary.Cell(r++, 1).Value = n;
        r++;
        string[] riskHead = ["Where", "Risk", "Direct identifiers", "Quasi-identifiers", "Identifiers in free text", "Rows", "Why"];
        for (var i = 0; i < riskHead.Length; i++) { summary.Cell(r, i + 1).Value = riskHead[i]; summary.Cell(r, i + 1).Style.Font.Bold = true; }
        foreach (var t in risk.Tables)
        {
            r++;
            summary.Cell(r, 1).Value = t.Where;
            summary.Cell(r, 2).Value = t.Level;
            summary.Cell(r, 3).Value = string.Join(", ", t.Direct.Select(Kinds.Label));
            summary.Cell(r, 4).Value = string.Join(", ", t.Quasi.Select(Kinds.Label));
            summary.Cell(r, 5).Value = t.TextFindings;
            summary.Cell(r, 6).Value = t.Rows;
            summary.Cell(r, 7).Value = t.Explanation;
            summary.Cell(r, 2).Style.Fill.BackgroundColor = t.Level switch { "High" => XLColor.FromHtml("#F8C9C4"), "Medium" => XLColor.FromHtml("#FBE3B8"), "Low" => XLColor.FromHtml("#FFF6C7"), _ => XLColor.FromHtml("#D9F0DC") };
        }
        r += 2;
        foreach (var line in Caveats) summary.Cell(r++, 1).Value = line;
        summary.Columns().AdjustToContents(1, 200);
        summary.Column(1).Width = Math.Min(summary.Column(1).Width, 60);

        var sheet = book.Worksheets.Add("Inventory");
        for (var i = 0; i < Headings.Length; i++) { sheet.Cell(1, i + 1).Value = Headings[i]; sheet.Cell(1, i + 1).Style.Font.Bold = true; }
        sheet.Cell(1, Headings.Length + 1).Value = "Why";
        sheet.Cell(1, Headings.Length + 1).Style.Font.Bold = true;
        var row = 2;
        foreach (var c in inventory.Columns)
        {
            var values = Row(c, project);
            for (var i = 0; i < values.Length; i++) sheet.Cell(row, i + 1).Value = values[i];
            sheet.Cell(row, values.Length + 1).Value = c.Reason;
            row++;
        }
        sheet.SheetView.FreezeRows(1);
        sheet.Columns().AdjustToContents(1, Math.Min(row, 300));

        var text = book.Worksheets.Add("Free-text findings");
        string[] th = ["Column", "Row", "Kind", "Found (masked)"];
        for (var i = 0; i < th.Length; i++) { text.Cell(1, i + 1).Value = th[i]; text.Cell(1, i + 1).Style.Font.Bold = true; }
        row = 2;
        foreach (var c in inventory.Columns.Where(c => c.Findings.Count > 0))
            foreach (var f in c.Findings)
            {
                text.Cell(row, 1).Value = $"{c.Id} {c.SafeDisplay}";
                text.Cell(row, 2).Value = f.Row;
                text.Cell(row, 3).Value = Kinds.Label(f.Kind);
                text.Cell(row, 4).Value = f.Masked;
                row++;
            }
        text.Columns().AdjustToContents(1, Math.Min(row, 300));

        if (verify != null)
        {
            var v = book.Worksheets.Add("Verify");
            v.Cell(1, 1).Value = verify.Summary;
            string[] vh = ["Kind", "Before (source)", "Left in the copy", "Kept by the policy"];
            for (var i = 0; i < vh.Length; i++) { v.Cell(3, i + 1).Value = vh[i]; v.Cell(3, i + 1).Style.Font.Bold = true; }
            var vr = 4;
            foreach (var k in verify.Before.Keys.Union(verify.After.Keys).Union(verify.Expected.Keys).Distinct())
            {
                v.Cell(vr, 1).Value = Kinds.Label(k);
                v.Cell(vr, 2).Value = verify.Before.GetValueOrDefault(k);
                v.Cell(vr, 3).Value = verify.After.GetValueOrDefault(k);
                v.Cell(vr, 4).Value = verify.Expected.GetValueOrDefault(k);
                vr++;
            }
            vr++;
            foreach (var l in verify.Leftovers)
            {
                v.Cell(vr, 1).Value = l.Where;
                v.Cell(vr, 2).Value = Kinds.Label(l.Kind);
                v.Cell(vr, 3).Value = l.Count;
                v.Cell(vr, 4).Value = string.Join("  ·  ", l.Examples);
                v.Cell(vr, 5).Value = l.Why;
                vr++;
            }
            v.Columns().AdjustToContents();
        }
        book.SaveAs(path);
    }

    public static readonly string[] Caveats =
    [
        "Detection is an aid, not a guarantee. The scanner reads samples, uses name lists and patterns, and can miss identifiers (a name nobody wrote down elsewhere, an identifier in an unusual format) or flag things that aren't.",
        "HIPAA Safe Harbor also requires that the covered entity has no actual knowledge that what is left could identify someone, alone or with other information. That judgement is yours, not the program's.",
        "Shifted dates keep intervals but are not Safe Harbor's own rule (which keeps only the year): with shifted dates, the result rests on an expert determination. Keyed tokens keep joins: keep the key secret and away from whoever receives the copy.",
    ];

    public static string Html(Inventory inventory, Project project, VerifyResult? verify = null)
    {
        var risk = RiskSummary.Of(inventory, project);
        string E(string s) => WebUtility.HtmlEncode(s);
        var h = new StringBuilder();
        h.Append("""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>PHI Scan Report</title>
            <style>
            :root{--bg:#fff;--fg:#1c1c1c;--muted:#666;--line:#ddd;--high:#f8c9c4;--medium:#fbe3b8;--low:#fff6c7;--none:#d9f0dc;--head:#f3f3f3}
            @media (prefers-color-scheme: dark){:root{--bg:#1f1f22;--fg:#e6e6e6;--muted:#aaa;--line:#444;--high:#6b2b25;--medium:#6b4b1c;--low:#5c5620;--none:#24492b;--head:#2b2b2e}}
            body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);margin:24px;line-height:1.4}
            h1{font-size:1.4em;margin:0 0 4px} h2{font-size:1.1em;margin-top:28px} .muted{color:var(--muted)}
            table{border-collapse:collapse;width:100%;font-size:.9em} th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
            th{background:var(--head);position:sticky;top:0} td.High{background:var(--high)} td.Medium{background:var(--medium)} td.Low{background:var(--low)} td.None{background:var(--none)}
            code{font-family:ui-monospace,Menlo,Consolas,monospace} .wrap{overflow-x:auto}
            </style></head><body>
            """);
        h.Append($"<h1>PHI scan report</h1><p class=\"muted\">AVA PHI Scanner · scanned {inventory.When:yyyy-MM-dd HH:mm} · {inventory.Datasets} datasets · {inventory.Columns.Count} columns · {inventory.RowsRead} rows read · policy: {E(project.Policy.Describe())}</p>");
        h.Append($"<h2>Risk: {E(risk.Overall)}</h2><p>Columns with direct identifiers: <b>{risk.DirectColumns}</b>; quasi-identifiers: <b>{risk.QuasiColumns}</b>; free text: <b>{risk.TextColumns}</b>.</p><ul>");
        foreach (var n in risk.Notes) h.Append($"<li>{E(n)}</li>");
        h.Append("</ul><div class=\"wrap\"><table><tr><th>Where</th><th>Risk</th><th>Direct</th><th>Quasi</th><th>In free text</th><th>Rows</th><th>Why</th></tr>");
        foreach (var t in risk.Tables)
            h.Append($"<tr><td>{E(t.Where)}</td><td class=\"{t.Level}\">{t.Level}</td><td>{E(string.Join(", ", t.Direct.Select(Kinds.Label)))}</td><td>{E(string.Join(", ", t.Quasi.Select(Kinds.Label)))}</td><td>{t.TextFindings}</td><td>{t.Rows}</td><td>{E(t.Explanation)}</td></tr>");
        h.Append("</table></div><h2>Inventory</h2><div class=\"wrap\"><table><tr>");
        foreach (var head in Headings) h.Append($"<th>{E(head)}</th>");
        h.Append("<th>Why</th></tr>");
        foreach (var c in inventory.Columns)
        {
            h.Append("<tr>");
            foreach (var v in Row(c, project)) h.Append($"<td>{E(v)}</td>");
            h.Append($"<td class=\"muted\">{E(c.Reason)}</td></tr>");
        }
        h.Append("</table></div>");
        var findings = inventory.Columns.Where(c => c.Findings.Count > 0).ToList();
        if (findings.Count > 0)
        {
            h.Append("<h2>Identifiers in free text</h2><div class=\"wrap\"><table><tr><th>Column</th><th>Row</th><th>Kind</th><th>Found (masked)</th></tr>");
            foreach (var c in findings)
                foreach (var f in c.Findings.Take(100))
                    h.Append($"<tr><td>{E(c.Id + " " + c.SafeDisplay)}</td><td>{f.Row}</td><td>{E(Kinds.Label(f.Kind))}</td><td><code>{E(f.Masked)}</code></td></tr>");
            h.Append("</table></div>");
        }
        if (verify != null)
        {
            h.Append($"<h2>Verification</h2><p>{E(verify.Summary)}</p>");
            if (verify.Leftovers.Count > 0)
            {
                h.Append("<div class=\"wrap\"><table><tr><th>Where</th><th>Kind</th><th>Count</th><th>Examples (masked)</th><th>Why</th></tr>");
                foreach (var l in verify.Leftovers) h.Append($"<tr><td>{E(l.Where)}</td><td>{E(Kinds.Label(l.Kind))}</td><td>{l.Count}</td><td>{E(string.Join(" · ", l.Examples))}</td><td>{E(l.Why)}</td></tr>");
                h.Append("</table></div>");
            }
        }
        h.Append("<h2>Before you share anything</h2><ul>");
        foreach (var c in Caveats) h.Append($"<li>{E(c)}</li>");
        h.Append("</ul></body></html>");
        return h.ToString();
    }
}
