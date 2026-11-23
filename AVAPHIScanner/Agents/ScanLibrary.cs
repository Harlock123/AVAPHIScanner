using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using AVAPHIScanner.Agents.Mcp;

namespace AVAPHIScanner.Agents;

/// <summary>
/// Draws the inventory as a picture (render_view, render_checkpoint, the chat's timeline): a control of its own built
/// by <see cref="InventoryLook"/>, inside <paramref name="host"/>, a panel in a window that has no size and clips, so
/// controls take their look but nothing shows on screen. Everything drawn is masked.
/// </summary>
public sealed class ScanLibrary(Panel host) : IScanLibrary
{
    public byte[] Picture(Project project, Inventory? inventory, double scale)
    {
        var view = InventoryLook.Build(project, inventory);
        var scaled = new LayoutTransformControl { Child = view, LayoutTransform = new ScaleTransform(scale, scale) };
        var stage = new Canvas();
        stage.Children.Add(scaled);
        host.Children.Add(stage);
        try
        {
            scaled.Measure(Size.Infinity);
            var want = scaled.DesiredSize;
            scaled.Arrange(new Rect(want));
            scaled.UpdateLayout();
            var pixels = new PixelSize(Math.Max(1, (int)Math.Ceiling(want.Width)), Math.Max(1, (int)Math.Ceiling(want.Height)));
            using var bitmap = new RenderTargetBitmap(pixels, new Vector(96, 96));
            bitmap.Render(scaled);
            using var png = new MemoryStream();
            bitmap.Save(png);
            return png.ToArray();
        }
        finally
        {
            stage.Children.Clear();
            host.Children.Remove(stage);
        }
    }
}

/// <summary>The inventory as a picture: a heading with the risk and the policy, then the PHI columns, coloured by kind.</summary>
public static class InventoryLook
{
    public static IBrush KindBrush(PhiKind kind) => Kinds.Info(kind).Category switch
    {
        KindCategory.Direct => new SolidColorBrush(Color.Parse("#F6C7C1")),
        KindCategory.Quasi => new SolidColorBrush(Color.Parse("#FBE2B4")),
        KindCategory.Text => new SolidColorBrush(Color.Parse("#D9D3F5")),
        KindCategory.Provider => new SolidColorBrush(Color.Parse("#CFE6F7")),
        _ => new SolidColorBrush(Color.Parse("#E3EFE3")),
    };

    public static Control Build(Project project, Inventory? inventory, int maxRows = 26)
    {
        var ink = new SolidColorBrush(Color.Parse("#1C1C1C"));
        var muted = new SolidColorBrush(Color.Parse("#5A5A5A"));
        var panel = new StackPanel { Spacing = 6, Margin = new Thickness(16), Width = 980 };
        panel.Children.Add(new TextBlock { Text = "PHI inventory", FontSize = 18, FontWeight = FontWeight.SemiBold, Foreground = ink });
        if (inventory is null)
        {
            panel.Children.Add(new TextBlock { Text = $"No scan yet. {project.Sources.Count} source{(project.Sources.Count == 1 ? "" : "s")}; policy: {project.Policy.Describe()}.", Foreground = muted });
            return Frame(panel);
        }
        var risk = RiskSummary.Of(inventory, project);
        var phi = inventory.Columns.Where(c => Kinds.IsPhi(project.EffectiveKind(c.Key, c.Detected)) || project.EffectiveKind(c.Key, c.Detected) == PhiKind.Npi).ToList();
        panel.Children.Add(new TextBlock
        {
            Text = $"{inventory.Datasets} datasets · {inventory.Columns.Count} columns · {phi.Count} with PHI · risk {risk.Overall} · {project.Policy.Describe()}",
            Foreground = muted, TextWrapping = TextWrapping.Wrap,
        });
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("44,300,170,60,60,*,96"), Margin = new Thickness(0, 6, 0, 0) };
        string[] heads = ["Id", "Where", "Kind", "Sure", "Count", "Examples (masked)", "Action"];
        var row = 0;
        void Add(Control c, int column, int r)
        {
            Grid.SetColumn(c, column);
            Grid.SetRow(c, r);
            grid.Children.Add(c);
        }
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        for (var i = 0; i < heads.Length; i++)
            Add(new Border { Background = new SolidColorBrush(Color.Parse("#ECECEC")), Padding = new Thickness(4, 3), Child = new TextBlock { Text = heads[i], FontWeight = FontWeight.SemiBold, Foreground = ink, FontSize = 12 } }, i, 0);
        foreach (var c in phi.Take(maxRows))
        {
            row++;
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var kind = project.EffectiveKind(c.Key, c.Detected);
            var set = project.Overrides.ContainsKey(c.Key);
            TextBlock Cell(string text, IBrush? fg = null) => new() { Text = text, Foreground = fg ?? ink, FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
            var line = new SolidColorBrush(Color.Parse("#E2E2E2"));
            Control Wrap(Control child, IBrush? bg = null) => new Border { BorderBrush = line, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(4, 3), Background = bg, Child = child };
            Add(Wrap(Cell(c.Id, muted)), 0, row);
            Add(Wrap(Cell(c.SafeDisplay)), 1, row);
            Add(Wrap(Cell(Kinds.Label(kind) + (set ? " ✓" : "")), KindBrush(kind)), 2, row);
            Add(Wrap(Cell($"{c.Confidence:P0}", c.Confidence < 0.6 ? new SolidColorBrush(Color.Parse("#B3261E")) : ink)), 3, row);
            Add(Wrap(Cell(c.Count.ToString())), 4, row);
            Add(Wrap(Cell(string.Join("  ·  ", c.Examples.Select(e => e.Replace('\n', ' '))), muted)), 5, row);
            Add(Wrap(Cell(Kinds.Id(project.ActionFor(c.Key, c.Detected)))), 6, row);
        }
        panel.Children.Add(grid);
        if (phi.Count > maxRows) panel.Children.Add(new TextBlock { Text = $"…and {phi.Count - maxRows} more.", Foreground = muted, FontSize = 12 });
        if (phi.Count == 0) panel.Children.Add(new TextBlock { Text = "No PHI found.", Foreground = muted });
        return Frame(panel);
    }

    private static Control Frame(Control content) => new Border { Background = Brushes.White, Child = content };
}
