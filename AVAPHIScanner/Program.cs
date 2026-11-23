using Avalonia;

namespace AVAPHIScanner;

class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static int Main(string[] args)
    {
        // AVAPHIScanner --mcp: the MCP server for AI agents, with no window (see Agents/AgentMain).
        if (Agents.Mcp.McpCommandLine.Wanted(args)) return Agents.AgentMain.Run(args);
        // AVAPHIScanner --scan … / --deidentify … / --verify …: the command line, with no window (Core/CommandLine).
        if (CommandLine.Wanted(args)) return CommandLine.Run(args, Console.Out, Console.Error);
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
