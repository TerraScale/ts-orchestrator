using System.Reflection;

namespace TsOrch.Cli;

internal static class CliApp
{
    public static string Version { get; } =
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("ts-orch is built without an informational version.");

    public static async Task<int> RunAsync(IReadOnlyList<string> args, CliConsole console, TimeProvider timeProvider, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(console);
        if (args is [] or ["help" or "--help" or "-h", ..])
        {
            console.Out.Write(CliCommands.Usage());
            return ExitCodes.Ok;
        }

        if (args is ["version" or "--version", ..])
        {
            console.Out.WriteLine(Version);
            return ExitCodes.Ok;
        }

        if (CliCommands.Find(args[0]) is not { } command)
        {
            console.Error.WriteLine($"ts-orch: unknown command '{args[0]}'");
            console.Error.Write(CliCommands.Usage());
            return ExitCodes.Usage;
        }

        using var httpClient = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"ts-orch/{Version.Split('+')[0]}");
        var http = new OrchHttp(httpClient, timeProvider);
        var api = new OrchApi(http, new OperatorAuth(http, console, timeProvider, command.InteractiveSigning));
        var environment = new CommandEnvironment(command.Name, console, timeProvider, http, api);
        return CliArguments.Parse([.. args.Skip(1)], command.Options) switch
        {
            CliArguments { HelpRequested: true } => Help(console, command),
            CliArguments arguments => await command.RunAsync(arguments, environment, cancellationToken),
            Validation failure => environment.Fail(failure),
        };
    }

    private static int Help(CliConsole console, CliCommand command)
    {
        console.Out.Write(CliCommands.Help(command));
        return ExitCodes.Ok;
    }
}
