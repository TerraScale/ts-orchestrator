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

        var parsed = CliArguments.Parse([.. args.Skip(1)], command.Options);
        if (!parsed.TryGetValue(out var arguments, out var parseError))
        {
            return Report(console, command, parseError);
        }

        if (arguments.HelpRequested)
        {
            console.Out.Write(CliCommands.Help(command));
            return ExitCodes.Ok;
        }

        using var httpClient = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"ts-orch/{Version.Split('+')[0]}");
        var http = new OrchHttp(httpClient, timeProvider);
        var api = new OrchApi(http, new OperatorAuth(http, console, timeProvider, command.InteractiveSigning));
        var outcome = await command.RunAsync(arguments, new CommandEnvironment(console, timeProvider, http, api), cancellationToken);
        return outcome switch
        {
            int exitCode => exitCode,
            OrchError error => Report(console, command, error),
        };
    }

    private static int Report(CliConsole console, CliCommand command, OrchError error)
    {
        console.Error.WriteLine($"ts-orch {command.Name}: {error.Message}");
        return ExitCodes.For(error);
    }
}
