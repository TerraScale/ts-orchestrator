using System.Collections.Frozen;
using System.Reflection;

namespace TsOrch.Cli;

public static class CliApp
{
    private static readonly FrozenSet<string> Commands = FrozenSet.Create(
        StringComparer.Ordinal,
        "login",
        "agent",
        "edge",
        "status",
        "top",
        "diff",
        "deploy",
        "rollback",
        "service",
        "node",
        "logs",
        "events",
        "exec",
        "secrets",
        "mcp");

    public static int Run(IReadOnlyList<string> args, TextWriter stdout, TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        if (args.Count == 0 || args[0] is "help" or "--help" or "-h")
        {
            stdout.WriteLine(Usage());
            return 0;
        }

        if (args[0] is "version" or "--version")
        {
            stdout.WriteLine(Version());
            return 0;
        }

        if (Commands.Contains(args[0]))
        {
            stderr.WriteLine($"ts-orch {args[0]}: not available in this build");
            return 69;
        }

        stderr.WriteLine($"ts-orch: unknown command '{args[0]}'");
        stderr.WriteLine(Usage());
        return 64;
    }

    private static string Version() =>
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("ts-orch is built without an informational version");

    private static string Usage() =>
        "usage: ts-orch <command>\ncommands: " + string.Join(", ", Commands.Order(StringComparer.Ordinal)) + ", version";
}
