using System.Text;

namespace TsOrch.Cli;

internal static class CliCommands
{
    public static IReadOnlyList<CliCommand> All { get; } =
    [
        new("login", "ts-orch login [--key PATH] [--url URL]", "Sign in with an SSH Ed25519 key and cache the session", LoginCommand.Options, LoginCommand.RunAsync),
        new("agent", "ts-orch agent [--backplane-url URL] [--state-dir DIR] [--runtime-dir DIR] ...", "Run the node agent until SIGINT/SIGTERM", AgentCommand.Options, AgentCommand.RunAsync),
        new("edge", "ts-orch edge [--runtime-dir DIR] [--bind IP] [--http-port N] [--https-port N] ...", "Run the HTTP/TLS/Postgres edge proxy until SIGINT/SIGTERM", EdgeCommand.Options, EdgeCommand.RunAsync),
        new("seed", "ts-orch seed [--fleet PATH] [--services DIR] [--replace]", "Seed the fleet config and service definitions", SeedCommand.Options, SeedCommand.RunAsync),
        new("status", "ts-orch status [--region R] [--json]", "Show regions, nodes, services and active rollouts", StatusCommand.Options, StatusCommand.RunAsync),
        new("top", "ts-orch top [--region R] [--once]", "Live node CPU, PSI, memory, disk, RPS and p95", TopCommand.Options, TopCommand.RunAsync),
        new("diff", "ts-orch diff [-f PATH]", "Diff local service definitions against live desired state", DiffCommand.Options, DiffCommand.RunAsync),
        new("deploy", "ts-orch deploy <service> <image> [--region R] [--wait]", "Start a canary and wave rollout", DeployCommand.Options, DeployCommand.RunAsync),
        new("rollback", "ts-orch rollback <service> [--region R]", "Roll a service back to its previous image", RollbackCommand.Options, RollbackCommand.RunAsync),
        new("service", "ts-orch service ls | apply -f <file-or-dir> | rm <name>", "Manage service definitions", ServiceCommand.Options, ServiceCommand.RunAsync),
        new("node", "ts-orch node ls | drain <id> | activate <id> | reboot <id>", "Manage nodes", NodeCommand.Options, NodeCommand.RunAsync),
        new("logs", "ts-orch logs <service> [--node ID] [--tail N] [-f]", "Stream container logs through the backplane", LogsCommand.Options, LogsCommand.RunAsync),
        new("events", "ts-orch events [-f] [--region R] [--limit N]", "Show or follow fleet events", EventsCommand.Options, EventsCommand.RunAsync),
        new("exec", "ts-orch exec <node> <service> [--timeout S] -- <cmd...>", "Run a bounded diagnostic command in a container", RemoteExecCommand.Options, RemoteExecCommand.RunAsync),
        new("secrets", "ts-orch secrets check [-f PATH] | refresh <service>", "Verify OCI Vault secrets or trigger a secret reload", SecretsCommand.Options, SecretsCommand.RunAsync),
        new("netbird", NetBirdCommand.Usage, "Initialize, join, enroll, or inspect the NetBird network", NetBirdCommand.Options, NetBirdCommand.RunAsync, InteractiveSigning: false),
        new("mcp", "ts-orch mcp", "Serve read-only MCP tools (status, logs, metrics, events, diff, netbird_status) on stdio", McpCommand.Options, McpCommand.RunAsync, InteractiveSigning: false),
    ];

    public static CliCommand? Find(string name) => All.FirstOrDefault(command => command.Name == name);

    public static string Usage()
    {
        var builder = new StringBuilder()
            .AppendLine("usage: ts-orch <command> [options]")
            .AppendLine()
            .AppendLine("commands:");
        var width = All.Max(static command => command.Name.Length);
        foreach (var command in All)
        {
            builder.Append("  ").Append(command.Name.PadRight(width)).Append("  ").AppendLine(command.Summary);
        }

        return builder
            .Append("  ").Append("version".PadRight(width)).AppendLine("  Print the ts-orch version")
            .AppendLine()
            .AppendLine("Run 'ts-orch <command> --help' for command usage.")
            .AppendLine()
            .Append("environment: ").Append(OperatorSettings.UrlVariable).Append(" (default ").Append(OperatorSettings.DefaultUrl.AbsoluteUri.TrimEnd('/')).Append("), ")
            .Append(OperatorSettings.TokenVariable).Append(", ").Append(OperatorSettings.KeyVariable).Append(", ").AppendLine(OperatorSettings.SessionVariable)
            .ToString();
    }

    public static string Help(CliCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        var builder = new StringBuilder().Append("usage: ").AppendLine(command.Usage).AppendLine().AppendLine(command.Summary);
        if (command.Options.Count > 0)
        {
            builder.AppendLine().AppendLine("options:");
            foreach (var option in command.Options)
            {
                builder.Append("  ");
                if (option.Short is { } shortName)
                {
                    builder.Append('-').Append(shortName).Append(", ");
                }

                builder.Append("--").Append(option.Name).AppendLine(option.TakesValue ? " VALUE" : string.Empty);
            }
        }

        return builder.ToString();
    }
}
