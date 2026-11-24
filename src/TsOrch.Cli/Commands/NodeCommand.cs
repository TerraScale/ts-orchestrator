using static System.FormattableString;

namespace TsOrch.Cli;

internal static class NodeCommand
{
    private const string UsageText = "ts-orch node ls | drain <id> | activate <id> | reboot <id> | rm <id> [--force] | upgrade <version> --url <url> --sha256 <sha256> [--node <id>]";

    public static IReadOnlyList<CliOption> Options { get; } =
    [
        new("url", null, true),
        new("sha256", null, true),
        new("node", null, true),
        new("force", null, false),
    ];

    public static Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["ls"] => ListAsync(environment, cancellationToken),
            [var action and ("drain" or "activate"), var nodeId] => ChangeStateAsync(nodeId, action, environment, cancellationToken),
            ["reboot", var nodeId] => RebootAsync(nodeId, environment, cancellationToken),
            ["rm", var nodeId] => RemoveAsync(nodeId, arguments.Flag("force"), environment, cancellationToken),
            ["upgrade", var version] => UpgradeAsync(version, arguments, environment, cancellationToken),
            _ => Task.FromResult(environment.Usage($"usage: {UsageText}")),
        };

    private static async Task<int> ListAsync(CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.GetAsync("/api/nodes", CliJsonContext.Default.NodeListResponse, response => Task.FromResult(Render(response, environment)), environment.FailRead, cancellationToken);

    private static int Render(NodeListResponse response, CommandEnvironment environment)
    {
        var table = new TextTable("NODE", "REGION", "POOL", "STATUS", "DRAIN", "VCN IP", "NETBIRD IP", "ARCH", "SHAPE", "FAULT DOMAIN", "CPU", "MEM GiB", "LAST SEEN");
        foreach (var node in response.Nodes.OrderBy(static node => node.Region, StringComparer.Ordinal).ThenBy(static node => node.Id, StringComparer.Ordinal))
        {
            table.Add(
                node.Id,
                node.Region,
                node.PoolKind.WireName,
                node.Status.WireName,
                node.DrainRequested ? "yes" : "no",
                node.VcnIp,
                node.NetbirdIp ?? "-",
                node.Arch.WireName,
                node.Shape,
                node.FaultDomain,
                Invariant($"{node.CpuTotalMilli / 1000.0:F1}"),
                Invariant($"{node.MemTotalMiB / 1024.0:F1}"),
                Display.Age(environment.TimeProvider, node.LastSeenAt));
        }

        table.WriteTo(environment.Out);
        return ExitCodes.Ok;
    }

    private static async Task<int> ChangeStateAsync(string nodeId, string action, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/{action}", CliJsonContext.Default.NodeInfo, node => Task.FromResult(Changed(node, environment.Out)), environment.Fail, cancellationToken);

    private static int Changed(NodeInfo node, TextWriter output)
    {
        output.WriteLine($"Node {node.Id}: {node.Status.WireName}{(node.DrainRequested ? ", drain requested" : string.Empty)}");
        return ExitCodes.Ok;
    }

    private static async Task<int> RebootAsync(string nodeId, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/reboot", CliJsonContext.Default.RebootResponse, response => Task.FromResult(Rebooted(response, environment.Out)), environment.Fail, cancellationToken);

    private static int Rebooted(RebootResponse response, TextWriter output)
    {
        output.WriteLine($"Node {response.NodeId}: {response.Action} requested for instance {response.InstanceId}");
        return ExitCodes.Ok;
    }

    private static async Task<int> RemoveAsync(string nodeId, bool force, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var path = Query.Build($"/api/nodes/{Uri.EscapeDataString(nodeId)}", ("force", force ? "true" : null));
        return await environment.Api.DeleteAsync(path, CliJsonContext.Default.DeletedNodeResponse, response => Task.FromResult(Removed(response, environment.Out)), environment.Fail, cancellationToken);
    }

    private static int Removed(DeletedNodeResponse response, TextWriter output)
    {
        output.WriteLine($"Removed node {response.Deleted}.");
        return ExitCodes.Ok;
    }

    private static async Task<int> UpgradeAsync(string version, CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var url = arguments.Value("url");
        var sha256 = arguments.Value("sha256");
        if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(sha256))
        {
            return environment.Usage("usage: ts-orch node upgrade <version> --url <url> --sha256 <sha256> [--node <id>]");
        }

        return await environment.Api.PostAsync(
            "/api/nodes/upgrade",
            new NodeUpgradeRequest(version, url, sha256, arguments.Value("node")),
            CliJsonContext.Default.NodeUpgradeRequest,
            CliJsonContext.Default.NodeUpgradeResponse,
            response => Task.FromResult(Upgraded(response, environment.Out)),
            environment.Fail,
            cancellationToken);
    }

    private static int Upgraded(NodeUpgradeResponse response, TextWriter output)
    {
        output.WriteLine($"Sent agent upgrade {response.Version} to {response.Nodes.Count} node(s): {Display.List(response.Nodes)}");
        return ExitCodes.Ok;
    }
}
