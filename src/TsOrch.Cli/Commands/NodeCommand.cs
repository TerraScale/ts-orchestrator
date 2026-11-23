using static System.FormattableString;

namespace TsOrch.Cli;

internal static class NodeCommand
{
    private const string UsageText = "ts-orch node ls | drain <id> | activate <id> | reboot <id>";

    public static IReadOnlyList<CliOption> Options { get; } = [];

    public static Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["ls"] => ListAsync(environment, cancellationToken),
            [var action and ("drain" or "activate"), var nodeId] => ChangeStateAsync(nodeId, action, environment, cancellationToken),
            ["reboot", var nodeId] => RebootAsync(nodeId, environment, cancellationToken),
            _ => Task.FromResult<OrchResult<int>>(new Validation($"usage: {UsageText}")),
        };

    private static async Task<OrchResult<int>> ListAsync(CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var listed = await environment.Api.GetAsync("/api/nodes", CliJsonContext.Default.NodeListResponse, cancellationToken);
        if (!listed.TryGetValue(out var response, out var error))
        {
            return error;
        }

        var table = new TextTable("NODE", "REGION", "POOL", "STATUS", "DRAIN", "VCN IP", "ARCH", "SHAPE", "FAULT DOMAIN", "CPU", "MEM GiB", "LAST SEEN");
        foreach (var node in response.Nodes.OrderBy(static node => node.Region, StringComparer.Ordinal).ThenBy(static node => node.Id, StringComparer.Ordinal))
        {
            table.Add(
                node.Id,
                node.Region,
                node.PoolKind.WireName,
                node.Status.WireName,
                node.DrainRequested ? "yes" : "no",
                node.VcnIp,
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

    private static async Task<OrchResult<int>> ChangeStateAsync(string nodeId, string action, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var changed = await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/{action}", CliJsonContext.Default.NodeInfo, cancellationToken);
        if (!changed.TryGetValue(out var node, out var error))
        {
            return error;
        }

        environment.Out.WriteLine($"Node {node.Id}: {node.Status.WireName}{(node.DrainRequested ? ", drain requested" : string.Empty)}");
        return ExitCodes.Ok;
    }

    private static async Task<OrchResult<int>> RebootAsync(string nodeId, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var rebooted = await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/reboot", CliJsonContext.Default.RebootResponse, cancellationToken);
        if (!rebooted.TryGetValue(out var response, out var error))
        {
            return error;
        }

        environment.Out.WriteLine($"Node {response.NodeId}: {response.Action} requested for instance {response.InstanceId}");
        return ExitCodes.Ok;
    }
}
