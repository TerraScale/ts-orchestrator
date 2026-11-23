using static System.FormattableString;

namespace TsOrch.Cli;

internal static class NodeCommand
{
    private const string UsageText = "ts-orch node ls | drain <id> | activate <id> | reboot <id>";

    public static IReadOnlyList<CliOption> Options { get; } = [];

    public static Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["ls"] => ListAsync(environment, cancellationToken),
            [var action and ("drain" or "activate"), var nodeId] => ChangeStateAsync(nodeId, action, environment, cancellationToken),
            ["reboot", var nodeId] => RebootAsync(nodeId, environment, cancellationToken),
            _ => Task.FromResult(environment.Fail(new Validation($"usage: {UsageText}"))),
        };

    private static async Task<int> ListAsync(CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.GetAsync("/api/nodes", CliJsonContext.Default.NodeListResponse, cancellationToken) switch
        {
            NodeListResponse response => Render(response, environment),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Render(NodeListResponse response, CommandEnvironment environment)
    {
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

    private static async Task<int> ChangeStateAsync(string nodeId, string action, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/{action}", CliJsonContext.Default.NodeInfo, cancellationToken) switch
        {
            NodeInfo node => Changed(node, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Changed(NodeInfo node, TextWriter output)
    {
        output.WriteLine($"Node {node.Id}: {node.Status.WireName}{(node.DrainRequested ? ", drain requested" : string.Empty)}");
        return ExitCodes.Ok;
    }

    private static async Task<int> RebootAsync(string nodeId, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostEmptyAsync($"/api/nodes/{Uri.EscapeDataString(nodeId)}/reboot", CliJsonContext.Default.RebootResponse, cancellationToken) switch
        {
            RebootResponse response => Rebooted(response, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Rebooted(RebootResponse response, TextWriter output)
    {
        output.WriteLine($"Node {response.NodeId}: {response.Action} requested for instance {response.InstanceId}");
        return ExitCodes.Ok;
    }
}
