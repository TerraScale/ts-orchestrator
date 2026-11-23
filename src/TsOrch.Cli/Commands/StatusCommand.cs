using static System.FormattableString;

namespace TsOrch.Cli;

internal static class StatusCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("json", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch status [--region R] [--json]") switch
        {
            Done when arguments.Flag("json") => await environment.Api.GetTextAsync(Path(arguments), cancellationToken) switch
            {
                string json => Print(json, environment.Out),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Done => await environment.Api.GetAsync(Path(arguments), ApiJsonContext.Default.StatusResponse, cancellationToken) switch
            {
                StatusResponse status => Render(status, environment.Out, environment.TimeProvider),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static string Path(CliArguments arguments) => Query.Build("/api/status", ("region", arguments.Value("region")));

    private static int Print(string json, TextWriter output)
    {
        output.WriteLine(json);
        return ExitCodes.Ok;
    }

    private static int Render(StatusResponse status, TextWriter output, TimeProvider timeProvider)
    {
        output.WriteLine($"REGIONS ({status.Regions.Count})");
        var regions = new TextTable("REGION", "HEALTH", "NODES", "READY", "STATEFUL", "WORKER", "CPU REQ/TOTAL", "MEM REQ/TOTAL GiB", "PACKING", "ATLAS DBS");
        foreach (var region in status.Regions)
        {
            regions.Add(
                region.Label,
                region.Health.WireName,
                Display.Integer(region.Nodes),
                Display.Integer(region.NodesReady),
                Display.Integer(region.StatefulNodes),
                Display.Integer(region.WorkerNodes),
                Invariant($"{region.CpuRequestedMilli / 1000.0:F1}/{region.CpuTotalMilli / 1000.0:F1}"),
                Invariant($"{region.MemRequestedMiB / 1024.0:F1}/{region.MemTotalMiB / 1024.0:F1}"),
                Invariant($"{region.PackingPct:F1}%"),
                Display.Integer(region.Databases));
        }

        regions.WriteTo(output);

        output.WriteLine();
        output.WriteLine($"NODES ({status.Nodes.Count})");
        var nodes = new TextTable("NODE", "REGION", "POOL", "STATUS", "VCN IP", "ARCH", "SHAPE", "CPU", "MEM GiB", "DISK GiB", "LAST SEEN", "AGENT");
        foreach (var node in status.Nodes.OrderBy(static node => node.Region, StringComparer.Ordinal).ThenBy(static node => node.Id, StringComparer.Ordinal))
        {
            nodes.Add(
                node.Id,
                node.Region,
                node.PoolKind.WireName,
                node.DrainRequested && node.Status == NodeStatus.Active ? "active (drain requested)" : node.Status.WireName,
                node.VcnIp,
                node.Arch.WireName,
                node.Shape,
                Invariant($"{node.CpuTotalMilli / 1000.0:F1}"),
                Invariant($"{node.MemTotalMiB / 1024.0:F1}"),
                Display.Integer(node.DiskTotalGiB),
                Display.Age(timeProvider, node.LastSeenAt),
                node.AgentVersion);
        }

        nodes.WriteTo(output);

        output.WriteLine();
        output.WriteLine($"SERVICES ({status.Services.Count})");
        var services = new TextTable("SERVICE", "MODE", "PRIORITY", "READY", "REGIONS", "IMAGE");
        foreach (var service in status.Services.OrderBy(static service => service.Name, StringComparer.Ordinal))
        {
            services.Add(
                service.Name,
                service.Mode.WireName,
                service.Priority.WireName,
                Invariant($"{service.Ready}/{service.Desired}"),
                Display.List(service.Regions),
                service.Image);
        }

        services.WriteTo(output);

        var active = status.Rollouts.Where(static rollout => !RolloutStates.IsTerminal(rollout.Phase)).ToList();
        output.WriteLine();
        output.WriteLine($"ACTIVE ROLLOUTS ({active.Count})");
        var rollouts = new TextTable("ROLLOUT", "SERVICE", "PHASE", "WAVE", "REGION", "STARTED", "TARGET");
        foreach (var rollout in active)
        {
            rollouts.Add(
                rollout.Id,
                rollout.ServiceName,
                rollout.Phase.WireName,
                Invariant($"{rollout.CurrentWave}/{rollout.TotalWaves}"),
                rollout.CurrentRegion ?? rollout.Region ?? "-",
                Display.Age(timeProvider, rollout.StartedAt),
                rollout.TargetImage);
        }

        rollouts.WriteTo(output);
        return ExitCodes.Ok;
    }
}
