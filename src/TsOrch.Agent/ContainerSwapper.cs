using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace TsOrch.Agent;

public sealed record class PlacementPlan(
    DesiredPlacement Desired,
    string ConfigHash,
    IReadOnlyDictionary<string, string> Env,
    IReadOnlyList<BindMount> Mounts)
{
    public ServiceSpec Service => Desired.Service;

    public string PlacementId => Desired.PlacementId;

    public bool RequiresStopStart => Service.Mode == PlacementMode.Stateful || Service.Mounts.Count > 0 || Service.UdpPorts.Count > 0;
}

public sealed record class PlacementPromoted(IReadOnlySet<string> LiveConfigurations);

public sealed record class InvalidPlacementPort(string PlacementId, int Port)
{
    public string Message => string.Create(CultureInfo.InvariantCulture, $"Host port {Port} for {PlacementId} is outside the TCP port range.");
}

public sealed record class PlacementDrainPending(string PlacementId);

public sealed record class PlacementImagePullFailed(string Image, string Message);

public sealed record class PlacementCreateFailed(string PlacementId, string Message);

public sealed record class PlacementStartFailed(string ContainerId, string Message);

public sealed record class PlacementProbeFailed(string ContainerId, string Message);

public readonly union PlacementSwap(
    PlacementPromoted, InvalidPlacementPort, PlacementDrainPending, PlacementImagePullFailed,
    PlacementCreateFailed, PlacementStartFailed, PlacementProbeFailed);

internal readonly union PlacementBindings(IReadOnlyList<PortMapping>, InvalidPlacementPort);

public sealed record class PlacementPorts(int? Http, int? Postgres);

public readonly union PlacementReadiness(PlacementPorts, PlacementProbeFailed);

public readonly record struct PlacementRetired;

public sealed record class PlacementContainersRemain(IReadOnlyList<string> ContainerIds);

public readonly union PlacementRetirement(PlacementRetired, PlacementDrainPending, PlacementContainersRemain);

public sealed class ContainerSwapper(
    DockerEngineClient docker,
    IHttpClientFactory httpClientFactory,
    RouteObserver routes,
    PlacementTracker tracker,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ContainerSwapper> logger)
{
    public const string ProbeClientName = "ts-orch-probe";
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(1);

    private int StopTimeoutSeconds => (int)Math.Ceiling(options.ContainerStopTimeout.TotalSeconds);

    public async Task<PlacementSwap> SwapAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> existing,
        Func<string, CancellationToken, Task> onImagePulled,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(onImagePulled);

        var serving = FindServing(plan.Desired, existing);
        if (serving is not null)
        {
            await tracker.ReportAsync(ServingReport(serving, plan.Service), cancellationToken);
        }

        var bindings = BuildPorts(plan);
        var outcome = bindings switch
        {
            IReadOnlyList<PortMapping> ports => await PullAndStartAsync(plan, existing, serving, ports, onImagePulled, cancellationToken),
            InvalidPlacementPort invalid => (PlacementSwap)invalid,
        };
        var message = outcome switch
        {
            PlacementPromoted => null,
            InvalidPlacementPort invalid => invalid.Message,
            PlacementDrainPending pending => $"Edge has not removed the routes for {pending.PlacementId}.",
            PlacementImagePullFailed failed => failed.Message,
            PlacementCreateFailed failed => failed.Message,
            PlacementStartFailed failed => failed.Message,
            PlacementProbeFailed failed => failed.Message,
        };
        if (message is not null)
        {
            AgentLog.PlacementFailed(logger, plan.PlacementId, plan.Service.Image, message);
            if (serving is null)
            {
                await ReportAsync(plan, PlacementState.Failed, null, message, cancellationToken);
            }
        }

        return outcome;
    }

    public ManagedContainer? FindServing(DesiredPlacement desired, IReadOnlyList<ManagedContainer> existing)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(existing);
        if (tracker.Find(desired.PlacementId) is { State: PlacementState.Ready } report
            && existing.FirstOrDefault(container => container.Running && container.ConfigHash == report.ConfigHash && container.Image == report.Image) is { } tracked)
        {
            return tracked;
        }

        if (routes.Current is { } snapshot
            && existing.FirstOrDefault(container => container.Running && RoutesUseContainer(snapshot, container)) is { } routed)
        {
            return routed;
        }

        return existing.Where(static container => container.Running).Take(2).ToArray() is [var only] ? only : null;
    }

    public PlacementReport ServingReport(ManagedContainer container, ServiceSpec service) =>
        tracker.Find(container.PlacementId) is { State: PlacementState.Ready } report
        && report.ConfigHash == container.ConfigHash && report.Image == container.Image
            ? report
            : ReadyReport(container, service);

    private static bool RoutesUseContainer(EdgeRoutesSnapshot snapshot, ManagedContainer container) =>
        snapshot.HttpRoutes.SelectMany(static route => route.Upstreams).Any(upstream => upstream.PlacementId == container.PlacementId
            && container.Ports.Any(port => port.Protocol == PortProtocol.Tcp && port.HostPort == upstream.Port))
        || snapshot.PostgresRoutes.SelectMany(static route => route.Upstreams).Any(upstream => upstream.PlacementId == container.PlacementId
            && container.Ports.Any(port => port.Protocol == PortProtocol.Tcp && port.HostPort == upstream.Port));

    public static PlacementReport ReadyReport(ManagedContainer container, ServiceSpec service)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(service);
        var ports = Ports(container.Ports, service);
        return new PlacementReport(container.PlacementId, container.ServiceName, PlacementState.Ready, container.Image, container.ConfigHash, ports.Http, PostgresHostPort: ports.Postgres);
    }

    public async Task<IReadOnlySet<string>> RetirePreviousAsync(
        DesiredPlacement desired,
        string currentConfigHash,
        IReadOnlyList<ManagedContainer> previous,
        PlacementPorts ports,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(ports);
        HashSet<string> keep = [with(StringComparer.Ordinal), currentConfigHash];
        if (previous.Any(static container => container.Running)
            && !await routes.WaitUntilAsync(snapshot => PointsTo(snapshot, desired, ports), options.RouteSwitchTimeout, cancellationToken))
        {
            AgentLog.RouteSwitchTimedOut(logger, desired.PlacementId, ports.Http ?? ports.Postgres ?? 0);
            keep.UnionWith(previous.Select(static container => container.ConfigHash));
            return keep;
        }

        foreach (var old in previous)
        {
            if (!await StopAndRemoveAsync(old.Id, cancellationToken))
            {
                keep.Add(old.ConfigHash);
            }
        }

        return keep;
    }

    public async Task<PlacementRetirement> RetireAsync(IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(containers);
        if (containers is not [var first, ..])
        {
            return new PlacementRetired();
        }

        var reference = containers.FirstOrDefault(static container => container.Running) ?? first;
        if (reference.Running && !await DrainAsync(reference, cancellationToken))
        {
            return new PlacementDrainPending(reference.PlacementId);
        }

        List<string> remaining = [];
        foreach (var container in containers)
        {
            if (!await StopAndRemoveAsync(container.Id, cancellationToken))
            {
                remaining.Add(container.Id);
            }
        }

        if (remaining.Count > 0)
        {
            return new PlacementContainersRemain(remaining);
        }

        await tracker.RetireAsync(new PlacementReport(reference.PlacementId, reference.ServiceName, PlacementState.Stopped, reference.Image, reference.ConfigHash), cancellationToken);
        return new PlacementRetired();
    }

    public async Task<bool> StopAndRemoveAsync(string containerId, CancellationToken cancellationToken)
    {
        await StopAsync(containerId, cancellationToken);
        return await RemoveAsync(containerId, cancellationToken);
    }

    private async Task<PlacementSwap> PullAndStartAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> existing,
        ManagedContainer? serving,
        IReadOnlyList<PortMapping> ports,
        Func<string, CancellationToken, Task> onImagePulled,
        CancellationToken cancellationToken)
    {
        foreach (var stale in existing.Where(static container => !container.Running))
        {
            await RemoveAsync(stale.Id, cancellationToken);
        }

        if (serving is null)
        {
            await ReportAsync(plan, PlacementState.Pulling, null, null, cancellationToken);
        }

        var pulled = await docker.PullImageAsync(plan.Service.Image, null, cancellationToken);
        var pullError = pulled switch
        {
            DockerRequestCompleted => null,
            DockerResourceMissing failure => failure.Message,
            DockerDaemonUnavailable failure => failure.Message,
            DockerResponseInvalid failure => failure.Message,
            DockerImagePullRejected failure => failure.Message,
        };
        if (pullError is not null)
        {
            return new PlacementImagePullFailed(plan.Service.Image, pullError);
        }

        await onImagePulled(plan.Service.Image, cancellationToken);
        List<ManagedContainer> previous = [.. existing.Where(static container => container.Running)];
        if (plan.RequiresStopStart && previous is [var first, ..])
        {
            if (!await DrainAsync(serving ?? first, cancellationToken))
            {
                if (serving is not null)
                {
                    await tracker.ReportAsync(ServingReport(serving, plan.Service), cancellationToken);
                }

                return new PlacementDrainPending(plan.PlacementId);
            }

            foreach (var old in previous)
            {
                await StopAsync(old.Id, cancellationToken);
            }
        }

        var candidate = await LaunchAsync(plan, ports, serving is null || plan.RequiresStopStart, cancellationToken);
        return candidate switch
        {
            ReadyCandidate ready => await PromoteAsync(plan, previous, ready, cancellationToken),
            PlacementCreateFailed failed => await RestoreAsync(plan, serving, failed, cancellationToken),
            PlacementStartFailed failed => await RestoreAsync(plan, serving, failed, cancellationToken),
            PlacementProbeFailed failed => await RestoreAsync(plan, serving, failed, cancellationToken),
        };
    }

    private async Task<CandidateLaunch> LaunchAsync(PlacementPlan plan, IReadOnlyList<PortMapping> ports, bool reportStarting, CancellationToken cancellationToken)
    {
        var spec = new DockerContainerSpec(
            $"{options.LabelPrefix}-{plan.PlacementId}-{plan.ConfigHash[..12]}",
            plan.Service.Image, options.LabelPrefix, plan.PlacementId, plan.Service.Name, plan.ConfigHash,
            plan.Env, plan.Mounts, plan.Service.Args, ports, ContainerResources.For(plan.Service, options.EnableCgroupParent),
            Stateful: plan.Service.Mode == PlacementMode.Stateful);
        var created = await docker.CreateContainerAsync(spec, cancellationToken);
        return created switch
        {
            string id => await StartAsync(plan, id, reportStarting, cancellationToken),
            DockerResourceMissing failure => new PlacementCreateFailed(plan.PlacementId, failure.Message),
            DockerResourceBusy failure => new PlacementCreateFailed(plan.PlacementId, failure.Message),
            DockerDaemonUnavailable failure => new PlacementCreateFailed(plan.PlacementId, failure.Message),
            DockerResponseInvalid failure => new PlacementCreateFailed(plan.PlacementId, failure.Message),
        };
    }

    private async Task<CandidateLaunch> StartAsync(PlacementPlan plan, string id, bool reportStarting, CancellationToken cancellationToken)
    {
        if (reportStarting)
        {
            await ReportAsync(plan, PlacementState.Starting, null, null, cancellationToken);
        }

        var started = await docker.StartContainerAsync(id, cancellationToken);
        var outcome = started switch
        {
            DockerRequestCompleted => await ProbeCandidateAsync(plan.Service, id, cancellationToken),
            DockerResourceMissing failure => (CandidateLaunch)new PlacementStartFailed(id, failure.Message),
            DockerDaemonUnavailable failure => (CandidateLaunch)new PlacementStartFailed(id, failure.Message),
            DockerResponseInvalid failure => (CandidateLaunch)new PlacementStartFailed(id, failure.Message),
        };
        var remove = outcome switch
        {
            ReadyCandidate => false,
            PlacementCreateFailed or PlacementStartFailed or PlacementProbeFailed => true,
        };
        if (remove)
        {
            await RemoveAsync(id, cancellationToken);
        }

        return outcome;
    }

    private async Task<CandidateLaunch> ProbeCandidateAsync(ServiceSpec service, string id, CancellationToken cancellationToken)
    {
        var readiness = await WaitReadyAsync(id, service, cancellationToken);
        return readiness switch
        {
            PlacementPorts ports => new ReadyCandidate(ports),
            PlacementProbeFailed failed => failed,
        };
    }

    private async Task<PlacementPromoted> PromoteAsync(PlacementPlan plan, IReadOnlyList<ManagedContainer> previous, ReadyCandidate ready, CancellationToken cancellationToken)
    {
        await ReportAsync(plan, PlacementState.Ready, ready.Ports, null, cancellationToken);
        AgentLog.PlacementReady(logger, plan.PlacementId, plan.Service.Image, plan.ConfigHash, ready.Ports.Http);
        return new PlacementPromoted(await RetirePreviousAsync(plan.Desired, plan.ConfigHash, previous, ready.Ports, cancellationToken));
    }

    private async Task<T> RestoreAsync<T>(PlacementPlan plan, ManagedContainer? serving, T failure, CancellationToken cancellationToken)
    {
        if (plan.RequiresStopStart && serving is not null)
        {
            var started = await docker.StartContainerAsync(serving.Id, cancellationToken);
            var error = started switch
            {
                DockerRequestCompleted => null,
                DockerResourceMissing missing => missing.Message,
                DockerDaemonUnavailable unavailable => unavailable.Message,
                DockerResponseInvalid invalid => invalid.Message,
            };
            if (error is null)
            {
                var readiness = await WaitReadyAsync(serving.Id, plan.Service, cancellationToken);
                var available = readiness switch
                {
                    PlacementPorts => true,
                    PlacementProbeFailed failed => LogCleanupFailure(serving.Id, failed.Message),
                };
                if (available)
                {
                    await tracker.ReportAsync(ServingReport(serving, plan.Service), cancellationToken);
                }
                else
                {
                    await ReportAsync(plan, PlacementState.Failed, null, "Previous container did not recover.", cancellationToken);
                }
            }
            else
            {
                LogCleanupFailure(serving.Id, error);
                await ReportAsync(plan, PlacementState.Failed, null, error, cancellationToken);
            }
        }

        return failure;
    }

    private async Task<bool> DrainAsync(ManagedContainer container, CancellationToken cancellationToken)
    {
        var report = tracker.Find(container.PlacementId) ?? new PlacementReport(container.PlacementId, container.ServiceName, PlacementState.Ready, container.Image, container.ConfigHash);
        await tracker.ReportAsync(report with { State = PlacementState.Draining }, cancellationToken);
        if (routes.Current is null || !await routes.WaitUntilAsync(snapshot => !RouteObserver.IsRouted(snapshot, container.PlacementId), options.RouteSwitchTimeout, cancellationToken))
        {
            AgentLog.RouteDrainTimedOut(logger, container.PlacementId);
            return false;
        }

        return true;
    }

    private async Task StopAsync(string containerId, CancellationToken cancellationToken)
    {
        var stopped = await docker.StopContainerAsync(containerId, StopTimeoutSeconds, cancellationToken);
        var message = stopped switch
        {
            DockerRequestCompleted => null,
            DockerDaemonUnavailable failure => failure.Message,
            DockerResponseInvalid failure => failure.Message,
        };
        if (message is not null)
        {
            LogCleanupFailure(containerId, message);
        }
    }

    private async Task<bool> RemoveAsync(string containerId, CancellationToken cancellationToken)
    {
        var removed = await docker.RemoveContainerAsync(containerId, force: true, cancellationToken);
        return removed switch
        {
            DockerRequestCompleted => true,
            DockerResourceBusy failure => LogCleanupFailure(containerId, failure.Message),
            DockerDaemonUnavailable failure => LogCleanupFailure(containerId, failure.Message),
            DockerResponseInvalid failure => LogCleanupFailure(containerId, failure.Message),
        };
    }

    private bool LogCleanupFailure(string containerId, string failure)
    {
        AgentLog.ContainerCleanupFailed(logger, containerId, failure);
        return false;
    }

    private ValueTask ReportAsync(PlacementPlan plan, PlacementState state, PlacementPorts? ports, string? error, CancellationToken cancellationToken) =>
        tracker.ReportAsync(new PlacementReport(plan.PlacementId, plan.Service.Name, state, plan.Service.Image, plan.ConfigHash, ports?.Http, error, ports?.Postgres), cancellationToken);

    private static PlacementBindings BuildPorts(PlacementPlan plan)
    {
        var service = plan.Service;
        List<PortMapping> ports = [.. service.UdpPorts.Select(static port => new PortMapping("0.0.0.0", port, port, PortProtocol.Udp))];
        List<(int ContainerPort, int? HostPort)> tcp = [];
        if (service.Port > 0)
        {
            tcp.Add((service.Port, plan.Desired.HostPort));
        }

        if (service.Postgres is { } postgres)
        {
            tcp.Add((postgres.Port, plan.Desired.PostgresHostPort));
        }

        foreach (var (containerPort, assignedPort) in tcp)
        {
            var hostPort = plan.RequiresStopStart ? assignedPort : null;
            if (hostPort is <= 0 or > IPEndPoint.MaxPort)
            {
                return new InvalidPlacementPort(plan.PlacementId, hostPort.GetValueOrDefault());
            }

            ports.Add(new PortMapping("0.0.0.0", hostPort, containerPort, PortProtocol.Tcp));
        }

        return ports;
    }

    public async Task<PlacementReadiness> WaitReadyAsync(string containerId, ServiceSpec service, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(service);
        var timeout = TimeSpan.FromSeconds(Math.Max(1, service.ReadyTimeoutSeconds));
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        using var client = httpClientFactory.CreateClient(ProbeClientName);
        using var timer = new PeriodicTimer(ProbeInterval, timeProvider);
        var readyPath = string.IsNullOrEmpty(service.ReadyPath) ? "/" : service.ReadyPath;
        string? inspectionError = null;
        try
        {
            do
            {
                var inspected = await docker.InspectContainerAsync(containerId, linked.Token);
                var state = inspected switch
                {
                    ContainerState found => new ReadinessInspection(found, null),
                    DockerResourceMissing failure => new ReadinessInspection(null, failure.Message),
                    DockerDaemonUnavailable failure => new ReadinessInspection(null, failure.Message),
                    DockerResponseInvalid failure => new ReadinessInspection(null, failure.Message),
                };
                inspectionError = state.Error;
                if (state.Container is { Running: false } exited)
                {
                    return new PlacementProbeFailed(containerId, string.Create(CultureInfo.InvariantCulture, $"Container exited with code {exited.ExitCode}{(exited.OomKilled ? " (OOM killed)" : string.Empty)} before becoming ready."));
                }

                if (state.Container is { } running)
                {
                    var ports = Ports(running.Ports, service);
                    if ((service.Port <= 0 || ports.Http is { } http && await ProbeHttpAsync(client, http, readyPath, linked.Token))
                        && (service.Postgres is null || ports.Postgres is { } postgres && await ProbeTcpAsync(postgres, linked.Token)))
                    {
                        return ports;
                    }
                }
            }
            while (await timer.WaitForNextTickAsync(linked.Token));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return TimedOut(containerId, timeout, inspectionError);
        }

        return TimedOut(containerId, timeout, inspectionError);
    }

    private static PlacementProbeFailed TimedOut(string containerId, TimeSpan timeout, string? inspectionError) =>
        new(containerId, string.Create(CultureInfo.InvariantCulture, $"Readiness checks did not pass within {timeout.TotalSeconds} s.{(inspectionError is { } error ? $" Last Docker error: {error}" : string.Empty)}"));

    private static PlacementPorts Ports(IReadOnlyList<PublishedPort> ports, ServiceSpec service) =>
        new(TcpHostPort(ports, service.Port), service.Postgres is { } postgres ? TcpHostPort(ports, postgres.Port) : null);

    private static int? TcpHostPort(IReadOnlyList<PublishedPort> ports, int port) =>
        ports.FirstOrDefault(published => published.ContainerPort == port && published.Protocol == PortProtocol.Tcp)?.HostPort;

    private static bool PointsTo(EdgeRoutesSnapshot snapshot, DesiredPlacement desired, PlacementPorts ports) =>
        RouteObserver.IsRoutedTo(snapshot, desired.PlacementId, desired.Service.Hostnames.Count > 0 ? ports.Http : null, ports.Postgres);

    private static async Task<bool> ProbeHttpAsync(HttpClient client, int hostPort, string readyPath, CancellationToken cancellationToken)
    {
        var uri = new Uri(string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{hostPort}{readyPath}"));
        try
        {
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return response.StatusCode == HttpStatusCode.OK;
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private static async Task<bool> ProbeTcpAsync(int hostPort, CancellationToken cancellationToken)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, hostPort, cancellationToken);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private sealed record class ReadinessInspection(ContainerState? Container, string? Error);

    private sealed record class ReadyCandidate(PlacementPorts Ports);

    private readonly union CandidateLaunch(ReadyCandidate, PlacementCreateFailed, PlacementStartFailed, PlacementProbeFailed);
}
