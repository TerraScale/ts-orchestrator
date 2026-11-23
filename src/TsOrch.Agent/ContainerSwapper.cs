using System.Globalization;
using System.Net;
using Microsoft.Extensions.Options;

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

    public bool IsRoutable => Service.Hostnames.Count > 0 || Service.Postgres is not null;
}

public sealed class ContainerSwapper(
    DockerEngineClient docker,
    IHttpClientFactory httpClientFactory,
    RouteObserver routes,
    PlacementTracker tracker,
    IOptions<AgentOptions> options,
    TimeProvider timeProvider,
    ILogger<ContainerSwapper> logger)
{
    public const string ProbeClientName = "ts-orch-probe";
    private const int StatefulPortOffset = 10_000;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(1);

    private readonly AgentOptions _options = options.Value;

    public async Task<OrchResult<ManagedContainer>> SwapAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> existing,
        Func<string, CancellationToken, Task> onImagePulled,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(onImagePulled);
        var service = plan.Service;
        foreach (var stale in existing.Where(static container => !container.Running))
        {
            await docker.RemoveContainerAsync(stale.Id, force: true, cancellationToken);
        }

        var previous = existing.Where(static container => container.Running).ToList();
        await ReportAsync(plan, PlacementState.Pulling, null, null, cancellationToken);
        var pulled = await docker.PullImageAsync(service.Image, null, cancellationToken);
        if (pulled is OrchError pullError)
        {
            return await FailAsync(plan, pullError, previous, restartPrevious: false, cancellationToken);
        }

        await onImagePulled(service.Image, cancellationToken);
        var portsResult = BuildPorts(plan);
        if (!portsResult.TryGetValue(out var ports, out var portsError))
        {
            return await FailAsync(plan, portsError, previous, restartPrevious: false, cancellationToken);
        }

        if (plan.RequiresStopStart)
        {
            foreach (var old in previous)
            {
                await DrainAsync(old, cancellationToken);
                await docker.StopContainerAsync(old.Id, StopTimeoutSeconds, cancellationToken);
            }
        }

        var spec = new DockerContainerSpec(
            ContainerName(plan),
            service.Image,
            _options.LabelPrefix,
            plan.PlacementId,
            service.Name,
            plan.ConfigHash,
            plan.Env,
            plan.Mounts,
            service.Args,
            ports,
            ContainerResources.For(service, _options.EnableCgroupParent));
        var createdResult = await docker.CreateContainerAsync(spec, cancellationToken);
        if (!createdResult.TryGetValue(out var containerId, out var createError))
        {
            return await FailAsync(plan, createError, previous, plan.RequiresStopStart, cancellationToken);
        }

        await ReportAsync(plan, PlacementState.Starting, null, null, cancellationToken);
        var started = await docker.StartContainerAsync(containerId, cancellationToken);
        if (started is OrchError startError)
        {
            await docker.RemoveContainerAsync(containerId, force: true, cancellationToken);
            return await FailAsync(plan, startError, previous, plan.RequiresStopStart, cancellationToken);
        }

        var readyResult = await WaitReadyAsync(containerId, service, cancellationToken);
        if (!readyResult.TryGetValue(out var hostPort, out var readyError))
        {
            await docker.RemoveContainerAsync(containerId, force: true, cancellationToken);
            return await FailAsync(plan, readyError, previous, plan.RequiresStopStart, cancellationToken);
        }

        int? reportedPort = hostPort > 0 ? hostPort : null;
        await ReportAsync(plan, PlacementState.Ready, reportedPort, null, cancellationToken);
        logger.PlacementReady(plan.PlacementId, service.Image, plan.ConfigHash, reportedPort);
        if (!plan.RequiresStopStart && previous.Count > 0 && reportedPort is { } port && service.Hostnames.Count > 0)
        {
            var switched = await routes.WaitUntilAsync(snapshot => RouteObserver.IsRoutedTo(snapshot, plan.PlacementId, port), _options.RouteSwitchTimeout, cancellationToken);
            if (!switched)
            {
                logger.RouteSwitchTimedOut(plan.PlacementId, port);
            }
        }

        foreach (var old in previous)
        {
            if (!plan.RequiresStopStart)
            {
                await docker.StopContainerAsync(old.Id, StopTimeoutSeconds, cancellationToken);
            }

            await docker.RemoveContainerAsync(old.Id, force: true, cancellationToken);
        }

        return new ManagedContainer(
            containerId,
            spec.Name,
            service.Image,
            service.Image,
            plan.PlacementId,
            service.Name,
            plan.ConfigHash,
            true,
            reportedPort is { } published ? [new PublishedPort("0.0.0.0", published, service.Port, PortProtocol.Tcp)] : []);
    }

    public async Task RetireAsync(IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(containers);
        if (containers.Count == 0)
        {
            return;
        }

        var reference = containers.FirstOrDefault(static container => container.Running) ?? containers[0];
        foreach (var container in containers.Where(static container => container.Running))
        {
            await DrainAsync(container, cancellationToken);
        }

        foreach (var container in containers)
        {
            await docker.StopContainerAsync(container.Id, StopTimeoutSeconds, cancellationToken);
            await docker.RemoveContainerAsync(container.Id, force: true, cancellationToken);
        }

        await tracker.RetireAsync(
            new PlacementReport(reference.PlacementId, reference.ServiceName, PlacementState.Stopped, reference.Image, reference.ConfigHash),
            cancellationToken);
    }

    public static int? HttpHostPort(ManagedContainer container, ServiceSpec service)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(service);
        return container.Ports.FirstOrDefault(port => port.ContainerPort == service.Port && port.Protocol == PortProtocol.Tcp)?.HostPort;
    }

    private int StopTimeoutSeconds => (int)Math.Ceiling(_options.ContainerStopTimeout.TotalSeconds);

    private async Task DrainAsync(ManagedContainer container, CancellationToken cancellationToken)
    {
        await tracker.ReportAsync(
            new PlacementReport(container.PlacementId, container.ServiceName, PlacementState.Draining, container.Image, container.ConfigHash, container.Ports.FirstOrDefault(static port => port.Protocol == PortProtocol.Tcp)?.HostPort),
            cancellationToken);
        if (routes.Current is { } current && RouteObserver.IsRouted(current, container.PlacementId))
        {
            var drained = await routes.WaitUntilAsync(snapshot => !RouteObserver.IsRouted(snapshot, container.PlacementId), _options.RouteSwitchTimeout, cancellationToken);
            if (!drained)
            {
                logger.RouteDrainTimedOut(container.PlacementId);
            }
        }
    }

    private async Task<OrchResult<ManagedContainer>> FailAsync(
        PlacementPlan plan,
        OrchError error,
        IReadOnlyList<ManagedContainer> previous,
        bool restartPrevious,
        CancellationToken cancellationToken)
    {
        logger.PlacementFailed(plan.PlacementId, plan.Service.Image, error.Message);
        await ReportAsync(plan, PlacementState.Failed, null, error.Message, cancellationToken);
        foreach (var old in previous)
        {
            if (restartPrevious)
            {
                await docker.StartContainerAsync(old.Id, cancellationToken);
            }

            await tracker.ReportAsync(
                new PlacementReport(old.PlacementId, old.ServiceName, PlacementState.Ready, old.Image, old.ConfigHash, HttpHostPort(old, plan.Service)),
                cancellationToken);
        }

        return error;
    }

    private ValueTask ReportAsync(PlacementPlan plan, PlacementState state, int? hostPort, string? error, CancellationToken cancellationToken) =>
        tracker.ReportAsync(new PlacementReport(plan.PlacementId, plan.Service.Name, state, plan.Service.Image, plan.ConfigHash, hostPort, error), cancellationToken);

    private string ContainerName(PlacementPlan plan) =>
        $"{_options.LabelPrefix}-{plan.PlacementId}-{plan.ConfigHash[..12]}";

    private static OrchResult<IReadOnlyList<PortMapping>> BuildPorts(PlacementPlan plan)
    {
        var service = plan.Service;
        List<PortMapping> ports = [];
        if (service.Port > 0)
        {
            var mapped = MapTcp(plan, service.Port);
            if (!mapped.TryGetValue(out var mapping, out var error))
            {
                return error;
            }

            ports.Add(mapping);
        }

        if (service.Postgres is { } postgres)
        {
            var mapped = MapTcp(plan, postgres.Port);
            if (!mapped.TryGetValue(out var mapping, out var error))
            {
                return error;
            }

            ports.Add(mapping);
        }

        foreach (var udpPort in service.UdpPorts)
        {
            ports.Add(new PortMapping("0.0.0.0", udpPort, udpPort, PortProtocol.Udp));
        }

        return ports;
    }

    private static OrchResult<PortMapping> MapTcp(PlacementPlan plan, int containerPort)
    {
        if (!plan.RequiresStopStart)
        {
            return new PortMapping("0.0.0.0", null, containerPort, PortProtocol.Tcp);
        }

        var hostPort = StatefulPortOffset + containerPort + plan.Desired.Slot;
        return hostPort is > 0 and <= IPEndPoint.MaxPort
            ? new PortMapping("0.0.0.0", hostPort, containerPort, PortProtocol.Tcp)
            : new Validation(string.Create(CultureInfo.InvariantCulture, $"Slot port {hostPort} for {plan.PlacementId} is outside the TCP port range."));
    }

    private async Task<OrchResult<int>> WaitReadyAsync(string containerId, ServiceSpec service, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + TimeSpan.FromSeconds(Math.Max(1, service.ReadyTimeoutSeconds));
        var readyPath = string.IsNullOrEmpty(service.ReadyPath) ? "/" : service.ReadyPath;
        using var client = httpClientFactory.CreateClient(ProbeClientName);
        while (true)
        {
            var inspected = await docker.InspectContainerAsync(containerId, cancellationToken);
            if (!inspected.TryGetValue(out var state, out var inspectError))
            {
                return inspectError;
            }

            if (!state.Running)
            {
                return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"Container exited with code {state.ExitCode}{(state.OomKilled ? " (OOM killed)" : string.Empty)} before becoming ready."));
            }

            if (service.Port <= 0)
            {
                return 0;
            }

            var hostPort = state.Ports.FirstOrDefault(port => port.ContainerPort == service.Port && port.Protocol == PortProtocol.Tcp)?.HostPort;
            if (hostPort is { } port && await ProbeAsync(client, port, readyPath, cancellationToken))
            {
                return port;
            }

            if (timeProvider.GetUtcNow() >= deadline)
            {
                return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{readyPath} did not return 200 within {service.ReadyTimeoutSeconds} s."));
            }

            await Task.Delay(ProbeInterval, timeProvider, cancellationToken);
        }
    }

    private static async Task<bool> ProbeAsync(HttpClient client, int hostPort, string readyPath, CancellationToken cancellationToken)
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
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
