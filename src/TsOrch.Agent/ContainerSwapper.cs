using System.Globalization;
using System.Net;

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
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ContainerSwapper> logger)
{
    public const string ProbeClientName = "ts-orch-probe";
    private const int StatefulPortOffset = 10_000;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(1);

    private int StopTimeoutSeconds => (int)Math.Ceiling(options.ContainerStopTimeout.TotalSeconds);

    public async Task<Result<ManagedContainer, Validation, NotFound, Conflict, Unavailable, InternalFailure>> SwapAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> existing,
        Func<string, CancellationToken, Task> onImagePulled,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(onImagePulled);
        foreach (var stale in existing.Where(static container => !container.Running))
        {
            await RemoveAsync(stale.Id, cancellationToken);
        }

        List<ManagedContainer> previous = [.. existing.Where(static container => container.Running)];
        await ReportAsync(plan, PlacementState.Pulling, null, null, cancellationToken);
        return await docker.PullImageAsync(plan.Service.Image, null, cancellationToken) switch
        {
            Done => await AfterPullAsync(plan, previous, onImagePulled, cancellationToken),
            NotFound failure => await FailAsync(plan, failure, failure.Message, previous, restartPrevious: false, cancellationToken),
            Unavailable failure => await FailAsync(plan, failure, failure.Message, previous, restartPrevious: false, cancellationToken),
            InternalFailure failure => await FailAsync(plan, failure, failure.Message, previous, restartPrevious: false, cancellationToken),
        };
    }

    public async Task RetireAsync(IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(containers);
        if (containers is not [var first, ..])
        {
            return;
        }

        var reference = containers.FirstOrDefault(static container => container.Running) ?? first;
        foreach (var container in containers.Where(static container => container.Running))
        {
            await DrainAsync(container, cancellationToken);
        }

        foreach (var container in containers)
        {
            await StopAndRemoveAsync(container.Id, cancellationToken);
        }

        await tracker.RetireAsync(
            new PlacementReport(reference.PlacementId, reference.ServiceName, PlacementState.Stopped, reference.Image, reference.ConfigHash),
            cancellationToken);
    }

    public async Task StopAndRemoveAsync(string containerId, CancellationToken cancellationToken)
    {
        await StopAsync(containerId, cancellationToken);
        await RemoveAsync(containerId, cancellationToken);
    }

    public static int? HttpHostPort(ManagedContainer container, ServiceSpec service)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(service);
        return container.Ports.FirstOrDefault(port => port.ContainerPort == service.Port && port.Protocol == PortProtocol.Tcp)?.HostPort;
    }

    private async Task<Result<ManagedContainer, Validation, NotFound, Conflict, Unavailable, InternalFailure>> AfterPullAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> previous,
        Func<string, CancellationToken, Task> onImagePulled,
        CancellationToken cancellationToken)
    {
        await onImagePulled(plan.Service.Image, cancellationToken);
        return BuildPorts(plan) switch
        {
            IReadOnlyList<PortMapping> ports => await CreateAsync(plan, previous, ports, cancellationToken),
            Validation failure => await FailAsync(plan, failure, failure.Message, previous, restartPrevious: false, cancellationToken),
        };
    }

    private async Task<Result<ManagedContainer, Validation, NotFound, Conflict, Unavailable, InternalFailure>> CreateAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> previous,
        IReadOnlyList<PortMapping> ports,
        CancellationToken cancellationToken)
    {
        if (plan.RequiresStopStart)
        {
            foreach (var old in previous)
            {
                await DrainAsync(old, cancellationToken);
                await StopAsync(old.Id, cancellationToken);
            }
        }

        var service = plan.Service;
        var spec = new DockerContainerSpec(
            ContainerName(plan),
            service.Image,
            options.LabelPrefix,
            plan.PlacementId,
            service.Name,
            plan.ConfigHash,
            plan.Env,
            plan.Mounts,
            service.Args,
            ports,
            ContainerResources.For(service, options.EnableCgroupParent));
        return await docker.CreateContainerAsync(spec, cancellationToken) switch
        {
            string containerId => await StartAsync(plan, previous, spec, containerId, cancellationToken),
            NotFound failure => await FailAsync(plan, failure, failure.Message, previous, plan.RequiresStopStart, cancellationToken),
            Conflict failure => await FailAsync(plan, failure, failure.Message, previous, plan.RequiresStopStart, cancellationToken),
            Unavailable failure => await FailAsync(plan, failure, failure.Message, previous, plan.RequiresStopStart, cancellationToken),
            InternalFailure failure => await FailAsync(plan, failure, failure.Message, previous, plan.RequiresStopStart, cancellationToken),
        };
    }

    private async Task<Result<ManagedContainer, Validation, NotFound, Conflict, Unavailable, InternalFailure>> StartAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> previous,
        DockerContainerSpec spec,
        string containerId,
        CancellationToken cancellationToken)
    {
        await ReportAsync(plan, PlacementState.Starting, null, null, cancellationToken);
        return await docker.StartContainerAsync(containerId, cancellationToken) switch
        {
            Done => await WaitReadyAsync(containerId, plan.Service, cancellationToken) switch
            {
                int hostPort => await PromoteAsync(plan, previous, spec, containerId, hostPort, cancellationToken),
                NotFound failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
                Unavailable failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
                InternalFailure failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
            },
            NotFound failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
            Unavailable failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
            InternalFailure failure => await AbandonAsync(plan, failure, failure.Message, previous, containerId, cancellationToken),
        };
    }

    private async Task<ManagedContainer> PromoteAsync(
        PlacementPlan plan,
        IReadOnlyList<ManagedContainer> previous,
        DockerContainerSpec spec,
        string containerId,
        int hostPort,
        CancellationToken cancellationToken)
    {
        var service = plan.Service;
        int? reportedPort = hostPort > 0 ? hostPort : null;
        await ReportAsync(plan, PlacementState.Ready, reportedPort, null, cancellationToken);
        AgentLog.PlacementReady(logger, plan.PlacementId, service.Image, plan.ConfigHash, reportedPort);
        if (!plan.RequiresStopStart && previous.Count > 0 && reportedPort is { } port && service.Hostnames.Count > 0)
        {
            var switched = await routes.WaitUntilAsync(snapshot => RouteObserver.IsRoutedTo(snapshot, plan.PlacementId, port), options.RouteSwitchTimeout, cancellationToken);
            if (!switched)
            {
                AgentLog.RouteSwitchTimedOut(logger, plan.PlacementId, port);
            }
        }

        foreach (var old in previous)
        {
            if (!plan.RequiresStopStart)
            {
                await StopAsync(old.Id, cancellationToken);
            }

            await RemoveAsync(old.Id, cancellationToken);
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

    private async Task<TFailure> AbandonAsync<TFailure>(
        PlacementPlan plan,
        TFailure failure,
        string message,
        IReadOnlyList<ManagedContainer> previous,
        string containerId,
        CancellationToken cancellationToken)
    {
        await RemoveAsync(containerId, cancellationToken);
        return await FailAsync(plan, failure, message, previous, plan.RequiresStopStart, cancellationToken);
    }

    private async Task<TFailure> FailAsync<TFailure>(
        PlacementPlan plan,
        TFailure failure,
        string message,
        IReadOnlyList<ManagedContainer> previous,
        bool restartPrevious,
        CancellationToken cancellationToken)
    {
        AgentLog.PlacementFailed(logger, plan.PlacementId, plan.Service.Image, message);
        await ReportAsync(plan, PlacementState.Failed, null, message, cancellationToken);
        foreach (var old in previous)
        {
            if (restartPrevious)
            {
                await RestartAsync(old.Id, cancellationToken);
            }

            await tracker.ReportAsync(
                new PlacementReport(old.PlacementId, old.ServiceName, PlacementState.Ready, old.Image, old.ConfigHash, HttpHostPort(old, plan.Service)),
                cancellationToken);
        }

        return failure;
    }

    private async Task DrainAsync(ManagedContainer container, CancellationToken cancellationToken)
    {
        await tracker.ReportAsync(
            new PlacementReport(container.PlacementId, container.ServiceName, PlacementState.Draining, container.Image, container.ConfigHash, container.Ports.FirstOrDefault(static port => port.Protocol == PortProtocol.Tcp)?.HostPort),
            cancellationToken);
        if (routes.Current is { } current && RouteObserver.IsRouted(current, container.PlacementId))
        {
            var drained = await routes.WaitUntilAsync(snapshot => !RouteObserver.IsRouted(snapshot, container.PlacementId), options.RouteSwitchTimeout, cancellationToken);
            if (!drained)
            {
                AgentLog.RouteDrainTimedOut(logger, container.PlacementId);
            }
        }
    }

    private async Task StopAsync(string containerId, CancellationToken cancellationToken)
    {
        var failure = await docker.StopContainerAsync(containerId, StopTimeoutSeconds, cancellationToken) switch
        {
            Done => null,
            Unavailable stopFailure => stopFailure.Message,
            InternalFailure stopFailure => stopFailure.Message,
        };
        LogCleanupFailure(containerId, failure);
    }

    private async Task RemoveAsync(string containerId, CancellationToken cancellationToken)
    {
        var failure = await docker.RemoveContainerAsync(containerId, force: true, cancellationToken) switch
        {
            Done => null,
            Conflict removeFailure => removeFailure.Message,
            Unavailable removeFailure => removeFailure.Message,
            InternalFailure removeFailure => removeFailure.Message,
        };
        LogCleanupFailure(containerId, failure);
    }

    private async Task RestartAsync(string containerId, CancellationToken cancellationToken)
    {
        var failure = await docker.StartContainerAsync(containerId, cancellationToken) switch
        {
            Done => null,
            NotFound startFailure => startFailure.Message,
            Unavailable startFailure => startFailure.Message,
            InternalFailure startFailure => startFailure.Message,
        };
        LogCleanupFailure(containerId, failure);
    }

    private void LogCleanupFailure(string containerId, string? failure)
    {
        if (failure is not null)
        {
            AgentLog.ContainerCleanupFailed(logger, containerId, failure);
        }
    }

    private ValueTask ReportAsync(PlacementPlan plan, PlacementState state, int? hostPort, string? error, CancellationToken cancellationToken) =>
        tracker.ReportAsync(new PlacementReport(plan.PlacementId, plan.Service.Name, state, plan.Service.Image, plan.ConfigHash, hostPort, error), cancellationToken);

    private string ContainerName(PlacementPlan plan) =>
        $"{options.LabelPrefix}-{plan.PlacementId}-{plan.ConfigHash[..12]}";

    private static Result<IReadOnlyList<PortMapping>, Validation> BuildPorts(PlacementPlan plan)
    {
        var service = plan.Service;
        List<int> tcpPorts = [];
        if (service.Port > 0)
        {
            tcpPorts.Add(service.Port);
        }

        if (service.Postgres is { } postgres)
        {
            tcpPorts.Add(postgres.Port);
        }

        List<PortMapping> ports = [];
        foreach (var containerPort in tcpPorts)
        {
            if (!plan.RequiresStopStart)
            {
                ports.Add(new PortMapping("0.0.0.0", null, containerPort, PortProtocol.Tcp));
                continue;
            }

            var hostPort = StatefulPortOffset + containerPort + plan.Desired.Slot;
            if (hostPort is <= 0 or > IPEndPoint.MaxPort)
            {
                return new Validation(string.Create(CultureInfo.InvariantCulture, $"Slot port {hostPort} for {plan.PlacementId} is outside the TCP port range."));
            }

            ports.Add(new PortMapping("0.0.0.0", hostPort, containerPort, PortProtocol.Tcp));
        }

        foreach (var udpPort in service.UdpPorts)
        {
            ports.Add(new PortMapping("0.0.0.0", udpPort, udpPort, PortProtocol.Udp));
        }

        return ports;
    }

    private async Task<Result<int, NotFound, Unavailable, InternalFailure>> WaitReadyAsync(string containerId, ServiceSpec service, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + TimeSpan.FromSeconds(Math.Max(1, service.ReadyTimeoutSeconds));
        var readyPath = string.IsNullOrEmpty(service.ReadyPath) ? "/" : service.ReadyPath;
        using var client = httpClientFactory.CreateClient(ProbeClientName);
        return await PollReadyAsync(new ReadyProbe(containerId, service, readyPath, deadline, client), cancellationToken);
    }

    private async Task<Result<int, NotFound, Unavailable, InternalFailure>> PollReadyAsync(ReadyProbe probe, CancellationToken cancellationToken) =>
        await docker.InspectContainerAsync(probe.ContainerId, cancellationToken) switch
        {
            ContainerState state => await CheckReadyAsync(probe, state, cancellationToken),
            NotFound failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private async Task<Result<int, NotFound, Unavailable, InternalFailure>> CheckReadyAsync(ReadyProbe probe, ContainerState state, CancellationToken cancellationToken)
    {
        if (!state.Running)
        {
            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"Container exited with code {state.ExitCode}{(state.OomKilled ? " (OOM killed)" : string.Empty)} before becoming ready."));
        }

        if (probe.Service.Port <= 0)
        {
            return 0;
        }

        var hostPort = state.Ports.FirstOrDefault(port => port.ContainerPort == probe.Service.Port && port.Protocol == PortProtocol.Tcp)?.HostPort;
        if (hostPort is { } port && await ProbeAsync(probe.Client, port, probe.ReadyPath, cancellationToken))
        {
            return port;
        }

        if (timeProvider.GetUtcNow() >= probe.Deadline)
        {
            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{probe.ReadyPath} did not return 200 within {probe.Service.ReadyTimeoutSeconds} s."));
        }

        await Task.Delay(ProbeInterval, timeProvider, cancellationToken);
        return await PollReadyAsync(probe, cancellationToken);
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

    private sealed record class ReadyProbe(string ContainerId, ServiceSpec Service, string ReadyPath, DateTimeOffset Deadline, HttpClient Client);
}
