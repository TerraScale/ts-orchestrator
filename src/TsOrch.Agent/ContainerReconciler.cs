using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;

namespace TsOrch.Agent;

internal readonly union PlacementPlanPreparation(PlacementPlan, SecretNameCollision, InvalidConfigFileTarget, ConfigFileSecretMissing, AtomicWriteFailed);

public readonly record struct NonStatefulContainersDrained;

public sealed record class NodeDrainUnverified(string Message);

public sealed record class NodeDrainIncomplete(IReadOnlyList<string> PlacementIds);

public readonly union NodeDrain(NonStatefulContainersDrained, NodeDrainIncomplete, NodeDrainUnverified);

public sealed class ContainerReconciler(
    DockerEngineClient docker,
    SecretStore secrets,
    ContainerSwapper swapper,
    PlacementTracker tracker,
    ImageHistoryStore images,
    ImageGarbageCollector imageGarbageCollector,
    HostMetricsCollector metrics,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ContainerReconciler> logger) : BackgroundService
{
    private const int MaxParallelPlacements = 4;
    private static readonly TimeSpan FirstRetryDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan ChownTimeout = TimeSpan.FromSeconds(10);

    private readonly Lock _desiredGate = new();
    private readonly SemaphoreSlim _reconcileGate = new(1, 1);
    private readonly ConcurrentDictionary<string, FailedAttempt> _failures = [with(StringComparer.Ordinal)];
    private readonly Channel<ReconcileSignal> _signals = Channel.CreateBounded<ReconcileSignal>(new BoundedChannelOptions(1)
    {
        FullMode = BoundedChannelFullMode.DropWrite,
        SingleReader = true,
    });

    private IReadOnlyList<DesiredPlacement>? _desired;
    private long _desiredRevision = long.MinValue;
    private string? _nodeId;
    private string? _region;
    private string? _vcnIp;
    private string? _netBirdIp;

    public void SetNodeIdentity(string nodeId, HostIdentity identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(identity);
        lock (_desiredGate)
        {
            _nodeId = nodeId;
            _region = identity.Region;
            _vcnIp = identity.VcnIp;
        }
    }

    public override void Dispose()
    {
        _reconcileGate.Dispose();
        base.Dispose();
    }

    public void ApplyDesired(SyncDesired desired)
    {
        ArgumentNullException.ThrowIfNull(desired);
        lock (_desiredGate)
        {
            if (desired.Revision < _desiredRevision)
            {
                AgentLog.StaleDesiredIgnored(logger, desired.Revision, _desiredRevision);
                return;
            }

            _desiredRevision = desired.Revision;
            _desired = desired.Placements;
        }

        Signal();
    }

    public void RefreshSecrets(string serviceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        List<DesiredPlacement> matching;
        lock (_desiredGate)
        {
            matching = [.. (_desired ?? []).Where(placement => placement.Service.Name == serviceName)];
        }

        secrets.Invalidate(matching.SelectMany(static placement => placement.Service.Secrets.Values));
        foreach (var placement in matching)
        {
            _failures.TryRemove(placement.PlacementId, out _);
        }

        AgentLog.SecretRefreshRequested(logger, serviceName, matching.Count);
        Signal();
    }

    public async Task<NodeDrain> DrainAsync(CancellationToken cancellationToken)
    {
        await _reconcileGate.WaitAsync(cancellationToken);
        try
        {
            IReadOnlyList<DesiredPlacement> desired;
            lock (_desiredGate)
            {
                desired = _desired ?? [];
                _desired = [.. desired.Where(static placement => placement.Service.Mode == PlacementMode.Stateful)];
            }

            var listed = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken);
            return listed switch
            {
                IReadOnlyList<ManagedContainer> containers => await DrainContainersAsync(desired, containers, cancellationToken),
                DockerDaemonUnavailable failed => new NodeDrainUnverified(failed.Message),
                DockerResponseInvalid failed => new NodeDrainUnverified(failed.Message),
            };
        }
        finally
        {
            _reconcileGate.Release();
        }
    }

    private async Task<NodeDrain> DrainContainersAsync(IReadOnlyList<DesiredPlacement> desired, IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        var stateful = desired.Where(static p => p.Service.Mode == PlacementMode.Stateful).Select(static p => p.PlacementId).ToHashSet(StringComparer.Ordinal);
        var desiredByPlacement = desired.ToDictionary(static p => p.PlacementId, static p => p.Service, StringComparer.Ordinal);
        foreach (var group in containers.Where(container => IsStateful(container, desired, stateful) == false).GroupBy(static container => container.PlacementId, StringComparer.Ordinal))
        {
            var retired = await swapper.RetireAsync([.. group], desiredByPlacement.GetValueOrDefault(group.Key), cancellationToken);
            CompleteRetirement(group.Key, retired);
        }

        var listed = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken);
        return listed switch
        {
            IReadOnlyList<ManagedContainer> remaining => VerifyDrain(desired, stateful, remaining),
            DockerDaemonUnavailable failed => new NodeDrainUnverified(failed.Message),
            DockerResponseInvalid failed => new NodeDrainUnverified(failed.Message),
        };
    }

    private bool? IsStateful(ManagedContainer container, IReadOnlyList<DesiredPlacement> desired, HashSet<string> stateful) =>
        container.Stateful ?? (stateful.Contains(container.PlacementId) ? true
            : options.PoolKindOverride == PoolKind.Worker || desired.Any(p => p.PlacementId == container.PlacementId) ? false : null);

    private NodeDrain VerifyDrain(IReadOnlyList<DesiredPlacement> desired, HashSet<string> stateful, IReadOnlyList<ManagedContainer> containers)
    {
        if (containers.Any(container => IsStateful(container, desired, stateful) is null))
        {
            return new NodeDrainUnverified("Managed containers without placement mode labels could not be classified.");
        }

        var remaining = containers.Where(container => IsStateful(container, desired, stateful) == false)
            .Select(static container => container.PlacementId).Distinct(StringComparer.Ordinal).ToArray();
        return remaining.Length == 0 ? new NonStatefulContainersDrained() : new NodeDrainIncomplete(remaining);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.WhenAll(
            ReconcileLoopAsync(stoppingToken),
            CollectImagesAsync(stoppingToken),
            TickAsync(options.ReconcileInterval, Signal, stoppingToken),
            TickAsync(
                options.SecretCheckInterval,
                () =>
                {
                    secrets.InvalidateAll();
                    Signal();
                },
                stoppingToken));

    private async Task CollectImagesAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(options.ImageGcInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            await _reconcileGate.WaitAsync(cancellationToken);
            try
            {
                await imageGarbageCollector.CollectAsync(cancellationToken);
            }
            finally
            {
                _reconcileGate.Release();
            }
        }
    }

    private void Signal() => _signals.Writer.TryWrite(new ReconcileSignal());

    private async Task TickAsync(TimeSpan interval, Action onTick, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval, timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            onTick();
        }
    }

    private async Task ReconcileLoopAsync(CancellationToken cancellationToken)
    {
        await foreach (var _ in _signals.Reader.ReadAllAsync(cancellationToken))
        {
            await ReconcileOnceAsync(cancellationToken);
        }
    }

    private async Task ReconcileOnceAsync(CancellationToken cancellationToken)
    {
        await _reconcileGate.WaitAsync(cancellationToken);
        try
        {
            IReadOnlyList<DesiredPlacement>? desired;
            lock (_desiredGate)
            {
                desired = _desired;
            }

            if (desired is null)
            {
                return;
            }

            var outcome = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken);
            var failure = outcome switch
            {
                IReadOnlyList<ManagedContainer> containers => await ReconcileAsync(desired, containers, cancellationToken),
                DockerDaemonUnavailable listFailure => listFailure.Message,
                DockerResponseInvalid listFailure => listFailure.Message,
            };
            if (failure is not null)
            {
                AgentLog.ReconcileListFailed(logger, failure);
            }
        }
        finally
        {
            _reconcileGate.Release();
        }
    }

    private async Task<string?> ReconcileAsync(IReadOnlyList<DesiredPlacement> desired, IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        string? vcnIp;
        lock (_desiredGate)
        {
            vcnIp = _vcnIp;
        }

        if (!IPAddress.TryParse(vcnIp, out var address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return $"Node VCN address '{vcnIp}' must be a concrete IP address.";
        }

        var observedNetBirdIp = IPAddress.IsLoopback(address) ? null : NodeReportComposer.FindNetBirdIpv4();
        var network = ResolvePlacementNetwork(address, observedNetBirdIp, containers);
        var byPlacement = containers
            .GroupBy(static container => container.PlacementId, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => (IReadOnlyList<ManagedContainer>)[.. group], StringComparer.Ordinal);
        var desiredIds = desired.Select(static placement => placement.PlacementId).ToHashSet(StringComparer.Ordinal);
        var retainedIds = byPlacement.Keys.Concat(desiredIds).ToHashSet(StringComparer.Ordinal);
        secrets.DeleteOrphanedPlacements(retainedIds);

        await Parallel.ForEachAsync(
            desired,
            new ParallelOptions { MaxDegreeOfParallelism = MaxParallelPlacements, CancellationToken = cancellationToken },
            async (placement, placementToken) => await ReconcilePlacementAsync(placement, byPlacement.GetValueOrDefault(placement.PlacementId) ?? [], network, placementToken));

        foreach (var (placementId, orphaned) in byPlacement)
        {
            if (desiredIds.Contains(placementId))
            {
                continue;
            }

            AgentLog.PlacementRetiring(logger, placementId);
            var retired = await swapper.RetireAsync(orphaned, service: null, cancellationToken);
            CompleteRetirement(placementId, retired);
        }

        return null;
    }

    private PlacementNetwork ResolvePlacementNetwork(IPAddress address, string? observedNetBirdIp, IReadOnlyList<ManagedContainer> containers)
    {
        var vcnIp = address.ToString();
        if (IPAddress.IsLoopback(address))
        {
            return new PlacementNetwork(vcnIp, null);
        }

        _netBirdIp = ValidNetBirdIp(observedNetBirdIp) ?? _netBirdIp
            ?? containers.OrderByDescending(static container => container.Running)
                .ThenByDescending(static container => container.Created)
                .Select(static container => ValidNetBirdIp(container.NetBirdIp))
                .FirstOrDefault(static ip => ip is not null);
        return new PlacementNetwork(vcnIp, _netBirdIp == vcnIp ? null : _netBirdIp);
    }

    private static string? ValidNetBirdIp(string? value) =>
        IPAddress.TryParse(value, out var address)
            && address.AddressFamily == AddressFamily.InterNetwork
            && !address.Equals(IPAddress.Any)
            && !IPAddress.IsLoopback(address)
            ? address.ToString()
            : null;

    private void CompleteRetirement(string placementId, PlacementRetirement outcome)
    {
        var retired = outcome switch
        {
            PlacementRetired => true,
            PlacementDrainPending or PlacementContainersRemain => false,
        };
        if (retired)
        {
            _failures.TryRemove(placementId, out _);
            metrics.ForgetPlacement(placementId);
            if (AgentNames.IsSafeToken(placementId))
            {
                secrets.DeletePlacement(placementId);
            }
        }
    }

    private async Task ReconcilePlacementAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, PlacementNetwork network, CancellationToken cancellationToken)
    {
        if (!AgentNames.IsSafeToken(placement.PlacementId))
        {
            await ReportFailureAsync(placement, string.Empty, $"Placement id {placement.PlacementId} is not a safe container name token.", cancellationToken);
            return;
        }

        if (placement.Service.Port > 0 && !ContainerSwapper.TryReadyPath(placement.Service.ReadyPath, out _))
        {
            var invalid = new InvalidPlacementReadyPath(placement.Service.ReadyPath);
            if (swapper.FindServing(placement, existing) is { } serving)
            {
                await tracker.ReportAsync(
                    swapper.ServingReport(serving, placement.Service) with { CandidateImage = placement.Service.Image, CandidateError = invalid.Message },
                    cancellationToken);
            }
            else
            {
                await ReportFailureAsync(placement, string.Empty, invalid.Message, cancellationToken);
            }

            return;
        }

        var outcome = await secrets.ResolveAsync(placement.Service, cancellationToken);
        await (outcome switch
        {
            ResolvedServiceSecrets resolved => ApplyAsync(placement, existing, network, resolved, cancellationToken),
            InvalidSecretName failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            SecretNameCollision failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            InvalidServiceSecretReference failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            SecretReadSuperseded => Task.CompletedTask,
            ServiceSecretUnreadable failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
        });
    }

    private async Task SecretsUnavailableAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, string reason, CancellationToken cancellationToken)
    {
        if (swapper.FindServing(placement, existing) is { } serving)
        {
            AgentLog.SecretResolveDeferred(logger, placement.PlacementId, reason);
            await tracker.ReportAsync(
                swapper.ServingReport(serving, placement.Service),
                cancellationToken);
            return;
        }

        await ReportFailureAsync(placement, string.Empty, reason, cancellationToken);
    }

    private async Task ApplyAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, PlacementNetwork network, ResolvedServiceSecrets resolved, CancellationToken cancellationToken)
    {
        var service = placement.Service;
        var configHash = ConfigHashCalculator.Compute(service, resolved.Versions, network);
        var current = existing.FirstOrDefault(container => container.Running && container.Image == service.Image && container.ConfigHash == configHash);
        if (current is not null)
        {
            await KeepCurrentAsync(placement, current, existing, network.VcnIp, cancellationToken);
            return;
        }

        if (_failures.TryGetValue(placement.PlacementId, out var failure) && failure.ConfigHash == configHash && timeProvider.GetUtcNow() < failure.RetryAt)
        {
            return;
        }

        if (service.ClusterPeers && network.NetBirdIp is { } netBirdIp && NodeReportComposer.FindNetBirdIpv4() != netBirdIp)
        {
            AgentLog.WaitingForNetBirdBinding(logger, placement.PlacementId, netBirdIp);
            if (swapper.FindServing(placement, existing) is { } serving)
            {
                await tracker.ReportAsync(swapper.ServingReport(serving, service), cancellationToken);
            }
            else
            {
                await tracker.ReportAsync(new PlacementReport(placement.PlacementId, service.Name, PlacementState.Pending, service.Image,
                    configHash, Error: $"Waiting for the NetBird bind address {netBirdIp}."), cancellationToken);
            }

            return;
        }

        var outcome = await BuildPlanAsync(placement, configHash, resolved, network, cancellationToken);
        var task = outcome switch
        {
            PlacementPlan plan => SwapAsync(placement, plan, existing, cancellationToken),
            SecretNameCollision planFailure => SecretsUnavailableAsync(placement, existing, planFailure.Message, cancellationToken),
            InvalidConfigFileTarget planFailure => SecretsUnavailableAsync(placement, existing, planFailure.Message, cancellationToken),
            ConfigFileSecretMissing planFailure => SecretsUnavailableAsync(placement, existing, planFailure.Message, cancellationToken),
            AtomicWriteFailed planFailure => SecretsUnavailableAsync(placement, existing, planFailure.Message, cancellationToken),
        };
        await task;
    }

    private async Task SwapAsync(DesiredPlacement placement, PlacementPlan plan, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        var service = placement.Service;
        AgentLog.PlacementSwapping(logger, placement.PlacementId, service.Image, plan.ConfigHash, plan.RequiresStopStart);
        var outcome = await swapper.SwapAsync(plan, existing, RecordPulledAsync, cancellationToken);
        var keep = outcome switch
        {
            PlacementPromoted promoted => await SwappedAsync(placement, promoted.LiveConfigurations, promoted.PulledImage, cancellationToken),
            InvalidPlacementPort or InvalidPlacementReadyPath or PlacementDrainPending or PlacementImagePullFailed or PlacementCreateFailed or PlacementStartFailed or PlacementProbeFailed
                => SwapFailed(placement, plan.ConfigHash, existing),
        };
        secrets.DeleteStaleGenerations(placement.PlacementId, keep);
    }

    private async Task<IReadOnlySet<string>> SwappedAsync(DesiredPlacement placement, IReadOnlySet<string> liveConfigurations, string pulledImage, CancellationToken cancellationToken)
    {
        _failures.TryRemove(placement.PlacementId, out _);
        var outcome = await images.RecordActiveAsync(placement.Service.Name, pulledImage, cancellationToken);
        var failure = outcome switch
        {
            ImageHistoryRecorded => null,
            ImageHistoryUnreadable recordFailure => recordFailure.Message,
            ImageHistoryWriteFailed recordFailure => recordFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageHistoryFailed(logger, failure);
        }

        return liveConfigurations;
    }

    private HashSet<string> SwapFailed(DesiredPlacement placement, string configHash, IReadOnlyList<ManagedContainer> existing)
    {
        RecordFailure(placement.PlacementId, configHash);
        return existing.Where(static container => container.Running).Select(static container => container.ConfigHash).ToHashSet(StringComparer.Ordinal);
    }

    private async Task RecordPulledAsync(string image, CancellationToken cancellationToken)
    {
        var outcome = await images.RecordPulledAsync(image, cancellationToken);
        var failure = outcome switch
        {
            ImageHistoryRecorded => null,
            ImageHistoryUnreadable recordFailure => recordFailure.Message,
            ImageHistoryWriteFailed recordFailure => recordFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageHistoryFailed(logger, failure);
        }
    }

    private async Task KeepCurrentAsync(DesiredPlacement placement, ManagedContainer current, IReadOnlyList<ManagedContainer> existing, string vcnIp, CancellationToken cancellationToken)
    {
        var report = ContainerSwapper.ReadyReport(current, placement.Service);
        if (tracker.Find(placement.PlacementId) != report)
        {
            if (swapper.FindServing(placement, existing) is { } serving && serving.Id != current.Id)
            {
                await tracker.ReportAsync(swapper.ServingReport(serving, placement.Service), cancellationToken);
            }

            var readiness = await swapper.WaitReadyAsync(current.Id, placement.Service, vcnIp, cancellationToken, allowExistingRestarts: true);
            var (ports, failure) = readiness switch
            {
                PlacementPorts ready => (ready, (PlacementProbeFailed?)null),
                PlacementProbeFailed failed => ((PlacementPorts?)null, failed),
            };
            if (failure is not null)
            {
                await swapper.StopAndRemoveAsync(current.Id, cancellationToken);
                await SecretsUnavailableAsync(placement, [.. existing.Where(container => container.Id != current.Id)], failure.Message, cancellationToken);
                Signal();
                return;
            }

            if (ports is { } readyPorts)
            {
                report = report with { HostPort = readyPorts.Http, PostgresHostPort = readyPorts.Postgres, InternalHostPort = readyPorts.Internal };
            }
            await tracker.ReportAsync(report, cancellationToken);
        }

        var keep = await swapper.RetirePreviousAsync(
            placement, current.ConfigHash, [.. existing.Where(container => container.Id != current.Id)],
            new PlacementPorts(report.HostPort, report.PostgresHostPort, report.InternalHostPort), cancellationToken);
        await SwappedAsync(placement, keep, current.PulledImage ?? current.Image, cancellationToken);
        secrets.DeleteStaleGenerations(placement.PlacementId, keep);
    }

    private async Task<PlacementPlanPreparation> BuildPlanAsync(
        DesiredPlacement placement,
        string configHash,
        ResolvedServiceSecrets resolved,
        PlacementNetwork network,
        CancellationToken cancellationToken)
    {
        var service = placement.Service;
        Dictionary<string, string> env = new(service.Env, StringComparer.Ordinal);
        string? nodeId;
        string? region;
        lock (_desiredGate)
        {
            nodeId = _nodeId;
            region = _region;
        }

        if (region is not null)
        {
            env.TryAdd("TS_REGION", region);
        }

        if (nodeId is not null)
        {
            env.TryAdd("TS_NODE", nodeId);
        }

        List<BindMount> mounts = [];
        foreach (var mount in service.Mounts)
        {
            await EnsureHostMountDirectoryAsync(mount.Source, cancellationToken);
            mounts.Add(new BindMount(mount.Source, mount.Target, ReadOnly: false));
        }

        if (service.ClusterPeers)
        {
            if (!File.Exists(options.PeersFile))
            {
                var seeded = await UnixFiles.WriteAtomicAsync(
                    [
                        new DirectoryMode(options.RuntimeDirectory, UnixFiles.WorldReadableDirectory),
                        new DirectoryMode(options.PeersDirectory, UnixFiles.WorldReadableDirectory),
                    ],
                    [new AtomicWrite(options.PeersFile, "[]"u8.ToArray(), UnixFiles.WorldReadable)],
                    cancellationToken);
                if (seeded is AtomicWriteFailed peerFailure)
                {
                    return peerFailure;
                }
            }

            mounts.Add(new BindMount(options.PeersDirectory, NodePaths.PeersDirectory, ReadOnly: true));
            env.TryAdd("TS_PEERS_FILE", NodePaths.PeersFile);
        }

        if (service.Secrets.Count == 0 && service.ConfigFiles is not { Count: > 0 })
        {
            return new PlacementPlan(placement, configHash, env, mounts, network);
        }

        var outcome = await secrets.MaterializeAsync(placement.PlacementId, configHash, service, resolved, cancellationToken);
        return outcome switch
        {
            SecretMounts secretMounts => WithSecrets(placement, configHash, env, mounts, network, secretMounts),
            InvalidConfigFileTarget invalid => invalid,
            ConfigFileSecretMissing missing => missing,
            AtomicWriteFailed failure => failure,
        };
    }

    private async Task EnsureHostMountDirectoryAsync(string sourcePath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !Path.IsPathFullyQualified(sourcePath))
        {
            return;
        }

        var existed = Directory.Exists(sourcePath);
        if (!existed)
        {
            Directory.CreateDirectory(sourcePath);
        }

        var normalized = Path.GetFullPath(sourcePath).TrimEnd('/');
        var dataRoot = Path.GetFullPath(options.DataVolumePath).TrimEnd('/');
        if (Environment.IsPrivilegedProcess
            && normalized.StartsWith(dataRoot + "/", StringComparison.Ordinal)
            && (!existed || normalized.EndsWith("/terrabase", StringComparison.Ordinal)))
        {
            await ProcessRunner.RunAsync("chown", ["1654:1654", normalized], ChownTimeout, timeProvider, cancellationToken);
        }
    }

    private static PlacementPlanPreparation WithSecrets(
        DesiredPlacement placement,
        string configHash,
        Dictionary<string, string> env,
        List<BindMount> mounts,
        PlacementNetwork network,
        SecretMounts secretMounts)
    {
        foreach (var (name, value) in secretMounts.Env)
        {
            if (!env.TryAdd(name, value))
            {
                return new SecretNameCollision(placement.Service.Name, name);
            }
        }

        mounts.AddRange(secretMounts.Mounts);
        return new PlacementPlan(placement, configHash, env, mounts, network);
    }

    private async Task ReportFailureAsync(DesiredPlacement placement, string configHash, string reason, CancellationToken cancellationToken)
    {
        AgentLog.PlacementFailed(logger, placement.PlacementId, placement.Service.Image, reason);
        await tracker.ReportAsync(
            new PlacementReport(
                placement.PlacementId,
                placement.Service.Name,
                PlacementState.Failed,
                placement.Service.Image,
                configHash,
                Error: reason,
                CandidateImage: placement.Service.Image,
                CandidateError: reason),
            cancellationToken);
    }

    private void RecordFailure(string placementId, string configHash)
    {
        var now = timeProvider.GetUtcNow();
        _failures.AddOrUpdate(
            placementId,
            static (_, state) => new FailedAttempt(state.ConfigHash, 1, state.Now + FirstRetryDelay),
            static (_, previous, state) =>
            {
                var attempts = previous.ConfigHash == state.ConfigHash ? previous.Attempts + 1 : 1;
                var delay = TimeSpan.FromTicks(Math.Min(MaxRetryDelay.Ticks, FirstRetryDelay.Ticks << Math.Min(attempts - 1, 10)));
                return new FailedAttempt(state.ConfigHash, attempts, state.Now + delay);
            },
            (ConfigHash: configHash, Now: now));
    }

    private readonly record struct ReconcileSignal;

    private sealed record class FailedAttempt(string ConfigHash, int Attempts, DateTimeOffset RetryAt);
}
