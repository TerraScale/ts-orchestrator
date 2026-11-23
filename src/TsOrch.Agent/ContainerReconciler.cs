using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;

namespace TsOrch.Agent;

public sealed class ContainerReconciler(
    DockerEngineClient docker,
    SecretStore secrets,
    ContainerSwapper swapper,
    PlacementTracker tracker,
    ImageHistoryStore images,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ContainerReconciler> logger) : BackgroundService
{
    private const int MaxParallelPlacements = 4;
    private static readonly TimeSpan FirstRetryDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(15);

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

    public async Task DrainAsync(CancellationToken cancellationToken)
    {
        lock (_desiredGate)
        {
            _desired = _desired is { } desired ? [.. desired.Where(static placement => placement.Service.Mode == PlacementMode.Stateful)] : null;
        }

        await ReconcileOnceAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await SeedAsync(stoppingToken);
        await Task.WhenAll(
            ReconcileLoopAsync(stoppingToken),
            TickAsync(options.ReconcileInterval, Signal, stoppingToken),
            TickAsync(
                options.SecretCheckInterval,
                () =>
                {
                    secrets.InvalidateAll();
                    Signal();
                },
                stoppingToken));
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

    private async Task SeedAsync(CancellationToken cancellationToken)
    {
        var containers = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken) switch
        {
            IReadOnlyList<ManagedContainer> listed => listed,
            Unavailable failure => ListFailed(failure.Message),
            InternalFailure failure => ListFailed(failure.Message),
        };
        foreach (var container in containers.Where(static container => container.Running))
        {
            await tracker.ReportAsync(
                new PlacementReport(
                    container.PlacementId,
                    container.ServiceName,
                    PlacementState.Ready,
                    container.Image,
                    container.ConfigHash,
                    container.Ports.FirstOrDefault(static port => port.Protocol == PortProtocol.Tcp)?.HostPort),
                cancellationToken);
        }
    }

    private IReadOnlyList<ManagedContainer> ListFailed(string reason)
    {
        AgentLog.ReconcileListFailed(logger, reason);
        return [];
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

            var failure = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken) switch
            {
                IReadOnlyList<ManagedContainer> containers => await ReconcileAsync(desired, containers, cancellationToken),
                Unavailable listFailure => listFailure.Message,
                InternalFailure listFailure => listFailure.Message,
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
        var byPlacement = containers
            .GroupBy(static container => container.PlacementId, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => (IReadOnlyList<ManagedContainer>)[.. group], StringComparer.Ordinal);
        await Parallel.ForEachAsync(
            desired,
            new ParallelOptions { MaxDegreeOfParallelism = MaxParallelPlacements, CancellationToken = cancellationToken },
            async (placement, placementToken) => await ReconcilePlacementAsync(placement, byPlacement.GetValueOrDefault(placement.PlacementId) ?? [], placementToken));

        var desiredIds = desired.Select(static placement => placement.PlacementId).ToHashSet(StringComparer.Ordinal);
        foreach (var (placementId, orphaned) in byPlacement)
        {
            if (desiredIds.Contains(placementId))
            {
                continue;
            }

            AgentLog.PlacementRetiring(logger, placementId);
            await swapper.RetireAsync(orphaned, cancellationToken);
            _failures.TryRemove(placementId, out _);
            if (AgentNames.IsSafeToken(placementId))
            {
                secrets.DeletePlacement(placementId);
            }
        }

        return null;
    }

    private async Task ReconcilePlacementAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        if (!AgentNames.IsSafeToken(placement.PlacementId))
        {
            await ReportFailureAsync(placement, string.Empty, $"Placement id {placement.PlacementId} is not a safe container name token.", cancellationToken);
            return;
        }

        var task = await secrets.ResolveAsync(placement.Service, cancellationToken) switch
        {
            ResolvedServiceSecrets resolved => ApplyAsync(placement, existing, resolved, cancellationToken),
            Validation failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            NotFound failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            Forbidden failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            Unavailable failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
            InternalFailure failure => SecretsUnavailableAsync(placement, existing, failure.Message, cancellationToken),
        };
        await task;
    }

    private async Task SecretsUnavailableAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, string reason, CancellationToken cancellationToken)
    {
        if (existing.FirstOrDefault(static container => container.Running) is { } serving)
        {
            AgentLog.SecretResolveDeferred(logger, placement.PlacementId, reason);
            await tracker.ReportAsync(
                new PlacementReport(placement.PlacementId, placement.Service.Name, PlacementState.Ready, serving.Image, serving.ConfigHash, ContainerSwapper.HttpHostPort(serving, placement.Service)),
                cancellationToken);
            return;
        }

        await ReportFailureAsync(placement, string.Empty, reason, cancellationToken);
    }

    private async Task ApplyAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, ResolvedServiceSecrets resolved, CancellationToken cancellationToken)
    {
        var service = placement.Service;
        var configHash = ConfigHashCalculator.Compute(service, resolved.Versions);
        var current = existing.FirstOrDefault(container => container.Running && container.Image == service.Image && container.ConfigHash == configHash);
        if (current is not null)
        {
            await KeepCurrentAsync(placement, current, existing, cancellationToken);
            return;
        }

        if (_failures.TryGetValue(placement.PlacementId, out var failure) && failure.ConfigHash == configHash && timeProvider.GetUtcNow() < failure.RetryAt)
        {
            return;
        }

        var task = await BuildPlanAsync(placement, configHash, resolved, cancellationToken) switch
        {
            PlacementPlan plan => SwapAsync(placement, plan, existing, cancellationToken),
            Validation planFailure => ReportFailureAsync(placement, configHash, planFailure.Message, cancellationToken),
            InternalFailure planFailure => ReportFailureAsync(placement, configHash, planFailure.Message, cancellationToken),
        };
        await task;
    }

    private async Task SwapAsync(DesiredPlacement placement, PlacementPlan plan, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        var service = placement.Service;
        AgentLog.PlacementSwapping(logger, placement.PlacementId, service.Image, plan.ConfigHash, plan.RequiresStopStart);
        var keep = await swapper.SwapAsync(plan, existing, RecordPulledAsync, cancellationToken) switch
        {
            ManagedContainer => await SwappedAsync(placement, plan.ConfigHash, cancellationToken),
            Validation => SwapFailed(placement, plan.ConfigHash, existing),
            NotFound => SwapFailed(placement, plan.ConfigHash, existing),
            Conflict => SwapFailed(placement, plan.ConfigHash, existing),
            Unavailable => SwapFailed(placement, plan.ConfigHash, existing),
            InternalFailure => SwapFailed(placement, plan.ConfigHash, existing),
        };
        secrets.DeleteStaleGenerations(placement.PlacementId, keep);
    }

    private async Task<IReadOnlySet<string>> SwappedAsync(DesiredPlacement placement, string configHash, CancellationToken cancellationToken)
    {
        _failures.TryRemove(placement.PlacementId, out _);
        var failure = await images.RecordActiveAsync(placement.Service.Name, placement.Service.Image, cancellationToken) switch
        {
            Done => null,
            InternalFailure recordFailure => recordFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageHistoryFailed(logger, failure);
        }

        return new HashSet<string>(StringComparer.Ordinal) { configHash };
    }

    private HashSet<string> SwapFailed(DesiredPlacement placement, string configHash, IReadOnlyList<ManagedContainer> existing)
    {
        RecordFailure(placement.PlacementId, configHash);
        return existing.Where(static container => container.Running).Select(static container => container.ConfigHash).ToHashSet(StringComparer.Ordinal);
    }

    private async Task RecordPulledAsync(string image, CancellationToken cancellationToken)
    {
        var failure = await images.RecordPulledAsync(image, cancellationToken) switch
        {
            Done => null,
            InternalFailure recordFailure => recordFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageHistoryFailed(logger, failure);
        }
    }

    private async Task KeepCurrentAsync(DesiredPlacement placement, ManagedContainer current, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        foreach (var leftover in existing.Where(container => container.Id != current.Id))
        {
            await swapper.StopAndRemoveAsync(leftover.Id, cancellationToken);
        }

        _failures.TryRemove(placement.PlacementId, out _);
        await tracker.ReportAsync(
            new PlacementReport(placement.PlacementId, placement.Service.Name, PlacementState.Ready, current.Image, current.ConfigHash, ContainerSwapper.HttpHostPort(current, placement.Service)),
            cancellationToken);
        secrets.DeleteStaleGenerations(placement.PlacementId, new HashSet<string>(StringComparer.Ordinal) { current.ConfigHash });
    }

    private async Task<Result<PlacementPlan, Validation, InternalFailure>> BuildPlanAsync(
        DesiredPlacement placement,
        string configHash,
        ResolvedServiceSecrets resolved,
        CancellationToken cancellationToken)
    {
        var service = placement.Service;
        Dictionary<string, string> env = new(service.Env, StringComparer.Ordinal);
        List<BindMount> mounts = [.. service.Mounts.Select(static mount => new BindMount(mount.Source, mount.Target, ReadOnly: false))];
        if (service.Secrets.Count == 0)
        {
            return new PlacementPlan(placement, configHash, env, mounts);
        }

        return await secrets.MaterializeAsync(placement.PlacementId, configHash, resolved, cancellationToken) switch
        {
            SecretMount secretMount => WithSecrets(placement, configHash, env, mounts, secretMount),
            InternalFailure failure => failure,
        };
    }

    private static Result<PlacementPlan, Validation, InternalFailure> WithSecrets(
        DesiredPlacement placement,
        string configHash,
        Dictionary<string, string> env,
        List<BindMount> mounts,
        SecretMount secretMount)
    {
        foreach (var (name, value) in secretMount.Env)
        {
            if (!env.TryAdd(name, value))
            {
                return new Validation($"Secret file variable {name} of {placement.Service.Name} collides with a plain environment variable.");
            }
        }

        mounts.Add(secretMount.Mount);
        return new PlacementPlan(placement, configHash, env, mounts);
    }

    private async Task ReportFailureAsync(DesiredPlacement placement, string configHash, string reason, CancellationToken cancellationToken)
    {
        AgentLog.PlacementFailed(logger, placement.PlacementId, placement.Service.Image, reason);
        await tracker.ReportAsync(
            new PlacementReport(placement.PlacementId, placement.Service.Name, PlacementState.Failed, placement.Service.Image, configHash, Error: reason),
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
