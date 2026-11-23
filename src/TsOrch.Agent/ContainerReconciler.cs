using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class ContainerReconciler(
    DockerEngineClient docker,
    SecretStore secrets,
    ContainerSwapper swapper,
    PlacementTracker tracker,
    ImageHistoryStore images,
    IOptions<AgentOptions> options,
    TimeProvider timeProvider,
    ILogger<ContainerReconciler> logger) : BackgroundService
{
    private const int MaxParallelPlacements = 4;
    private static readonly TimeSpan FirstRetryDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(15);

    private readonly AgentOptions _options = options.Value;
    private readonly Lock _desiredGate = new();
    private readonly SemaphoreSlim _reconcileGate = new(1, 1);
    private readonly ConcurrentDictionary<string, FailedAttempt> _failures = new(StringComparer.Ordinal);
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
                logger.StaleDesiredIgnored(desired.Revision, _desiredRevision);
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

        logger.SecretRefreshRequested(serviceName, matching.Count);
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
            TickAsync(_options.ReconcileInterval, Signal, stoppingToken),
            TickAsync(
                _options.SecretCheckInterval,
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
        var listed = await docker.ListManagedContainersAsync(_options.LabelPrefix, cancellationToken);
        if (!listed.TryGetValue(out var containers, out var error))
        {
            logger.ReconcileListFailed(error.Message);
            return;
        }

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

            var listed = await docker.ListManagedContainersAsync(_options.LabelPrefix, cancellationToken);
            if (!listed.TryGetValue(out var containers, out var listError))
            {
                logger.ReconcileListFailed(listError.Message);
                return;
            }

            var byPlacement = containers
                .GroupBy(static container => container.PlacementId, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => (IReadOnlyList<ManagedContainer>)[.. group], StringComparer.Ordinal);
            await Parallel.ForEachAsync(
                desired,
                new ParallelOptions { MaxDegreeOfParallelism = MaxParallelPlacements, CancellationToken = cancellationToken },
                async (placement, token) => await ReconcilePlacementAsync(placement, byPlacement.GetValueOrDefault(placement.PlacementId) ?? [], token));

            var desiredIds = desired.Select(static placement => placement.PlacementId).ToHashSet(StringComparer.Ordinal);
            foreach (var (placementId, orphaned) in byPlacement)
            {
                if (desiredIds.Contains(placementId))
                {
                    continue;
                }

                logger.PlacementRetiring(placementId);
                await swapper.RetireAsync(orphaned, cancellationToken);
                _failures.TryRemove(placementId, out _);
                if (AgentNames.IsSafeToken(placementId))
                {
                    secrets.DeletePlacement(placementId);
                }
            }
        }
        finally
        {
            _reconcileGate.Release();
        }
    }

    private async Task ReconcilePlacementAsync(DesiredPlacement placement, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        var service = placement.Service;
        if (!AgentNames.IsSafeToken(placement.PlacementId))
        {
            await ReportFailureAsync(placement, string.Empty, new Validation($"Placement id {placement.PlacementId} is not a safe container name token."), cancellationToken);
            return;
        }

        var resolvedResult = await secrets.ResolveAsync(service, cancellationToken);
        if (!resolvedResult.TryGetValue(out var resolved, out var secretError))
        {
            if (existing.FirstOrDefault(static container => container.Running) is { } serving)
            {
                logger.SecretResolveDeferred(placement.PlacementId, secretError.Message);
                await tracker.ReportAsync(
                    new PlacementReport(placement.PlacementId, service.Name, PlacementState.Ready, serving.Image, serving.ConfigHash, ContainerSwapper.HttpHostPort(serving, service)),
                    cancellationToken);
                return;
            }

            await ReportFailureAsync(placement, string.Empty, secretError, cancellationToken);
            return;
        }

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

        var planResult = await BuildPlanAsync(placement, configHash, resolved, cancellationToken);
        if (!planResult.TryGetValue(out var plan, out var planError))
        {
            await ReportFailureAsync(placement, configHash, planError, cancellationToken);
            return;
        }

        logger.PlacementSwapping(placement.PlacementId, service.Image, configHash, plan.RequiresStopStart);
        var swapped = await swapper.SwapAsync(plan, existing, images.RecordPulledAsync, cancellationToken);
        switch (swapped)
        {
            case ManagedContainer:
                _failures.TryRemove(placement.PlacementId, out _);
                await images.RecordActiveAsync(service.Name, service.Image, cancellationToken);
                secrets.DeleteStaleGenerations(placement.PlacementId, new HashSet<string>(StringComparer.Ordinal) { configHash });
                break;
            case OrchError:
                RecordFailure(placement.PlacementId, configHash);
                secrets.DeleteStaleGenerations(placement.PlacementId, existing.Where(static container => container.Running).Select(static container => container.ConfigHash).ToHashSet(StringComparer.Ordinal));
                break;
        }
    }

    private async Task KeepCurrentAsync(DesiredPlacement placement, ManagedContainer current, IReadOnlyList<ManagedContainer> existing, CancellationToken cancellationToken)
    {
        foreach (var leftover in existing.Where(container => container.Id != current.Id))
        {
            await docker.StopContainerAsync(leftover.Id, (int)Math.Ceiling(_options.ContainerStopTimeout.TotalSeconds), cancellationToken);
            await docker.RemoveContainerAsync(leftover.Id, force: true, cancellationToken);
        }

        _failures.TryRemove(placement.PlacementId, out _);
        await tracker.ReportAsync(
            new PlacementReport(placement.PlacementId, placement.Service.Name, PlacementState.Ready, current.Image, current.ConfigHash, ContainerSwapper.HttpHostPort(current, placement.Service)),
            cancellationToken);
        secrets.DeleteStaleGenerations(placement.PlacementId, new HashSet<string>(StringComparer.Ordinal) { current.ConfigHash });
    }

    private async Task<OrchResult<PlacementPlan>> BuildPlanAsync(
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

        SecretMount secretMount;
        try
        {
            var materialized = await secrets.MaterializeAsync(placement.PlacementId, configHash, resolved, cancellationToken);
            if (!materialized.TryGetValue(out var mount, out var error))
            {
                return error;
            }

            secretMount = mount;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new Internal($"Writing secret files for {placement.PlacementId} failed: {exception.Message}");
        }

        foreach (var (name, value) in secretMount.Env)
        {
            if (!env.TryAdd(name, value))
            {
                return new Validation($"Secret file variable {name} of {service.Name} collides with a plain environment variable.");
            }
        }

        mounts.Add(secretMount.Mount);
        return new PlacementPlan(placement, configHash, env, mounts);
    }

    private async Task ReportFailureAsync(DesiredPlacement placement, string configHash, OrchError error, CancellationToken cancellationToken)
    {
        logger.PlacementFailed(placement.PlacementId, placement.Service.Image, error.Message);
        await tracker.ReportAsync(
            new PlacementReport(placement.PlacementId, placement.Service.Name, PlacementState.Failed, placement.Service.Image, configHash, Error: error.Message),
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
