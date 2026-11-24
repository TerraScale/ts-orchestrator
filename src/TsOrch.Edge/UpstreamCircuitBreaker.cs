using System.Collections.Concurrent;
using System.Collections.Immutable;

namespace TsOrch.Edge;

public sealed class UpstreamCircuitBreaker(TimeProvider timeProvider)
{
    public const int FailureThreshold = 2;

    public static readonly TimeSpan QuarantineDuration = TimeSpan.FromSeconds(5);

    private readonly ConcurrentDictionary<(string Address, int Port), UpstreamHealth> _upstreams = new();
    private int _rotation;

    public EdgeUpstream? Select(ImmutableArray<EdgeUpstream> upstreams, ReadOnlySpan<EdgeUpstream> excluded)
    {
        if (upstreams.IsDefaultOrEmpty)
        {
            return null;
        }

        var nowTicks = timeProvider.GetUtcNow().UtcTicks;
        var offset = (int)((uint)Interlocked.Increment(ref _rotation) % (uint)upstreams.Length);
        EdgeUpstream? best = null;
        var bestRank = (Quarantined: true, Remote: true, Active: int.MaxValue, Until: long.MaxValue);
        for (var index = 0; index < upstreams.Length; index++)
        {
            var upstream = upstreams[(index + offset) % upstreams.Length];
            if (excluded.Contains(upstream))
            {
                continue;
            }

            var health = Health(upstream);
            var until = Volatile.Read(ref health.QuarantinedUntilTicks);
            var rank = (Quarantined: until > nowTicks, Remote: !upstream.Local, Active: Volatile.Read(ref health.ActiveConnections), Until: until);
            if (best is null || rank.CompareTo(bestRank) < 0)
            {
                best = upstream;
                bestRank = rank;
            }
        }

        return best;
    }

    public UpstreamLease Acquire(EdgeUpstream upstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        var health = Health(upstream);
        Interlocked.Increment(ref health.ActiveConnections);
        return new UpstreamLease(health);
    }

    public void ReportSuccess(EdgeUpstream upstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        Volatile.Write(ref Health(upstream).ConsecutiveFailures, 0);
    }

    public void ReportFailure(EdgeUpstream upstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        var health = Health(upstream);
        if (Interlocked.Increment(ref health.ConsecutiveFailures) < FailureThreshold)
        {
            return;
        }

        Volatile.Write(ref health.QuarantinedUntilTicks, timeProvider.GetUtcNow().Add(QuarantineDuration).UtcTicks);
        Volatile.Write(ref health.ConsecutiveFailures, 0);
    }

    public bool IsQuarantined(EdgeUpstream upstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        return Volatile.Read(ref Health(upstream).QuarantinedUntilTicks) > timeProvider.GetUtcNow().UtcTicks;
    }

    public void Retain(EdgeRouteSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var live = snapshot.HttpRoutes
            .Concat(snapshot.PostgresRoutes)
            .Concat(snapshot.InternalRoutes)
            .SelectMany(static route => route.Upstreams)
            .Select(static upstream => (upstream.Address, upstream.Port))
            .ToHashSet();
        foreach (var (key, health) in _upstreams)
        {
            if (!live.Contains(key) && Volatile.Read(ref health.ActiveConnections) == 0)
            {
                _upstreams.TryRemove(new KeyValuePair<(string Address, int Port), UpstreamHealth>(key, health));
            }
        }
    }

    private UpstreamHealth Health(EdgeUpstream upstream) =>
        _upstreams.GetOrAdd((upstream.Address, upstream.Port), static _ => new UpstreamHealth());
}

internal sealed class UpstreamHealth
{
    public int ConsecutiveFailures;
    public int ActiveConnections;
    public long QuarantinedUntilTicks;
}

public readonly record struct UpstreamLease : IDisposable
{
    private readonly UpstreamHealth? _health;

    internal UpstreamLease(UpstreamHealth health) => _health = health;

    public void Dispose()
    {
        if (_health is not null)
        {
            Interlocked.Decrement(ref _health.ActiveConnections);
        }
    }
}
