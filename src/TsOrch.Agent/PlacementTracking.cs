using System.Threading.Channels;

namespace TsOrch.Agent;

public sealed class AgentOutbox
{
    private const int Capacity = 1024;

    private readonly Channel<AgentMessage> _channel = Channel.CreateBounded<AgentMessage>(new BoundedChannelOptions(Capacity)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
    });

    public ChannelReader<AgentMessage> Reader => _channel.Reader;

    public ValueTask EnqueueAsync(AgentMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        return _channel.Writer.WriteAsync(message, cancellationToken);
    }
}

public sealed class PlacementTracker(AgentOutbox outbox)
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, PlacementReport> _reports = [with(StringComparer.Ordinal)];

    public async ValueTask ReportAsync(PlacementReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        bool changed;
        lock (_gate)
        {
            changed = !_reports.TryGetValue(report.PlacementId, out var previous) || previous != report;
            _reports[report.PlacementId] = report;
        }

        if (changed)
        {
            await outbox.EnqueueAsync(ToEvent(report), cancellationToken);
        }
    }

    public async ValueTask RetireAsync(PlacementReport finalReport, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finalReport);
        lock (_gate)
        {
            _reports.Remove(finalReport.PlacementId);
        }

        await outbox.EnqueueAsync(ToEvent(finalReport), cancellationToken);
    }

    public PlacementReport? Find(string placementId)
    {
        lock (_gate)
        {
            return _reports.GetValueOrDefault(placementId);
        }
    }

    public IReadOnlyList<PlacementReport> Snapshot()
    {
        lock (_gate)
        {
            return [.. _reports.Values.OrderBy(static report => report.PlacementId, StringComparer.Ordinal)];
        }
    }

    private static PlacementEvent ToEvent(PlacementReport report) =>
        new(report.PlacementId, report.State, report.Image, report.ConfigHash, report.HostPort, report.Error);
}

public sealed class RouteObserver(TimeProvider timeProvider)
{
    private readonly Lock _gate = new();
    private readonly List<RouteWaiter> _waiters = [];
    private EdgeRoutesSnapshot? _current;

    public EdgeRoutesSnapshot? Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    public bool TryPublish(EdgeRoutesSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        List<RouteWaiter> satisfied = [];
        lock (_gate)
        {
            if (_current is { } current && current.Revision > snapshot.Revision)
            {
                return false;
            }

            _current = snapshot;
            foreach (var waiter in _waiters)
            {
                if (waiter.Predicate(snapshot))
                {
                    satisfied.Add(waiter);
                }
            }

            _waiters.RemoveAll(satisfied.Contains);
        }

        foreach (var waiter in satisfied)
        {
            waiter.Completion.TrySetResult();
        }

        return true;
    }

    public static bool IsRouted(EdgeRoutesSnapshot snapshot, string placementId)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.HttpRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId))
            || snapshot.PostgresRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId));
    }

    public static bool IsRoutedTo(EdgeRoutesSnapshot snapshot, string placementId, int hostPort)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.HttpRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId && upstream.Port == hostPort));
    }

    public async Task<bool> WaitUntilAsync(Func<EdgeRoutesSnapshot, bool> predicate, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        var waiter = new RouteWaiter(predicate, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        lock (_gate)
        {
            if (_current is { } current && predicate(current))
            {
                return true;
            }

            _waiters.Add(waiter);
        }

        try
        {
            await waiter.Completion.Task.WaitAsync(timeout, timeProvider, cancellationToken);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        finally
        {
            lock (_gate)
            {
                _waiters.Remove(waiter);
            }
        }
    }

    private sealed record class RouteWaiter(Func<EdgeRoutesSnapshot, bool> Predicate, TaskCompletionSource Completion);
}
