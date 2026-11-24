using System.Text.Json;
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
        new(
            report.PlacementId,
            report.State,
            report.Image,
            report.ConfigHash,
            report.HostPort,
            report.Error,
            report.PostgresHostPort,
            report.InternalHostPort,
            report.CandidateImage,
            report.CandidateError);
}

public sealed class RouteObserver(AgentOptions options, TimeProvider timeProvider)
{
    private readonly Lock _gate = new();
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);
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
        lock (_gate)
        {
            if (_current is { } current && current.Revision > snapshot.Revision)
            {
                return false;
            }

            _current = snapshot;
        }

        return true;
    }

    public static bool IsRouted(EdgeRoutesSnapshot snapshot, string placementId)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.HttpRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId))
            || snapshot.PostgresRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId))
            || (snapshot.InternalRoutes is { } internalRoutes && internalRoutes.Any(route => route.Upstreams.Any(upstream => upstream.PlacementId == placementId)));
    }

    public static bool IsRoutedTo(EdgeRoutesSnapshot snapshot, string placementId, int? httpPort, int? postgresPort, int? internalPort = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var http = snapshot.HttpRoutes.SelectMany(static route => route.Upstreams).Where(upstream => upstream.PlacementId == placementId);
        var postgres = snapshot.PostgresRoutes.SelectMany(static route => route.Upstreams).Where(upstream => upstream.PlacementId == placementId);
        var internalUpstreams = (snapshot.InternalRoutes ?? []).SelectMany(static route => route.Upstreams).Where(upstream => upstream.PlacementId == placementId);
        return (httpPort is { } httpTarget ? http.Any() && http.All(upstream => upstream.Port == httpTarget) : !http.Any())
            && (postgresPort is { } postgresTarget ? postgres.Any() && postgres.All(upstream => upstream.Port == postgresTarget) : !postgres.Any())
            && (internalPort is { } internalTarget ? internalUpstreams.Any() && internalUpstreams.All(upstream => upstream.Port == internalTarget) : !internalUpstreams.Any());
    }

    public async Task<bool> WaitUntilAsync(Func<EdgeRoutesSnapshot, bool> predicate, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        using var timer = new PeriodicTimer(PollInterval, timeProvider);
        try
        {
            do
            {
                var applied = await ReadAppliedAsync(linked.Token);
                if (applied is { } ack && Current is { } snapshot && ack.Revision >= snapshot.Revision && predicate(snapshot))
                {
                    return true;
                }
            }
            while (await timer.WaitForNextTickAsync(linked.Token));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        return false;
    }

    private async Task<EdgeAppliedRoutes?> ReadAppliedAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(options.AppliedRoutesFile, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous);
            return await JsonSerializer.DeserializeAsync(stream, EdgeJsonContext.Default.EdgeAppliedRoutes, cancellationToken);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
