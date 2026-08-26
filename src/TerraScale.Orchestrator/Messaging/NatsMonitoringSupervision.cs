namespace TerraScale.Orchestrator.Messaging;

/// <summary>The supervision decision for the monitoring observer itself.</summary>
internal enum NatsMonitoringSupervisionAction
{
    /// <summary>Observations are current; keep serving the aggregate.</summary>
    Continue = 1,

    /// <summary>Observations are aging or partially failing; keep the last truthful aggregate marked degraded.</summary>
    MarkDegraded = 2,

    /// <summary>No current observation at all; report unavailability instead of stale numbers.</summary>
    MarkUnavailable = 3
}

/// <summary>
/// Supervision for the NATS monitoring observer. The contract is one-directional by
/// construction: supervision can only change how observability reports itself
/// (available, degraded, unavailable); it has no capability that could gate, delay,
/// or fail regional control, and its evaluation is a pure function of observation
/// freshness and failure counts. Advisory loss degrades the advisory counters only.
/// </summary>
internal static class NatsMonitoringSupervision
{
    /// <summary>Observations older than this stay truthful-but-degraded.</summary>
    internal static readonly TimeSpan DegradedAfter = TimeSpan.FromSeconds(30);

    /// <summary>Observations older than this are reported unavailable, never stale-served.</summary>
    internal static readonly TimeSpan UnavailableAfter = TimeSpan.FromMinutes(2);

    /// <summary>Consecutive failed observation rounds tolerated before degrading.</summary>
    internal const int DegradedAfterConsecutiveFailures = 1;

    internal static NatsMonitoringSupervisionAction Evaluate(
        DateTimeOffset? lastSuccessfulObservation,
        int consecutiveFailedRounds,
        DateTimeOffset now)
    {
        if (consecutiveFailedRounds < 0) throw new ArgumentOutOfRangeException(nameof(consecutiveFailedRounds));
        if (lastSuccessfulObservation is { } observed)
        {
            var age = now - observed;
            if (age < DegradedAfter && consecutiveFailedRounds == 0)
                return NatsMonitoringSupervisionAction.Continue;
            if (age < UnavailableAfter)
                return NatsMonitoringSupervisionAction.MarkDegraded;
            return NatsMonitoringSupervisionAction.MarkUnavailable;
        }
        // No successful observation yet: never report healthy. Starting without
        // failures is degraded (no data yet); any failure before the first
        // success is unavailable.
        return consecutiveFailedRounds == 0
            ? NatsMonitoringSupervisionAction.MarkDegraded
            : NatsMonitoringSupervisionAction.MarkUnavailable;
    }

    internal static NatsMonitoringAvailability Availability(
        DateTimeOffset? lastSuccessfulObservation,
        int consecutiveFailedRounds,
        DateTimeOffset now) =>
        Evaluate(lastSuccessfulObservation, consecutiveFailedRounds, now) switch
        {
            NatsMonitoringSupervisionAction.Continue => NatsMonitoringAvailability.Available,
            NatsMonitoringSupervisionAction.MarkDegraded => NatsMonitoringAvailability.Degraded,
            _ => NatsMonitoringAvailability.Unavailable
        };

    /// <summary>
    /// True when a degraded or unavailable observer leaves regional control fully
    /// operative. Always true by construction; the pure function exists so tests can
    /// pin the invariant that no supervision state ever suppresses control.
    /// </summary>
    internal static bool RegionalControlContinues(NatsMonitoringSupervisionAction action) => true;
}
