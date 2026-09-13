using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Observation counters of one message-id duplicate window. They sit next to — never in place
/// of — the operation-level idempotency-replay counters so the two layers stay distinguishable.
/// </summary>
internal sealed record NatsMessageIdDeduplicationSnapshot(
    int Admitted,
    int Suppressed,
    int Conflicting,
    int BeyondWindow,
    int Resident);

/// <summary>
/// The transport-level message-id duplicate window for one durable work channel, layered
/// BENEATH operation-level idempotency: <see cref="Record"/> is called only after a consumer
/// proved the durable effect (or recorded a terminal disposition), and <see cref="Inspect"/>
/// is read-only, so a suppressed replay is always a verified idempotent replay and can never
/// skip unprocessed work. The window is bounded (FIFO capacity), pure (explicit timestamps),
/// and makes no exactly-once claim.
/// </summary>
internal sealed class NatsMessageIdDeduplication
{
    /// <summary>Bounded resident set: the memory ceiling of one channel's transport window.</summary>
    internal const int DefaultCapacity = 4096;

    private readonly MessageIdDuplicateWindow window;
    private int admitted;
    private int suppressed;
    private int conflicting;
    private int beyondWindow;

    internal NatsMessageIdDeduplication(DuplicateWindowPolicy policy, int capacity = DefaultCapacity)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!policy.IsWellFormed)
            throw new ArgumentException("The duplicate-window policy is not well formed.", nameof(policy));
        window = new MessageIdDuplicateWindow(policy.Window, capacity);
        Policy = policy;
    }

    internal DuplicateWindowPolicy Policy { get; }

    internal string Channel => Policy.Channel;

    internal TimeSpan Window => Policy.Window;

    internal NatsMessageIdDeduplicationSnapshot Snapshot =>
        new(admitted, suppressed, conflicting, beyondWindow, window.Count);

    /// <summary>Read-only pre-dispatch decision; never records anything.</summary>
    internal DuplicateWindowDecision Inspect(string messageId, string digest, DateTimeOffset now) =>
        window.Inspect(messageId, digest, now);

    /// <summary>
    /// Records one COMPLETED message identity. Call only after the durable effect exists or a
    /// terminal disposition was recorded for this exact delivery.
    /// </summary>
    internal DuplicateWindowDecision Record(string messageId, string digest, DateTimeOffset now)
    {
        var decision = window.Observe(messageId, digest, now);
        switch (decision)
        {
            case DuplicateWindowDecision.Admit:
                admitted++;
                break;
            case DuplicateWindowDecision.Suppress:
                suppressed++;
                break;
            case DuplicateWindowDecision.Conflict:
                conflicting++;
                break;
            case DuplicateWindowDecision.AdmitBeyondWindow:
                beyondWindow++;
                break;
        }

        return decision;
    }
}

