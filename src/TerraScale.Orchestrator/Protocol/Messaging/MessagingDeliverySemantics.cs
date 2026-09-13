namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// Acknowledgement policy: a worker acknowledges only after the durable effect exists or an
/// idempotent replay of the same effect is proven. This pins the landed behaviour — the
/// acceptance journal record precedes the double-ack, and authority loss after acceptance
/// withholds the ack so the next epoch holder re-derives the outcome.
/// </summary>
public sealed record DurableEffectAcknowledgementPolicy(
    bool RequiresDoubleAck,
    TimeSpan? ProgressHeartbeat,
    string DurableEffectEvidence)
{
    public static DurableEffectAcknowledgementPolicy Landed { get; } =
        new(true, TimeSpan.FromSeconds(30), "Journal acceptance or convergence record for the exact operation id");

    public bool IsWellFormed =>
        RequiresDoubleAck &&
        !string.IsNullOrWhiteSpace(DurableEffectEvidence) &&
        DurableEffectEvidence.Length <= 256 &&
        (ProgressHeartbeat is null || ProgressHeartbeat > TimeSpan.Zero);
}

/// <summary>
/// Bounded redelivery policy. JetStream derives the effective ack wait from the first backoff
/// interval, so the declared ack wait must equal it. Exhaustion stops redelivery only with
/// terminal evidence — no message may disappear silently. The pinned maximum ack-pending is
/// the landed CellSpec consumer profile; per-consumer flow control may tighten it further
/// (the fenced CI runner inbox pins 1) but never loosens the redelivery contract.
/// </summary>
public sealed record BoundedRedeliveryPolicy(
    int MaximumDeliveries,
    IReadOnlyList<TimeSpan> BackoffLadder,
    int MaximumAckPending,
    bool ExhaustionRequiresTerminalEvidence)
{
    public static BoundedRedeliveryPolicy Landed { get; } = new(
        5,
        [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30)],
        8,
        true);

    /// <summary>The declared ack wait must equal the first backoff interval.</summary>
    public TimeSpan AckWait => BackoffLadder.Count > 0
        ? BackoffLadder[0]
        : throw new InvalidOperationException("The backoff ladder is empty.");

    public bool IsWellFormed =>
        MaximumDeliveries is >= 1 and <= 100 &&
        BackoffLadder is { Count: >= 1 and <= 16 } &&
        BackoffLadder.All(static step => step > TimeSpan.Zero) &&
        BackoffLadderStrictlyIncreasing() &&
        MaximumAckPending >= 1 &&
        ExhaustionRequiresTerminalEvidence;

    private bool BackoffLadderStrictlyIncreasing()
    {
        for (var index = 1; index < BackoffLadder.Count; index++)
        {
            if (BackoffLadder[index] <= BackoffLadder[index - 1])
            {
                return false;
            }
        }

        return true;
    }
}

public enum PoisonDisposition
{
    Unspecified = 0,
    /// <summary>A deterministic durable conflict: terminate now with terminal evidence.</summary>
    Terminate,
    /// <summary>Transient failure: negative-acknowledge with the next backoff delay.</summary>
    RetryWithDelay,
    /// <summary>Operational capacity issue: retry with delay, stay loud, and never terminate the healthy message.</summary>
    HoldForOperator,
    /// <summary>The delivery budget is exhausted: redelivery stops and terminal evidence is mandatory.</summary>
    Exhausted,
}

/// <summary>Why a message was terminated or exhausted; the reason must survive in terminal evidence.</summary>
public enum PoisonTerminalReason
{
    Unspecified = 0,
    DeterministicIdentityConflict,
    MalformedEnvelope,
    DuplicateOperationWithDifferentPayload,
    DeliveryBudgetExhausted,
    JournalRetentionOverflow,
}

/// <summary>
/// Poison-message decision core. A deterministic conflict (identical inputs, same wrong result
/// every redelivery) terminates immediately; a transient failure retries with delay; an
/// operational capacity failure holds loudly; exhaustion always produces terminal evidence.
/// </summary>
public static class PoisonMessagePolicy
{
    public sealed record PoisonDecision(PoisonDisposition Disposition, PoisonTerminalReason Reason, TimeSpan? Delay)
    {
        public static readonly PoisonDecision None = new(PoisonDisposition.Unspecified, PoisonTerminalReason.Unspecified, null);
    }

    /// <summary>
    /// Decides the disposition of one delivery attempt. <paramref name="deliveryCount"/> is
    /// 1-based; <paramref name="maximumDeliveries"/> comes from the consumer profile.
    /// </summary>
    public static PoisonDecision Decide(
        bool deterministicConflict,
        bool malformedInput,
        bool operationalCapacityFailure,
        int deliveryCount,
        int maximumDeliveries,
        IReadOnlyList<TimeSpan> backoffLadder)
    {
        if (maximumDeliveries < 1 || deliveryCount < 1 || backoffLadder.Count == 0)
        {
            return PoisonDecision.None;
        }

        if (deterministicConflict)
        {
            return new PoisonDecision(
                PoisonDisposition.Terminate,
                PoisonTerminalReason.DeterministicIdentityConflict,
                null);
        }

        if (operationalCapacityFailure)
        {
            return new PoisonDecision(
                PoisonDisposition.HoldForOperator,
                PoisonTerminalReason.JournalRetentionOverflow,
                backoffLadder[^1]);
        }

        if (malformedInput && deliveryCount >= maximumDeliveries)
        {
            return new PoisonDecision(
                PoisonDisposition.Exhausted,
                PoisonTerminalReason.MalformedEnvelope,
                null);
        }

        var delayIndex = Math.Min(deliveryCount - 1, backoffLadder.Count - 1);
        return new PoisonDecision(
            PoisonDisposition.RetryWithDelay,
            malformedInput ? PoisonTerminalReason.MalformedEnvelope : PoisonTerminalReason.Unspecified,
            backoffLadder[delayIndex]);
    }
}

/// <summary>
/// Cancellation policy: cancelling before the durable effect means the message is NOT
/// acknowledged (it returns for redelivery); cancelling during the effect completes or
/// compensates through the journal; there is no partial acknowledgement.
/// </summary>
public sealed record CancellationPolicy(bool AcknowledgeOnlyAfterDurableEffect, bool PartialAcknowledgementAllowed)
{
    public static CancellationPolicy Landed { get; } = new(true, false);

    public bool IsWellFormed => AcknowledgeOnlyAfterDurableEffect && !PartialAcknowledgementAllowed;
}

/// <summary>
/// Message-ID duplicate windows are TRANSPORT suppression layered beneath operation-level
/// idempotency. The contract makes no exactly-once claim: outside the window a duplicate is
/// admitted and the idempotency key remains the authority.
/// </summary>
public sealed record DuplicateWindowPolicy(TimeSpan Window, string Channel)
{
    public const string NoExactlyOnceClaim =
        "Duplicate windows suppress transport-level replays only; correctness is owned by "
        + "operation-level idempotency keys, and no delivery is claimed to be exactly-once.";

    public static DuplicateWindowPolicy CellStreams { get; } = new(TimeSpan.FromMinutes(2), "regional-cell-streams");

    public static DuplicateWindowPolicy GlobalCiStream { get; } = new(TimeSpan.FromHours(24), "global-ci-stream");

    public bool IsWellFormed => Window > TimeSpan.Zero && Window <= TimeSpan.FromHours(24) &&
        !string.IsNullOrWhiteSpace(Channel);
}

/// <summary>Pure transport-suppression decision for one message id.</summary>
public enum DuplicateWindowDecision
{
    Unspecified = 0,
    /// <summary>First observation inside the window: admit and remember.</summary>
    Admit,
    /// <summary>Same message id with the SAME digest inside the window: suppress.</summary>
    Suppress,
    /// <summary>Same message id with a DIFFERENT digest inside the window: conflict — surface, never silently drop.</summary>
    Conflict,
    /// <summary>Outside the window the transport no longer suppresses: admit (idempotency decides the effect).</summary>
    AdmitBeyondWindow,
}

/// <summary>
/// Deterministic, bounded message-id duplicate-window tracker. It is pure: every observation
/// carries an explicit timestamp, and callers must still apply operation-level idempotency.
/// </summary>
public sealed class MessageIdDuplicateWindow
{
    private readonly TimeSpan window;
    private readonly int capacity;
    private readonly Dictionary<string, (string Digest, DateTimeOffset ObservedAt)> observed;
    private readonly Queue<string> evictionOrder;

    public MessageIdDuplicateWindow(TimeSpan window, int capacity)
    {
        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window));
        }

        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        this.window = window;
        this.capacity = capacity;
        observed = new Dictionary<string, (string, DateTimeOffset)>(capacity, StringComparer.Ordinal);
        evictionOrder = new Queue<string>(capacity);
    }

    public int Count => observed.Count;

    public DuplicateWindowDecision Observe(string messageId, string digest, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(messageId) || string.IsNullOrEmpty(digest))
        {
            return DuplicateWindowDecision.Admit;
        }

        if (observed.TryGetValue(messageId, out var prior))
        {
            if (now - prior.ObservedAt > window)
            {
                // The id is still RESIDENT here, so refresh it in place: it must keep its
                // single FIFO eviction slot. Remove + Remember would re-enqueue the id while
                // its old slot stayed queued, giving one id two slots — later evictions then
                // dequeue ids that are no longer tracked, observed.Count can exceed capacity,
                // and the queue grows without bound under beyond-window redelivery churn.
                observed[messageId] = (digest, now);
                return DuplicateWindowDecision.AdmitBeyondWindow;
            }

            return string.Equals(prior.Digest, digest, StringComparison.Ordinal)
                ? DuplicateWindowDecision.Suppress
                : DuplicateWindowDecision.Conflict;
        }

        Remember(messageId, digest, now);
        return DuplicateWindowDecision.Admit;
    }

    /// <summary>
    /// Read-only decision for one message id: exactly the decision <see cref="Observe"/> would
    /// return, without recording anything. Consumers use it before dispatch (the recording
    /// happens only after the durable effect is proven) so suppression can never skip work.
    /// </summary>
    public DuplicateWindowDecision Inspect(string messageId, string digest, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(messageId) || string.IsNullOrEmpty(digest))
        {
            return DuplicateWindowDecision.Admit;
        }

        if (!observed.TryGetValue(messageId, out var prior))
        {
            return DuplicateWindowDecision.Admit;
        }

        if (now - prior.ObservedAt > window)
        {
            return DuplicateWindowDecision.AdmitBeyondWindow;
        }

        return string.Equals(prior.Digest, digest, StringComparison.Ordinal)
            ? DuplicateWindowDecision.Suppress
            : DuplicateWindowDecision.Conflict;
    }

    private void Remember(string messageId, string digest, DateTimeOffset now)
    {
        if (observed.Count >= capacity)
        {
            var evicted = evictionOrder.Dequeue();
            observed.Remove(evicted);
        }

        if (!observed.ContainsKey(messageId))
        {
            evictionOrder.Enqueue(messageId);
        }

        observed[messageId] = (digest, now);
    }
}

/// <summary>The delivery action a consumer derives from one transport duplicate-window decision.</summary>
public enum DuplicateWindowDeliveryAction
{
    Unspecified = 0,
    /// <summary>First observation or beyond-window observation: run the normal journal/idempotency path.</summary>
    Process,
    /// <summary>
    /// This exact message id and digest were already completed locally: acknowledge the delivery
    /// without reprocessing. Recording only ever happens after the durable effect (or a terminal
    /// disposition) exists, so this is a verified idempotent replay, not a skipped effect.
    /// </summary>
    AcknowledgeSuppressedReplay,
    /// <summary>
    /// The same message id arrived with a different digest: a deterministic identity conflict.
    /// Terminate the delivery with terminal evidence; the transport window must never silently
    /// swallow a payload change under a reused identity.
    /// </summary>
    TerminateConflictingIdentity,
}

/// <summary>Pure mapping from a duplicate-window decision to the consumer delivery action.</summary>
public static class DuplicateWindowDelivery
{
    public static DuplicateWindowDeliveryAction Decide(DuplicateWindowDecision decision) => decision switch
    {
        DuplicateWindowDecision.Admit or DuplicateWindowDecision.AdmitBeyondWindow =>
            DuplicateWindowDeliveryAction.Process,
        DuplicateWindowDecision.Suppress => DuplicateWindowDeliveryAction.AcknowledgeSuppressedReplay,
        DuplicateWindowDecision.Conflict => DuplicateWindowDeliveryAction.TerminateConflictingIdentity,
        _ => DuplicateWindowDeliveryAction.Unspecified,
    };
}

/// <summary>
/// The fenced authority claim a handler must hold to own work. Mirrors the landed
/// RegionalAuthorityCoordinator lease document: epoch from KV CAS, lease expiry, and the
/// KV revision of the accepted authority generation.
/// </summary>
public sealed record AuthorityLeaseClaim(
    long Epoch,
    long KvRevision,
    DateTimeOffset LeaseExpiresAt,
    string AuthorityId,
    string CandidateId)
{
    public bool IsLive(DateTimeOffset now) => Epoch > 0 && KvRevision > 0 && LeaseExpiresAt > now;

    public bool IsWellFormed => Epoch > 0 && KvRevision > 0 &&
        !string.IsNullOrWhiteSpace(AuthorityId) && !string.IsNullOrWhiteSpace(CandidateId);
}

public enum QueueGroupAdmission
{
    Unspecified = 0,
    /// <summary>The holder owns this work: epoch and generation match the live claim.</summary>
    Admit,
    /// <summary>The message names an older epoch than the live claim: fence it — do not act, do not acknowledge.</summary>
    StaleEpoch,
    /// <summary>The message names a newer epoch than the live claim: this holder lost the lease; leave the work for the new holder.</summary>
    LeaseLost,
    /// <summary>This holder is not the leader: a queue-group peer that is equivalent may act, an authoritative writer may not.</summary>
    NotLeader,
}

/// <summary>
/// Queue-group ownership and handler-fencing decision core. Queue groups distribute only
/// equivalent-worker work; authoritative writes additionally require the live fenced lease,
/// checked BEFORE the effect and again BEFORE the acknowledgement, which is what prevents
/// split writers: two holders can never both pass a CAS-backed epoch equality check.
/// </summary>
public static class QueueGroupOwnership
{
    public static QueueGroupAdmission Decide(
        AuthorityLeaseClaim? liveClaim,
        bool isLeader,
        long messageEpoch,
        long messageGeneration,
        bool requiresAuthority)
    {
        if (!requiresAuthority)
        {
            // Equivalent-worker fanout: any queue-group member may answer; no fenced lease applies.
            return QueueGroupAdmission.Admit;
        }

        if (liveClaim is null || !liveClaim.IsWellFormed)
        {
            return QueueGroupAdmission.NotLeader;
        }

        if (!isLeader)
        {
            return QueueGroupAdmission.NotLeader;
        }

        if (messageEpoch < liveClaim.Epoch)
        {
            return QueueGroupAdmission.StaleEpoch;
        }

        if (messageEpoch > liveClaim.Epoch)
        {
            return QueueGroupAdmission.LeaseLost;
        }

        return messageGeneration == liveClaim.KvRevision
            ? QueueGroupAdmission.Admit
            : QueueGroupAdmission.StaleEpoch;
    }

    /// <summary>
    /// Split-writer check for an authoritative journal append: the same fenced claim must be
    /// live immediately before the durable write and immediately before the acknowledgement.
    /// A loss at either checkpoint abandons or withholds — the in-flight write either never
    /// happened or is re-derived by the next epoch holder.
    /// </summary>
    public static bool MayCommitAuthoritativeWrite(
        AuthorityLeaseClaim? claimBeforeEffect,
        AuthorityLeaseClaim? claimBeforeAcknowledge,
        DateTimeOffset now) =>
        claimBeforeEffect is not null && claimBeforeAcknowledge is not null &&
        claimBeforeEffect.Epoch == claimBeforeAcknowledge.Epoch &&
        claimBeforeEffect.KvRevision == claimBeforeAcknowledge.KvRevision &&
        claimBeforeEffect.CandidateId == claimBeforeAcknowledge.CandidateId &&
        claimBeforeEffect.IsLive(now) && claimBeforeAcknowledge.IsLive(now);
}

