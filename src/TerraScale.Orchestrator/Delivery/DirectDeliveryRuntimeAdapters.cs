using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>Raised when a concurrent delivery admitted the same operationId with a different request.</summary>
internal sealed class DirectDeliveryJournalConflictException : Exception
{
    public DirectDeliveryJournalConflictException() : base(
        "The direct delivery operation was admitted concurrently with a different request.")
    { }
}

/// <summary>
/// Durable direct-operation records backed by the provisioned NATS KV ledger. The first append
/// is a compare-and-set admission: a concurrent create loses and a different request fingerprint
/// can never overwrite the winner, and completed operation history is pruned under a bound.
/// </summary>
internal sealed class NatsDirectDeliveryJournal(IForgejoDeliveryLedger ledger) : IDeliveryJournal
{
    internal const int DefaultOperationHistoryCap = 1024;
    internal const int DefaultPruneInterval = 1;
    private const string OperationKeyPrefix = "direct.operation.";
    // The journal writes into the provisioned ORCH_DELIVERY KV bucket, whose MaxValueSize
    // (NatsTopology.Delivery) is 16 KiB. The journal's own cap must never exceed the KV cap:
    // a record the journal accepts but KV rejects retries forever. The invariant
    // MaximumRecordBytes <= NatsTopology.Delivery.MaxValueSize is pinned by tests.
    internal const int MaximumRecordBytes = 16 * 1024;
    // direct.target.* records hold only each region's CURRENT deployed digest; the pre-mutation
    // digests rollback needs live in the direct.operation.* records. They are live state and are
    // never pruned by the history bound.
    private readonly IForgejoDeliveryLedger ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
    private readonly IForgejoDeliveryRetentionLedger? retention = ledger as IForgejoDeliveryRetentionLedger;
    private readonly int operationHistoryCap = DefaultOperationHistoryCap;
    private readonly int pruneInterval = DefaultPruneInterval;
    private int appendsSincePrune;

    internal NatsDirectDeliveryJournal(
        IForgejoDeliveryLedger ledger,
        IForgejoDeliveryRetentionLedger retention,
        int operationHistoryCap = DefaultOperationHistoryCap,
        int pruneInterval = DefaultPruneInterval) : this(ledger)
    {
        this.retention = retention ?? throw new ArgumentNullException(nameof(retention));
        if (operationHistoryCap is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(operationHistoryCap));
        if (pruneInterval is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(pruneInterval));
        this.operationHistoryCap = operationHistoryCap;
        this.pruneInterval = pruneInterval;
    }

    public async ValueTask<DeliveryJournalRecord?> ReadAsync(
        string operationId,
        CancellationToken cancellationToken)
    {
        var entry = await ledger.GetAsync(Key(operationId), cancellationToken).ConfigureAwait(false);
        if (entry is null) return null;
        var record = Read(entry.Value);
        if (!string.Equals(record.OperationId, operationId, StringComparison.Ordinal))
            throw new InvalidDataException("A direct delivery journal record changed operation identity.");
        return record;
    }

    public async ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        Validate(record);
        var value = JsonSerializer.Serialize(record, DeliveryWireCodec.JsonOptions);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The direct delivery journal record exceeded its bound.");
        var key = Key(record.OperationId);
        var existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            try
            {
                await ledger.CreateAsync(key, value, cancellationToken).ConfigureAwait(false);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
                // Admission race: another writer created the record between our read and create.
                // Same request converges (progress append); a different request is fenced out.
                existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false)
                    ?? throw new DirectDeliveryJournalConflictException();
                EnsureContinuity(Read(existing.Value), record);
                try
                {
                    await ledger.UpdateAsync(key, value, existing.Revision, cancellationToken).ConfigureAwait(false);
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                    // A second-order conflict on the recovery write is the same admission race.
                    throw new DirectDeliveryJournalConflictException();
                }
            }
        }
        else
        {
            EnsureContinuity(Read(existing.Value), record);
            try
            {
                await ledger.UpdateAsync(key, value, existing.Revision, cancellationToken).ConfigureAwait(false);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
                throw new DirectDeliveryJournalConflictException();
            }
        }
        // The cap is an invariant, not an eventual target. The interval remains a constructor
        // compatibility input but cannot permit an append to leave the durable key count above
        // the configured bound.
        _ = Interlocked.Increment(ref appendsSincePrune);
        await DeliveryJournalRetention.PruneAsync(
            retention,
            OperationKeyPrefix,
            operationHistoryCap,
            (entry, _, token) => Task.FromResult(new DeliveryJournalPruneDecision(
                IsPrunable(Read(entry.Value)))),
            "in-flight or rollback-recovery-pending direct delivery operations",
            cancellationToken).ConfigureAwait(false);
    }

    private static void EnsureContinuity(DeliveryJournalRecord current, DeliveryJournalRecord record)
    {
        if (!string.Equals(current.RequestFingerprint, record.RequestFingerprint, StringComparison.Ordinal) ||
            current.ArtifactDigest is not null && record.ArtifactDigest is not null &&
            !string.Equals(current.ArtifactDigest, record.ArtifactDigest, StringComparison.OrdinalIgnoreCase) ||
            current.AuthorityGeneration != record.AuthorityGeneration ||
            current.WriterEpoch != record.WriterEpoch ||
            current.Attempt != record.Attempt)
            throw new DirectDeliveryJournalConflictException();
        // Terminal success is absorbing: once a delivery is durably Succeeded or RolledBack, a
        // late concurrent append of the same request (a stale Accepted/Applying/transient-Failed
        // record) must never regress it — that would fabricate a rollback for a completed
        // delivery. Replayable failure states stay overwritable by design.
        if (current.State is DeliveryJournalState.Succeeded or DeliveryJournalState.RolledBack &&
            record.State != current.State)
            throw new DirectDeliveryJournalConflictException();
        if (RecordStateRank(record.State) < RecordStateRank(current.State) &&
            !(current.State == DeliveryJournalState.Failed && (IsReplayable(current) || current.Receipt is null)))
            throw new DirectDeliveryJournalConflictException();
        if (current.Regions is { } currentRegions && record.Regions is { } nextRegions)
        {
            var next = nextRegions.ToDictionary(static region => region.Region, StringComparer.Ordinal);
            foreach (var previous in currentRegions)
            {
                if (!next.TryGetValue(previous.Region, out var candidate)) continue;
                if (RegionStateRank(candidate.State) < RegionStateRank(previous.State))
                    throw new DirectDeliveryJournalConflictException();
                // Recorded write-ahead rollback material is durable: a later append (including
                // the create-race recovery write) may never clear or change it — resetting the
                // pre-mutation digests would erase the only exact rollback target. BOTH halves
                // of the rollback identity are guarded: restoring the artifact digest against a
                // changed manifest digest would restore an unverifiable artifact. Digests are
                // compared case-insensitively, consistent with digest semantics everywhere else
                // in this seam (the coordinator adopts adapter-reported digests on
                // OrdinalIgnoreCase agreement; a case-only difference is the same digest).
                if (previous.PreviousArtifactDigest is { } recorded &&
                    !string.Equals(candidate.PreviousArtifactDigest, recorded, StringComparison.OrdinalIgnoreCase))
                    throw new DirectDeliveryJournalConflictException();
                if (previous.PreviousManifestDigest is { } recordedManifest &&
                    !string.Equals(candidate.PreviousManifestDigest, recordedManifest, StringComparison.OrdinalIgnoreCase))
                    throw new DirectDeliveryJournalConflictException();
            }
        }
    }

    /// <summary>
    /// Prunable means terminal AND recovered: a Failed record that still owes rollback recovery
    /// (rollback-pending/failed regions, a rollback-failed receipt, or a receipt-less record
    /// whose regions still carry write-ahead rollback material) holds the only durable copy of
    /// the pre-mutation digests and must never be pruned.
    /// </summary>
    /// <remarks>
    /// Third agreeing site: the coordinator's <c>NeedsRollbackRecovery</c>/<c>HasWriteAheadDebt</c>
    /// decide that a durable shape owes rollback recovery, this journal's replay continuity
    /// rules decide which progress appends that recovery may write, and this predicate decides
    /// whether retention may delete the record at all. All three must classify the same shapes
    /// the same way: pruning a record those route to recovery would destroy the only durable
    /// pre-mutation digests, and a retry would re-apply over an owed or finished rollback.
    /// </remarks>
    private static bool IsPrunable(DeliveryJournalRecord record) =>
        record.State switch
        {
            DeliveryJournalState.Succeeded => true,
            DeliveryJournalState.RolledBack => true,
            DeliveryJournalState.Failed =>
                record.Regions?.Any(static region =>
                    region.State is "rollback_failed" or "rollback_pending") != true &&
                record.Receipt?.Error.Code != DirectDeliveryErrorCode.RollbackFailed &&
                !(record.Receipt is null && HasWriteAheadRollbackMaterial(record)),
            _ => false,
        };

    /// <summary>
    /// Mirrors the coordinator's write-ahead-debt test, including completed
    /// <c>rollback_succeeded</c> regions: deleting a receipt-less completed rollback would let
    /// replay re-apply the artifact over a finished rollback. Digest presence uses the same
    /// content-addressed hex shape the journal validates elsewhere.
    /// </summary>
    private static bool HasWriteAheadRollbackMaterial(DeliveryJournalRecord record) =>
        record.Regions?.Any(static region =>
            region.State is "applied" or "healthy" or "health_failed" or "rollback_pending" or
                "rollback_failed" or "rollback_succeeded" &&
            region.PreviousArtifactDigest is { } artifact && Sha256(artifact) &&
            region.PreviousManifestDigest is { } manifest && Sha256(manifest)) == true;

    private static DeliveryJournalRecord Read(string value)
    {
        if (value is null || Encoding.UTF8.GetByteCount(value) is < 2 or > MaximumRecordBytes)
            throw new InvalidDataException("A direct delivery journal record is empty or oversized.");
        try
        {
            var record = JsonSerializer.Deserialize<DeliveryJournalRecord>(value, DeliveryWireCodec.JsonOptions)
                ?? throw new JsonException();
            Validate(record);
            if (!string.Equals(JsonSerializer.Serialize(record, DeliveryWireCodec.JsonOptions), value,
                    StringComparison.Ordinal))
                throw new InvalidDataException("A direct delivery journal record is not canonical.");
            return record;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A direct delivery journal record is invalid.", exception);
        }
    }

    private static void Validate(DeliveryJournalRecord record)
    {
        if (record.OperationId is not { Length: > 0 and <= 128 } operationId || operationId.Any(char.IsControl) ||
            record.RequestFingerprint is not { Length: 71 } fingerprint || !Sha256(fingerprint) ||
            record.State is not (DeliveryJournalState.Accepted or DeliveryJournalState.Applying or
                DeliveryJournalState.RollingBack or DeliveryJournalState.Failed or DeliveryJournalState.RolledBack or
                DeliveryJournalState.Succeeded or "applied" or "healthy") || record.AuthorityGeneration <= 0 || record.WriterEpoch <= 0 ||
            record.Attempt <= 0 || record.Attempt > 1_000_000 ||
            record.ArtifactDigest is not null && !Sha256(record.ArtifactDigest))
            throw new InvalidDataException("A direct delivery journal record identity or state is invalid.");
        if (record.Regions is { } regions)
        {
            if (regions.Count is < 1 or > DirectDeliveryCoordinator.MaximumRegionCount)
                throw new InvalidDataException("A direct delivery journal region set is invalid.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var region in regions)
            {
                if (region is null or { Region.Length: 0 or > DirectDeliveryCoordinator.MaximumTextLength } ||
                    region.Region.Any(char.IsControl) || !seen.Add(region.Region) ||
                    region.State is not ("pending" or "applying" or "applied" or "healthy" or "health_failed" or
                        "failed" or "rolling_back" or "rollback_pending" or "rollback_failed" or "rollback_succeeded") ||
                    region.PreviousArtifactDigest is not null && !Sha256(region.PreviousArtifactDigest) ||
                    region.PreviousManifestDigest is not null && !Sha256(region.PreviousManifestDigest) ||
                    (region.PreviousArtifactDigest is null) != (region.PreviousManifestDigest is null) ||
                    region.ErrorCode is not null && !KnownError(region.ErrorCode))
                    throw new InvalidDataException("A direct delivery journal region record is invalid.");
            }
        }
        if (record.Receipt is not null)
            ValidateReceipt(record.Receipt, record.OperationId);
    }

    private static void ValidateReceipt(DeliveryReceipt receipt, string operationId)
    {
        if (receipt.SchemaVersion != DeliveryRequest.CurrentSchemaVersion ||
            receipt.OperationId != operationId || receipt.Status is not (DeliveryReceiptStatus.Succeeded or
                DeliveryReceiptStatus.Failed or DeliveryReceiptStatus.RolledBack) ||
            receipt.ArtifactDigest is not null && !Sha256(receipt.ArtifactDigest) ||
            receipt.ArtifactManifestDigest is not null && !Sha256(receipt.ArtifactManifestDigest) ||
            // The deployed artifact's digest and manifest travel as a pair, exactly like the
            // rollback target's: a receipt that names one without the other cannot prove which
            // exact artifact (or rollback) it is about.
            (receipt.ArtifactDigest is null) != (receipt.ArtifactManifestDigest is null) ||
            receipt.Provenance is null || receipt.Health is null || receipt.Rollback is null ||
            receipt.AuditId is not { Length: > 0 and <= DirectDeliveryCoordinator.MaximumOperationIdLength } ||
            receipt.AuditId.Any(char.IsControl) || receipt.Rollback.Status is not (DeliveryRollbackStatus.NotRequired or
                DeliveryRollbackStatus.Succeeded or DeliveryRollbackStatus.Failed) ||
            receipt.Rollback.TargetArtifactDigest is not null && !Sha256(receipt.Rollback.TargetArtifactDigest) ||
            receipt.Rollback.TargetManifestDigest is not null && !Sha256(receipt.Rollback.TargetManifestDigest) ||
            (receipt.Rollback.TargetArtifactDigest is null) != (receipt.Rollback.TargetManifestDigest is null) ||
            receipt.Error is null && receipt.Status == DeliveryReceiptStatus.Failed ||
            receipt.Error is not null && receipt.Error.Code is not null && !KnownError(receipt.Error.Code))
            throw new InvalidDataException("A direct delivery receipt is invalid.");
        if (receipt.Provenance.ConfigurationRevision is not null && !Sha256(receipt.Provenance.ConfigurationRevision) ||
            receipt.Provenance.MigrationRevision is not null && !Sha256(receipt.Provenance.MigrationRevision) ||
            receipt.Health.Checks is null || receipt.Health.Checks.Count > 128 ||
            receipt.Health.Checks.Any(static check => check is null || check.Name is not { Length: > 0 and <= 512 } ||
                check.Name.Any(char.IsControl) || check.Status is not (DeliveryHealthStatus.Passed or DeliveryHealthStatus.Failed)))
            throw new InvalidDataException("A direct delivery receipt evidence section is invalid.");
    }

    private static bool IsReplayable(DeliveryJournalRecord record) =>
        record.Receipt?.Error.Code is DirectDeliveryErrorCode.JournalUnavailable or DirectDeliveryErrorCode.Cancelled or
            DirectDeliveryErrorCode.AuthorizationUnavailable or DirectDeliveryErrorCode.ProvenanceUnavailable;

    /// <summary>
    /// Phase classes for the operation-record state: in-flight work is freely re-sequenced (a
    /// multi-region delivery interleaves applying/applied/healthy/rolling_back per region), a
    /// replayable failure may be re-entered, and terminal states are absorbing (enforced
    /// separately above). A total order over the in-flight names would reject region two's
    /// write-ahead after region one's health gate and make every multi-region delivery
    /// impossible, so the rank is a class, not a sequence.
    /// </summary>
    private static int RecordStateRank(string state) => state switch
    {
        DeliveryJournalState.Accepted or DeliveryJournalState.Applying or "applied" or
            DeliveryJournalState.RollingBack or "healthy" => 0,
        DeliveryJournalState.Failed => 1,
        DeliveryJournalState.RolledBack or DeliveryJournalState.Succeeded => 2,
        _ => -1,
    };

    /// <summary>
    /// Phase classes for one region's progress: pending, forward delivery (whose gates re-run
    /// idempotently on replay), and rollback recovery (whose states legitimately cycle —
    /// rollback_failed retried, rollback_succeeded demoted when convergence fails). The durable
    /// protections that matter per region are the phase never going backwards and the write-ahead
    /// digest immutability above, not an intra-phase ordering.
    /// </summary>
    private static int RegionStateRank(string state) => state switch
    {
        "pending" => 0,
        "applying" or "applied" or "healthy" or "health_failed" or "failed" => 1,
        "rollback_pending" or "rolling_back" or "rollback_failed" or "rollback_succeeded" => 2,
        _ => -1,
    };

    private static bool Sha256(string value) => value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
        value[7..].Length == 64 && value[7..].All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool KnownError(string value) => value is DirectDeliveryErrorCode.InvalidInput or
        DirectDeliveryErrorCode.UnsupportedSchema or DirectDeliveryErrorCode.MissingSourceAndArtifact or
        DirectDeliveryErrorCode.InvalidDigest or DirectDeliveryErrorCode.StaleDigest or DirectDeliveryErrorCode.UnknownTarget or
        DirectDeliveryErrorCode.UnauthorizedActor or DirectDeliveryErrorCode.UnboundedText or DirectDeliveryErrorCode.ProvenanceFailed or
        DirectDeliveryErrorCode.HealthFailed or DirectDeliveryErrorCode.ConvergenceFailed or DirectDeliveryErrorCode.RollbackFailed or
        DirectDeliveryErrorCode.JournalUnavailable or DirectDeliveryErrorCode.OperationConflict or DirectDeliveryErrorCode.Cancelled or
        DirectDeliveryErrorCode.MutationFailed or DirectDeliveryErrorCode.MutationRace or DirectDeliveryErrorCode.AuthorizationUnavailable or
        DirectDeliveryErrorCode.ProvenanceUnavailable or DirectDeliveryErrorCode.AuthorityFenced;

    private static string Key(string operationId)
    {
        if (operationId is not { Length: > 0 and <= 128 } || operationId.Any(char.IsControl))
            throw new ArgumentException("The direct delivery operation identity is invalid.", nameof(operationId));
        return $"direct.operation.{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(operationId)))}";
    }
}

/// <summary>
/// Operational (never payload) condition: the durable journal history exceeded its retention cap
/// with records that cannot be pruned. Consumers retry this condition while deterministic durable
/// conflicts remain terminal.
/// </summary>
internal sealed class JournalRetentionOverflowException : Exception
{
    public JournalRetentionOverflowException(string message) : base(message) { }
}

/// <summary>A prune decision for one durable journal entry, including its object-store payload.</summary>
internal sealed record DeliveryJournalPruneDecision(bool Prunable, string? ObjectNameToDelete = null);

/// <summary>
/// Bounded oldest-first pruning for durable delivery journal keys. Records the caller cannot
/// prove prunable (in-flight, unacknowledged, recovery-pending, or unreadable) are never pruned;
/// if the bound is exceeded unrecoverably the prune fails closed with a
/// <see cref="JournalRetentionOverflowException"/> instead of growing without limit. When the
/// decider names the entry's object-store payload, the object is deleted with its pointer so the
/// bounded history also bounds object storage.
/// </summary>
internal static class DeliveryJournalRetention
{
    internal static async Task PruneAsync(
        IForgejoDeliveryRetentionLedger? retention,
        string keyPrefix,
        int cap,
        Func<ForgejoDeliveryLedgerEntry, ulong, CancellationToken, Task<DeliveryJournalPruneDecision>> decide,
        string unprunableDescription,
        CancellationToken cancellationToken,
        IDeliveryRetentionObjectStore? objects = null)
    {
        if (retention is null) return;
        if (retention is not IForgejoDeliveryLedger ledger)
            throw new ArgumentException("The retention ledger cannot read entry revisions.", nameof(retention));
        var keys = new List<string>();
        await foreach (var key in retention.ListKeysAsync($"{keyPrefix}>", cancellationToken)
                           .WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            if (!key.StartsWith(keyPrefix, StringComparison.Ordinal))
                throw new InvalidDataException("Delivery journal retention discovered an invalid key.");
            keys.Add(key);
        }
        if (keys.Count <= cap) return;

        // Oldest-first by ledger revision (a monotonically increasing write order); the newest
        // observed revision is the decider's bounded-age horizon reference.
        var candidates = new List<(string Key, ulong Revision)>(keys.Count);
        foreach (var key in keys)
        {
            if (await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false) is not { } entry) continue;
            candidates.Add((key, entry.Revision));
        }
        var newestRevision = candidates.Count == 0 ? 0UL : candidates.Max(static candidate => candidate.Revision);
        var unreadable = 0;
        foreach (var (key, revision) in candidates.OrderBy(static candidate => candidate.Revision))
        {
            if (keys.Count <= cap) return;
            if (await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false) is not { } entry) continue;
            DeliveryJournalPruneDecision decision;
            try
            {
                // Retention ledgers return values independently of their keys; restore the key on
                // the callback entry so callers can safely bind sibling anchors and object names.
                decision = await decide(entry with { Key = key }, newestRevision, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                // A record the decider cannot read (a pre-codec shape, or corrupted bytes) is
                // retained fail-closed: NEVER deleted. One such record must not kill every
                // append either — the scan continues, the unreadable record keeps counting
                // against the cap, and the bounded overflow path below produces the operator
                // error instead of an untyped read failure escaping the prune. Direct reads
                // of the same record still surface the typed journal failure.
                unreadable++;
                continue;
            }
            if (!decision.Prunable) continue;
            if (await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false) is not { } current) continue;
            await retention.DeleteAsync(key, current.Revision, cancellationToken).ConfigureAwait(false);
            if (decision.ObjectNameToDelete is { } objectName && objects is not null)
                await objects.DeleteIfExistsAsync(objectName, cancellationToken).ConfigureAwait(false);
            keys.Remove(key);
        }
        if (keys.Count > cap)
            throw new JournalRetentionOverflowException(
                $"The durable delivery journal exceeded its retention cap of {cap} keys for '{keyPrefix}': " +
                $"{keys.Count - cap} keys are {unprunableDescription} that cannot be pruned" +
                (unreadable > 0
                    ? $" ({unreadable} could not be read by the current record codec and are retained for manual reconciliation)"
                    : string.Empty) +
                ". Raise the retention cap or let the bounded-age horizon pass; delivery retries after operator action.");
    }
}

/// <summary>
/// The leader-probe half of the direct-delivery authorization seam: the current
/// regional/global leader authorizes directly requested product mutations in addition to the
/// signed command-envelope admission at the mutation endpoint, which registers only with a
/// configured verifier. A leadership probe alone is never production trust.
/// </summary>
internal sealed class DirectDeliveryLeaderProbeAuthorizer(Func<bool> isLeader) : IDeliveryAuthorizer
{
    private readonly Func<bool> isLeader = isLeader ?? throw new ArgumentNullException(nameof(isLeader));

    public ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(
        DeliveryRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new DeliveryAuthorizationResult(
            isLeader() && request.RequestedBy is { Length: > 0 }));
    }
}

/// <summary>
/// Durable regional target state. The adapter performs the mutation through the provisioned
/// regional ledger and reports health from the exact stored artifact digest.
/// </summary>
internal sealed class NatsDirectDeliveryTarget(IForgejoDeliveryLedger ledger) : IDeliveryTarget
{
    private readonly IForgejoDeliveryLedger ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));

    public async ValueTask<string?> ObserveCurrentDigestAsync(
        DeliveryRequest request,
        string region,
        CancellationToken cancellationToken)
    {
        var current = await ObserveCurrentArtifactAsync(request, region, cancellationToken).ConfigureAwait(false);
        return current?.Digest;
    }

    public async ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
        DeliveryRequest request,
        string region,
        CancellationToken cancellationToken)
    {
        var existing = await ledger.GetAsync(
                Key(RequiredTarget(request), region), cancellationToken).ConfigureAwait(false);
        if (existing is null) return null;
        var state = Read(existing.Value);
        return new DeliveryArtifact(state.ArtifactDigest, state.ManifestDigest, state.Kind);
    }

    public async ValueTask<DeliveryMutationResult> ApplyAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        CancellationToken cancellationToken) =>
        await ApplyCoreAsync(request, artifact, region, expectedPreviousDigest: null, fence: false, cancellationToken)
            .ConfigureAwait(false);

    public async ValueTask<DeliveryMutationResult> ApplyFencedAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        string? expectedPreviousArtifactDigest,
        CancellationToken cancellationToken) =>
        await ApplyCoreAsync(request, artifact, region, expectedPreviousArtifactDigest, fence: true, cancellationToken)
            .ConfigureAwait(false);

    /// <summary>
    /// One mutation path for the unfenced legacy call and the fenced per-mutation fence. The
    /// fence is a compare-and-swap at mutation time: the region must STILL hold the digest the
    /// coordinator durably recorded as its rollback target, otherwise a concurrent writer raced
    /// the observe→apply window and the adapter reports the typed mutation race WITHOUT
    /// mutating — leaving the region to its concurrent owner instead of recording a stale
    /// rollback target.
    /// </summary>
    private async ValueTask<DeliveryMutationResult> ApplyCoreAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        string? expectedPreviousDigest,
        bool fence,
        CancellationToken cancellationToken)
    {
        var key = Key(RequiredTarget(request), region);
        var existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false);
        var currentState = existing is null ? null : Read(existing.Value);
        var current = currentState?.ArtifactDigest;
        var requested = RequiredDigest(artifact);
        if (currentState is not null && SameArtifactIdentity(currentState, artifact))
            // The region already runs the requested digest: nothing mutated, so there is no
            // rollback target — reporting the requested digest as "previous" would let a later
            // rollback "restore" an artifact this delivery never replaced. This also makes a
            // crash-replayed fence (region already applied, journal still 'applying') a no-op
            // instead of a false race.
            return new(true, false, null);
        if (fence && !StringComparer.OrdinalIgnoreCase.Equals(current, expectedPreviousDigest))
            // The current digest is neither the requested artifact nor the recorded previous
            // one (including a pristine expectation met by a deployed region): a concurrent
            // mutation owns this region now. Do not mutate and do not let this delivery record
            // rollback material for a replacement it never performed.
            return new(false, false, current, DirectDeliveryErrorCode.MutationRace);
        var previous = current;
        var state = JsonSerializer.Serialize(new DirectDeliveryState(
            requested, RequiredManifestDigest(artifact), RequiredKind(artifact)),
            DeliveryWireCodec.JsonOptions);
        try
        {
            if (existing is null)
                await ledger.CreateAsync(key, state, cancellationToken).ConfigureAwait(false);
            else
                await ledger.UpdateAsync(key, state, existing.Revision, cancellationToken).ConfigureAwait(false);
            return new(true, true, previous,
                PreviousManifestDigest: currentState?.ManifestDigest);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            // The revision compare-and-set lost: another writer mutated the region between this
            // call's read and write, so the digest fence no longer holds either — the typed race
            // outcome, never a generic mutation failure.
            return new(false, false, previous, DirectDeliveryErrorCode.MutationRace);
        }
    }

    public async ValueTask<DeliveryHealthResult> CheckHealthAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        CancellationToken cancellationToken)
    {
        var entry = await ledger.GetAsync(Key(RequiredTarget(request), region), cancellationToken).ConfigureAwait(false);
        var passed = entry is not null && SameArtifactIdentity(Read(entry.Value), artifact);
        return new(passed, [new($"{region}-delivery", passed ? DeliveryHealthStatus.Passed : DeliveryHealthStatus.Failed)]);
    }

    public async ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        IReadOnlyList<string> orderedRegions,
        CancellationToken cancellationToken)
    {
        foreach (var region in orderedRegions)
        {
            var entry = await ledger.GetAsync(Key(RequiredTarget(request), region), cancellationToken).ConfigureAwait(false);
            if (entry is null || !SameArtifactIdentity(Read(entry.Value), artifact))
                return new(false);
        }
        return new(true);
    }

    public async ValueTask<DeliveryRollbackResult> RollbackAsync(
        DeliveryRequest request,
        string region,
        string targetArtifactDigest,
        CancellationToken cancellationToken)
        => new(false, targetArtifactDigest);

    public async ValueTask<DeliveryRollbackResult> RollbackAsync(
        DeliveryRequest request,
        string region,
        string targetArtifactDigest,
        string? targetManifestDigest,
        CancellationToken cancellationToken)
    {
        var key = Key(RequiredTarget(request), region);
        if (!IsDigest(targetArtifactDigest) || targetManifestDigest is not { } manifest || !IsDigest(manifest))
            return new(false, targetArtifactDigest);
        var existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false);
        if (existing is null)
            return new(false, targetArtifactDigest);
        var current = Read(existing.Value);
        var rollback = JsonSerializer.Serialize(
            current with
            {
                ArtifactDigest = targetArtifactDigest,
                ManifestDigest = manifest,
            },
            DeliveryWireCodec.JsonOptions);
        try
        {
            await ledger.UpdateAsync(key, rollback, existing.Revision, cancellationToken).ConfigureAwait(false);
            return new(true, targetArtifactDigest,
                new DeliveryArtifact(targetArtifactDigest, manifest, current.Kind));
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            return new(false, targetArtifactDigest);
        }
    }

    private static DeliveryTarget RequiredTarget(DeliveryRequest request) =>
        request.Target is { } target
            ? target
            : throw new InvalidDataException("A direct delivery mutation has no admitted target.");

    private static string RequiredDigest(DeliveryArtifact artifact) =>
        artifact.Digest is { } digest
            ? digest
            : throw new InvalidDataException("A direct delivery mutation has no artifact digest.");

    private static string RequiredManifestDigest(DeliveryArtifact artifact) =>
        artifact.ManifestDigest is { } manifest
            ? manifest
            : throw new InvalidDataException("A direct delivery mutation has no manifest digest.");

    private static bool SameArtifactIdentity(DirectDeliveryState current, DeliveryArtifact requested) =>
        StringComparer.OrdinalIgnoreCase.Equals(current.ArtifactDigest, RequiredDigest(requested)) &&
        StringComparer.OrdinalIgnoreCase.Equals(current.ManifestDigest, RequiredManifestDigest(requested));

    private static string RequiredKind(DeliveryArtifact artifact) =>
        artifact.Kind is { } kind
            ? kind
            : throw new InvalidDataException("A direct delivery mutation has no artifact kind.");

    private static string Key(DeliveryTarget target, string region) =>
        target.Service is not { } service || target.Environment is not { } environment
            ? throw new InvalidDataException("A direct delivery target is not admitted.")
            : DirectDeliveryTargetKey.For(service, environment, region);

    private static DirectDeliveryState Read(string value) =>
        JsonSerializer.Deserialize<DirectDeliveryState>(value, DeliveryWireCodec.JsonOptions)
        ?? throw new InvalidDataException("A direct delivery target record is empty.");

    private static bool IsDigest(string? value) => value is { Length: 71 } &&
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
        value[7..].All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or
            >= 'A' and <= 'F');

    private sealed record DirectDeliveryState(string ArtifactDigest, string ManifestDigest, string Kind);
}
