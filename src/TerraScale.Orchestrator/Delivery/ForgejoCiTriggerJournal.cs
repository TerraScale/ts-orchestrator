using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Delivery;

internal enum ForgejoCiTriggerJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    IdentityConflict,
    StaleAuthority,
}

internal sealed record ForgejoCiTriggerJournalReceipt(
    ForgejoCiTriggerJournalDisposition Disposition,
    ForgejoCiTriggerPlan Plan);

/// <summary>Persists the closed trust decision for one normalized Forgejo inbox event.</summary>
internal sealed class ForgejoCiTriggerJournal(
    IForgejoDeliveryLedger ledger,
    int triggerHistoryCap = 4096,
    int dispatchAnchorRevisionHorizon = 8192)
{
    private const int MaximumRecordBytes = 16 * 1024;
    internal const int TriggerHistoryCap = 4096;

    internal async Task<ForgejoCiTriggerPlan?> ReadAsync(
        string dedupeKey,
        CancellationToken cancellationToken = default)
    {
        ValidateDedupeKey(dedupeKey);
        var entry = await ledger.GetAsync(Index(dedupeKey), cancellationToken);
        return entry is null ? null : Deserialize(entry.Value).ToPlan(dedupeKey);
    }

    internal async Task<ForgejoCiTriggerJournalReceipt> RecordAsync(
        ForgejoCiTriggerPlan plan,
        long authorityEpoch,
        long authorityRevision,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (authorityRevision <= 0) throw new ArgumentOutOfRangeException(nameof(authorityRevision));
        var proposed = ForgejoCiTriggerJournalDocument.From(plan, authorityEpoch, authorityRevision);
        proposed.Validate();
        var key = Index(plan.Envelope.DedupeKey);
        var existing = await ledger.GetAsync(key, cancellationToken);
        if (existing is not null) return Compare(existing, proposed, plan.Envelope.DedupeKey);
        if (!authorityStillValid()) return new(ForgejoCiTriggerJournalDisposition.StaleAuthority, plan);
        try
        {
            await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
            await PruneAsync(cancellationToken).ConfigureAwait(false);
            return new(ForgejoCiTriggerJournalDisposition.Recorded, plan);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("A concurrently committed trigger decision disappeared.");
            return Compare(observed, proposed, plan.Envelope.DedupeKey);
        }
    }

    /// <summary>
    /// Bounded oldest-first history prune. The scan lists and reads every key under the prefix,
    /// but it is still required at each append so the durable history never exceeds its cap.
    /// Prunability:
    ///  - Ignored/Held decisions never anchor anything: prunable immediately.
    ///  - Dispatch decisions anchor redelivery only while their pipeline pointer exists AND the
    ///    bounded-age horizon has not passed. The KV store exposes no wall clock, so ledger
    ///    revision distance is the age proxy: once the newest revision is this far beyond the
    ///    anchor's write, the JetStream delivery budget for that event is long exhausted and the
    ///    anchor is dead weight. Without this horizon ordinary pushes would eventually exceed
    ///    any cap with immortal anchors.
    /// </summary>
    private async Task PruneAsync(CancellationToken cancellationToken)
    {
        // Pruning is cap-driven (checked on every record): trigger records are small KV
        // pointers, so the scan cost is bounded by the cap itself.
        if (ledger is not IForgejoDeliveryRetentionLedger retention) return;
        await DeliveryJournalRetention.PruneAsync(
            retention,
            "ci-trigger.",
            triggerHistoryCap,
            (entry, newestRevision, _) =>
            {
                var document = Deserialize(entry.Value);
                if (document.Disposition != ForgejoCiTriggerDisposition.Dispatch)
                    return Task.FromResult(new DeliveryJournalPruneDecision(true));
                if (newestRevision - entry.Revision < (ulong)dispatchAnchorRevisionHorizon)
                    return Task.FromResult(new DeliveryJournalPruneDecision(false));
                // Once the bounded delivery horizon passes, this inbox anchor is no longer an
                // active redelivery proof. Let it go even if the pipeline pointer exists; the
                // pipeline journal can then reclaim its paired object on its next append. Keeping
                // both journals mutually alive would make either cap impossible to satisfy.
                return Task.FromResult(new DeliveryJournalPruneDecision(true));
            },
            "dispatch-decision triggers inside the bounded-age horizon that still anchor pipelines",
            cancellationToken).ConfigureAwait(false);
    }

    private static ForgejoCiTriggerJournalReceipt Compare(
        ForgejoDeliveryLedgerEntry entry,
        ForgejoCiTriggerJournalDocument proposed,
        string dedupeKey)
    {
        var observed = Deserialize(entry.Value);
        return new(
            observed.TriggerDigest == proposed.TriggerDigest && observed.Event.DedupeKey == dedupeKey
                ? ForgejoCiTriggerJournalDisposition.Duplicate
                : ForgejoCiTriggerJournalDisposition.IdentityConflict,
            observed.ToPlan(dedupeKey));
    }

    private static ForgejoCiTriggerJournalDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                ForgejoCiTriggerJournalJsonContext.Default.ForgejoCiTriggerJournalDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A persisted Forgejo trigger decision is invalid.", exception);
        }
    }

    private static string Serialize(ForgejoCiTriggerJournalDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            ForgejoCiTriggerJournalJsonContext.Default.ForgejoCiTriggerJournalDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The Forgejo trigger decision exceeded its bound.");
        return value;
    }

    private static string Index(string dedupeKey) => $"ci-trigger.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(dedupeKey)))}";

    private static void ValidateDedupeKey(string? value)
    {
        if (value is not { Length: >= 1 and <= 512 } || value.Any(char.IsControl))
            throw new ArgumentException("Forgejo trigger dedupe identity is invalid.", nameof(value));
    }
}

internal sealed record ForgejoCiTriggerJournalDocument(
    int SchemaVersion,
    ForgejoWebhookEventDocument Event,
    string TriggerDigest,
    ForgejoCiTriggerDisposition Disposition,
    ForgejoCiTriggerReason Reason,
    JobKind JobKind,
    TrustZone TrustZone,
    RunnerCapability[] Capabilities,
    bool MayPublishArtifacts,
    long AuthorityEpoch,
    long AuthorityRevision)
{
    internal static ForgejoCiTriggerJournalDocument From(
        ForgejoCiTriggerPlan plan,
        long authorityEpoch,
        long authorityRevision)
    {
        var eventDocument = ForgejoWebhookEventDocument.From(plan.Envelope);
        return new(
            1,
            eventDocument,
            Digest(plan),
            plan.Disposition,
            plan.Reason,
            plan.JobKind,
            plan.TrustZone,
            plan.Capabilities.ToArray(),
            plan.MayPublishArtifacts,
            authorityEpoch,
            authorityRevision);
    }

    internal ForgejoCiTriggerPlan ToPlan(string expectedDedupeKey)
    {
        Validate();
        if (Event.DedupeKey != expectedDedupeKey)
            throw new InvalidDataException("A Forgejo trigger decision changed event identity.");
        return ForgejoCiTriggerPlanner.Plan(Event.ToEnvelope());
    }

    internal void Validate()
    {
        Event?.Validate();
        var planned = Event is null ? null : ForgejoCiTriggerPlanner.Plan(Event.ToEnvelope());
        if (SchemaVersion != 1 || planned is null || !DigestValue(TriggerDigest) ||
            TriggerDigest != Digest(planned) || Disposition != planned.Disposition || Reason != planned.Reason ||
            JobKind != planned.JobKind || TrustZone != planned.TrustZone ||
            Capabilities is null || !Capabilities.SequenceEqual(planned.Capabilities) ||
            MayPublishArtifacts != planned.MayPublishArtifacts ||
            AuthorityEpoch <= 0 || AuthorityRevision <= 0)
            throw new InvalidDataException("A persisted Forgejo trigger decision is invalid.");
    }

    private static string Digest(ForgejoCiTriggerPlan plan)
    {
        using var value = ZString.CreateStringBuilder();
        value.Append(plan.Envelope.DedupeKey);
        value.Append('\n');
        value.Append(plan.Disposition);
        value.Append(':');
        value.Append(plan.Reason);
        value.Append(':');
        value.Append(plan.JobKind);
        value.Append(':');
        value.Append(plan.TrustZone);
        value.Append('\n');
        value.AppendJoin(',', plan.Capabilities);
        value.Append('\n');
        value.Append(plan.MayPublishArtifacts ? '1' : '0');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    private static bool DigestValue(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal sealed class ForgejoCiInboxHandler(
    ForgejoCiTriggerJournal journal,
    Func<RegionalAuthoritySnapshot> authority)
{
    internal async Task<ForgejoCiTriggerJournalReceipt> HandleAsync(
        string payload,
        CancellationToken cancellationToken = default)
    {
        var observed = authority();
        var document = ForgejoWebhookEventDocument.Deserialize(payload);
        var plan = ForgejoCiTriggerPlanner.Plan(document.ToEnvelope());
        if (!observed.Ready || !observed.IsLeader || observed.Epoch <= 0 || observed.KvRevision <= 0)
            return new(ForgejoCiTriggerJournalDisposition.StaleAuthority, plan);
        return await journal.RecordAsync(
            plan,
            observed.Epoch,
            observed.KvRevision,
            () =>
            {
                var current = authority();
                return current.Ready && current.IsLeader && current.Epoch == observed.Epoch &&
                    current.KvRevision >= observed.KvRevision;
            },
            cancellationToken);
    }
}

[JsonSerializable(typeof(ForgejoCiTriggerJournalDocument))]
internal sealed partial class ForgejoCiTriggerJournalJsonContext : JsonSerializerContext;
