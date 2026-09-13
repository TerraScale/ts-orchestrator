using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// A controller's membership signing identity: one P-256 key pair. Unless
/// composition supplies a persistent identity, a fresh key is generated per
/// process — which is the current production behavior, because
/// <see cref="NatsRuntime"/> starts membership without an identity — so a
/// restart heals its deterministic slot through the expired-lease key-rotation
/// path. Tests (and a future composition follow-up) may pass a persistent
/// identity for continuity across restarts. The private key never leaves the
/// process: only the key identifier, the public key, and the signature travel
/// in the record.
/// </summary>
internal sealed class RegionalRuntimeMembershipIdentity : IDisposable
{
    private readonly ECDsa privateKey;

    private RegionalRuntimeMembershipIdentity(ECDsa privateKey)
    {
        this.privateKey = privateKey;
        var publicKey = privateKey.ExportSubjectPublicKeyInfo();
        PublicKey = Convert.ToBase64String(publicKey);
        KeyId = Convert.ToHexStringLower(SHA256.HashData(publicKey))[..32];
    }

    internal string KeyId { get; }

    internal string PublicKey { get; }

    internal static RegionalRuntimeMembershipIdentity Create() =>
        new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>Signs the record's canonical material; the signature covers every field except itself.</summary>
    internal string Sign(RegionalRuntimeMember member) =>
        Convert.ToBase64String(
            privateKey.SignData(
                Encoding.UTF8.GetBytes(member.CanonicalMaterial()),
                HashAlgorithmName.SHA256));

    /// <summary>
    /// Verifies a record's self-contained signature: the key identifier must be the
    /// fingerprint of the embedded public key and the signature must verify under it.
    /// </summary>
    internal static bool Verify(RegionalRuntimeMember member)
    {
        if (!member.HasWellFormedIdentityMaterial()) return false;
        try
        {
            var publicKey = Convert.FromBase64String(member.IdentityPublicKey);
            if (Convert.ToHexStringLower(SHA256.HashData(publicKey))[..32] != member.IdentityKeyId)
                return false;
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(
                Encoding.UTF8.GetBytes(member.CanonicalMaterial()),
                Convert.FromBase64String(member.IdentitySignature),
                HashAlgorithmName.SHA256);
        }
        catch (Exception exception) when (
            exception is FormatException or ArgumentException or CryptographicException)
        {
            return false;
        }
    }

    public void Dispose() => privateKey.Dispose();
}

/// <summary>
/// The reader taxonomy for regional membership records. A reader classifies the
/// evidence it observes — never the transport it arrived on.
/// </summary>
internal enum RegionalRuntimeMembershipRecordClass
{
    Unspecified = 0,
    /// <summary>A structurally valid, correctly signed, lease-live record for an expected instance.</summary>
    Healthy = 1,
    /// <summary>The record's semantic lease expired; the instance is presumed stale, not gone.</summary>
    Stale = 2,
    /// <summary>An expected instance slot has no record at all.</summary>
    Missing = 3,
    /// <summary>A lease-live record for an instance the cell does not expect.</summary>
    Unexpected = 4,
    /// <summary>The record names a different cell than the reader's cell.</summary>
    WrongCell = 5,
    /// <summary>A new session replaced the previous session while its lease was still live.</summary>
    ConflictingSession = 6,
    /// <summary>The record carries an authority epoch older than the newest one already observed for the slot.</summary>
    StaleEpoch = 7,
    /// <summary>The record's signed identity does not verify or breaks the instance's key continuity.</summary>
    InvalidSignature = 8,
    /// <summary>The record fails its structural contract (schema, ordering, time bounds).</summary>
    Malformed = 9,
}

/// <summary>
/// Pure membership-record classification. The precedence is fixed: a record is
/// wrong-cell before it is malformed, malformed before it is unsigned, and
/// signature/fencing problems are distinguished from lease staleness so readers
/// never conflate a dead peer with a forged or stale-epoch one. Epoch fencing
/// dominates session conflicts: a replayed older generation is inert as
/// stale-epoch regardless of which session it names.
/// </summary>
internal static class RegionalRuntimeMembershipReader
{
    /// <param name="expectedCell">The reader's own cell.</param>
    /// <param name="instance">The instance slot being classified. A record whose
    /// instance id does not match this slot is classified wrong-cell: the check
    /// doubles as the wrong-instance guard.</param>
    /// <param name="expectedInstances">
    /// The instance ids the cell expects (for example controller-1..N). Null skips the
    /// unexpected-controller classification. When supplied, a record is classified
    /// unexpected regardless of its lease state: a lease-expired record for a slot
    /// the cell does not expect is still an unexpected controller, not a stale one.
    /// </param>
    /// <param name="previous">The previously observed record for the slot, if any.</param>
    /// <param name="record">The incoming record; null classifies an absent slot. With
    /// no memory of a predecessor the slot is missing; with one, the slot's record
    /// was deleted or purged — departed, so also missing, never silently healthy.</param>
    internal static RegionalRuntimeMembershipRecordClass Classify(
        string expectedCell,
        string instance,
        IReadOnlySet<string>? expectedInstances,
        RegionalRuntimeMember? previous,
        RegionalRuntimeMember? record,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedCell);
        ArgumentException.ThrowIfNullOrWhiteSpace(instance);
        if (record is null)
            return RegionalRuntimeMembershipRecordClass.Missing;

        if (record.Cell != expectedCell || record.Instance != instance)
            return RegionalRuntimeMembershipRecordClass.WrongCell;
        if (!record.IsValidFor(expectedCell, now))
            return RegionalRuntimeMembershipRecordClass.Malformed;
        if (!RegionalRuntimeMembershipIdentity.Verify(record))
            return RegionalRuntimeMembershipRecordClass.InvalidSignature;
        // Key continuity under a live lease: a different signing key may not
        // replace the observed one while it still holds the slot. After the lease
        // lapses, healing may rotate the key with the takeover.
        if (previous is not null &&
            previous.HasWellFormedIdentityMaterial() &&
            previous.IdentityPublicKey != record.IdentityPublicKey &&
            previous.LeaseExpiresAt > now)
            return RegionalRuntimeMembershipRecordClass.InvalidSignature;
        if (previous is not null && record.AuthorityEpoch < previous.AuthorityEpoch)
            return RegionalRuntimeMembershipRecordClass.StaleEpoch;
        if (previous is not null &&
            previous.LeaseExpiresAt > now &&
            previous.SessionId != record.SessionId)
            return RegionalRuntimeMembershipRecordClass.ConflictingSession;
        if (expectedInstances is not null && !expectedInstances.Contains(instance))
            return RegionalRuntimeMembershipRecordClass.Unexpected;
        return record.LeaseExpiresAt > now
            ? RegionalRuntimeMembershipRecordClass.Healthy
            : RegionalRuntimeMembershipRecordClass.Stale;
    }

    /// <summary>The expected instance ids of a symmetric controller set, for example 3 replicas.</summary>
    internal static IReadOnlySet<string> ExpectedInstances(int expectedControllers)
    {
        if (expectedControllers is not (1 or 3 or 5))
            throw new ArgumentOutOfRangeException(nameof(expectedControllers));
        return Enumerable.Range(1, expectedControllers)
            .Select(static index => $"controller-{index}")
            .ToHashSet(StringComparer.Ordinal);
    }
}

/// <summary>The disposition of one publisher's attempt to mutate a membership record.</summary>
internal enum RegionalRuntimeMembershipMutationClass
{
    Unspecified = 0,
    /// <summary>No record exists for the instance slot: create it under compare-and-swap.</summary>
    CreateOwnRecord = 1,
    /// <summary>The publisher's own live record: renew it under its compare-and-swap revision.</summary>
    RenewOwnRecord = 2,
    /// <summary>The previous lease expired: healing may take the slot over under the observed revision.</summary>
    TakeOverExpiredLease = 3,
    /// <summary>A foreign session still holds a live lease: hold — never write and never delete it.</summary>
    HoldForLiveForeignLease = 4,
    /// <summary>The proposal would regress the authority epoch already published for the slot.</summary>
    RejectStaleEpoch = 5,
    /// <summary>The proposal is not bound to this publisher's own cell, cluster, instance, or identity key.</summary>
    RejectWrongBinding = 6,
}

/// <summary>
/// Pure compare-and-swap mutation policy for regional membership records. A publisher
/// may mutate only the record bound to its own instance and cell, under its own signing
/// identity; healing reuses the expired slot only after the previous semantic lease has
/// actually lapsed, and a live foreign session is never overwritten or deleted.
/// </summary>
internal static class RegionalRuntimeMembershipMutation
{
    /// <param name="boundCell">The publisher's own cell: the only cell it may write.</param>
    /// <param name="boundInstance">The publisher's own instance id: the only record it may write.</param>
    internal static RegionalRuntimeMembershipMutationClass Decide(
        string boundCell,
        string boundInstance,
        RegionalRuntimeMember proposed,
        RegionalRuntimeMember? existing,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(proposed);
        if (!proposed.HasWellFormedIdentityMaterial())
            return RegionalRuntimeMembershipMutationClass.RejectWrongBinding;
        if (proposed.Cell != boundCell || proposed.Instance != boundInstance)
            return RegionalRuntimeMembershipMutationClass.RejectWrongBinding;

        if (existing is null)
            return RegionalRuntimeMembershipMutationClass.CreateOwnRecord;

        if (existing.Cell != boundCell ||
            existing.Cluster != proposed.Cluster ||
            existing.Instance != boundInstance)
            return RegionalRuntimeMembershipMutationClass.RejectWrongBinding;

        // The same session must keep its signing key: a session's records are
        // identity-continuous. A different session may rotate the key only with
        // the expired-lease takeover below, which is what lets a restarted
        // process (fresh per-process key until composition persists one) heal
        // its deterministic slot instead of being locked out forever.
        if (existing.SessionId == proposed.SessionId &&
            existing.HasWellFormedIdentityMaterial() &&
            existing.IdentityPublicKey != proposed.IdentityPublicKey)
            return RegionalRuntimeMembershipMutationClass.RejectWrongBinding;

        if (existing.SessionId != proposed.SessionId)
            return existing.LeaseExpiresAt > now
                ? RegionalRuntimeMembershipMutationClass.HoldForLiveForeignLease
                : RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease;

        if (proposed.AuthorityEpoch < existing.AuthorityEpoch)
            return RegionalRuntimeMembershipMutationClass.RejectStaleEpoch;
        if (proposed.AuthorityEpoch == existing.AuthorityEpoch &&
            proposed.AuthorityRevision < existing.AuthorityRevision)
            return RegionalRuntimeMembershipMutationClass.RejectStaleEpoch;

        return existing.LeaseExpiresAt > now
            ? RegionalRuntimeMembershipMutationClass.RenewOwnRecord
            : RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease;
    }

    /// <summary>
    /// The deletion rule: a publisher may delete only its own session's record under its
    /// own compare-and-swap revision. Every other current membership record — including a
    /// foreign session's live record and a record the revision no longer matches — is left
    /// in place for its owner or the lease to resolve.
    /// </summary>
    internal static bool MayDeleteCurrentRecord(
        string boundSessionId,
        RegionalRuntimeMember? current,
        ulong heldRevision) =>
        current is not null &&
        current.SessionId == boundSessionId &&
        heldRevision != 0;
}

