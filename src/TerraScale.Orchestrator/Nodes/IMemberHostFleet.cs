namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The production member-host execution seam: observe, provision, cordon,
/// drain, and retire the hosts that run TerraBase members. This is the
/// provider-facing half of the placement reconciler; binary convergence of
/// a provisioned host stays with the host's own digest path.
/// </summary>
internal interface IMemberHostFleet
{
    /// <summary>Observes every owned member host: one filtered provider
    /// listing, ownership-tag scoped, with the live per-member health.</summary>
    Task<IReadOnlyList<MemberHostObservation>> ObserveAsync(CancellationToken cancellationToken);

    /// <summary>Creates one member host and waits for it to report ready.
    /// The create key is the provider idempotency token: a retried create
    /// resolves to the same instance, never a second one.</summary>
    Task<ProviderResourceId> ProvisionAsync(MemberHostRequest request, CancellationToken cancellationToken);

    /// <summary>Marks one host cordoned: it keeps serving but receives no
    /// new placements while a drain is in flight.</summary>
    Task CordonAsync(ProviderResourceId id, CancellationToken cancellationToken);

    /// <summary>Asks the host's agent to drain its member gracefully; the
    /// caller observes the member's health to confirm completion.</summary>
    Task DrainAsync(ProviderResourceId id, CancellationToken cancellationToken);

    /// <summary>Terminates exactly the identified instance, fenced by its
    /// current ETag; never resolves by name or tag alone.</summary>
    Task RetireAsync(ProviderResourceId id, string etag, CancellationToken cancellationToken);

    /// <summary>
    /// Detaches the member's retained volume from its live instance, exactly as the
    /// storage attachment planner decided. Idempotent: a volume with no live attachment
    /// on that instance is already detached.
    /// </summary>
    Task<MemberVolumeOutcome> DetachVolumeAsync(string volumeId, ProviderResourceId id, CancellationToken cancellationToken);

    /// <summary>
    /// Attaches the member's retained volume to its new instance; the create key is the
    /// idempotency token, so a retried attach resolves the same attachment, never a
    /// second one. An unknown outcome is reported, never retried as a second attach.
    /// </summary>
    Task<MemberVolumeOutcome> AttachVolumeAsync(string volumeId, ProviderResourceId id, string createKey, CancellationToken cancellationToken);
}

/// <summary>The outcome of one provider volume mutation; unknown is held for durable reconciliation.</summary>
internal enum MemberVolumeOutcome { Completed = 1, OutcomeUnknown = 2 }

/// <summary>A provider resource identity: the opaque instance reference and
/// the ETag that last observed it. Both round-trip through durable state.</summary>
internal sealed record ProviderResourceId(string InstanceId);

/// <summary>One observed member host and the member it runs.</summary>
internal sealed record MemberHostObservation(
    ProviderResourceId ResourceId,
    string ETag,
    string MemberId,
    string Region,
    MemberHostState State,
    bool Cordon,
    MemberHealth MemberHealth,
    string? VolumeId = null);

internal enum MemberHostState
{
    Provisioning,
    Running,
    Stopped,
    Terminating,
    Terminated,
    Unknown,
}

/// <summary>The execution request for one new member host.</summary>
internal sealed record MemberHostRequest(
    string Database,
    string MemberId,
    string Region,
    string PartitionId,
    bool Permanent,
    string CreateKey);

/// <summary>
/// The member-level health the placement reconciler gates on: liveness, the
/// replication lag in sequences, the member's current TerraBase role, and
/// the replica acknowledgement floor it reports.
/// </summary>
internal sealed record MemberHealth(
    bool Up,
    long ReplicationLagSequences,
    string Role,
    int PeerAckCount,
    int MinReplicas);
