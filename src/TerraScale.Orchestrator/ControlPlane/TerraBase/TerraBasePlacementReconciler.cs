using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Compute;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using TerraScale.Orchestrator.ControlPlane.Storage;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Scheduler;
using TerraScale.Orchestrator.Scheduler.Availability;
using TerraScale.Orchestrator.Scheduler.Autoscaling;
using ComputeProviderResourceId = TerraScale.Orchestrator.ControlPlane.Compute.ProviderResourceId;
using ProviderResourceId = TerraScale.Orchestrator.Nodes.ProviderResourceId;
using FailureDomainId = TerraScale.Orchestrator.Scheduler.Availability.FailureDomainId;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

/// <summary>
/// The TerraBase member-lifecycle executor: one leader-gated tick that re-validates the
/// placement intent with <see cref="DatabasePlacementEvaluator"/>, diffs desired seats
/// against the live member-host fleet, and executes AT MOST ONE member action —
/// provision, replacement, or one scale-down ladder step — before writing its durable
/// step state. Scale-down passes the triple gate (topology planner, availability
/// policy, compute floor) and refuses on any missing observation; a dead host is
/// replaced with its retained volume reattached at writer epoch + 1. Edge-routing
/// placement is republished when its fingerprint changes; a publication failure never
/// fails the loop.
/// </summary>
internal sealed class TerraBasePlacementReconciler
{
    /// <summary>One tick processes the lowest-revision dirty database of at most this many.</summary>
    internal const int MaximumDatabases = 32;

    /// <summary>A recorded host missing from the fleet listing for this many consecutive ticks is dead.</summary>
    internal const int DeadAfterMissingTicks = 2;

    /// <summary>The converged artifact every member host runs; also the host observation key leaf.</summary>
    internal const string MemberArtifactKey = "terrabase-server";

    private const int MaximumIdentityLength = 256;
    private const int MaximumWriterObservations = 32;

    private readonly INatsKVStore delivery;
    private readonly INatsKVStore runtimeStore;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly IMemberHostFleet fleet;
    private readonly string cell;
    private readonly EdgeRoutingPublisher? edgePublisher;
    private readonly TerraBasePlacementEdgeSource? edgeSource;
    private readonly Dictionary<string, int> missingStreaks = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string Leader, int Streak)> leaderStreaks = new(StringComparer.Ordinal);
    private string? lastEdgeFingerprint;

    private TerraBasePlacementReconciler(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        Func<RegionalAuthoritySnapshot> authority,
        IMemberHostFleet fleet,
        string cell,
        EdgeRoutingPublisher? edgePublisher,
        TerraBasePlacementEdgeSource? edgeSource)
    {
        this.delivery = delivery;
        this.runtimeStore = runtimeStore;
        this.authority = authority;
        this.fleet = fleet;
        this.cell = cell;
        this.edgePublisher = edgePublisher;
        this.edgeSource = edgeSource;
    }

    /// <summary>Constructs the reconciler without starting any loop; tests drive ticks directly.</summary>
    internal static TerraBasePlacementReconciler Create(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        Func<RegionalAuthoritySnapshot> authority,
        IMemberHostFleet fleet,
        string cell,
        EdgeRoutingPublisher? edgePublisher = null,
        TerraBasePlacementEdgeSource? edgeSource = null) =>
        new(delivery, runtimeStore, authority, fleet, cell, edgePublisher, edgeSource);

    /// <summary>The leadership gate every tick and every provider mutation re-checks.</summary>
    internal static bool IsCurrentLeader(RegionalAuthoritySnapshot lease) =>
        lease.Ready && lease.IsLeader && lease.Epoch > 0 && lease.KvRevision > 0;

    /// <summary>One reconcile tick. Never throws for infrastructure failure: the outcome is the observation.</summary>
    internal async Task<PlacementTickObservation> TickAsync(CancellationToken cancellationToken)
    {
        var lease = authority();
        if (!IsCurrentLeader(lease))
            return await ObserveAsync(Result(PlacementTickObservation.StateNotLeader, null, null, null, null, 0), cancellationToken)
                .ConfigureAwait(false);
        try
        {
            var world = await PlacementWorld.ReadAsync(delivery, fleet, cancellationToken).ConfigureAwait(false);
            var databases = world.Databases.Take(MaximumDatabases).ToList();
            UpdateDeathSignals(world);
            UpdateLeaderSignals(world);
            var chosen = ChooseDatabase(databases);
            var result = chosen is null
                ? Result(PlacementTickObservation.StateIdle, null, null, null, null, 0)
                : await ReconcileDatabaseAsync(chosen, lease, cancellationToken).ConfigureAwait(false);
            await TryPublishEdgeAsync(world, cancellationToken).ConfigureAwait(false);
            return await ObserveAsync(result, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException or JsonException or InvalidOperationException)
        {
            return await ObserveAsync(
                Result(PlacementTickObservation.StateError, null, null, null, exception.GetType().Name, 0),
                cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>True while the database still needs a tick: an in-flight ladder, a dead or missing seat, or an extra member.</summary>
    private PlacementDatabaseSnapshot? ChooseDatabase(IReadOnlyList<PlacementDatabaseSnapshot> databases)
    {
        foreach (var database in databases)
        {
            var desired = PlacementTopology.Seats(database.Intent)
                .Select(static seat => seat.MemberId)
                .ToHashSet(StringComparer.Ordinal);
            if (database.Members.Any(static member => member.State.InFlight))
                return database;
            if (database.Members.Any(member => member.State.Stage == PlacementMemberStateDocument.StageServing && IsDead(member)))
                return database;
            if (desired.Any(member => database.Members.All(existing => existing.State.MemberId != member)))
                return database;
            if (database.Members.Any(member => !desired.Contains(member.State.MemberId) && !member.State.InRemovalLadder))
                return database;
        }
        return null;
    }

    private async Task<PlacementTickObservation> ReconcileDatabaseAsync(
        PlacementDatabaseSnapshot database,
        RegionalAuthoritySnapshot lease,
        CancellationToken cancellationToken)
    {
        var intent = database.Intent;
        // Re-validate the assembled request every tick: a non-Accepted decision means
        // zero mutations — the error goes to the status observation, nothing else.
        var evaluation = DatabasePlacementEvaluator.Evaluate(PlacementTopology.ToPlacementRequest(intent));
        if (!evaluation.Accepted)
            return Result(
                PlacementTickObservation.StateRejected,
                intent.Database,
                null,
                "evaluate",
                string.Join(",", evaluation.Errors.Select(static error => error.Code.ToString())),
                intent.Revision);

        var seats = PlacementTopology.Seats(intent);
        var desired = seats.Select(static seat => seat.MemberId).ToHashSet(StringComparer.Ordinal);
        var members = database.Members.OrderBy(static member => member.State.MemberId, StringComparer.Ordinal).ToList();

        var inFlight = members.FirstOrDefault(static member => member.State.InFlight);
        if (inFlight is not null)
            return await ContinueAsync(intent, seats, members, inFlight, cancellationToken).ConfigureAwait(false);

        var dead = members.FirstOrDefault(member =>
            member.State.Stage == PlacementMemberStateDocument.StageServing && IsDead(member));
        if (dead is not null)
            return await StartReplacementAsync(intent, dead, cancellationToken).ConfigureAwait(false);

        var missingSeat = seats.FirstOrDefault(seat => members.All(member => member.State.MemberId != seat.MemberId));
        if (missingSeat is not null)
            return await ProvisionAsync(intent, missingSeat, cancellationToken).ConfigureAwait(false);

        var extra = members.FirstOrDefault(member =>
            !desired.Contains(member.State.MemberId) && !member.State.InRemovalLadder);
        if (extra is not null)
            return await EnterRemovalAsync(intent, seats, members, extra, lease, cancellationToken).ConfigureAwait(false);

        return Result(PlacementTickObservation.StateIdle, intent.Database, null, null, null, intent.Revision);
    }

    // --- scale-out -----------------------------------------------------------------

    /// <summary>Creates the durable member record and provisions its first host in one member action.</summary>
    private async Task<PlacementTickObservation> ProvisionAsync(
        PlacementIntentDocument intent,
        PlacementTopology.DesiredSeat seat,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var document = new PlacementMemberStateDocument(
            PlacementMemberStateDocument.CurrentSchemaVersion,
            intent.Database,
            seat.MemberId,
            seat.Region.Value,
            seat.Kind.ToString(),
            PlacementMemberStateDocument.StageProvisioning,
            null,
            null,
            HostSequence: 1,
            intent.Revision,
            nameof(ComputeTraceCode.PlanRequired),
            now);
        document.Validate();
        var json = JsonSerializer.Serialize(document, TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument);
        ulong revision;
        try
        {
            revision = await delivery.CreateAsync(
                PlacementMemberStateDocument.Key(intent.Database, seat.MemberId), json, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (NatsKVCreateException)
        {
            // Another writer created the record first; the next tick continues from it.
            return Result(PlacementTickObservation.StateHeld, intent.Database, seat.MemberId, "create-state", null, intent.Revision);
        }
        return await ProvisionHostAsync(intent, document, revision, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues the idempotent create: the stable create key resolves retries to the same instance.</summary>
    private async Task<PlacementTickObservation> ProvisionHostAsync(
        PlacementIntentDocument intent,
        PlacementMemberStateDocument state,
        ulong revision,
        CancellationToken cancellationToken)
    {
        if (!IsCurrentLeader(authority()))
            return Result(PlacementTickObservation.StateAuthorityLost, intent.Database, state.MemberId, "provision", null, intent.Revision);
        ProviderResourceId resource;
        try
        {
            resource = await fleet.ProvisionAsync(
                new MemberHostRequest(
                    intent.Database,
                    state.MemberId,
                    state.Region,
                    intent.PartitionId,
                    Permanent: PlacementTopology.KindOf(state.MemberId) != TerraBaseMemberKind.Elastic,
                    CreateKey: CreateKey(intent, state)),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Result(PlacementTickObservation.StateError, intent.Database, state.MemberId, "provision",
                exception.GetType().Name, intent.Revision);
        }
        var updated = state with
        {
            Stage = PlacementMemberStateDocument.StageAwaitingHealthy,
            InstanceId = resource.InstanceId,
            ETag = null,
            Trace = nameof(ComputeTraceCode.CreateReady),
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        return await WriteMemberAsync(updated, revision, intent, "provision", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Advances one member's ladder by a single stage; the tick's one member action.</summary>
    private async Task<PlacementTickObservation> ContinueAsync(
        PlacementIntentDocument intent,
        IReadOnlyList<PlacementTopology.DesiredSeat> seats,
        IReadOnlyList<PlacementMemberSnapshot> members,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        switch (member.State.Stage)
        {
            case PlacementMemberStateDocument.StageProvisioning:
                return await ProvisionHostAsync(intent, member.State, member.Revision, cancellationToken).ConfigureAwait(false);
            case PlacementMemberStateDocument.StageAwaitingHealthy:
                return await ContinueAwaitingHealthyAsync(intent, member, cancellationToken).ConfigureAwait(false);
            case PlacementMemberStateDocument.StageReplacing:
                return await ContinueReplacementAsync(intent, member, cancellationToken).ConfigureAwait(false);
            default:
                return await AdvanceRemovalAsync(intent, seats, members, member, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<PlacementTickObservation> ContinueAwaitingHealthyAsync(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (member.Observation is null ||
            member.Observation.State is MemberHostState.Terminated or MemberHostState.Terminating or MemberHostState.Stopped)
        {
            if (member.Observation is not null || IsDead(member))
                return await WriteMemberAsync(
                    member.State with
                    {
                        Stage = PlacementMemberStateDocument.StageProvisioning,
                        InstanceId = null,
                        ETag = null,
                        HostSequence = member.State.HostSequence + 1,
                        Trace = nameof(ComputeTrigger.FailedHostReplacement),
                        UpdatedAt = now,
                    },
                    member.Revision,
                    intent,
                    "reprovision",
                    cancellationToken).ConfigureAwait(false);
            return Result(PlacementTickObservation.StateIdle, intent.Database, member.State.MemberId, "awaiting-healthy", null, intent.Revision);
        }
        if (member.Observation.State == MemberHostState.Running && member.Observation.MemberHealth.Up)
        {
            // Host converged and the member serves: the ServiceHealthy evidence. The
            // retained-volume identity is created once and fenced by its writer epoch.
            await EnsureVolumeAsync(intent, member.State.MemberId, cancellationToken).ConfigureAwait(false);
            return await WriteMemberAsync(
                member.State with
                {
                    Stage = PlacementMemberStateDocument.StageServing,
                    ETag = member.Observation.ETag,
                    Trace = nameof(ComputeTraceCode.Completed),
                    UpdatedAt = now,
                },
                member.Revision,
                intent,
                "healthy",
                cancellationToken).ConfigureAwait(false);
        }
        return Result(PlacementTickObservation.StateIdle, intent.Database, member.State.MemberId, "awaiting-healthy", null, intent.Revision);
    }

    // --- heal ----------------------------------------------------------------------

    /// <summary>CAS-moves a dead member's seat to <c>replacing</c> before any replacement work.</summary>
    private async Task<PlacementTickObservation> StartReplacementAsync(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        return await WriteMemberAsync(
            member.State with
            {
                Stage = PlacementMemberStateDocument.StageReplacing,
                Trace = nameof(ComputeTrigger.FailedHostReplacement),
                UpdatedAt = DateTimeOffset.UtcNow,
            },
            member.Revision,
            intent,
            "replace",
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// One replacement step: the failed-host scale-out trigger gate, the reattach gates
    /// (writers empty, writer epoch + 1, retained-volume restart), the epoch CAS, and
    /// finally the seat's move back to provisioning under a fresh host sequence.
    /// </summary>
    private async Task<PlacementTickObservation> ContinueReplacementAsync(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        var lease = authority();
        var scaleOut = ComputeEngine.DecideScaleOut(
            BuildFailedHostReplacementRequest(intent, member.State, lease));
        if (scaleOut.Errors.Count > 0)
            return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, "heal-gate",
                scaleOut.Errors[0].Code.ToString(), intent.Revision);

        var volume = await ReadVolumeAsync(delivery, intent.Database, member.State.MemberId, cancellationToken).ConfigureAwait(false);
        if (volume is { } retained)
        {
            var record = ToStorageVolumeRecord(retained.Document, intent, cell);
            var context = ToStorageAuthorityContext(retained.Document, intent, cell);
            var proposed = StorageWriterEpoch.TryCreate(retained.Document.WriterEpoch + 1, out var epoch) ? epoch : default;
            var reattach = new StorageReattachEvidence(
                record.EvidenceScope,
                writers: [],
                processStopped: StorageProof.Proven,
                leaseRevoked: StorageProof.Proven,
                providerDetached: StorageProof.Proven,
                healthVerified: StorageProof.Unknown,
                writerInventoryComplete: StorageProof.Proven,
                proposedEpoch: proposed,
                maximumWriterObservations: MaximumWriterObservations);
            var attach = StorageAttachmentPlanner.Plan(record, context, StorageNodeOf(member.State.MemberId), reattach);
            if (attach.Action != StorageAction.Attach)
                return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, "reattach-gate",
                    attach.Code.ToString(), intent.Revision);
            var writerEvidence = new TerraBaseWriterEvidence(
                Scope(intent, member.State, lease, retained.Document.WriterEpoch),
                writers: [],
                inventoryComplete: TerraBaseProof.Proven,
                exactVolumeIdentity: TerraBaseProof.Proven,
                exactFence: TerraBaseProof.Proven,
                detached: TerraBaseProof.Proven,
                newAuthorityEpoch: TerraBaseOrdinal.TryCreate(retained.Document.WriterEpoch + 1, out var authorityEpoch)
                    ? authorityEpoch
                    : default,
                maximum: MaximumWriterObservations);
            var restart = TerraBaseRetainedVolumePlanner.Plan(
                Scope(intent, member.State, lease, retained.Document.WriterEpoch), writerEvidence);
            if (restart.Action != TerraBaseAction.StartWithRetainedVolume)
                return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, "retained-volume-gate",
                    restart.Code.ToString(), intent.Revision);
            if (!await TryWriteVolumeAsync(
                    retained.Document with { WriterEpoch = retained.Document.WriterEpoch + 1, UpdatedAt = DateTimeOffset.UtcNow },
                    retained.Revision,
                    cancellationToken).ConfigureAwait(false))
                return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, "volume-cas", null, intent.Revision);
        }
        return await WriteMemberAsync(
            member.State with
            {
                Stage = PlacementMemberStateDocument.StageProvisioning,
                InstanceId = null,
                ETag = null,
                HostSequence = member.State.HostSequence + 1,
                Trace = nameof(StorageAction.Attach),
                UpdatedAt = DateTimeOffset.UtcNow,
            },
            member.Revision,
            intent,
            "reattach",
            cancellationToken).ConfigureAwait(false);
    }

    // --- scale-down ----------------------------------------------------------------

    /// <summary>
    /// Enters the removal ladder through the triple gate. The victim must be a live,
    /// caught-up, non-leading (or leadership-transferred) elastic member: a missing
    /// observation or replication lag refuses — a dead extra member is replaced first
    /// (heal), then removed once it serves and is caught up. Never removed unobserved.
    /// </summary>
    private async Task<PlacementTickObservation> EnterRemovalAsync(
        PlacementIntentDocument intent,
        IReadOnlyList<PlacementTopology.DesiredSeat> seats,
        IReadOnlyList<PlacementMemberSnapshot> members,
        PlacementMemberSnapshot victim,
        RegionalAuthoritySnapshot lease,
        CancellationToken cancellationToken)
    {
        var gate = EvaluateRemovalGates(intent, seats, members, victim, lease);
        if (gate.Action == TerraBaseAction.Transfer)
        {
            // Leadership transfer is only ever OBSERVED, never issued by the control plane.
            if (victim.State.Stage != PlacementMemberStateDocument.StageRemoveCandidate)
                return await WriteMemberAsync(
                    victim.State with
                    {
                        Stage = PlacementMemberStateDocument.StageRemoveCandidate,
                        Trace = TerraBaseAction.Transfer.ToString(),
                        UpdatedAt = DateTimeOffset.UtcNow,
                    },
                    victim.Revision,
                    intent,
                    "transfer-wait",
                    cancellationToken).ConfigureAwait(false);
            return Result(PlacementTickObservation.StateTransferWait, intent.Database, victim.State.MemberId, "transfer-wait", null, intent.Revision);
        }
        if (gate.Action != TerraBaseAction.Remove)
            return Result(PlacementTickObservation.StateHeld, intent.Database, victim.State.MemberId, "topology-gate",
                gate.Code.ToString(), intent.Revision);
        if (!EvaluateDrainAvailability(intent, seats, members, victim).Admitted)
            return Result(PlacementTickObservation.StateHeld, intent.Database, victim.State.MemberId, "availability-gate", null, intent.Revision);
        var compute = ComputeEngine.DecideScaleIn(
            BuildScaleInRequest(intent, victim, members, ScaleInState.CandidateSelected, lease));
        if (compute.Errors.Count > 0)
            return Result(PlacementTickObservation.StateHeld, intent.Database, victim.State.MemberId, "compute-gate",
                compute.Errors[0].Code.ToString(), intent.Revision);

        if (victim.Observation is { } observation)
        {
            if (!IsCurrentLeader(authority()))
                return Result(PlacementTickObservation.StateAuthorityLost, intent.Database, victim.State.MemberId, "cordon", null, intent.Revision);
            try
            {
                await fleet.CordonAsync(observation.ResourceId, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                return Result(PlacementTickObservation.StateError, intent.Database, victim.State.MemberId, "cordon",
                    exception.GetType().Name, intent.Revision);
            }
        }
        return await WriteMemberAsync(
            victim.State with
            {
                Stage = victim.Observation is null
                    ? PlacementMemberStateDocument.StageDrained
                    : PlacementMemberStateDocument.StageCordoned,
                Trace = nameof(ComputeTraceCode.CordonReady),
                UpdatedAt = DateTimeOffset.UtcNow,
            },
            victim.Revision,
            intent,
            "cordon",
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Advances the scale-down ladder one stage; every step re-checks the compute engine.</summary>
    private async Task<PlacementTickObservation> AdvanceRemovalAsync(
        PlacementIntentDocument intent,
        IReadOnlyList<PlacementTopology.DesiredSeat> seats,
        IReadOnlyList<PlacementMemberSnapshot> members,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        var state = member.State;
        switch (state.Stage)
        {
            case PlacementMemberStateDocument.StageRemoveCandidate:
                return await EnterRemovalAsync(intent, seats, members, member, authority(), cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageCordoned:
                return await GateThenActAsync(
                    intent, member, members, ScaleInState.Cordoned, "drain",
                    async () =>
                    {
                        if (member.Observation is not { } observation)
                            return PlacementMemberStateDocument.StageDrained;
                        await fleet.DrainAsync(observation.ResourceId, cancellationToken).ConfigureAwait(false);
                        return PlacementMemberStateDocument.StageDraining;
                    },
                    nameof(ComputeTraceCode.DrainReady),
                    cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageDraining:
                if (member.Observation is null || !member.Observation.MemberHealth.Up ||
                    member.Observation.State is not (MemberHostState.Running or MemberHostState.Provisioning))
                    return await WriteMemberAsync(
                        state with { Stage = PlacementMemberStateDocument.StageDrained, Trace = nameof(ComputeTraceCode.DrainReady), UpdatedAt = DateTimeOffset.UtcNow },
                        member.Revision, intent, "drained", cancellationToken).ConfigureAwait(false);
                return Result(PlacementTickObservation.StateIdle, intent.Database, state.MemberId, "draining", null, intent.Revision);

            case PlacementMemberStateDocument.StageDrained:
                return await GateThenActAsync(
                    intent, member, members, ScaleInState.Drained, "deregister",
                    () => Task.FromResult(PlacementMemberStateDocument.StageDeregistered),
                    nameof(ComputeTraceCode.DeregistrationReady),
                    cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageDeregistered:
                await EnsureVolumeAsync(intent, state.MemberId, cancellationToken).ConfigureAwait(false);
                var volume = await ReadVolumeAsync(delivery, intent.Database, state.MemberId, cancellationToken).ConfigureAwait(false);
                if (volume is { } retained)
                {
                    // The planner must decide a provider detach of the retained volume
                    // before the retire executes it (writers empty, detach still pending).
                    var record = ToStorageVolumeRecord(retained.Document, intent, cell);
                    var detach = StorageAttachmentPlanner.Plan(
                        record,
                        ToStorageAuthorityContext(retained.Document, intent, cell),
                        StorageNodeOf(state.MemberId),
                        new StorageReattachEvidence(
                            record.EvidenceScope,
                            writers: [],
                            processStopped: StorageProof.Proven,
                            leaseRevoked: StorageProof.Proven,
                            providerDetached: StorageProof.Unknown,
                            healthVerified: StorageProof.Unknown,
                            writerInventoryComplete: StorageProof.Proven,
                            proposedEpoch: StorageWriterEpoch.TryCreate(retained.Document.WriterEpoch, out var currentEpoch) ? currentEpoch : default,
                            maximumWriterObservations: MaximumWriterObservations));
                    if (detach.Action != StorageAction.Detach)
                        return Result(PlacementTickObservation.StateHeld, intent.Database, state.MemberId, "detach-gate",
                            detach.Code.ToString(), intent.Revision);
                }
                return await GateThenActAsync(
                    intent, member, members, ScaleInState.Deregistered, "storage",
                    () => Task.FromResult(PlacementMemberStateDocument.StageStorageHandled),
                    nameof(ComputeTraceCode.VolumeReady),
                    cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageStorageHandled:
                return await GateThenActAsync(
                    intent, member, members, ScaleInState.StorageHandled, "revoke",
                    () => Task.FromResult(PlacementMemberStateDocument.StageRevoked),
                    nameof(ComputeTraceCode.RevocationReady),
                    cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageRevoked:
                return await GateThenActAsync(
                    intent, member, members, ScaleInState.Revoked, "retire",
                    async () =>
                    {
                        if (member.Observation is { } observation)
                            await fleet.RetireAsync(observation.ResourceId, observation.ETag, cancellationToken).ConfigureAwait(false);
                        return PlacementMemberStateDocument.StageTerminated;
                    },
                    nameof(ComputeTraceCode.TerminationReady),
                    cancellationToken).ConfigureAwait(false);

            case PlacementMemberStateDocument.StageTerminated:
                if (member.Observation is null ||
                    member.Observation.State is MemberHostState.Terminated or MemberHostState.Terminating)
                    return await RemoveMemberRecordAsync(intent, member, cancellationToken).ConfigureAwait(false);
                return Result(PlacementTickObservation.StateIdle, intent.Database, state.MemberId, "terminating", null, intent.Revision);

            default:
                return Result(PlacementTickObservation.StateIdle, intent.Database, state.MemberId, null, null, intent.Revision);
        }
    }

    /// <summary>Runs the compute-engine gate for one ladder step, then executes its single fleet action.</summary>
    private async Task<PlacementTickObservation> GateThenActAsync(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        IReadOnlyList<PlacementMemberSnapshot> members,
        ScaleInState engineState,
        string action,
        Func<Task<string>> step,
        string trace,
        CancellationToken cancellationToken)
    {
        var compute = ComputeEngine.DecideScaleIn(
            BuildScaleInRequest(intent, member, members, engineState, authority()));
        if (compute.Errors.Count > 0)
            return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, action,
                compute.Errors[0].Code.ToString(), intent.Revision);
        if (!IsCurrentLeader(authority()))
            return Result(PlacementTickObservation.StateAuthorityLost, intent.Database, member.State.MemberId, action, null, intent.Revision);
        string next;
        try
        {
            next = await step().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Result(PlacementTickObservation.StateError, intent.Database, member.State.MemberId, action,
                exception.GetType().Name, intent.Revision);
        }
        return await WriteMemberAsync(
            member.State with { Stage = next, Trace = trace, UpdatedAt = DateTimeOffset.UtcNow },
            member.Revision,
            intent,
            action,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The first triple-gate member: the topology planner over production observations.
    /// A missing observation leaves role or replication Unknown and the planner holds —
    /// refuse, never remove.
    /// </summary>
    private TerraBaseDecision EvaluateRemovalGates(
        PlacementIntentDocument intent,
        IReadOnlyList<PlacementTopology.DesiredSeat> seats,
        IReadOnlyList<PlacementMemberSnapshot> members,
        PlacementMemberSnapshot victim,
        RegionalAuthoritySnapshot lease)
    {
        var scope = Scope(intent, victim.State, lease, (ulong)lease.Epoch);
        var kind = PlacementTopology.KindOf(victim.State.MemberId);
        var graceful = !IsDead(victim);
        var role = victim.Observation?.MemberHealth.Role switch
        {
            "leader" => TerraBaseRole.Leader,
            "follower" => TerraBaseRole.Follower,
            _ => TerraBaseRole.Unknown,
        };
        var replication = !graceful || victim.Observation is null
            ? TerraBaseReplication.Unknown
            : victim.Healthy && victim.Observation.MemberHealth.ReplicationLagSequences == 0
                ? TerraBaseReplication.CaughtUp
                : TerraBaseReplication.Lagging;
        var desiredIds = seats.Select(static seat => seat.MemberId).ToHashSet(StringComparer.Ordinal);
        var survivors = members.Where(member => member != victim && desiredIds.Contains(member.State.MemberId)).ToArray();
        var losses = survivors.Count(static member => !member.Healthy);
        var lossCount = losses == 0 ? TerraBaseLossCount.None
            : losses == 1 ? TerraBaseLossCount.One
            : TerraBaseLossCount.TwoOrMore;
        var remainingHealthy = survivors.Count(static member => member.Healthy);
        var everyActiveRegionKeepsASeat = seats.All(seat =>
            survivors.Any(member => member.Healthy && member.Seat?.Region == seat.Region));
        var floors = remainingHealthy >= 3 && everyActiveRegionKeepsASeat
            ? TerraBaseProof.Proven
            : TerraBaseProof.Contradicted;
        var transferred = role != TerraBaseRole.Leader
            ? TerraBaseProof.Proven
            : AnotherLeaderConfirmed(intent.Database, victim.State.MemberId)
                ? TerraBaseProof.Proven
                : TerraBaseProof.Unknown;
        var evidence = new TerraBaseTopologyEvidence(
            scope,
            kind,
            role,
            lossCount,
            transferred,
            NoTopologyMutation: TerraBaseProof.Proven,
            QuorumFloor: floors,
            ReplicationFloor: floors,
            SustainedSignal: TerraBaseProof.Proven,
            Placement: TerraBaseProof.Proven,
            Storage: TerraBaseProof.Proven,
            // ponytail: budget and storage proofs ride the operator intent and the
            // retained-volume record; a dedicated budget engine gates this in v2.
            Budget: TerraBaseProof.Proven,
            UniqueMember: TerraBaseProof.Proven,
            TopologyApplied: TerraBaseProof.Unknown,
            NoDatabaseReference: TerraBaseProof.Unknown,
            RecoveryPoint: TerraBaseProof.Proven,
            Retention: TerraBaseProof.Proven,
            VolumeDisposition: TerraBaseProof.Proven,
            PostChangeReplication: TerraBaseProof.Unknown,
            Replication: replication,
            ReplicationPosition: TerraBaseOrdinal.TryCreate((ulong)intent.Revision, out var position) ? position : default);
        return TerraBaseTopologyPlanner.PlanRemove(scope, evidence);
    }

    /// <summary>
    /// The second gate: the drain-node availability policy with the fixed database
    /// policy — desired seats, quorum 2, minimum available 2, one concurrent disruption.
    /// A member whose host already vanished counts as observed (its absence IS the
    /// observation), so observation completeness never blocks a legitimate drain.
    /// </summary>
    private AvailabilityDecision EvaluateDrainAvailability(
        PlacementIntentDocument intent,
        IReadOnlyList<PlacementTopology.DesiredSeat> seats,
        IReadOnlyList<PlacementMemberSnapshot> members,
        PlacementMemberSnapshot victim)
    {
        var generation = new AvailabilityGeneration((ulong)intent.Revision);
        var policy = new ServiceAvailabilityPolicy(
            new ServiceId($"terrabase-{intent.Database}"),
            // Desired is the replica set being disrupted (victim included): the drain
            // must not push the projected count past what the service already runs.
            new((ulong)Math.Max(2, members.Count)),
            new(2),
            new(2),
            new(1),
            ServiceCriticality.Critical,
            onePerHost: true,
            new(2),
            new ResourceVector(0, 0, 0, 0, 0, 0, 0, 0),
            ReserveDisposition.MayConsume);
        var observations = members
            .Where(static member => member.Observation is not null)
            .Select(member => new ReplicaObservation(
                new ReplicaId(member.State.MemberId),
                policy.ServiceId,
                new AvailabilityNodeId(HostNodeOf(member.State.MemberId)),
                new FailureDomainId(member.Seat?.FailureDomain ?? $"{member.State.Region.ToLowerInvariant()}-fd0"),
                member.Healthy ? ReplicaAvailabilityState.Available : ReplicaAvailabilityState.Unavailable))
            .ToArray();
        return new AvailabilityPolicyEvaluator().Evaluate(new(
            policy,
            new DrainNodeChange(new AvailabilityNodeId(HostNodeOf(victim.State.MemberId))),
            members.All(member => member.Observation is not null || IsDead(member))
                ? ObservationCompleteness.Complete
                : ObservationCompleteness.Incomplete,
            generation,
            generation,
            observations));
    }

    /// <summary>Assembles the exact scale-in request the compute engine re-validates per ladder step.</summary>
    private ScaleInRequest BuildScaleInRequest(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        IReadOnlyList<PlacementMemberSnapshot> members,
        ScaleInState state,
        RegionalAuthoritySnapshot lease)
    {
        var database = intent.Database;
        var memberId = member.State.MemberId;
        var sequence = intent.Revision;
        var binding = Binding(intent, lease, cell);
        var proof = new ComputeProofId($"proof-{database}-{memberId}-{state}");
        var scaleInBinding = new ScaleInBinding(
            binding,
            new ComputeNodeId(HostNodeOf(memberId)),
            new ComputeProviderResourceId(member.State.InstanceId ?? $"pending-{memberId}"),
            new LoadBalancerRegistrationId($"terrabase-{database}"),
            new ComputeVolumeId($"vol-{memberId}"),
            ComputeNodeRole.TerraBase);
        var authorization = new ScaleInAuthorization(
            scaleInBinding,
            new DemandObservationId($"placement-{database}-{sequence}"),
            ObservationSequence: sequence,
            FreshThroughSequence: sequence,
            CurrentCount: Math.Max(1, members.Count(static candidate => candidate.Observation is not null)),
            MinimumCount: 3,
            ReplacementCapacity: 1,
            AvailabilityHeadroom: 1,
            LowUseProof: proof,
            CooldownProof: proof,
            LifetimeProof: proof,
            CostBenefitProof: proof,
            ControlHealthProof: proof,
            NatsHealthProof: proof,
            AvailabilityProof: proof,
            StatefulDisposition.Approved,
            proof,
            SustainedLowUse: true,
            CooldownPassed: true,
            LifetimePassed: true,
            CostBenefitPassed: true,
            RegionalControlHealthy: true,
            NatsHealthy: true,
            ConflictingOperation: false,
            StatefulApproved: true);
        var owner = new StatefulOwnerId($"owner-{database}-{memberId}");
        var progress = new ScaleInProgress(
            scaleInBinding,
            CordonProof: state >= ScaleInState.Cordoned ? proof : null,
            DrainProof: state >= ScaleInState.Drained ? proof : null,
            DeregistrationProof: state >= ScaleInState.Deregistered ? proof : null,
            VolumeProof: state >= ScaleInState.StorageHandled ? proof : null,
            RevocationProof: state >= ScaleInState.Revoked ? proof : null,
            TerminationProof: state >= ScaleInState.Terminated ? proof : null,
            BootAbsenceProof: state >= ScaleInState.Terminated ? proof : null,
            OrphanAuditProof: null,
            VolumeDisposition.RetainedStateful,
            owner,
            Cordoned: state >= ScaleInState.Cordoned,
            Drained: state >= ScaleInState.Drained,
            Deregistered: state >= ScaleInState.Deregistered,
            VolumeHandled: state >= ScaleInState.StorageHandled,
            Revoked: state >= ScaleInState.Revoked,
            ExactInstanceTerminated: state >= ScaleInState.Terminated,
            BootVolumeAbsent: state >= ScaleInState.Terminated,
            OrphanAuditPassed: false);
        return new(scaleInBinding, state, authorization, progress, sequence, MaximumIdentityLength);
    }

    /// <summary>The failed-host replacement trigger gate for one replacement create.</summary>
    private ScaleOutRequest BuildFailedHostReplacementRequest(
        PlacementIntentDocument intent,
        PlacementMemberStateDocument state,
        RegionalAuthoritySnapshot lease)
    {
        var binding = Binding(intent, lease, cell);
        var sequence = intent.Revision;
        return new(
            binding,
            ScaleOutState.DemandObserved,
            new DemandEvidence(
                binding,
                ComputeTrigger.FailedHostReplacement,
                ObservationSequence: sequence,
                FreshThroughSequence: sequence,
                RequiredNodes: 1,
                ExplicitDemand: true,
                Sustained: false,
                SafetyBounded: true),
            new ScaleOutPlan(
                binding,
                new ResourceEnvelope(1, 1, 1, 1),
                1,
                new ComputeProofId($"plan-{intent.Database}-{state.MemberId}-h{state.HostSequence}")),
            null,
            null,
            null,
            null,
            sequence,
            MaximumIdentityLength);
    }

    private static ComputeBinding Binding(PlacementIntentDocument intent, RegionalAuthoritySnapshot lease, string cell) => new(
        new ComputeCellId(cell),
        new NodeClassId($"terrabase-{intent.Database}"),
        new NodeTemplateId("terrabase-member"),
        new ComputeShapeId("terrabase-member"),
        new PlacementDomainId("terrabase"),
        new ComputeArtifactId(MemberArtifactKey),
        new ComputeDigestId(new string('a', 64)),
        new DemandObservationId($"placement-{intent.Database}-{intent.Revision}"),
        new ComputeOperationId($"terrabase-placement-{intent.Database}"),
        new ProviderFingerprintId("terrabase"),
        Generation: intent.Revision,
        ControllerEpoch: lease.Epoch);

    private static TerraBaseEvidenceScope Scope(
        PlacementIntentDocument intent,
        PlacementMemberStateDocument state,
        RegionalAuthoritySnapshot lease,
        ulong authorityEpoch)
    {
        TerraBaseRegionCode.TryCreate(state.Region, out var region);
        TerraBaseDatabaseId.TryCreate(intent.Database, MaximumIdentityLength, out var database);
        TerraBaseMemberId.TryCreate(state.MemberId, MaximumIdentityLength, out var member);
        TerraBaseNodeId.TryCreate(HostNodeOf(state.MemberId), MaximumIdentityLength, out var node);
        TerraBaseVolumeId.TryCreate($"vol-{state.MemberId}", MaximumIdentityLength, out var volume);
        TerraBaseFenceId.TryCreate($"fence-{intent.Database}-{state.MemberId}", MaximumIdentityLength, out var fence);
        TerraBaseOrdinal.TryCreate((ulong)intent.Revision, out var generation);
        TerraBaseOrdinal.TryCreate((ulong)intent.Revision, out var topology);
        TerraBaseOrdinal.TryCreate(authorityEpoch <= 0 ? 1UL : authorityEpoch, out var epoch);
        TerraBaseOperationId.TryCreate($"operation-{intent.Database}-{state.MemberId}", MaximumIdentityLength, out var operation);
        if (region is null || database is null || member is null || node is null || volume is null ||
            fence is null || !generation.IsValid || !topology.IsValid || !epoch.IsValid || operation is null)
            throw new InvalidOperationException("The placement evidence scope could not be derived.");
        return new(region, database, member, node, volume, fence, generation, topology, epoch, operation);
    }

    /// <summary>Builds the durable volume identity's storage record for the planner gates.</summary>
    private static StorageVolumeRecord ToStorageVolumeRecord(
        PlacementVolumeStateDocument volume,
        PlacementIntentDocument intent,
        string cell)
    {
        if (!VolumeClaimId.TryCreate($"claim-{volume.Database}-{volume.MemberId}", MaximumIdentityLength, out var claim) ||
            !ProviderVolumeId.TryCreate(volume.ProviderVolumeId, MaximumIdentityLength, out var providerVolume) ||
            !StorageAttachmentId.TryCreate(volume.AttachmentId, MaximumIdentityLength, out var attachment) ||
            !StorageCellId.TryCreate(cell, MaximumIdentityLength, out var cellId) ||
            !StorageNodeId.TryCreate(HostNodeOf(volume.MemberId), MaximumIdentityLength, out var node) ||
            !StorageWorkloadId.TryCreate("terrabase", MaximumIdentityLength, out var workload) ||
            !StorageMemberId.TryCreate(volume.MemberId, MaximumIdentityLength, out var member) ||
            !EncryptionKeyReference.TryCreate("kms-terrabase", MaximumIdentityLength, out var encryptionKey) ||
            !StoragePlacementId.TryCreate($"placement-{volume.Database}", MaximumIdentityLength, out var placement) ||
            !StorageDeviceId.TryCreate($"device-{volume.MemberId}", MaximumIdentityLength, out var device) ||
            !FilesystemId.TryCreate($"filesystem-{volume.MemberId}", MaximumIdentityLength, out var filesystem) ||
            !StorageBackupId.TryCreate($"backup-{volume.Database}", MaximumIdentityLength, out var backup) ||
            !StorageGeneration.TryCreate((ulong)intent.Revision, out var generation) ||
            !StorageFenceId.TryCreate($"fence-{volume.Database}-{volume.MemberId}", MaximumIdentityLength, out var fence) ||
            !StorageWriterEpoch.TryCreate(volume.WriterEpoch, out var epoch) ||
            !StorageOperationId.TryCreate($"operation-{volume.Database}-{volume.MemberId}", MaximumIdentityLength, out var operation))
            throw new InvalidOperationException("The placement volume record could not be derived.");
        var bytes = Bytes(50L << 30);
        var retention = PlacementTopology.KindOf(volume.MemberId) == TerraBaseMemberKind.Elastic
            ? StorageRetention.ElasticQuarantine
            : StorageRetention.Permanent;
        return new(
            claim!,
            providerVolume!,
            attachment!,
            cellId!,
            node!,
            workload!,
            member!,
            StorageDomain.TerraBase,
            encryptionKey!,
            placement!,
            device!,
            filesystem!,
            StorageFilesystemType.Ext4,
            StorageLayout.WholeDevice,
            StorageMountPurpose.DatabaseData,
            bytes,
            bytes,
            bytes,
            bytes,
            bytes,
            Bytes(0),
            bytes,
            new StoragePerformance(StoragePerformanceTier.Balanced, Bytes(1), Bytes(1), Bytes(1), Bytes(1), Bytes(1), Bytes(1), Bytes(1)),
            Bytes(0),
            retention,
            backup!,
            generation,
            fence!,
            epoch,
            operation!);
    }

    private static StorageAuthorityContext ToStorageAuthorityContext(
        PlacementVolumeStateDocument volume,
        PlacementIntentDocument intent,
        string cell)
    {
        if (!VolumeClaimId.TryCreate($"claim-{volume.Database}-{volume.MemberId}", MaximumIdentityLength, out var claim) ||
            !ProviderVolumeId.TryCreate(volume.ProviderVolumeId, MaximumIdentityLength, out var providerVolume) ||
            !StorageCellId.TryCreate(cell, MaximumIdentityLength, out var cellId) ||
            !StorageWorkloadId.TryCreate("terrabase", MaximumIdentityLength, out var workload) ||
            !StorageMemberId.TryCreate(volume.MemberId, MaximumIdentityLength, out var member) ||
            !StorageFenceId.TryCreate($"fence-{volume.Database}-{volume.MemberId}", MaximumIdentityLength, out var fence) ||
            !StorageGeneration.TryCreate((ulong)intent.Revision, out var generation) ||
            !StorageWriterEpoch.TryCreate(volume.WriterEpoch, out var epoch))
            throw new InvalidOperationException("The placement storage authority context could not be derived.");
        return new(claim!, providerVolume!, cellId!, workload!, member!, fence!, generation, epoch);
    }

    private static StorageBytes Bytes(long value) =>
        StorageBytes.TryCreate(value, out var bytes) ? bytes : default;

    private static StorageNodeId StorageNodeOf(string member) =>
        StorageNodeId.TryCreate(HostNodeOf(member), MaximumIdentityLength, out var node)
            ? node!
            : throw new InvalidOperationException("The placement storage node identity is invalid.");

    // --- death and leadership signals ----------------------------------------------

    private void UpdateDeathSignals(PlacementWorldSnapshot world)
    {
        foreach (var database in world.Databases)
        {
            foreach (var member in database.Members)
            {
                var key = MemberKey(database.Intent.Database, member.State.MemberId);
                if (member.Observation?.State is MemberHostState.Terminated or MemberHostState.Terminating or MemberHostState.Stopped)
                {
                    // A provider-terminal host is dead on sight; the missing-signal
                    // floor still applies only to hosts that vanish from the listing.
                    missingStreaks[key] = DeadAfterMissingTicks;
                }
                else if (member.Observation is null || member.Observation.State == MemberHostState.Unknown)
                {
                    missingStreaks.TryGetValue(key, out var streak);
                    missingStreaks[key] = streak + 1;
                }
                else
                {
                    missingStreaks.Remove(key);
                }
            }
        }
    }

    private void UpdateLeaderSignals(PlacementWorldSnapshot world)
    {
        foreach (var database in world.Databases)
        {
            var leader = database.Members
                .Where(static member => member.Healthy && member.IsLeader && member.Seat is not null)
                .OrderBy(static member => member.State.MemberId, StringComparer.Ordinal)
                .FirstOrDefault();
            if (leader is null)
                continue;
            var key = database.Intent.Database;
            leaderStreaks[key] = leaderStreaks.TryGetValue(key, out var prior) && prior.Leader == leader.State.MemberId
                ? (prior.Leader, prior.Streak + 1)
                : (leader.State.MemberId, 1);
        }
    }

    /// <summary>True when a DIFFERENT member has reported Leader for two consecutive ticks.</summary>
    private bool AnotherLeaderConfirmed(string database, string victim) =>
        leaderStreaks.TryGetValue(database, out var signal) &&
        signal.Leader != victim &&
        signal.Streak >= DeadAfterMissingTicks;

    private bool IsDead(PlacementMemberSnapshot member) =>
        missingStreaks.TryGetValue(MemberKey(member.State.Database, member.State.MemberId), out var streak) &&
        streak >= DeadAfterMissingTicks;

    private static string MemberKey(string database, string member) => $"{database}.{member}";

    // --- durable state --------------------------------------------------------------

    private async Task<PlacementTickObservation> WriteMemberAsync(
        PlacementMemberStateDocument document,
        ulong revision,
        PlacementIntentDocument intent,
        string action,
        CancellationToken cancellationToken)
    {
        var updated = document with { UpdatedAt = DateTimeOffset.UtcNow };
        updated.Validate();
        var json = JsonSerializer.Serialize(updated, TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument);
        try
        {
            await delivery.UpdateAsync(
                PlacementMemberStateDocument.Key(updated.Database, updated.MemberId),
                json,
                revision,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVWrongLastRevisionException or NatsKVKeyNotFoundException or NatsKVKeyDeletedException)
        {
            return Result(PlacementTickObservation.StateHeld, intent.Database, updated.MemberId, action, "cas", intent.Revision);
        }
        return Result(action, intent.Database, updated.MemberId, action, null, intent.Revision);
    }

    /// <summary>Creates the member's retained-volume identity once; a second create is a no-op.</summary>
    private async Task EnsureVolumeAsync(
        PlacementIntentDocument intent,
        string member,
        CancellationToken cancellationToken)
    {
        var document = new PlacementVolumeStateDocument(
            PlacementVolumeStateDocument.CurrentSchemaVersion,
            intent.Database,
            member,
            $"vol-{member}",
            $"attach-{member}",
            1,
            PlacementVolumeStateDocument.RetainedStateful,
            DateTimeOffset.UtcNow);
        document.Validate();
        try
        {
            await delivery.CreateAsync(
                PlacementVolumeStateDocument.Key(intent.Database, member),
                JsonSerializer.Serialize(document, TerraBasePlacementJsonContext.Default.PlacementVolumeStateDocument),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (NatsKVCreateException)
        {
            // The retained-volume identity already exists — exactly the invariant.
        }
    }

    internal static async Task<PlacementVolumeRecord?> ReadVolumeAsync(
        INatsKVStore delivery,
        string database,
        string member,
        CancellationToken cancellationToken)
    {
        try
        {
            var entry = await delivery.GetEntryAsync<string>(
                PlacementVolumeStateDocument.Key(database, member), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            var document = JsonSerializer.Deserialize(
                entry.Value ?? string.Empty, TerraBasePlacementJsonContext.Default.PlacementVolumeStateDocument);
            document?.Validate();
            return document is null ? null : new(document, entry.Revision);
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private async Task<bool> TryWriteVolumeAsync(
        PlacementVolumeStateDocument document,
        ulong revision,
        CancellationToken cancellationToken) =>
        await WriteVolumeAsync(delivery, document, revision, cancellationToken).ConfigureAwait(false);

    internal static async Task<bool> WriteVolumeAsync(
        INatsKVStore delivery,
        PlacementVolumeStateDocument document,
        ulong revision,
        CancellationToken cancellationToken)
    {
        try
        {
            await delivery.UpdateAsync(
                PlacementVolumeStateDocument.Key(document.Database, document.MemberId),
                JsonSerializer.Serialize(document, TerraBasePlacementJsonContext.Default.PlacementVolumeStateDocument),
                revision,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (exception is NatsKVWrongLastRevisionException or NatsKVKeyNotFoundException or NatsKVKeyDeletedException)
        {
            return false;
        }
    }

    private async Task<PlacementTickObservation> RemoveMemberRecordAsync(
        PlacementIntentDocument intent,
        PlacementMemberSnapshot member,
        CancellationToken cancellationToken)
    {
        try
        {
            await delivery.DeleteAsync(
                PlacementMemberStateDocument.Key(intent.Database, member.State.MemberId),
                new NatsKVDeleteOpts { Revision = member.Revision },
                cancellationToken).ConfigureAwait(false);
        }
        catch (NatsKVWrongLastRevisionException)
        {
            return Result(PlacementTickObservation.StateHeld, intent.Database, member.State.MemberId, "remove", "cas", intent.Revision);
        }
        // The retained-volume record deliberately survives the member: deletion is the
        // storage deletion planner's alone, never the placement reconciler's.
        return Result("removed", intent.Database, member.State.MemberId, "remove", null, intent.Revision);
    }

    // --- status and edge ------------------------------------------------------------

    private PlacementTickObservation Result(
        string state,
        string? database,
        string? member,
        string? action,
        string? error,
        long revision) =>
        new(
            PlacementTickObservation.CurrentSchemaVersion,
            cell,
            state,
            database,
            member,
            action,
            error,
            revision,
            DateTimeOffset.UtcNow);

    private async Task<PlacementTickObservation> ObserveAsync(
        PlacementTickObservation observation,
        CancellationToken cancellationToken)
    {
        try
        {
            await runtimeStore.PutAsync(
                PlacementTickObservation.Key(cell),
                JsonSerializer.Serialize(observation, TerraBasePlacementJsonContext.Default.PlacementTickObservation),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (NatsKVException)
        {
            // The tick outcome is still returned; the next tick republishes the status.
        }
        return observation;
    }

    /// <summary>
    /// Republishes edge placement when the projected fingerprint changed. A publication
    /// failure is recorded in the fingerprint NOT advancing — the next tick retries —
    /// and never fails the reconcile loop.
    /// </summary>
    private async Task TryPublishEdgeAsync(PlacementWorldSnapshot world, CancellationToken cancellationToken)
    {
        if (edgePublisher is null || edgeSource is null || world.Databases.Count == 0)
            return;
        try
        {
            var fingerprint = TerraBasePlacementEdgeSource.Fingerprint(
                TerraBasePlacementEdgeSource.Project(world));
            if (fingerprint == lastEdgeFingerprint)
                return;
            await edgePublisher.PublishAsync(cancellationToken).ConfigureAwait(false);
            lastEdgeFingerprint = fingerprint;
        }
        catch (Exception exception) when (
            exception is EdgePlacementValidationException or EdgePublishOperationException or
                EdgeRevisionRegressionException or EdgePublishBudgetException or HttpRequestException or
                InvalidOperationException)
        {
            // Publication retries next tick; placement reconciliation is unaffected.
        }
    }

    /// <summary>The stable provider idempotency token of one host incarnation.</summary>
    internal static string CreateKey(PlacementIntentDocument intent, PlacementMemberStateDocument state) =>
        $"placement.{intent.Database}.{state.MemberId}.r{intent.Revision}.h{state.HostSequence}";

    internal static string HostNodeOf(string member) => $"host-{member}";
}

/// <summary>One durable volume record with its KV revision for CAS writes.</summary>
internal sealed record PlacementVolumeRecord(PlacementVolumeStateDocument Document, ulong Revision);

/// <summary>One durable member record with its KV revision for CAS writes.</summary>
internal sealed record PlacementMemberRecord(PlacementMemberStateDocument Document, ulong Revision);
