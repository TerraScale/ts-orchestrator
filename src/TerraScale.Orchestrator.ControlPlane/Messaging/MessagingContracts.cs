using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Messaging;

/// <summary>Technical caller-input snapshot limits; these are not membership, replica, or resource policy caps.</summary>
public static class MessagingTechnicalInputLimits
{
    public const int MaximumCapturedItems = 4_096;
}

internal static class MessagingInputSnapshot
{
    internal static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var values = new List<T>(256);
        try
        {
            using var iterator = source.GetEnumerator();
            while (iterator.MoveNext())
            {
                if (values.Count == MessagingTechnicalInputLimits.MaximumCapturedItems)
                    throw new ArgumentException("Messaging input exceeds the technical snapshot bound.", parameterName);
                var current = iterator.Current;
                if (current is null) throw new ArgumentException("Messaging input contains a null item.", parameterName);
                values.Add(current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException("Messaging input could not be captured safely.", parameterName);
        }
        return new ReadOnlyCollection<T>(values.ToArray());
    }
}

public sealed record CellId { public CellId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record ClusterId { public ClusterId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record ServerId { public ServerId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record AccountId { public AccountId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record StreamId { public StreamId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record BucketId { public BucketId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record PeerId { public PeerId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record StoreId { public StoreId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record PlacementId { public PlacementId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record MessagingOperationId { public MessagingOperationId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }
public sealed record MessagingObservationId { public MessagingObservationId(string value) => Value = value ?? throw new ArgumentNullException(nameof(value)); public string Value { get; } }

public enum MessagingPlane { Unspecified, Control, Product }
public enum MessagingDurability { Unspecified, Critical, Bounded }
public enum MessagingRetention { Unspecified, Limits, WorkQueue, Interest }
public enum MessagingDiscard { Unspecified, Old, New }
public enum MessagingAcknowledgement { Unspecified, NoAck, Leader, Replicated }
public enum MessagingDiskSyncClass { Unspecified, AcknowledgedWriteStrict, BoundedLoss }
public enum MessagingAction { Unspecified, Configure, Observe, AddPeer, ReattachStore, WaitCatchup, RemovePeer, Hold }
public enum PeerHealth { Unspecified, Current, Failed, Ambiguous }
public enum StoreClassification { Unspecified, Surviving, Lost, Ambiguous }
public enum CompatibilityFeature { Unspecified, Commands, Snapshots, SchemaReads, LeadershipTransfer }
public enum CompatibilityPair { Unspecified, CurrentToCurrent, CurrentToPrevious, PreviousToCurrent }
public enum AuthorityScope { Unspecified, Regional, Global }
public enum ConnectivityState { Unspecified, Connected, GlobalDisconnected, RegionalQuorumLost }

public enum MessagingErrorCode
{
    Unspecified,
    InvalidInput,
    InvalidCatalog,
    IsolationViolation,
    MembershipFloorViolation,
    DurabilityViolation,
    IncompleteObservation,
    DuplicateEvidence,
    ConflictingEvidence,
    StaleEvidence,
    FutureEvidence,
    ReplacementConflict,
    StoreAmbiguous,
    RemovalUnsafe,
    PartitionDenied,
    StaleAuthority,
    CompatibilityUnavailable,
    ArithmeticOverflow,
}

public enum MessagingTraceCode
{
    Unspecified,
    ConfigurationAccepted,
    ObservationRequired,
    ReplacementMustPersist,
    ReplacementAddRequired,
    SurvivingStoreReattachRequired,
    ReplacementCatchupRequired,
    ReplicaVerificationRequired,
    FailedPeerRemovalAllowed,
    ReplacementComplete,
    Held,
    RegionalOperationAllowed,
    CompatibilityAccepted,
}

public sealed record MessagingError(
    MessagingErrorCode Code,
    string Requirement,
    MessagingOperationId? Operation,
    ServerId? Server,
    PeerId? Peer);

public sealed record RouteLink(ServerId From, ServerId To);

public sealed class AccountPolicy
{
    public AccountPolicy(AccountId id, IEnumerable<string> subjectRoots)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        SubjectRoots = Copy(subjectRoots);
    }
    public AccountId Id { get; }
    public IReadOnlyList<string> SubjectRoots { get; }
    private static IReadOnlyList<string> Copy(IEnumerable<string> values) =>
        CopyValues(values);
    private static IReadOnlyList<string> CopyValues(IEnumerable<string> values) =>
        MessagingInputSnapshot.Copy(values, nameof(values));
}

public sealed record ServerPolicy(ServerId Server, PeerId Peer, PlacementId Placement);

public sealed record StreamPolicy(
    StreamId Id,
    AccountId Account,
    string SubjectRoot,
    int Replicas,
    MessagingDurability Durability,
    MessagingRetention Retention,
    long MaximumAgeTicks,
    long MaximumBytes,
    MessagingDiscard Discard,
    PlacementId Placement,
    long DuplicateWindowTicks,
    MessagingAcknowledgement Acknowledgement,
    MessagingDiskSyncClass DiskSyncClass);

public sealed record BucketPolicy(
    BucketId Id,
    AccountId Account,
    string SubjectRoot,
    int Replicas,
    MessagingDurability Durability,
    long MaximumAgeTicks,
    long MaximumBytes,
    PlacementId Placement,
    MessagingAcknowledgement Acknowledgement,
    MessagingDiskSyncClass DiskSyncClass);

public sealed class PlanePolicy
{
    public PlanePolicy(
        MessagingPlane plane,
        CellId cell,
        ClusterId cluster,
        long generation,
        int membershipFloor,
        IEnumerable<ServerPolicy> servers,
        IEnumerable<RouteLink> routes,
        IEnumerable<ClusterId> gateways,
        IEnumerable<AccountPolicy> accounts,
        IEnumerable<StreamPolicy> streams,
        IEnumerable<BucketPolicy> buckets)
    {
        Plane = plane;
        Cell = cell ?? throw new ArgumentNullException(nameof(cell));
        Cluster = cluster ?? throw new ArgumentNullException(nameof(cluster));
        Generation = generation;
        MembershipFloor = membershipFloor;
        Servers = ReadOnly(servers);
        Routes = ReadOnly(routes);
        Gateways = ReadOnly(gateways);
        Accounts = ReadOnly(accounts);
        Streams = ReadOnly(streams);
        Buckets = ReadOnly(buckets);
    }
    public MessagingPlane Plane { get; }
    public CellId Cell { get; }
    public ClusterId Cluster { get; }
    public long Generation { get; }
    public int MembershipFloor { get; }
    public IReadOnlyList<ServerPolicy> Servers { get; }
    public IReadOnlyList<RouteLink> Routes { get; }
    public IReadOnlyList<ClusterId> Gateways { get; }
    public IReadOnlyList<AccountPolicy> Accounts { get; }
    public IReadOnlyList<StreamPolicy> Streams { get; }
    public IReadOnlyList<BucketPolicy> Buckets { get; }
    private static IReadOnlyList<T> ReadOnly<T>(IEnumerable<T> values) =>
        ReadOnlyChecked(values);
    private static IReadOnlyList<T> ReadOnlyChecked<T>(IEnumerable<T> values) =>
        MessagingInputSnapshot.Copy(values, nameof(values));
}

public sealed class MessagingTopologyPolicy
{
    public MessagingTopologyPolicy(
        PlanePolicy control,
        PlanePolicy product,
        int maximumIdentityLength,
        int maximumSubjectLength,
        int maximumResources,
        IEnumerable<CompatibilityFeature> knownFeatures)
    {
        Control = control ?? throw new ArgumentNullException(nameof(control));
        Product = product ?? throw new ArgumentNullException(nameof(product));
        MaximumIdentityLength = maximumIdentityLength;
        MaximumSubjectLength = maximumSubjectLength;
        MaximumResources = maximumResources;
        KnownFeatures = MessagingInputSnapshot.Copy(knownFeatures, nameof(knownFeatures));
    }
    public PlanePolicy Control { get; }
    public PlanePolicy Product { get; }
    public int MaximumIdentityLength { get; }
    public int MaximumSubjectLength { get; }
    public int MaximumResources { get; }
    public IReadOnlyList<CompatibilityFeature> KnownFeatures { get; }
}

public sealed record PeerObservation(
    ServerId Server,
    PeerId Peer,
    PeerHealth Health,
    StoreClassification Store,
    bool ProcessFenced,
    bool OwnershipProven,
    bool CaughtUp,
    SurvivingStoreProof? SurvivingStoreProof = null);

public sealed record SurvivingStoreProof(
    StoreId Store,
    long StoreGeneration,
    long ObservedMembershipSequence,
    MessagingPlane Plane,
    CellId Cell,
    ClusterId Cluster,
    ServerId RecordedOwner,
    ServerId? ActiveAttachment,
    long OwnershipEpoch,
    bool Compatible);

public sealed record ReplicaObservation(
    string ResourceIdentity,
    int CurrentReplicas,
    int HealthyReplicas,
    long LastSequence);

public sealed class ClusterObservation
{
    public ClusterObservation(
        MessagingObservationId observationId,
        ClusterId cluster,
        long configurationGeneration,
        long membershipSequence,
        IEnumerable<PeerObservation> peers,
        IEnumerable<ReplicaObservation> streamReplicas,
        IEnumerable<ReplicaObservation> bucketReplicas)
    {
        ObservationId = observationId ?? throw new ArgumentNullException(nameof(observationId));
        Cluster = cluster ?? throw new ArgumentNullException(nameof(cluster));
        ConfigurationGeneration = configurationGeneration;
        MembershipSequence = membershipSequence;
        Peers = ReadOnly(peers);
        StreamReplicas = ReadOnly(streamReplicas);
        BucketReplicas = ReadOnly(bucketReplicas);
    }
    public MessagingObservationId ObservationId { get; }
    public ClusterId Cluster { get; }
    public long ConfigurationGeneration { get; }
    public long MembershipSequence { get; }
    public IReadOnlyList<PeerObservation> Peers { get; }
    public IReadOnlyList<ReplicaObservation> StreamReplicas { get; }
    public IReadOnlyList<ReplicaObservation> BucketReplicas { get; }
    private static IReadOnlyList<T> ReadOnly<T>(IEnumerable<T> values) =>
        ReadOnlyChecked(values);
    private static IReadOnlyList<T> ReadOnlyChecked<T>(IEnumerable<T> values) =>
        MessagingInputSnapshot.Copy(values, nameof(values));
}

public sealed record ReplacementOperation(
    MessagingOperationId OperationId,
    MessagingPlane Plane,
    CellId Cell,
    ClusterId Cluster,
    long OperationGeneration,
    long AuthorityEpoch,
    long ConfigurationGeneration,
    long MinimumObservationSequence,
    long MaximumObservationSequence,
    ServerId FailedServer,
    PeerId FailedPeer,
    ServerId ReplacementServer,
    PeerId ReplacementPeer,
    PlacementId ReplacementPlacement);

public sealed record ReplacementRequest(
    PlanePolicy Policy,
    ReplacementOperation Proposed,
    ReplacementOperation? Persisted,
    ClusterObservation? Observation,
    int MaximumIdentityLength);

public sealed record CompatibilityOutcome(
    CompatibilityFeature Feature,
    CompatibilityPair Pair,
    bool Available);

public sealed class CompatibilityPolicy
{
    public CompatibilityPolicy(long currentVersion, long previousVersion, IEnumerable<CompatibilityOutcome> outcomes)
    {
        CurrentVersion = currentVersion;
        PreviousVersion = previousVersion;
        Outcomes = MessagingInputSnapshot.Copy(outcomes, nameof(outcomes));
    }
    public long CurrentVersion { get; }
    public long PreviousVersion { get; }
    public IReadOnlyList<CompatibilityOutcome> Outcomes { get; }
}

public sealed class CompatibilityAcceptance
{
    private readonly ReadOnlyCollection<CompatibilityOutcome> _outcomes;

    internal CompatibilityAcceptance(
        long currentVersion,
        long previousVersion,
        IEnumerable<CompatibilityOutcome> outcomes)
    {
        CurrentVersion = currentVersion;
        PreviousVersion = previousVersion;
        _outcomes = new ReadOnlyCollection<CompatibilityOutcome>(outcomes
            .OrderBy(static outcome => (int)outcome.Feature)
            .ThenBy(static outcome => (int)outcome.Pair)
            .ToArray());
    }

    public long CurrentVersion { get; }

    public long PreviousVersion { get; }

    public IReadOnlyList<CompatibilityOutcome> Outcomes => _outcomes;
}

public sealed record PartitionRequest(
    CellId Cell,
    int MaximumIdentityLength,
    ConnectivityState Connectivity,
    AuthorityScope Scope,
    long CurrentRegionalEpoch,
    long CommandRegionalEpoch,
    long AcceptedGlobalGeneration,
    long CommandGlobalGeneration,
    long CurrentGlobalEpoch,
    long CommandGlobalEpoch,
    bool CallerAuthorizesLocalOperation,
    bool HoldsCurrentGlobalAuthority);

public abstract record MessagingIntent
{
    internal MessagingIntent(MessagingAction action) => Action = action;
    public MessagingAction Action { get; }
}
public sealed record ConfigurePlaneIntent : MessagingIntent { internal ConfigurePlaneIntent(PlanePolicy policy) : base(MessagingAction.Configure) => Policy = policy; public PlanePolicy Policy { get; } }
public sealed record ConfigureReplacementIntent : MessagingIntent { internal ConfigureReplacementIntent(ReplacementOperation operation) : base(MessagingAction.Configure) => Operation = operation; public ReplacementOperation Operation { get; } }
public sealed record ObserveClusterIntent : MessagingIntent
{
    internal ObserveClusterIntent(MessagingOperationId operation, ClusterId cluster, long minimumSequence, long maximumSequence) : base(MessagingAction.Observe)
    { Operation = operation; Cluster = cluster; MinimumSequence = minimumSequence; MaximumSequence = maximumSequence; }
    public MessagingOperationId Operation { get; } public ClusterId Cluster { get; } public long MinimumSequence { get; } public long MaximumSequence { get; }
}
public sealed record AddPeerIntent : MessagingIntent
{
    internal AddPeerIntent(MessagingOperationId operation, ClusterId cluster, ServerId server, PeerId peer, PlacementId placement, long authorityEpoch) : base(MessagingAction.AddPeer)
    { Operation = operation; Cluster = cluster; Server = server; Peer = peer; Placement = placement; AuthorityEpoch = authorityEpoch; }
    public MessagingOperationId Operation { get; } public ClusterId Cluster { get; } public ServerId Server { get; } public PeerId Peer { get; } public PlacementId Placement { get; } public long AuthorityEpoch { get; }
}
public sealed record ReattachSurvivingStoreIntent : MessagingIntent
{
    internal ReattachSurvivingStoreIntent(MessagingOperationId operation, MessagingPlane plane, CellId cell, ClusterId cluster,
        ServerId recordedServer, PeerId recordedPeer, PlacementId replacementPlacement, StoreId store,
        long storeGeneration, long observedMembershipSequence, long ownershipEpoch) : base(MessagingAction.ReattachStore)
    { Operation = operation; Plane = plane; Cell = cell; Cluster = cluster; RecordedServer = recordedServer; RecordedPeer = recordedPeer;
      ReplacementPlacement = replacementPlacement; Store = store; StoreGeneration = storeGeneration;
      ObservedMembershipSequence = observedMembershipSequence; OwnershipEpoch = ownershipEpoch; }
    public MessagingOperationId Operation { get; } public MessagingPlane Plane { get; } public CellId Cell { get; }
    public ClusterId Cluster { get; } public ServerId RecordedServer { get; } public PeerId RecordedPeer { get; }
    public PlacementId ReplacementPlacement { get; } public StoreId Store { get; } public long StoreGeneration { get; }
    public long ObservedMembershipSequence { get; } public long OwnershipEpoch { get; }
}
public sealed record WaitCatchupIntent : MessagingIntent
{
    internal WaitCatchupIntent(MessagingOperationId operation, ClusterId cluster, PeerId peer, long requiredSequence) : base(MessagingAction.WaitCatchup)
    { Operation = operation; Cluster = cluster; Peer = peer; RequiredSequence = requiredSequence; }
    public MessagingOperationId Operation { get; } public ClusterId Cluster { get; } public PeerId Peer { get; } public long RequiredSequence { get; }
}
public sealed record RemovePeerIntent : MessagingIntent
{
    internal RemovePeerIntent(MessagingOperationId operation, ClusterId cluster, ServerId failedServer, PeerId failedPeer,
        PeerId replacementPeer, long verifiedMembershipSequence, long authorityEpoch) : base(MessagingAction.RemovePeer)
    { Operation = operation; Cluster = cluster; FailedServer = failedServer; FailedPeer = failedPeer; ReplacementPeer = replacementPeer;
      VerifiedMembershipSequence = verifiedMembershipSequence; AuthorityEpoch = authorityEpoch; }
    public MessagingOperationId Operation { get; } public ClusterId Cluster { get; } public ServerId FailedServer { get; }
    public PeerId FailedPeer { get; } public PeerId ReplacementPeer { get; } public long VerifiedMembershipSequence { get; }
    public long AuthorityEpoch { get; }
}
public sealed record ContinueRegionalIntent : MessagingIntent
{
    internal ContinueRegionalIntent(CellId cell, long regionalEpoch, long acceptedGlobalGeneration) : base(MessagingAction.Configure)
    { Cell = cell; RegionalEpoch = regionalEpoch; AcceptedGlobalGeneration = acceptedGlobalGeneration; }
    public CellId Cell { get; } public long RegionalEpoch { get; } public long AcceptedGlobalGeneration { get; }
}
public sealed record ContinueGlobalIntent : MessagingIntent
{
    internal ContinueGlobalIntent(CellId cell, long globalEpoch, long acceptedGlobalGeneration) : base(MessagingAction.Configure)
    { Cell = cell; GlobalEpoch = globalEpoch; AcceptedGlobalGeneration = acceptedGlobalGeneration; }
    public CellId Cell { get; } public long GlobalEpoch { get; } public long AcceptedGlobalGeneration { get; }
}
public sealed record HoldMessagingIntent : MessagingIntent
{
    internal HoldMessagingIntent(MessagingErrorCode reason, MessagingOperationId? operation, ServerId? server, PeerId? peer) : base(MessagingAction.Hold)
    { Reason = reason; Operation = operation; Server = server; Peer = peer; }
    public MessagingErrorCode Reason { get; } public MessagingOperationId? Operation { get; } public ServerId? Server { get; } public PeerId? Peer { get; }
}
public sealed record MessagingTrace(int Sequence, MessagingTraceCode Code, MessagingAction Action);
public sealed record MessagingDecision
{
    internal MessagingDecision(
        IReadOnlyList<MessagingIntent> intents,
        IReadOnlyList<MessagingError> errors,
        IReadOnlyList<MessagingTrace> trace,
        CompatibilityAcceptance? compatibility = null)
    { Intents = intents; Errors = errors; Trace = trace; Compatibility = compatibility; }
    public IReadOnlyList<MessagingIntent> Intents { get; } public IReadOnlyList<MessagingError> Errors { get; }
    public IReadOnlyList<MessagingTrace> Trace { get; }
    public CompatibilityAcceptance? Compatibility { get; }
}
