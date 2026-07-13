using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Messaging;

public sealed record CellId(string Value);
public sealed record ClusterId(string Value);
public sealed record ServerId(string Value);
public sealed record AccountId(string Value);
public sealed record StreamId(string Value);
public sealed record BucketId(string Value);
public sealed record PeerId(string Value);
public sealed record StoreId(string Value);
public sealed record PlacementId(string Value);
public sealed record MessagingOperationId(string Value);
public sealed record MessagingObservationId(string Value);

public enum MessagingPlane { Control, Product }
public enum MessagingDurability { Critical, Bounded }
public enum MessagingRetention { Limits, WorkQueue, Interest }
public enum MessagingDiscard { Old, New }
public enum MessagingAcknowledgement { None, Leader, Replicated }
public enum MessagingDiskSyncClass { AcknowledgedWriteStrict, BoundedLoss }
public enum MessagingAction { Configure, Observe, AddPeer, ReattachStore, WaitCatchup, RemovePeer, Hold }
public enum PeerHealth { Current, Failed, Ambiguous }
public enum StoreClassification { Surviving, Lost, Ambiguous }
public enum CompatibilityFeature { Commands, Snapshots, SchemaReads, LeadershipTransfer }
public enum CompatibilityPair { CurrentToCurrent, CurrentToPrevious, PreviousToCurrent }
public enum AuthorityScope { Regional, Global }
public enum ConnectivityState { Connected, GlobalDisconnected, RegionalQuorumLost }

public enum MessagingErrorCode
{
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
        Id = id;
        SubjectRoots = Copy(subjectRoots);
    }
    public AccountId Id { get; }
    public IReadOnlyList<string> SubjectRoots { get; }
    private static IReadOnlyList<string> Copy(IEnumerable<string> values) =>
        new ReadOnlyCollection<string>((values ?? throw new ArgumentNullException(nameof(values))).ToArray());
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
        Cell = cell;
        Cluster = cluster;
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
        new ReadOnlyCollection<T>((values ?? throw new ArgumentNullException(nameof(values))).ToArray());
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
        Control = control;
        Product = product;
        MaximumIdentityLength = maximumIdentityLength;
        MaximumSubjectLength = maximumSubjectLength;
        MaximumResources = maximumResources;
        KnownFeatures = new ReadOnlyCollection<CompatibilityFeature>(
            (knownFeatures ?? throw new ArgumentNullException(nameof(knownFeatures))).ToArray());
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
        ObservationId = observationId;
        Cluster = cluster;
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
        new ReadOnlyCollection<T>((values ?? throw new ArgumentNullException(nameof(values))).ToArray());
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
        Outcomes = new ReadOnlyCollection<CompatibilityOutcome>(
            (outcomes ?? throw new ArgumentNullException(nameof(outcomes))).ToArray());
    }
    public long CurrentVersion { get; }
    public long PreviousVersion { get; }
    public IReadOnlyList<CompatibilityOutcome> Outcomes { get; }
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

public abstract record MessagingIntent(MessagingAction Action);
public sealed record ConfigurePlaneIntent(PlanePolicy Policy) : MessagingIntent(MessagingAction.Configure);
public sealed record ConfigureReplacementIntent(ReplacementOperation Operation) : MessagingIntent(MessagingAction.Configure);
public sealed record ObserveClusterIntent(MessagingOperationId Operation, ClusterId Cluster, long MinimumSequence, long MaximumSequence) : MessagingIntent(MessagingAction.Observe);
public sealed record AddPeerIntent(MessagingOperationId Operation, ClusterId Cluster, ServerId Server, PeerId Peer, PlacementId Placement, long AuthorityEpoch) : MessagingIntent(MessagingAction.AddPeer);
public sealed record ReattachSurvivingStoreIntent(
    MessagingOperationId Operation,
    MessagingPlane Plane,
    CellId Cell,
    ClusterId Cluster,
    ServerId FailedServer,
    ServerId ReplacementServer,
    PeerId ReplacementPeer,
    StoreId Store,
    long StoreGeneration,
    long ObservedMembershipSequence,
    long OwnershipEpoch)
    : MessagingIntent(MessagingAction.ReattachStore);
public sealed record WaitCatchupIntent(MessagingOperationId Operation, ClusterId Cluster, PeerId Peer, long RequiredSequence) : MessagingIntent(MessagingAction.WaitCatchup);
public sealed record RemovePeerIntent(MessagingOperationId Operation, ClusterId Cluster, ServerId FailedServer, PeerId FailedPeer, PeerId ReplacementPeer, long VerifiedMembershipSequence, long AuthorityEpoch) : MessagingIntent(MessagingAction.RemovePeer);
public sealed record ContinueRegionalIntent(CellId Cell, long RegionalEpoch, long AcceptedGlobalGeneration) : MessagingIntent(MessagingAction.Configure);
public sealed record ContinueGlobalIntent(CellId Cell, long GlobalEpoch, long AcceptedGlobalGeneration) : MessagingIntent(MessagingAction.Configure);
public sealed record HoldMessagingIntent(MessagingErrorCode Reason, MessagingOperationId? Operation, ServerId? Server, PeerId? Peer) : MessagingIntent(MessagingAction.Hold);

public sealed record MessagingTrace(int Sequence, MessagingTraceCode Code, MessagingAction Action);
public sealed record MessagingDecision(IReadOnlyList<MessagingIntent> Intents, IReadOnlyList<MessagingError> Errors, IReadOnlyList<MessagingTrace> Trace);
