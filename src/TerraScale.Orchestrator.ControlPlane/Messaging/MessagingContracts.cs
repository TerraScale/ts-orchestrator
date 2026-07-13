using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Messaging;

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
    private static IReadOnlyList<string> CopyValues(IEnumerable<string> values)
    {
        var copy = (values ?? throw new ArgumentNullException(nameof(values))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Collection contains null.", nameof(values));
        return new ReadOnlyCollection<string>(copy);
    }
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
    private static IReadOnlyList<T> ReadOnlyChecked<T>(IEnumerable<T> values)
    {
        var copy = (values ?? throw new ArgumentNullException(nameof(values))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Collection contains null.", nameof(values));
        return new ReadOnlyCollection<T>(copy);
    }
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
    private static IReadOnlyList<T> ReadOnlyChecked<T>(IEnumerable<T> values)
    {
        var copy = (values ?? throw new ArgumentNullException(nameof(values))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Collection contains null.", nameof(values));
        return new ReadOnlyCollection<T>(copy);
    }
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
        var copy = (outcomes ?? throw new ArgumentNullException(nameof(outcomes))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Collection contains null.", nameof(outcomes));
        Outcomes = new ReadOnlyCollection<CompatibilityOutcome>(copy);
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
    ServerId RecordedServer,
    PeerId RecordedPeer,
    PlacementId ReplacementPlacement,
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
