using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

public sealed record NatsTopology(string Cell, int Replicas, string Instance = "local")
{
    public string HealthSubject => NatsSubjectTaxonomy.ControllerHealthSubject(Cell);

    public string InstanceHealthSubject => NatsSubjectTaxonomy.ControllerInstanceHealthSubject(Cell, Instance);

    public string StatusSubject => NatsSubjectTaxonomy.ControllerStatusSubject(Cell);

    public string MembersSubject => NatsSubjectTaxonomy.ControllerMembersSubject(Cell);

    /// <summary>Read-only service statistics endpoint: version, schema, health, request/error/latency aggregates.</summary>
    public string StatsSubject => NatsSubjectTaxonomy.ControllerStatsSubject(Cell);

    public string DirectDeliverySubject => NatsSubjectTaxonomy.DirectDeliverySubject(Cell);

    public string OperationJournalCreateSubject => NatsSubjectTaxonomy.OperationJournalCreateSubject(Cell);

    public string OperationJournalUpdateSubject => NatsSubjectTaxonomy.OperationJournalUpdateSubject(Cell);

    public string OperationJournalReplySubject(string callerIdentity, string nonce) =>
        NatsSubjectTaxonomy.OperationJournalReplySubject(Cell, callerIdentity, nonce);

    public string OperationJournalWriterQueueGroup => $"terrascale_orchestrator_journal_writer_{Cell}";

    public string CellSpecSubject => NatsSubjectTaxonomy.CellSpecSubject(Cell);

    public string StartupSubject => NatsSubjectTaxonomy.RuntimeStartupSubject(Cell, Instance);

    public string ProtocolObject => "orchestrator-protocol-v2";

    public string ServiceName => $"terrascale_orchestrator_{Cell}";

    public string ServiceQueueGroup => $"orchestrator_{Cell}";

    public IReadOnlyList<StreamConfig> Streams =>
    [
        Stream("CELL_SPEC", NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.DesiredFamilySegment), 256 * 1024 * 1024),
        Stream("CELL_OPERATIONS", NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.OperationFamilySegment), 1024 * 1024 * 1024),
        Stream("CELL_EVENTS", NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.ObservationFamilySegment), 256 * 1024 * 1024)
    ];

    public NatsKVConfig Leaders => new("ORCH_LEADERS")
    {
        Description = $"Fenced authority leases for {Cell}",
        History = 5,
        MaxBytes = 8 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    public NatsKVConfig Runtime => new("ORCH_RUNTIME")
    {
        Description = $"Live orchestrator registrations for {Cell}",
        History = 2,
        MaxAge = TimeSpan.FromMinutes(5),
        MaxBytes = 8 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    public NatsKVConfig Delivery => new("ORCH_DELIVERY")
    {
        Description = $"Durable regional delivery and handoff coordination for {Cell}",
        History = 2,
        MaxValueSize = 16 * 1024,
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    public NatsKVConfig Operations => new("ORCH_OPERATIONS")
    {
        Description = $"Authoritative encrypted regional operation journal for {Cell}",
        History = 2,
        MaxValueSize = 16 * 1024,
        MaxBytes = 256 * 1024 * 1024,
        // This authoritative journal is provisioned only by the infrastructure
        // identity; controller TS_ORCH_REPLICAS must never reconfigure it.
        NumberOfReplicas = 3
    };

    /// <summary>Expiry-bounded R3 records that make each private journal authority proof single-use.</summary>
    public NatsKVConfig OperationProofConsumptions => new("ORCH_OPERATION_PROOFS")
    {
        Description = $"Expiry-bounded single-use operation journal authority proofs for {Cell}",
        History = 1,
        MaxAge = TimeSpan.FromMinutes(5),
        MaxValueSize = 256,
        MaxBytes = 8 * 1024 * 1024,
        // As with ORCH_OPERATIONS, this is provisioned only by infrastructure
        // and must never inherit the controller's development replica count.
        NumberOfReplicas = 3
    };

    public NatsObjConfig Bundles => new("CELL_BUNDLES")
    {
        Description = $"Signed regional control bundles for {Cell}",
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    /// <summary>The controller may read only this immutable canonical protocol package.</summary>
    public NatsObjConfig ProtocolPackage => new("ORCH_PROTOCOL_PACKAGE")
    {
        Description = $"Immutable canonical orchestrator protocol package for {Cell}",
        MaxBytes = 256 * 1024,
        NumberOfReplicas = Replicas
    };

    public ConsumerConfig StartupConsumer => new("runtime_startup")
    {
        Description = $"Acknowledged runtime startup events for {Cell}",
        FilterSubject = NatsSubjectTaxonomy.RuntimeStartupPattern(Cell),
        // JetStream derives the effective acknowledgement wait from the first
        // backoff interval, so declare the value it will return on readback.
        AckWait = TimeSpan.FromSeconds(1),
        MaxDeliver = 5,
        MaxAckPending = 32,
        MaxWaiting = 16,
        Backoff =
        [
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(15),
            TimeSpan.FromSeconds(30)
        ],
        NumReplicas = Replicas
    };

    public ConsumerConfig CellSpecConsumer => new($"gitops_cell_spec_{Instance}")
    {
        Description = $"Durable signed native GitOps CellSpecs for {Cell}/{Instance}",
        DeliverPolicy = ConsumerConfigDeliverPolicy.All,
        AckPolicy = ConsumerConfigAckPolicy.Explicit,
        FilterSubject = CellSpecSubject,
        ReplayPolicy = ConsumerConfigReplayPolicy.Instant,
        // Keep the declared value aligned with the first backoff interval.
        AckWait = TimeSpan.FromSeconds(1),
        MaxDeliver = 5,
        MaxAckPending = 8,
        MaxWaiting = 8,
        MaxBatch = 1,
        MaxExpires = TimeSpan.FromSeconds(30),
        Backoff =
        [
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(15),
            TimeSpan.FromSeconds(30)
        ],
        NumReplicas = Replicas
    };

    private StreamConfig Stream(string name, string subject, long maxBytes) => new(name, [subject])
    {
        Description = $"TerraScale Orchestrator {name} for {Cell}",
        MaxConsumers = -1,
        MaxMsgs = -1,
        MaxMsgsPerSubject = -1,
        MaxBytes = maxBytes,
        MaxAge = TimeSpan.FromDays(30),
        MaxMsgSize = -1,
        DuplicateWindow = TimeSpan.FromMinutes(2),
        NumReplicas = Replicas,
        Retention = StreamConfigRetention.Limits,
        Storage = StreamConfigStorage.File,
        Compression = StreamConfigCompression.None,
        NoAck = false,
        Discard = StreamConfigDiscard.Old,
        Sealed = false,
        DenyDelete = false,
        DenyPurge = false,
        AllowRollupHdrs = false,
        AllowDirect = false,
        MirrorDirect = false,
        DiscardNewPerSubject = false,
        AllowMsgTTL = false,
        SubjectDeleteMarkerTTL = TimeSpan.Zero,
        AllowMsgCounter = false,
        AllowMsgSchedules = false,
        AllowAtomicPublish = false,
    };
}
