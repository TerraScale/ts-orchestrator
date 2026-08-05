using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Messaging;

public sealed record NatsTopology(string Cell, int Replicas, string Instance = "local")
{
    private string Root => $"ts.orch.v1.{Cell}";

    public string HealthSubject => $"{Root}.query.health";

    public string InstanceHealthSubject => $"{HealthSubject}.{Instance}";

    public string StatusSubject => $"{Root}.query.status";

    public string CellSpecSubject => $"{Root}.desired.gitops";

    public string StartupSubject => $"{Root}.event.runtime.started.{Instance}";

    public string ProtocolObject => "orchestrator-protocol-v1";

    public string ServiceName => $"terrascale_orchestrator_{Cell}";

    public string ServiceQueueGroup => $"orchestrator_{Cell}";

    public IReadOnlyList<StreamConfig> Streams =>
    [
        Stream("CELL_SPEC", $"{Root}.desired.>", 256 * 1024 * 1024),
        Stream("CELL_OPERATIONS", $"{Root}.operation.>", 1024 * 1024 * 1024),
        Stream("CELL_EVENTS", $"{Root}.event.>", 256 * 1024 * 1024)
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

    public NatsObjConfig Bundles => new("CELL_BUNDLES")
    {
        Description = $"Signed regional control and protocol bundles for {Cell}",
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    public ConsumerConfig StartupConsumer => new($"runtime_startup_{Instance}")
    {
        Description = $"Acknowledged runtime startup events for {Cell}/{Instance}",
        FilterSubject = StartupSubject,
        AckWait = TimeSpan.FromSeconds(15),
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
        FilterSubject = CellSpecSubject,
        AckWait = TimeSpan.FromSeconds(15),
        MaxDeliver = 5,
        MaxAckPending = 8,
        MaxWaiting = 8,
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
        MaxBytes = maxBytes,
        MaxAge = TimeSpan.FromDays(30),
        DuplicateWindow = TimeSpan.FromMinutes(2),
        NumReplicas = Replicas,
        Retention = StreamConfigRetention.Limits,
        Storage = StreamConfigStorage.File,
        Discard = StreamConfigDiscard.Old
    };
}
