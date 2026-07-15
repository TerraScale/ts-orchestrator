using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Messaging;

public sealed record NatsTopology(string Cell, int Replicas)
{
    private string Root => $"ts.orch.v1.{Cell}";

    public string HealthSubject => $"{Root}.query.health";

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

    public NatsObjConfig Bundles => new("CELL_BUNDLES")
    {
        Description = $"Signed control bundles for {Cell}",
        MaxBytes = 64 * 1024 * 1024,
        NumberOfReplicas = Replicas
    };

    private StreamConfig Stream(string name, string subject, long maxBytes) => new(name, [subject])
    {
        Description = $"TerraScale Orchestrator {name} for {Cell}",
        MaxBytes = maxBytes,
        MaxAge = TimeSpan.FromDays(30),
        DuplicateWindow = TimeSpan.FromMinutes(2),
        NumReplicas = Replicas
    };
}
