using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Messaging;

public sealed class GlobalNatsTopology
{
    private const string Root = "ts.orch.v1.global";

    public GlobalNatsTopology(int replicas)
    {
        if (replicas != 3)
            throw new ArgumentOutOfRangeException(nameof(replicas), "Global control state requires R3.");
        Replicas = replicas;
    }

    public int Replicas { get; }

    public IReadOnlyList<StreamConfig> Streams =>
    [
        new("GLOBAL_SPEC", [$"{Root}.desired.>"])
        {
            Description = "Accepted global revisions and compiled cell handoffs",
            MaxBytes = 256 * 1024 * 1024,
            MaxAge = TimeSpan.FromDays(30),
            DuplicateWindow = TimeSpan.FromMinutes(2),
            NumReplicas = Replicas,
            Retention = StreamConfigRetention.Limits,
            Storage = StreamConfigStorage.File,
            Discard = StreamConfigDiscard.Old,
        },
    ];

    public NatsKVConfig Leaders => new("ORCH_LEADERS")
    {
        Description = "Fenced global authority leases",
        History = 5,
        MaxBytes = 8 * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };

    public NatsKVConfig Releases => new("GLOBAL_RELEASES")
    {
        Description = "Candidate, release-set, approval, promotion, and rollback journal",
        History = 64,
        MaxAge = TimeSpan.FromDays(365),
        MaxValueSize = 16 * 1024,
        MaxBytes = 1024L * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };

    public NatsObjConfig Bundles => new("GLOBAL_BUNDLES")
    {
        Description = "Content-addressed global candidate and handoff records",
        MaxBytes = 1024L * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };
}
