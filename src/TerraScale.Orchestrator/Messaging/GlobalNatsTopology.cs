using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Messaging;

public sealed class GlobalNatsTopology
{
    private const string Root = "ts.orch.v1.global";
    public const string CiStream = "GLOBAL_CI";
    public const string CiSubject = $"{Root}.ci.forgejo";
    public const string CiJobSubjectPrefix = $"{Root}.ci.job";

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
        new(CiStream, [$"{Root}.ci.>"])
        {
            Description = "Durable normalized CI events and fenced runner commands",
            MaxBytes = 1024L * 1024 * 1024,
            MaxAge = TimeSpan.FromDays(30),
            DuplicateWindow = TimeSpan.FromHours(24),
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

    public NatsKVConfig RunnerJobs => new("CI_RUNNER_JOBS")
    {
        Description = "Fenced durable CI runner command acceptance pointers",
        History = 8,
        MaxAge = TimeSpan.FromDays(30),
        MaxValueSize = 16 * 1024,
        MaxBytes = 512L * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };

    public NatsObjConfig Bundles => new("GLOBAL_BUNDLES")
    {
        Description = "Content-addressed global candidate, handoff, and runner command records",
        MaxBytes = 1024L * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };

    public ConsumerConfig CiConsumer => new("global_ci_trigger")
    {
        Description = "Leader-only normalized Forgejo trigger decisions",
        FilterSubject = CiSubject,
        AckWait = TimeSpan.FromSeconds(15),
        MaxDeliver = 5,
        MaxAckPending = 32,
        MaxWaiting = 16,
        Backoff =
        [
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(15),
            TimeSpan.FromSeconds(30),
        ],
        NumReplicas = Replicas,
    };
}
