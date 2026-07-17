using System.Security.Cryptography;
using System.Text;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Messaging;

public sealed class GlobalNatsTopology
{
    private const string Root = "ts.orch.v1.global";
    public const string CellSpecStream = "GLOBAL_SPEC";
    public const string CiStream = "GLOBAL_CI";
    public const string CiSubject = $"{Root}.ci.forgejo";
    public const string CiJobSubjectPrefix = $"{Root}.ci.job";
    public const string RunnerJobsBucket = "CI_RUNNER_JOBS";
    public const string RunnerBundlesBucket = "CI_RUNNER_BUNDLES";

    public GlobalNatsTopology(int replicas)
    {
        if (replicas != 3)
            throw new ArgumentOutOfRangeException(nameof(replicas), "Global control state requires R3.");
        Replicas = replicas;
    }

    public int Replicas { get; }

    public IReadOnlyList<StreamConfig> Streams =>
    [
        new(CellSpecStream, [$"{Root}.desired.>"])
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

    public NatsKVConfig RunnerJobs => new(RunnerJobsBucket)
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
        Description = "Content-addressed global candidate and handoff records",
        MaxBytes = 1024L * 1024 * 1024,
        NumberOfReplicas = Replicas,
    };

    public NatsObjConfig RunnerBundles => new(RunnerBundlesBucket)
    {
        Description = "Content-addressed fenced CI runner command and signature records",
        MaxAge = TimeSpan.FromDays(30),
        MaxBytes = 512L * 1024 * 1024,
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

    public ConsumerConfig CellSpecConsumer(string cell)
    {
        var subject = CellSpecSubject(cell);
        return new($"gitops_global_cell_spec_{cell}")
        {
            Description = $"Durable globally signed native GitOps CellSpecs for {cell}",
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            FilterSubject = subject,
            ReplayPolicy = ConsumerConfigReplayPolicy.Instant,
            AckWait = TimeSpan.FromSeconds(15),
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
                TimeSpan.FromSeconds(30),
            ],
            NumReplicas = Replicas,
        };
    }

    public ConsumerConfig CiJobConsumer(string zone, string runner)
    {
        var subject = CiJobSubject(zone, runner);
        var runnerHash = subject[(subject.LastIndexOf('.') + 1)..];
        return new($"ci_runner_{zone.Replace('-', '_')}_{runnerHash}")
        {
            Description = $"Durable fenced CI command inbox for {zone} runner {runnerHash}",
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            FilterSubject = subject,
            ReplayPolicy = ConsumerConfigReplayPolicy.Instant,
            AckWait = TimeSpan.FromSeconds(30),
            MaxDeliver = 5,
            MaxAckPending = 1,
            MaxWaiting = 4,
            MaxBatch = 1,
            MaxExpires = TimeSpan.FromSeconds(30),
            InactiveThreshold = TimeSpan.FromHours(24),
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

    public static string CiJobSubject(string zone, string runner)
    {
        if (zone is not ("untrusted-product" or "trusted-build"))
            throw new ArgumentException("The CI runner subject zone is invalid.", nameof(zone));
        var hash = CiRunnerIdentityHash(runner);
        return $"{CiJobSubjectPrefix}.{zone}.{hash[..24]}";
    }

    public static string CellSpecSubject(string cell)
    {
        if (cell is not { Length: >= 1 and <= 63 } ||
            cell[0] == '-' || cell[^1] == '-' ||
            cell.Any(static character => character is not (>= 'a' and <= 'z') and
                not (>= '0' and <= '9') and not '-'))
            throw new ArgumentException("The global CellSpec cell is not a lowercase DNS-style token.", nameof(cell));
        return $"{Root}.desired.gitops.{cell}";
    }

    public static string CiRunnerJournalPrefix(string runner) =>
        $"ci.runner.{CiRunnerIdentityHash(runner)}.job";

    public static string CiRunnerIdentityHash(string runner)
    {
        if (runner is not { Length: >= 1 and <= 512 } ||
            runner.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("The CI runner subject identity is invalid.", nameof(runner));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(runner)));
    }
}
