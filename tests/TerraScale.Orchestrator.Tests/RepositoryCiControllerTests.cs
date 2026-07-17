using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiControllerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string BaseCommit = "affe000000000000000000000000000000000001";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";

    [Test]
    public async Task CapacityMutationRequiresTheSameLiveAuthorityEpoch()
    {
        var now = DateTimeOffset.UtcNow;
        var expected = new RegionalAuthoritySnapshot(
            "leader",
            true,
            5,
            9,
            now.AddMinutes(1),
            now,
            null);

        await Assert.That(RepositoryCiController.SameAuthority(
            expected,
            expected with { KvRevision = 10 })).IsTrue();
        await Assert.That(RepositoryCiController.SameAuthority(
            expected,
            expected with { Epoch = 6 })).IsFalse();
        await Assert.That(RepositoryCiController.SameAuthority(
            expected,
            expected with { IsLeader = false })).IsFalse();
    }

    [Test]
    public async Task DurableForgejoEventDispatchesToAnObservedPreemptibleRunner()
    {
        var root = Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-controller-{Guid.NewGuid():N}"));
        RepositoryCiController? controller = null;
        try
        {
            var pool = await PoolAsync(root.FullName);
            var slot = pool.Slots.Single();
            var now = DateTimeOffset.UtcNow;
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var runnerLedger = new ForgejoWebhookJournalTests.TestLedger();
            var objects = new TestObjectStore();
            var triggers = new ForgejoCiTriggerJournal(ledger);
            var trigger = Trigger();
            _ = await triggers.RecordAsync(trigger, 5, 9, static () => true);
            var pipelines = new RepositoryCiPipelineJournal(ledger, objects);
            var pipelineCoordinator = new RepositoryCiPipelineCoordinator(
                triggers,
                pipelines,
                static (_, _) => Task.FromResult<IReadOnlyList<string>>(["src/file.cs"]),
                static (_, _, _) => Task.FromResult(new RepositoryCiPipelineGraph(
                    [Descriptor()],
                    [new(Repository, Commit, Tree, signatureVerified: false)])));
            var jobs = new RepositoryCiJobJournal(ledger);
            var transport = new TestTransport();
            var dispatch = new RepositoryCiJobDispatchCoordinator(
                jobs,
                new(objects),
                new(jobs, new(transport, new TestSigner())),
                static (source, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    var content = new byte[] { 0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4 };
                    return Task.FromResult(new ForgejoSourceArchive(
                        source,
                        Convert.ToHexStringLower(SHA256.HashData(content)),
                        content));
                },
                (job, runner, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(slot.Isolation(job));
                });
            var availability = new OciCiRunnerAvailability();
            var capacity = new TestCapacity(new(
                "ocid1.instance.oc1.sa-saopaulo-1.runner",
                "etag-runner",
                slot.Demand.Runner,
                slot.Demand.Sequence,
                OciCiRunnerNodeState.Running,
                ActiveJob: false,
                now,
                Preemptible: true,
                PreserveBootVolume: false,
                OciCiRunnerCapacityEngine.Tags(slot.Demand, pool.Template.Generation)));
            var authority = new RegionalAuthoritySnapshot(
                "leader",
                true,
                5,
                9,
                now.AddMinutes(1),
                now,
                null);
            var consumerReconciliations = 0;
            controller = new(
                pipelines,
                pipelineCoordinator,
                jobs,
                new(
                    jobs,
                    dispatch,
                    new(
                        jobs,
                        new(runnerLedger),
                        new RepositoryCiJobResultReconcilerTests.TestEvidenceVerifier()),
                    availability.ReadAsync),
                availability,
                (zone, runner, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    if (zone != "untrusted-product" || runner != slot.Demand.Runner)
                        throw new InvalidDataException("The controller changed the runner consumer identity.");
                    consumerReconciliations++;
                    return Task.CompletedTask;
                },
                static (_, _, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.CompletedTask;
                },
                pool,
                capacity,
                () => authority,
                "gru-controller-1");

            var receipt = await controller.ProcessOnceAsync(trigger.Envelope.DedupeKey);
            var pipeline = await pipelines.ReadAsync(trigger.Envelope.DedupeKey);
            var run = await jobs.ReadAsync(pipeline!);

            await Assert.That(receipt.Disposition).IsEqualTo(RepositoryCiControllerDisposition.Active);
            await Assert.That(run.Jobs.Single().Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
            await Assert.That(transport.Messages).Count().IsEqualTo(1);
            await Assert.That(consumerReconciliations).IsEqualTo(1);
            await Assert.That(capacity.Mutations).IsEmpty();
        }
        finally
        {
            if (controller is not null) await controller.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task NondispatchableTerminalTriggerReportsErrorBeforeItCanBeAcknowledged()
    {
        var root = Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-controller-status-{Guid.NewGuid():N}"));
        RepositoryCiController? controller = null;
        try
        {
            var pool = await PoolAsync(root.FullName);
            var slot = pool.Slots.Single();
            var now = DateTimeOffset.UtcNow;
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var objects = new TestObjectStore();
            var triggers = new ForgejoCiTriggerJournal(ledger);
            var trigger = QualificationTrigger();
            _ = await triggers.RecordAsync(trigger, 5, 9, static () => true);
            var pipelines = new RepositoryCiPipelineJournal(ledger, objects);
            var jobs = new RepositoryCiJobJournal(ledger);
            var availability = new OciCiRunnerAvailability();
            var statuses = new List<string>();
            controller = new(
                pipelines,
                new(
                    triggers,
                    pipelines,
                    static (_, _) => throw new InvalidOperationException("A held trigger read changed paths."),
                    static (_, _, _) => throw new InvalidOperationException("A held trigger resolved sources.")),
                jobs,
                new(
                    jobs,
                    new(
                        jobs,
                        new(objects),
                        new(jobs, new(new TestTransport(), new TestSigner())),
                        static (_, _) => throw new InvalidOperationException("A held trigger read an archive."),
                        static (_, _, _) => throw new InvalidOperationException("A held trigger selected isolation.")),
                    new(
                        jobs,
                        new(new ForgejoWebhookJournalTests.TestLedger()),
                        new RepositoryCiJobResultReconcilerTests.TestEvidenceVerifier()),
                    availability.ReadAsync),
                availability,
                static (_, _, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.CompletedTask;
                },
                (commit, state, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    statuses.Add($"{commit}:{state}");
                    return Task.CompletedTask;
                },
                pool,
                new TestCapacity(new(
                    "ocid1.instance.oc1.sa-saopaulo-1.runner",
                    "etag-runner",
                    slot.Demand.Runner,
                    slot.Demand.Sequence,
                    OciCiRunnerNodeState.Running,
                    ActiveJob: false,
                    now,
                    Preemptible: true,
                    PreserveBootVolume: false,
                    OciCiRunnerCapacityEngine.Tags(slot.Demand, pool.Template.Generation))),
                () => new(
                    "leader",
                    true,
                    5,
                    9,
                    now.AddMinutes(1),
                    now,
                    null),
                "gru-controller-1");

            var handled = await controller.RunToCompletionAsync(trigger, default);

            await Assert.That(handled).IsTrue();
            await Assert.That(statuses).IsEquivalentTo([$"{Commit}:Error"]);
            await Assert.That(await pipelines.ReadAsync(trigger.Envelope.DedupeKey)).IsNull();
        }
        finally
        {
            if (controller is not null) await controller.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task SuccessfulReleaseRequiresDurableCandidateBeforeAcknowledgement()
    {
        var release = RepositoryCiCandidateCoordinatorTests.ReleasePipeline();
        var receipt = new RepositoryCiControllerReceipt(
            RepositoryCiControllerDisposition.Succeeded,
            release);
        var calls = 0;

        var missingVerifier = await RepositoryCiController.CanAcknowledgeAsync(receipt, null);
        var held = await RepositoryCiController.CanAcknowledgeAsync(
            receipt,
            (_, token) =>
            {
                token.ThrowIfCancellationRequested();
                calls++;
                return Task.FromResult(false);
            });
        var recorded = await RepositoryCiController.CanAcknowledgeAsync(
            receipt,
            (_, token) =>
            {
                token.ThrowIfCancellationRequested();
                calls++;
                return Task.FromResult(true);
            });
        var failed = await RepositoryCiController.CanAcknowledgeAsync(
            receipt with { Disposition = RepositoryCiControllerDisposition.Failed },
            (_, _) => throw new InvalidOperationException("A failed pipeline tried to record a candidate."));
        var feature = await RepositoryCiController.CanAcknowledgeAsync(
            receipt with { Pipeline = RepositoryCiPipelineJournalTests.Pipeline() },
            (_, _) => throw new InvalidOperationException("A feature pipeline tried to record a candidate."));

        await Assert.That(missingVerifier).IsFalse();
        await Assert.That(held).IsFalse();
        await Assert.That(recorded).IsTrue();
        await Assert.That(failed).IsTrue();
        await Assert.That(feature).IsTrue();
        await Assert.That(calls).IsEqualTo(2);
    }

    private static async Task<OciCiRunnerPoolConfiguration> PoolAsync(string root)
    {
        await File.WriteAllTextAsync(
            Path.Combine(root, "runner.cloud-init"),
            "#cloud-config\nruncmd:\n  - [oci, secrets, secret-bundle, get, --secret-id, ocid1.vaultsecret.oc1..runner]\n");
        var path = Path.Combine(root, "pool.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
            compartmentId = "ocid1.compartment.oc1..ci",
            availabilityDomain = "sa-saopaulo-1-ad-1",
            faultDomain = "FAULT-DOMAIN-1",
            subnetId = "ocid1.subnet.oc1.sa-saopaulo-1.ci",
            networkSecurityGroupIds = new[] { "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci" },
            imageId = "ocid1.image.oc1.sa-saopaulo-1.runner",
            generation = 7,
            idleSeconds = 60,
            pollSeconds = 1,
            runners = new[]
            {
                new { runner = "ci-untrusted-1", zone = "untrusted-product", sequence = 10, bootstrapFile = "runner.cloud-init" },
            }
        }));
        return OciCiRunnerPoolConfiguration.Load(path)!;
    }

    private static ForgejoCiTriggerPlan Trigger() => ForgejoCiTriggerPlanner.Plan(new(
        Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        Commit,
        "refs/heads/develop",
        null,
        null,
        false,
        new string('a', 64)));

    private static ForgejoCiTriggerPlan QualificationTrigger() => ForgejoCiTriggerPlanner.Plan(new(
        Guid.Parse("c47d2580-70d2-45c2-b3a3-3a416630f21d"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        Commit,
        "refs/heads/main",
        null,
        null,
        false,
        new string('b', 64)));

    private static ForgejoSourceFile Descriptor()
    {
        var content = Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{Repository}}",
              "candidateRetentionDays":7,
              "promotion":"None",
              "repositoryDependencies":[],
              "nodes":[
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/"]}
              ]
            }
            """);
        return new(
            Repository,
            Commit,
            RepositoryCiImpactPlanner.DescriptorPath,
            new string('c', 40),
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    private sealed class TestCapacity(OciCiRunnerNodeObservation observation) : IOciCiRunnerCapacityAdapter
    {
        internal List<OciCiRunnerCapacityAction> Mutations { get; } = [];

        public Task<IReadOnlyList<OciCiRunnerNodeObservation>> ObserveAsync(
            OciCiRunnerLaunchTemplate template,
            CancellationToken cancellationToken)
        {
            _ = template;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<OciCiRunnerNodeObservation>>([observation]);
        }

        public Task<OciCiRunnerMutationReceipt> ExecuteAsync(
            OciCiRunnerCapacityAction action,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Mutations.Add(action);
            return Task.FromResult(new OciCiRunnerMutationReceipt(
                observation.InstanceId,
                observation.ETag,
                "request",
                "work-request"));
        }

        public void Dispose() { }
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values[name].ToArray());
        }
    }

    private sealed class TestTransport : IRepositoryCiJobTransport
    {
        internal List<RepositoryCiJobWireMessage> Messages { get; } = [];

        public Task<RepositoryCiJobTransportAck> PublishAsync(
            string subject,
            string messageId,
            RepositoryCiJobWireMessage message,
            CancellationToken cancellationToken)
        {
            _ = subject;
            _ = messageId;
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(message);
            return Task.FromResult(new RepositoryCiJobTransportAck(
                GlobalNatsTopology.CiStream,
                41,
                Duplicate: false));
        }
    }

    private sealed class TestSigner : IRepositoryCiJobSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            _ = material;
            OpaqueSignature.TryCopyFrom([1, 2, 3], out var signature);
            return signature!;
        }
    }
}
