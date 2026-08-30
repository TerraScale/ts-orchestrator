using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsTopologyTests
{
    // TODO(rehome-agent): GlobalAndRegionalAccountsRequireDistinctCompleteIdentities and
    // AuthorityAndDirectoryRolesRequireDistinctIdentitiesEndToEnd were removed with the
    // production Development/ lab fixtures; rehome them onto a test-owned NATS identity
    // fixture so the distinct-identity parsing rules keep their positive paths covered.

    [Test]
    public async Task GlobalStateHasAnExplicitR3AccountTopology()
    {
        var topology = new GlobalNatsTopology(3);
        var specification = topology.Streams.Single(stream => stream.Name == "GLOBAL_SPEC");
        var ci = topology.Streams.Single(stream => stream.Name == GlobalNatsTopology.CiStream);
        var runner = topology.CiJobConsumer("untrusted-product", "runner-static");
        var runtimeProof = topology.CiRuntimeProofConsumer;

        await Assert.That(specification.Name).IsEqualTo("GLOBAL_SPEC");
        await Assert.That(specification.Subjects).IsEquivalentTo(["ts.orch.v1.global.desired.>"]);
        await Assert.That(specification.NumReplicas).IsEqualTo(3);
        await Assert.That(specification.Storage).IsEqualTo(StreamConfigStorage.File);
        await Assert.That(ci.Subjects).IsEquivalentTo(["ts.orch.v1.global.ci.>"]);
        await Assert.That(GlobalNatsTopology.CiJobSubjectPrefix)
            .IsEqualTo("ts.orch.v1.global.ci.job");
        await Assert.That(ci.NumReplicas).IsEqualTo(3);
        await Assert.That(ci.DuplicateWindow).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(topology.CiConsumer.FilterSubject).IsEqualTo(GlobalNatsTopology.CiSubject);
        await Assert.That(topology.CiConsumer.MaxDeliver).IsEqualTo(5);
        await Assert.That(topology.CiConsumer.MaxAckPending).IsEqualTo(32);
        await Assert.That(runtimeProof.Name).IsEqualTo("global_ci_runtime_proof");
        await Assert.That(runtimeProof.DurableName).IsEqualTo(runtimeProof.Name);
        await Assert.That(runtimeProof.FilterSubject).IsEqualTo(GlobalNatsTopology.CiRuntimeProofSubject);
        await Assert.That(runtimeProof.DeliverPolicy).IsEqualTo(ConsumerConfigDeliverPolicy.All);
        await Assert.That(runtimeProof.AckPolicy).IsEqualTo(ConsumerConfigAckPolicy.Explicit);
        await Assert.That(runtimeProof.ReplayPolicy).IsEqualTo(ConsumerConfigReplayPolicy.Instant);
        await Assert.That(runtimeProof.MaxDeliver).IsEqualTo(5);
        await Assert.That(runtimeProof.MaxAckPending).IsEqualTo(32);
        await Assert.That(runtimeProof.MaxBatch).IsEqualTo(1);
        await Assert.That(runtimeProof.NumReplicas).IsEqualTo(3);
        await Assert.That(topology.Leaders.Bucket).IsEqualTo("ORCH_LEADERS");
        await Assert.That(topology.Leaders.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Cells.Bucket).IsEqualTo("GLOBAL_CELLS");
        await Assert.That(topology.Cells.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Cells.History).IsEqualTo(16);
        await Assert.That(topology.Cells.MaxAge).IsEqualTo(TimeSpan.FromDays(30));
        await Assert.That(topology.Cells.MaxValueSize).IsEqualTo(64 * 1024);
        await Assert.That(GlobalNatsTopology.CellAdvertisementKey("gru")).IsEqualTo("cell.gru");
        await Assert.That(GlobalNatsTopology.CellDirectorySubject)
            .IsEqualTo("ts.orch.v1.global.query.cells");
        await Assert.That(topology.Releases.Bucket).IsEqualTo("GLOBAL_RELEASES");
        await Assert.That(topology.Releases.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Releases.History).IsEqualTo(64);
        await Assert.That(topology.Releases.MaxAge).IsEqualTo(TimeSpan.FromDays(365));
        await Assert.That(topology.Releases.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(topology.RunnerJobs.Bucket).IsEqualTo("CI_RUNNER_JOBS");
        await Assert.That(topology.RunnerJobs.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.RunnerJobs.History).IsEqualTo(8);
        await Assert.That(topology.RunnerJobs.MaxAge).IsEqualTo(TimeSpan.FromDays(30));
        await Assert.That(topology.RunnerJobs.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(topology.RunnerBundles.Bucket).IsEqualTo("CI_RUNNER_BUNDLES");
        await Assert.That(topology.RunnerBundles.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.RunnerBundles.MaxAge).IsEqualTo(TimeSpan.FromDays(30));
        await Assert.That(topology.RunnerBundles.MaxBytes).IsEqualTo(64L * 1024 * 1024 * 1024);
        await Assert.That(runner.Name).StartsWith("ci_runner_untrusted_product_");
        await Assert.That(runner.DurableName).IsEqualTo(runner.Name);
        await Assert.That(runner.FilterSubject)
            .IsEqualTo(GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-static"));
        await Assert.That(runner.DeliverPolicy).IsEqualTo(ConsumerConfigDeliverPolicy.All);
        await Assert.That(runner.AckPolicy).IsEqualTo(ConsumerConfigAckPolicy.Explicit);
        await Assert.That(runner.ReplayPolicy).IsEqualTo(ConsumerConfigReplayPolicy.Instant);
        await Assert.That(runner.AckWait).IsEqualTo(TimeSpan.FromSeconds(1));
        await Assert.That(runner.MaxDeliver).IsEqualTo(5);
        await Assert.That(runner.MaxAckPending).IsEqualTo(1);
        await Assert.That(runner.MaxWaiting).IsEqualTo(4);
        await Assert.That(runner.MaxBatch).IsEqualTo(1);
        await Assert.That(runner.MaxExpires).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(runner.InactiveThreshold).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(runner.NumReplicas).IsEqualTo(3);
        await Assert.That(() => new GlobalNatsTopology(1)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => topology.CiJobConsumer("production-release", "runner-static"))
            .Throws<ArgumentException>();
        await Assert.That(() => topology.CiJobConsumer("trusted-build", "bad runner"))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task PartialOrNonR3GlobalConfigurationFailsBeforeConnecting()
    {
        await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_GLOBAL_NATS_URL" ? "tls://global.internal:4222" : null))
            .Throws<ArgumentException>();

        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["TS_ORCH_REPLICAS"] = "1",
            ["TS_ORCH_GLOBAL_NATS_URL"] = "tls://global.internal:4222",
            ["TS_ORCH_GLOBAL_NATS_NKEY_FILE"] = "nkey",
            ["TS_ORCH_GLOBAL_NATS_TLS_CA_FILE"] = "ca",
            ["TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE"] = "certificate",
            ["TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE"] = "key",
        };
        await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => values.GetValueOrDefault(name)))
            .Throws<ArgumentException>();
    }
}
