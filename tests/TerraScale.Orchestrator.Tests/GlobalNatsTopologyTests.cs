using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsTopologyTests
{
    [Test]
    public async Task GlobalStateHasAnExplicitR3AccountTopology()
    {
        var topology = new GlobalNatsTopology(3);
        var specification = topology.Streams.Single(stream => stream.Name == "GLOBAL_SPEC");
        var ci = topology.Streams.Single(stream => stream.Name == GlobalNatsTopology.CiStream);
        var runner = topology.CiJobConsumer("untrusted-product", "runner-static");

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
        await Assert.That(topology.Leaders.Bucket).IsEqualTo("ORCH_LEADERS");
        await Assert.That(topology.Leaders.NumberOfReplicas).IsEqualTo(3);
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
        await Assert.That(topology.RunnerBundles.MaxBytes).IsEqualTo(512L * 1024 * 1024);
        await Assert.That(runner.Name).StartsWith("ci_runner_untrusted_product_");
        await Assert.That(runner.DurableName).IsEqualTo(runner.Name);
        await Assert.That(runner.FilterSubject)
            .IsEqualTo(GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-static"));
        await Assert.That(runner.DeliverPolicy).IsEqualTo(ConsumerConfigDeliverPolicy.All);
        await Assert.That(runner.AckPolicy).IsEqualTo(ConsumerConfigAckPolicy.Explicit);
        await Assert.That(runner.ReplayPolicy).IsEqualTo(ConsumerConfigReplayPolicy.Instant);
        await Assert.That(runner.AckWait).IsEqualTo(TimeSpan.FromSeconds(30));
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

    [Test]
    public async Task GlobalAndRegionalAccountsRequireDistinctCompleteIdentities()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-global-nats-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
            var gru = security.Cell("gru");
            var controller = cell.OfKind(DevelopmentResourceKind.ControllerAgent).Single();
            var regionalNkey = gru.Controllers[controller.Replica].SeedFile;
            var regionalTls = gru.Tls.Control.Clients[controller.Name];
            var globalNkey = gru.Operator.SeedFile;
            var globalTls = gru.Tls.Control.Clients["operator-read"];
            var values = Values(regionalNkey, regionalTls, globalNkey, globalTls);
            var forgejoSecret = Path.Combine(directory, "forgejo-secret");
            var forgejoToken = Path.Combine(directory, "forgejo-token");
            await File.WriteAllTextAsync(forgejoSecret, "0123456789abcdef0123456789abcdef");
            await File.WriteAllTextAsync(forgejoToken, "0123456789abcdef0123456789abcdef01234567");
            File.SetUnixFileMode(forgejoSecret, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(forgejoToken, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            values["TS_ORCH_FORGEJO_LISTEN_PREFIX"] = "http://127.0.0.1:8080/hooks/forgejo/";
            values["TS_ORCH_FORGEJO_API_URL"] = "https://git.terrascale.tech/";
            values["TS_ORCH_FORGEJO_REPOSITORY"] = "TerraScale/TerraScale.Orchestrator";
            values["TS_ORCH_FORGEJO_SECRET_FILE"] = forgejoSecret;
            values["TS_ORCH_FORGEJO_API_TOKEN_FILE"] = forgejoToken;

            var options = OrchestratorOptions.Parse(
                ["check"],
                name => values.GetValueOrDefault(name));

            await Assert.That(options.GlobalNats).IsNotNull();
            await Assert.That(options.GlobalNats!.Url).IsEqualTo("tls://global-control.internal:4222/");
            await Assert.That(options.GlobalNats.NKeyFile).IsEqualTo(globalNkey);
            await Assert.That(options.ForgejoWebhook).IsNotNull();
            await Assert.That(options.ForgejoSource).IsNotNull();

            var reused = Values(regionalNkey, regionalTls, regionalNkey, regionalTls);
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => reused.GetValueOrDefault(name)))
                .Throws<ArgumentException>();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static Dictionary<string, string> Values(
        string regionalNkey,
        DevelopmentTlsIdentity regionalTls,
        string globalNkey,
        DevelopmentTlsIdentity globalTls) => new(StringComparer.Ordinal)
    {
        ["TS_ORCH_REPLICAS"] = "3",
        ["TS_ORCH_NATS_URL"] = "tls://regional-control.internal:4222",
        ["TS_ORCH_NATS_NKEY_FILE"] = regionalNkey,
        ["TS_ORCH_NATS_TLS_CA_FILE"] = regionalTls.CaFile,
        ["TS_ORCH_NATS_TLS_CERT_FILE"] = regionalTls.CertificateFile,
        ["TS_ORCH_NATS_TLS_KEY_FILE"] = regionalTls.KeyFile,
        ["TS_ORCH_GLOBAL_NATS_URL"] = "tls://global-control.internal:4222",
        ["TS_ORCH_GLOBAL_NATS_NKEY_FILE"] = globalNkey,
        ["TS_ORCH_GLOBAL_NATS_TLS_CA_FILE"] = globalTls.CaFile,
        ["TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE"] = globalTls.CertificateFile,
        ["TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE"] = globalTls.KeyFile,
    };
}
