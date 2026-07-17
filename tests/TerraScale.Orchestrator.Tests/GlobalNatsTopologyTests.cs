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
        var specification = topology.Streams.Single();

        await Assert.That(specification.Name).IsEqualTo("GLOBAL_SPEC");
        await Assert.That(specification.Subjects).IsEquivalentTo(["ts.orch.v1.global.desired.>"]);
        await Assert.That(specification.NumReplicas).IsEqualTo(3);
        await Assert.That(specification.Storage).IsEqualTo(StreamConfigStorage.File);
        await Assert.That(topology.Leaders.Bucket).IsEqualTo("ORCH_LEADERS");
        await Assert.That(topology.Leaders.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Releases.Bucket).IsEqualTo("GLOBAL_RELEASES");
        await Assert.That(topology.Releases.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Releases.History).IsEqualTo(64);
        await Assert.That(topology.Releases.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(() => new GlobalNatsTopology(1)).Throws<ArgumentOutOfRangeException>();
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

            var options = OrchestratorOptions.Parse(
                ["check"],
                name => values.GetValueOrDefault(name));

            await Assert.That(options.GlobalNats).IsNotNull();
            await Assert.That(options.GlobalNats!.Url).IsEqualTo("tls://global-control.internal:4222/");
            await Assert.That(options.GlobalNats.NKeyFile).IsEqualTo(globalNkey);

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
