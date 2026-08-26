using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Composition seam for the advertised cell endpoints: the
/// <c>TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS</c> family member that a real Run
/// composition uses to give its publisher valid control endpoints, and the
/// fail-fast behavior when publishing is enabled without any.
/// </summary>
public sealed class GlobalDirectoryEndpointsConfigurationTests
{
    [Test]
    public async Task EndpointListParsesBothSeparatorsAndSorts()
    {
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints(null)).IsNull();
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints("")).IsNull();
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints("   ")).IsNull();

        var single = GlobalDirectoryNatsConfiguration.ParseEndpoints("tls://control-sfo.internal:4222");
        await Assert.That(single).IsEquivalentTo(["tls://control-sfo.internal:4222"]);

        var mixed = GlobalDirectoryNatsConfiguration.ParseEndpoints(
            "tls://b.internal:4223; tls://a.internal:4222,https://c.internal:8443");
        await Assert.That(mixed).IsEquivalentTo(
            ["https://c.internal:8443", "tls://a.internal:4222", "tls://b.internal:4223"]);
    }

    [Test]
    public async Task InvalidEndpointListsFailClosed()
    {
        foreach (var invalid in new[]
                 {
                     "control-gru.internal",
                     "tls://control-gru.internal",
                     "tls://control-gru.internal:99999",
                     "tls://control-gru.internal:4222/path",
                     "tls://control-gru.internal:4222?query=1",
                     "https://user:secret@control-gru.internal:4222",
                     ";,",
                     string.Join(",", Enumerable.Range(0, 9).Select(index => $"tls://c{index}.internal:4222")),
                 })
        {
            await Assert.That(() => GlobalDirectoryNatsConfiguration.ParseEndpoints(invalid))
                .Throws<ArgumentException>()
                .Because(invalid);
        }
    }

    [Test]
    public async Task OptionsWireTheEndpointsIntoTheDirectoryConfiguration()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-directory-endpoints-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateRegional();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var gru = security.Cell("gru");
            var controller = topology.Cells.Single(candidate => candidate.Cell == "gru")
                .OfKind(DevelopmentResourceKind.ControllerAgent).Single();
            var regionalNkey = gru.Controllers[controller.Replica].SeedFile;
            var regionalTls = gru.Tls.Control.Clients[controller.Name];

            Dictionary<string, string> Values(string? endpoints) =>
                new(StringComparer.Ordinal)
                {
                    ["TS_ORCH_CELL"] = "gru",
                    ["TS_ORCH_REPLICAS"] = "3",
                    ["TS_ORCH_NATS_URL"] = "tls://regional-control.internal:4222",
                    ["TS_ORCH_NATS_NKEY_FILE"] = regionalNkey,
                    ["TS_ORCH_NATS_TLS_CA_FILE"] = regionalTls.CaFile,
                    ["TS_ORCH_NATS_TLS_CERT_FILE"] = regionalTls.CertificateFile,
                    ["TS_ORCH_NATS_TLS_KEY_FILE"] = regionalTls.KeyFile,
                    ["TS_ORCH_GLOBAL_DIRECTORY_NATS_URL"] = "tls://global-directory.internal:4222",
                    ["TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE"] = gru.Operator.SeedFile,
                    ["TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE"] = gru.Tls.Control.Clients["operator-read"].CaFile,
                    ["TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE"] = gru.Tls.Control.Clients["operator-read"].CertificateFile,
                    ["TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE"] = gru.Tls.Control.Clients["operator-read"].KeyFile,
                    ["TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS"] = endpoints ?? "",
                };

            // Without endpoints the composition is watch-only legal: empty list.
            var watchOnly = OrchestratorOptions.Parse(
                ["check"],
                name => Values(null).GetValueOrDefault(name));
            await Assert.That(watchOnly.GlobalDirectoryNats).IsNotNull();
            await Assert.That(watchOnly.GlobalDirectoryNats!.Endpoints).IsEmpty();

            // With endpoints they are parsed, validated, and carried in order.
            var publishing = OrchestratorOptions.Parse(
                ["check"],
                name => Values("tls://b.gru.internal:4223,tls://a.gru.internal:4222").GetValueOrDefault(name));
            await Assert.That(publishing.GlobalDirectoryNats).IsNotNull();
            await Assert.That(publishing.GlobalDirectoryNats!.Endpoints)
                .IsEquivalentTo(["tls://a.gru.internal:4222", "tls://b.gru.internal:4223"]);

            // An invalid value fails closed at parse time, before any runtime starts.
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => Values("tls://gru.internal").GetValueOrDefault(name)))
                .Throws<ArgumentException>();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task PublishingWithoutConfiguredEndpointsFailsFast()
    {
        var authority = new RegionalAuthoritySnapshot(
            "leader", true, 1, 1,
            DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow, null);
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var health = new RegionalRuntimeMembershipHealth(
            1, 1, 0, 0, 0, 0, 0, 1, true, 0,
            RegionalRuntimeMembershipCondition.Healthy, observedAt);
        var member = MembershipRecord("sfo", identity, observedAt);
        var membership = new RegionalRuntimeMembershipSnapshot(2, "sfo", observedAt, health, [member]);

        // A watch-only composition may legitimately carry no endpoints.
        var watchOnly = new GlobalDirectoryNatsConfiguration(
            "tls://global-directory.internal:4222",
            NatsAuthenticationFiles.FromNKeyFile("unused-seed"),
            new NatsTlsFiles("ca.pem", "cert.pem", "key.pem"),
            3,
            "sfo");
        await Assert.That(watchOnly.Endpoints).IsEmpty();

        // The composition entry point (the supervised lifecycle's start function)
        // refuses a publishing runtime without endpoints BEFORE any connection is
        // created. Note: through the supervised lifecycle this surfaces as a
        // logged-and-retried failure (the process stays regionally healthy but
        // never advertises) - config-class failures are not yet terminal there;
        // the follow-up to reject Run-without-endpoints at options parse is
        // recorded on the ticket.
        try
        {
            await GlobalCellDirectoryRuntime.StartAsync(
                watchOnly,
                () => membership,
                () => authority,
                publishEnabled: true);
            throw new InvalidOperationException("The publishing start without endpoints unexpectedly succeeded.");
        }
        catch (ArgumentException failure)
        {
            await Assert.That(failure.Message)
                .Contains("Publishing a cell advertisement requires the cell's advertised control endpoints");
        }
    }

    private static RegionalRuntimeMember MembershipRecord(
        string cell,
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt)
    {
        var member = new RegionalRuntimeMember(
            1,
            cell,
            $"orchestrator-control-{cell}",
            "controller-1",
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            7,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }
}
