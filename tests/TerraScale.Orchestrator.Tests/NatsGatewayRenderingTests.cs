using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Deterministic rendering, fail-closed admission before rendering, and the
/// evidence rules for generated gateway configuration: stable output, no
/// secret material, and redaction of anything unsuitable for evidence.
/// </summary>
public sealed class NatsGatewayRenderingTests
{
    // NKey-shaped public keys: a type-letter prefix (accounts are 'A') followed
    // by base32 characters only — exactly what the render context accepts.
    private const string SystemKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP";
    private const string DirectoryKey = "ACDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
    private const string SfoKey = "ADEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQR";

    private static NatsGatewayRenderContext Context() => new(
        "/etc/terrascale/pki/nats/control/operator.jwt",
        [
            new NatsGatewayRenderAccount(
                "system",
                SystemKey,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc"),
            new NatsGatewayRenderAccount(
                "ts-orch-global-directory",
                DirectoryKey,
                "dddddddddddddddddddddddddddd.eeeeeeeeeeeeeeeeeeeeeeeeeeee.ffffffffffffffffffffffffffff"),
            new NatsGatewayRenderAccount(
                "ts-orch-regional-control-sfo",
                SfoKey,
                "gggggggggggggggggggggggggggg.hhhhhhhhhhhhhhhhhhhhhhhhhhhh.iiiiiiiiiiiiiiiiiiiiiiiiiiii"),
        ]);

    [Test]
    public async Task RenderingIsDeterministicForTheSameTypedPlan()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster(configurationGeneration: 7);
        var rendered = NatsGatewayConfigurationRenderer.Render(plan, "gru", "gru-control-nats-2", Context());
        var renderedAgain = NatsGatewayConfigurationRenderer.Render(
            NatsGatewayPlaneTopology.CreateControlSupercluster(configurationGeneration: 7),
            "gru",
            "gru-control-nats-2",
            Context());

        await Assert.That(renderedAgain).IsEqualTo(rendered);
        await Assert.That(NatsGatewayConfigurationRenderer.Digest(renderedAgain))
            .IsEqualTo(NatsGatewayConfigurationRenderer.Digest(rendered));
        await Assert.That(NatsGatewayConfigurationRenderer.Digest(rendered)).Length().IsEqualTo(64);
    }

    [Test]
    public async Task RenderedConfigurationCarriesTheExactTypedShape()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var rendered = NatsGatewayConfigurationRenderer.Render(plan, "gru", "gru-control-nats-2", Context());

        await Assert.That(rendered).Contains("server_name: \"gru-control-nats-2\"");
        await Assert.That(rendered).Contains("port: 4222");
        await Assert.That(rendered).Contains("operator: \"/etc/terrascale/pki/nats/control/operator.jwt\"");
        await Assert.That(rendered).Contains("domain: \"ORCH_GRU\"");
        await Assert.That(rendered).Contains("store_dir: \"/var/lib/terrascale/nats/control/gru/gru-control-nats-2\"");
        await Assert.That(rendered).Contains("name: \"orchestrator-control-gru\"");
        await Assert.That(rendered).Contains("verify: true");

        // Client, route, and gateway transports use their own certificate files.
        await Assert.That(rendered).Contains("cert_file: \"/etc/terrascale/pki/nats/control/gru-control-nats-2-client.pem\"");
        await Assert.That(rendered).Contains("cert_file: \"/etc/terrascale/pki/nats/control/gru-control-nats-2-route.pem\"");
        await Assert.That(rendered).Contains("cert_file: \"/etc/terrascale/pki/nats/control/gru-control-nats-2-gateway.pem\"");

        // Routes point at the two siblings, sorted; never at this server.
        await Assert.That(rendered)
            .Contains("\"nats-route://seed-1.gru.internal.terrascale.tech:6222\", \"nats-route://seed-3.gru.internal.terrascale.tech:6222\"");
        await Assert.That(rendered.Contains(
                "nats-gateway://seed-2.gru.internal.terrascale.tech",
                StringComparison.Ordinal))
            .IsFalse();

        // The gateway block names the two remote clusters in ordinal order with
        // each remote server's gateway URL.
        await Assert.That(rendered).Contains("gateway {");
        await Assert.That(rendered.IndexOf("name: \"orchestrator-control-fra\"", StringComparison.Ordinal))
            .IsLessThan(rendered.IndexOf("name: \"orchestrator-control-sfo\"", StringComparison.Ordinal));
        await Assert.That(rendered).Contains("\"nats-gateway://seed-1.sfo.internal.terrascale.tech:7222\"");
        await Assert.That(rendered.Contains(
                "nats-gateway://seed-2.gru.internal.terrascale.tech",
                StringComparison.Ordinal))
            .IsFalse();

        // The resolver preload is sorted by account name, so its output is stable.
        var preloadStart = rendered.IndexOf("resolver_preload: {", StringComparison.Ordinal);
        var preloadEnd = rendered.IndexOf('}', preloadStart);
        var preload = rendered[preloadStart..preloadEnd];
        var firstKey = preload.IndexOf("ABCDEF", StringComparison.Ordinal);
        var secondKey = preload.IndexOf("ACDEFG", StringComparison.Ordinal);
        var thirdKey = preload.IndexOf("ADEFGH", StringComparison.Ordinal);
        await Assert.That(firstKey < secondKey && secondKey < thirdKey).IsTrue();
    }

    [Test]
    public async Task SingleServerClusterRendersItsOwnRouteAsTheSelfRoute()
    {
        // The RF1 shape: one server per regional cluster. The rendered cluster
        // block must solicit exactly that server's own route endpoint — the
        // upstream single-node shape the pinned server requires before
        // clustered JetStream (which a gateway listener always implies) may
        // start — and no sibling route.
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var filteredClusters = plan.Clusters
            .Select(cluster => (
                Source: cluster,
                Servers: cluster.Servers
                    .Where(server => cluster.Cell != "sfo" || server.ServerName == "sfo-control-nats-1")
                    .ToArray()))
            .ToArray();
        var singleServer = new NatsGatewayPlan(
            plan.Plane,
            plan.OperatorName,
            plan.TrustGeneration,
            plan.ConfigurationGeneration,
            [.. filteredClusters.Select(entry => new NatsGatewayCluster(
                entry.Source.Plane,
                entry.Source.Cell,
                entry.Source.ClusterName,
                entry.Source.JetStreamDomain,
                entry.Source.OperatorName,
                [.. entry.Servers.Select(server => RebindControlPeerIdentities(
                    server,
                    entry.Source,
                    entry.Servers,
                    filteredClusters))],
                entry.Source.Accounts,
                entry.Source.JetStreamAssets,
                entry.Source.CgroupSlice,
                entry.Source.TrustGeneration,
                entry.Source.ConfigurationGeneration))],
            plan.GatewayRelationships,
            plan.Accounts,
            plan.Exports,
            plan.Imports);
        var rendered = NatsGatewayConfigurationRenderer.Render(singleServer, "sfo", "sfo-control-nats-1", Context());

        await Assert.That(rendered).Contains("cluster {");
        await Assert.That(rendered).Contains("name: \"orchestrator-control-sfo\"");
        await Assert.That(rendered).Contains("host: \"seed-1.sfo.internal.terrascale.tech\"");
        await Assert.That(rendered).Contains("port: 6222");
        await Assert.That(rendered)
            .Contains("routes: [\"nats-route://seed-1.sfo.internal.terrascale.tech:6222\"]");
        await Assert.That(rendered.Contains(
                "nats-route://seed-2.sfo.internal.terrascale.tech",
                StringComparison.Ordinal))
            .IsFalse();
        await Assert.That(rendered.Contains(
                "nats-route://seed-3.sfo.internal.terrascale.tech",
                StringComparison.Ordinal))
            .IsFalse();
        // The multi-server shape is unchanged: a peer's rendering still
        // solicits siblings and never itself.
        var multiServer = NatsGatewayConfigurationRenderer.Render(plan, "sfo", "sfo-control-nats-2", Context());
        await Assert.That(multiServer).Contains(
            "\"nats-route://seed-1.sfo.internal.terrascale.tech:6222\", \"nats-route://seed-3.sfo.internal.terrascale.tech:6222\"");
        await Assert.That(multiServer.Contains(
                "nats-route://seed-2.sfo.internal.terrascale.tech",
                StringComparison.Ordinal))
            .IsFalse();
    }

    private static NatsGatewayServerIdentity RebindControlPeerIdentities(
        NatsGatewayServerIdentity server,
        NatsGatewayCluster sourceCluster,
        IReadOnlyList<NatsGatewayServerIdentity> clusterServers,
        IReadOnlyList<(NatsGatewayCluster Source, NatsGatewayServerIdentity[] Servers)> clusters)
    {
        var routePeers = clusterServers
            .Where(peer => peer.ServerName != server.ServerName)
            .Select(peer => NatsGatewayPlaneTopology.ControlServerSpiffeId(peer.ServerName))
            .DefaultIfEmpty(NatsGatewayPlaneTopology.ControlServerSpiffeId(server.ServerName));
        var gatewayPeers = clusters
            .Where(entry => entry.Source.Cell != sourceCluster.Cell)
            .SelectMany(static entry => entry.Servers)
            .Select(peer => NatsGatewayPlaneTopology.ControlServerSpiffeId(peer.ServerName));
        var profiles = new[]
        {
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Client,
                server.Profile(NatsGatewayTransport.Client).CertificateFile,
                server.Profile(NatsGatewayTransport.Client).KeyFile,
                server.Profile(NatsGatewayTransport.Client).CaFile,
                [NatsGatewayPlaneTopology.ControlClientSpiffePrefix]),
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Route,
                server.Profile(NatsGatewayTransport.Route).CertificateFile,
                server.Profile(NatsGatewayTransport.Route).KeyFile,
                server.Profile(NatsGatewayTransport.Route).CaFile,
                routePeers),
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Gateway,
                server.Profile(NatsGatewayTransport.Gateway).CertificateFile,
                server.Profile(NatsGatewayTransport.Gateway).KeyFile,
                server.Profile(NatsGatewayTransport.Gateway).CaFile,
                gatewayPeers),
        };
        return new NatsGatewayServerIdentity(
            server.ServerName,
            server.FailureDomain,
            server.Client,
            server.Route,
            server.Gateway,
            profiles,
            server.Process,
            server.StoreDirectory);
    }

    [Test]
    public async Task RenderContextRejectsHostileStringsBeforeAnyRendering()
    {
        // The public key is emitted unquoted as a resolver_preload map key, so
        // anything outside the bounded NKey public-key shape fails at the typed
        // boundary: wrong alphabet digits, lowercase, quotes, and newlines.
        foreach (var hostileKey in new[]
                 {
                     "SYSKEY0000000000000000000000000000000000", // digits outside base32
                     SystemKey.ToLowerInvariant(),              // lowercase
                     SystemKey + "\"",                          // quote injection
                     SystemKey + "\nx: ",                       // newline injection
                     "S" + SystemKey[1..],                      // seed-prefixed (S is not a public-key prefix)
                     "SHORTKEY",
                 })
        {
            await Assert.That(() => new NatsGatewayRenderAccount(
                    "system", hostileKey, "aaaa.bbbb.cccc"))
                .Throws<ArgumentException>();
        }

        // The JWT must be exactly three non-empty base64url segments.
        foreach (var hostileJwt in new[]
                 {
                     "two.segments",
                     ".bbb.ccc",
                     "aaa..ccc",
                     "aaa.b\"bb.ccc",
                     "aaa.b\nbb.ccc",
                 })
        {
            await Assert.That(() => new NatsGatewayRenderAccount(
                    "system", SystemKey, hostileJwt))
                .Throws<ArgumentException>();
        }

        // The operator JWT file must be an absolute .jwt path without quotes,
        // control characters, or traversal.
        foreach (var hostileOperatorFile in new[]
                 {
                     "operator.jwt",
                     "/etc/terrascale/operator.conf",
                     "/etc/terrascale/operator\".jwt",
                     "/etc/../terrascale/operator.jwt",
                 })
        {
            await Assert.That(() => new NatsGatewayRenderContext(
                    hostileOperatorFile,
                [
                    new NatsGatewayRenderAccount("system", SystemKey, "aaaa.bbbb.cccc"),
                ]))
                .Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task RenderingFailsClosedBeforeAnyTextIsProduced()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var incompleteMesh = new NatsGatewayPlan(
            plan.Plane,
            plan.OperatorName,
            plan.TrustGeneration,
            plan.ConfigurationGeneration,
            plan.Clusters,
            [.. plan.GatewayRelationships.Skip(1)],
            plan.Accounts,
            plan.Exports,
            plan.Imports);
        await Assert.That(() => NatsGatewayConfigurationRenderer.Render(
                incompleteMesh, "gru", "gru-control-nats-1", Context()))
            .Throws<InvalidOperationException>();

        await Assert.That(() => NatsGatewayConfigurationRenderer.Render(
                plan, "gru", "gru-control-nats-1",
                new NatsGatewayRenderContext("/etc/operator.jwt",
                [
                    new NatsGatewayRenderAccount("system", SystemKey, "only-two-segments"),
                ])))
            .Throws<ArgumentException>();

        await Assert.That(() => new NatsGatewayRenderContext("/etc/operator.jwt",
            [
                new NatsGatewayRenderAccount("system", SystemKey, "aaaa.bbbb.cccc"),
                new NatsGatewayRenderAccount("system", DirectoryKey, "dddd.eeee.ffff"),
            ]))
            .Throws<ArgumentException>();

        await Assert.That(() => NatsGatewayConfigurationRenderer.Render(
                plan, "gru", "sfo-control-nats-1", Context()))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ProductionRenderingRejectsLoopbackPlansByDefault()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var loopbackCluster = plan.Cluster("sfo")!;
        var loopbackServers = loopbackCluster.Servers.Select((server, index) => new NatsGatewayServerIdentity(
            server.ServerName,
            server.FailureDomain,
            new NatsGatewayEndpoint("127.0.0.1", 14000 + index),
            new NatsGatewayEndpoint("127.0.0.1", 15000 + index),
            new NatsGatewayEndpoint("127.0.0.1", 16000 + index),
            server.CertificateProfiles,
            server.Process,
            $"/tmp/conformance-store/{server.ServerName}")).ToArray();
        var loopback = new NatsGatewayPlan(
            plan.Plane,
            plan.OperatorName,
            plan.TrustGeneration,
            plan.ConfigurationGeneration,
            [.. plan.Clusters.Select(cluster => cluster.Cell == "sfo"
                ? new NatsGatewayCluster(
                    cluster.Plane, cluster.Cell, cluster.ClusterName, cluster.JetStreamDomain,
                    cluster.OperatorName, loopbackServers, cluster.Accounts, cluster.JetStreamAssets,
                    cluster.CgroupSlice, cluster.TrustGeneration,
                    cluster.ConfigurationGeneration)
                : cluster)],
            plan.GatewayRelationships,
            plan.Accounts,
            plan.Exports,
            plan.Imports);

        await Assert.That(() => NatsGatewayConfigurationRenderer.Render(
                loopback, "sfo", "sfo-control-nats-1", Context()))
            .Throws<InvalidOperationException>();
        var rendered = NatsGatewayConfigurationRenderer.Render(
            loopback,
            "sfo",
            "sfo-control-nats-1",
            Context(),
            NatsGatewayValidationOptions.LocalConformance);
        await Assert.That(rendered).Contains("host: \"127.0.0.1\"");
    }

    [Test]
    public async Task RenderedConfigurationCarriesNoSecretMaterial()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var rendered = NatsGatewayConfigurationRenderer.Render(plan, "fra", "fra-control-nats-1", Context());
        await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(rendered))).IsEmpty();

        await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(
                "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----")))
            .Contains("private-key-pem-block");
        // The scan covers every NKey seed type prefix, not only SU/SA: server
        // (SN) and cluster (SC) seeds are flagged too, while public keys (no
        // S prefix) are not.
        foreach (var seed in new[]
                 {
                     "seed SUAAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
                     "seed SNAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
                     "seed SCAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
                     "seed SOAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
                     "seed SAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
                 })
        {
            await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(seed))
                .Contains("nkey-seed")).IsTrue();
        }
        await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(
                $"public key {SystemKey}"))
            .Contains("nkey-seed")).IsFalse();
        await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(
                "password: hunter2"))
            .Contains("password-assignment")).IsTrue();
    }

    [Test]
    public async Task EvidenceCopiesAreRedacted()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var rendered = NatsGatewayConfigurationRenderer.Render(plan, "gru", "gru-control-nats-1", Context());

        var redacted = NatsGatewayConfigurationRenderer.RedactForEvidence(rendered);
        await Assert.That(redacted).Contains("<redacted-jwt>");
        await Assert.That(redacted).DoesNotContain("aaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc");
        // Public keys are public: they survive redaction.
        await Assert.That(redacted.Contains(SystemKey, StringComparison.Ordinal)).IsTrue();
        await Assert.That(redacted).DoesNotContain("-----BEGIN");

        var hostile = string.Join('\n',
            "-----BEGIN RSA PRIVATE KEY-----",
            "secret",
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAA",
            "-----END OPENSSH PRIVATE KEY-----",
            "seed: SUAAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQF",
            "seed: SNAAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQ",
            "seed: SCAAJSUVB3FJDSEVKZ7ZZWRHQDSM3OJ4T7NNI5W3XUJQ",
            "password: hunter2",
            "jwt: eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJ4In0.c2lnbmF0dXJl");
        var sanitized = NatsGatewayConfigurationRenderer.RedactForEvidence(hostile);
        await Assert.That(sanitized).Contains("[redacted-private-key]");
        await Assert.That(sanitized.Contains("OPENSSH", StringComparison.Ordinal)).IsFalse();
        await Assert.That(sanitized).Contains("[redacted-nkey-seed]");
        await Assert.That(sanitized).Contains("password: [redacted-password]");
        await Assert.That(sanitized).Contains("<redacted-jwt>");
        await Assert.That(sanitized.Contains("hunter2", StringComparison.Ordinal)).IsFalse();
        await Assert.That(sanitized.Contains("secret", StringComparison.Ordinal)).IsFalse();

        // The scan also recognizes the OPENSSH private-key variant.
        await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----")))
            .Contains("private-key-pem-block");
    }

    [Test]
    public async Task EvidenceIdentityBindsGenerationPlanAndDigest()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster(trustGeneration: 3, configurationGeneration: 9);
        var rendered = NatsGatewayConfigurationRenderer.Render(plan, "sfo", "sfo-control-nats-3", Context());
        var identity = NatsGatewayConfigurationRenderer.RenderEvidenceIdentity(plan, "sfo", "sfo-control-nats-3", rendered);

        await Assert.That(identity).Contains("orchestrator-control-sfo/sfo-control-nats-3");
        await Assert.That(identity).Contains("trust=3");
        await Assert.That(identity).Contains("config=9");
        await Assert.That(identity).Contains($"digest={NatsGatewayConfigurationRenderer.Digest(rendered)}");
        await Assert.That(identity.Contains("resolver_preload", StringComparison.Ordinal)).IsFalse();
    }
}
