using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Pure topology tests for the typed NATS gateway plans: production shape,
/// full-mesh generation and rejection, dual-plane isolation, regional
/// JetStream domains, identities, the cross-account service allowlist,
/// rotation sequences, and the fail-closed admission gate.
/// </summary>
public sealed class NatsGatewayTopologyTests
{
    [Test]
    public async Task ProductionControlPlanShapesEveryRegionalCluster()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();

        await Assert.That(plan.Plane).IsEqualTo(NatsGatewayPlane.Control);
        await Assert.That(plan.OperatorName).IsEqualTo(NatsGatewayPlaneTopology.ControlOperatorName);
        await Assert.That(plan.TrustGeneration).IsEqualTo(1);
        await Assert.That(plan.ConfigurationGeneration).IsEqualTo(1);
        await Assert.That(plan.Clusters.Select(static cluster => cluster.Cell))
            .IsEquivalentTo(["fra", "gru", "sfo"]);

        var gru = plan.Cluster("gru")!;
        await Assert.That(gru.ClusterName).IsEqualTo("orchestrator-control-gru");
        await Assert.That(gru.JetStreamDomain).IsEqualTo("ORCH_GRU");
        await Assert.That(gru.Servers).Count().IsEqualTo(3);
        await Assert.That(gru.Servers.Select(static server => server.ServerName))
            .IsEquivalentTo(["gru-control-nats-1", "gru-control-nats-2", "gru-control-nats-3"]);
        var first = gru.Server("gru-control-nats-1");
        await Assert.That(first.Client.Qualified).IsEqualTo("seed-1.gru.internal.terrascale.tech:4222");
        await Assert.That(first.Route.Port).IsEqualTo(6222);
        await Assert.That(first.Gateway!.Port).IsEqualTo(7222);
        await Assert.That(first.FailureDomain).IsEqualTo("seed-1.gru.internal.terrascale.tech");
        await Assert.That(first.Process.UnitName).IsEqualTo("terrascale-control-nats@gru-1.service");
        await Assert.That(first.Process.Cgroup)
            .IsEqualTo("/terrascale.slice/terrascale-nats-control.slice/terrascale-control-nats@gru-1.service");
        await Assert.That(first.StoreDirectory)
            .IsEqualTo("/var/lib/terrascale/nats/control/gru/gru-control-nats-1");

        foreach (var cluster in plan.Clusters)
        {
            await Assert.That(cluster.OperatorName).IsEqualTo(plan.OperatorName);
            await Assert.That(cluster.Accounts)
                .IsEquivalentTo(
                [
                    "system",
                    GlobalNatsAccountNames.GlobalAuthority,
                    GlobalNatsAccountNames.GlobalDirectory,
                    "ts-orch-regional-control-fra",
                    "ts-orch-regional-control-gru",
                    "ts-orch-regional-control-sfo",
                ]);
            foreach (var server in cluster.Servers)
            {
                await Assert.That(server.CertificateProfiles).Count().IsEqualTo(3);
                var certificates = server.CertificateProfiles
                    .Select(static profile => profile.CertificateFile)
                    .Distinct()
                    .ToArray();
                await Assert.That(certificates).Count().IsEqualTo(3);
                var keys = server.CertificateProfiles
                    .Select(static profile => profile.KeyFile)
                    .Distinct()
                    .ToArray();
                await Assert.That(keys).Count().IsEqualTo(3);
                await Assert.That(server.CertificateProfiles.Select(static profile => profile.CaFile).Distinct())
                    .Count().IsEqualTo(1);
            }
        }

        // The GRU gateway profile expects the six remote peers, never its own cell.
        var fraServer = plan.Cluster("fra")!.Server("fra-control-nats-2");
        var gatewayPeers = fraServer.Profile(NatsGatewayTransport.Gateway).ExpectedPeerIdentities;
        await Assert.That(gatewayPeers).Count().IsEqualTo(6);
        await Assert.That(gatewayPeers.Any(identity => identity.Contains("gru-control-nats", StringComparison.Ordinal)))
            .IsTrue();
        await Assert.That(gatewayPeers.Any(identity => identity.Contains("sfo-control-nats", StringComparison.Ordinal)))
            .IsTrue();
        await Assert.That(gatewayPeers.Any(identity => identity.Contains("fra-control-nats", StringComparison.Ordinal)))
            .IsFalse();
        var routePeers = fraServer.Profile(NatsGatewayTransport.Route).ExpectedPeerIdentities;
        await Assert.That(routePeers).Count().IsEqualTo(2);
    }

    [Test]
    public async Task ControlAccountsStaySeparatelyScopedWithVersionedSigningKeys()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster(trustGeneration: 4);

        var scopes = plan.Accounts.ToDictionary(static scope => scope.AccountName, StringComparer.Ordinal);
        await Assert.That(scopes.Keys).IsEquivalentTo(
        [
            "system",
            GlobalNatsAccountNames.GlobalAuthority,
            GlobalNatsAccountNames.GlobalDirectory,
            "ts-orch-regional-control-fra",
            "ts-orch-regional-control-gru",
            "ts-orch-regional-control-sfo",
        ]);
        foreach (var scope in plan.Accounts)
        {
            await Assert.That(scope.SigningKeyNames).Count().IsEqualTo(1);
            await Assert.That(scope.SigningKeyNames[0]).IsEqualTo($"{scope.AccountName}-signing-v4");
            await Assert.That(scope.Users.Count > 0).IsTrue();
            await Assert.That(scope.Limits.MaxConnections > 0).IsTrue();
            await Assert.That(scope.Limits.MaxPayloadBytes > 0).IsTrue();
        }
        var gruScope = scopes["ts-orch-regional-control-gru"];
        var sfoScope = scopes["ts-orch-regional-control-sfo"];
        await Assert.That(gruScope.Users.Contains("cell-directory-reader-gru")).IsFalse();
        await Assert.That(sfoScope.Users.Contains("cell-directory-reader-sfo")).IsTrue();
        await Assert.That(gruScope.Cell).IsEqualTo("gru");
        await Assert.That(sfoScope.Cell).IsEqualTo("sfo");
        var directory = scopes[GlobalNatsAccountNames.GlobalDirectory];
        await Assert.That(directory.Users).IsEquivalentTo(
        [
            "cell-directory-publisher-fra",
            "cell-directory-publisher-sfo",
            "cell-directory-service-gru",
            "global-directory-infrastructure",
        ]);
    }

    [Test]
    public async Task FullMeshGenerationProducesEveryDirectedPairOnce()
    {
        var mesh = NatsGatewayMesh.FullMesh(["gru", "sfo", "fra"]);
        await Assert.That(mesh).Count().IsEqualTo(6);
        await Assert.That(mesh.Select(static relationship => (relationship.FromCell, relationship.ToCell)))
            .IsEquivalentTo(
            [
                ("fra", "gru"), ("fra", "sfo"), ("gru", "fra"),
                ("gru", "sfo"), ("sfo", "fra"), ("sfo", "gru"),
            ]);
        await Assert.That(() => NatsGatewayMesh.FullMesh(["gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsGatewayMesh.FullMesh(["gru", "gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsGatewayMesh.FullMesh(["gru", "SFO"]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task GatewayEndpointsAcceptOnlyQualifiedHostPortPairs()
    {
        await Assert.That(NatsGatewayEndpoint.Parse("nats.gru.internal:4222").Qualified)
            .IsEqualTo("nats.gru.internal:4222");
        await Assert.That(NatsGatewayEndpoint.Parse("127.0.0.1:4222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("seed-1.fra.internal.terrascale.tech:6222").IsLoopback)
            .IsFalse();
        foreach (var unqualified in new[]
                 {
                     "seed-1.fra.internal.terrascale.tech", "host:", ":4222", "*:4222", "host:0",
                     "host:65536", "host:port", "host:4222:extra", "tls://host:4222", "", "  :4222",
                 })
        {
            await Assert.That(NatsGatewayEndpoint.TryParse(unqualified, out _)).IsFalse();
            await Assert.That(() => NatsGatewayEndpoint.Parse(unqualified)).Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task ProductionPlansPassTheirOwnAdmissionGate()
    {
        var control = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var product = NatsGatewayPlaneTopology.CreateProductPlane();

        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(control))).IsEmpty();
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(product))).IsEmpty();
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.ValidateDualPlane(control, product)))
            .IsEmpty();
        NatsGatewayPlanValidation.EnsureValid(control);
        NatsGatewayPlanValidation.EnsureValid(product);
    }

    [Test]
    public async Task RegionalJetStreamDomainsKeepGlobalAssetsOnOneRegion()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();

        await Assert.That(plan.Clusters.Select(static cluster => cluster.JetStreamDomain))
            .IsEquivalentTo(["ORCH_FRA", "ORCH_GRU", "ORCH_SFO"]);
        foreach (var cell in new[] { "fra", "sfo" })
        {
            var assets = plan.Cluster(cell)!.JetStreamAssets;
            await Assert.That(assets.Any(asset =>
                    asset.StartsWith("GLOBAL_", StringComparison.Ordinal) ||
                    asset.StartsWith("CI_", StringComparison.Ordinal)))
                .IsFalse();
        }
        var gruAssets = plan.Cluster("gru")!.JetStreamAssets;
        await Assert.That(gruAssets.Where(static asset => asset.StartsWith("GLOBAL_", StringComparison.Ordinal)))
            .IsEquivalentTo(["GLOBAL_BUNDLES", "GLOBAL_CELLS", "GLOBAL_CI", "GLOBAL_RELEASES", "GLOBAL_SPEC"]);

        // The declared asset names track the landed regional and global topologies.
        foreach (var cell in new[] { "fra", "gru", "sfo" })
        {
            var expected = ExpectedRegionalAssets(cell);
            await Assert.That(plan.Cluster(cell)!.JetStreamAssets.Where(static asset =>
                    !asset.StartsWith("GLOBAL_", StringComparison.Ordinal) &&
                    !asset.StartsWith("CI_", StringComparison.Ordinal)))
                .IsEquivalentTo(expected);
        }
        var global = new GlobalNatsTopology(3);
        await Assert.That(gruAssets).Contains(GlobalNatsTopology.CiStream);
        await Assert.That(gruAssets).Contains(GlobalNatsTopology.RunnerJobsBucket);
    }

    [Test]
    public async Task MeshValidationRejectsMissingDuplicateSelfHubOnlyAndProductEdges()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();

        var missing = Rebuild(plan,
            relationships: [.. plan.GatewayRelationships.Where(relationship =>
                relationship is not { FromCell: "gru", ToCell: "sfo" })]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(missing)))
            .Contains("missing the gateway relationship gru->sfo");

        var duplicate = Rebuild(plan,
            relationships: [.. plan.GatewayRelationships, new NatsGatewayRelationship("gru", "sfo")]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(duplicate)))
            .Contains("gru->sfo is declared more than once");

        var self = Rebuild(plan,
            relationships: [.. plan.GatewayRelationships, new NatsGatewayRelationship("gru", "gru")]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(self)))
            .Contains("is a self edge");

        var unknown = Rebuild(plan,
            relationships: [.. plan.GatewayRelationships, new NatsGatewayRelationship("gru", "xxx")]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(unknown)))
            .Contains("references an undeclared cell");

        // Hub-and-spoke: every edge touches GRU, no SFO<->FRA pair.
        var hub = Rebuild(plan,
            relationships:
            [
                new NatsGatewayRelationship("gru", "sfo"),
                new NatsGatewayRelationship("sfo", "gru"),
                new NatsGatewayRelationship("gru", "fra"),
                new NatsGatewayRelationship("fra", "gru"),
            ]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(hub)))
            .Contains("missing the gateway relationship fra->sfo");
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(hub)))
            .Contains("missing the gateway relationship sfo->fra");

        var product = NatsGatewayPlaneTopology.CreateProductPlane();
        var productWithEdge = Rebuild(product, relationships: [new NatsGatewayRelationship("gru", "sfo")]);
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(productWithEdge)))
            .Contains("must not declare any gateway relationship");

        var controlWithoutListener = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers:
                [
                    .. cluster.Servers.Select(server => Rebuild(server,
                        clearGateway: true,
                        profiles:
                        [
                            .. server.CertificateProfiles.Where(static profile =>
                                profile.Transport != NatsGatewayTransport.Gateway),
                        ])),
                ])
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayMesh.Validate(controlWithoutListener)))
            .Contains("has no gateway listener");
    }

    [Test]
    public async Task PlaneSeparationRejectsEverySharedSurface()
    {
        var control = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var product = NatsGatewayPlaneTopology.CreateProductPlane();

        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, product)))
            .IsEmpty();

        var sharedOperator = Rebuild(
            product,
            operatorName: NatsGatewayPlaneTopology.ControlOperatorName,
            clusters:
            [
                .. product.Clusters.Select(cluster => Rebuild(cluster,
                    operatorName: NatsGatewayPlaneTopology.ControlOperatorName)),
            ]);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, sharedOperator)))
            .Contains("share one operator trust root");

        var sharedAccount = Rebuild(product,
            accounts: [.. product.Accounts, new NatsGatewayAccountScope(
                "gru",
                GlobalNatsAccountNames.GlobalDirectory,
                ["shared-signing"],
                ["shared-user"],
                new NatsGatewayAccountLimits(1, 1, 1, 0, 0, 0))]);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, sharedAccount)))
            .Contains("is declared in both planes");

        // The operator-scoped system account is the one shared name by design.
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, product)))
            .DoesNotContain("system");

        var productOnControlPort = Rebuild(product, clusters:
        [
            .. product.Clusters.Select(cluster => Rebuild(cluster, servers:
            [
                .. cluster.Servers.Select(server => Rebuild(server,
                    client: new NatsGatewayEndpoint(server.Client.Host, NatsGatewayCluster.ControlClientPort),
                    route: new NatsGatewayEndpoint(server.Route.Host, NatsGatewayCluster.ControlRoutePort))),
            ])),
        ]);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, productOnControlPort)))
            .Contains("share listener port 4222");

        var sharedStore = Rebuild(product, clusters:
        [
            .. product.Clusters.Select(cluster => Rebuild(cluster, servers:
            [
                .. cluster.Servers.Select(server => Rebuild(server,
                    storeDirectory: control.Clusters[0].Servers[0].StoreDirectory)),
            ])),
        ]);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, sharedStore)))
            .Contains("share the store directory");

        var sharedCredential = Rebuild(product, clusters:
        [
            .. product.Clusters.Select(cluster => Rebuild(cluster, servers:
            [
                .. cluster.Servers.Select(server =>
                {
                    var client = server.Profile(NatsGatewayTransport.Client);
                    return Rebuild(server, profiles:
                    [
                        new NatsGatewayCertificateProfile(
                            NatsGatewayTransport.Client,
                            client.CertificateFile,
                            client.KeyFile,
                            control.Clusters[0].Servers[0].Profile(NatsGatewayTransport.Client).CaFile,
                            [NatsGatewayPlaneTopology.ProductClientSpiffePrefix]),
                        .. server.CertificateProfiles.Where(static profile =>
                            profile.Transport == NatsGatewayTransport.Route),
                    ]);
                }),
            ])),
        ]);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, sharedCredential)))
            .Contains("never crosses planes");

        // The record itself rejects a product-plane gateway listener, so no typed
        // product plan can ever reach the isolation check with one; the check is
        // defense in depth for record evolution.
        await Assert.That(() => Rebuild(product.Clusters[0], servers: product.Clusters[0].Servers
            .Select(server => Rebuild(server,
                gateway: new NatsGatewayEndpoint(server.Client.Host, 7223),
                profiles:
                [
                    .. server.CertificateProfiles,
                    new NatsGatewayCertificateProfile(
                        NatsGatewayTransport.Gateway,
                        $"{NatsGatewayPlaneTopology.ProductPkiRoot}/{server.ServerName}-gateway.pem",
                        $"{NatsGatewayPlaneTopology.ProductPkiRoot}/{server.ServerName}-gateway.key.pem",
                        $"{NatsGatewayPlaneTopology.ProductPkiRoot}/ca.pem",
                        ["spiffe://terrascale.product.internal/nats/server/peer"]),
                ])).ToArray()))
            .Throws<ArgumentException>();

        var productExchange = Rebuild(product,
            exports: [new NatsGatewayServiceExport("terrascale-product-gru", "some.subject")],
            imports: []);
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidatePlaneSeparation(control, productExchange)))
            .Contains("cross-account import or export");
    }

    [Test]
    public async Task DomainIsolationRejectsSharedDomainsAndSpanningGlobalAssets()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();

        var sharedDomain = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo" ? Rebuild(cluster, jetStreamDomain: "ORCH_GRU") : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayIsolation.ValidateRegionalDomainIsolation(sharedDomain)))
            .Contains("declared by more than one cluster");

        var spanning = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, assets: [.. cluster.JetStreamAssets, "GLOBAL_SPEC"])
                : cluster).ToArray());
        var spanningErrors = string.Join("; ", NatsGatewayIsolation.ValidateRegionalDomainIsolation(spanning));
        await Assert.That(spanningErrors).Contains("spans the regions");
        await Assert.That(spanningErrors).Contains("gru, sfo");
    }

    [Test]
    public async Task ServiceCatalogAllowsOnlyTheApprovedVersionedControlService()
    {
        await Assert.That(NatsGatewayServiceCatalog.IsApprovedService(GlobalNatsTopology.CellDirectorySubject))
            .IsTrue();
        await Assert.That(NatsGatewayServiceCatalog.ApprovedServices)
            .IsEquivalentTo([NatsSubjectTaxonomy.GlobalDirectoryQuerySubject]);

        var root = NatsSubjectTaxonomy.GlobalRoot;
        var denied = new[]
        {
            $"{root}.desired.gitops.gru",                              // global authority journals
            $"{root}.ci.forgejo",                                      // CI
            $"{root}.ci.job.untrusted-product.hash",                   // CI runner inbox
            "$KV.GLOBAL_RELEASES.>",                                   // release ledger
            "$KV.GLOBAL_RELEASES.release.1",                           // release record
            "$O.GLOBAL_BUNDLES.M.>",                                   // object store
            "$O.CI_RUNNER_BUNDLES.C.>",                                // object store
            "ts.orch.v1.gru.internal.operation-journal.create",        // regional journal (other cell)
            "ts.orch.v1.sfo.internal.runtime-lifecycle-journal.write", // regional journal (other cell)
            "ts.orch.v1.gru.desired.gitops",                           // regional control of another cell
            "ts.product.v1.gru.queue.customer",                        // product plane
            "unknown.subject",                                         // outside the taxonomy
            $"{GlobalNatsTopology.CellDirectorySubject}.>",            // wildcard
            $"{root}.query.cells.>",                                   // wildcard
            $"{root}.query",                                           // not the exact service
        };
        foreach (var subject in denied)
        {
            var deniedByCatalog = NatsGatewayServiceCatalog.TryDeny(subject, out var reason);
            await Assert.That(deniedByCatalog).IsTrue();
            await Assert.That(string.IsNullOrWhiteSpace(reason)).IsFalse();
        }

        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        await Assert.That(string.Join("; ",
                plan.Imports.SelectMany(import => NatsGatewayServiceCatalog.ValidateImport(plan, import))))
            .IsEmpty();
        await Assert.That(string.Join("; ",
                plan.Exports.SelectMany(export => NatsGatewayServiceCatalog.ValidateExport(plan, export))))
            .IsEmpty();

        var withoutExport = Rebuild(plan, exports: []);
        await Assert.That(string.Join("; ", plan.Imports
                .SelectMany(import => NatsGatewayServiceCatalog.ValidateImport(withoutExport, import))))
            .Contains("has no matching export");

        var rogueImport = Rebuild(plan, imports:
        [
            .. plan.Imports,
            new NatsGatewayServiceImport(
                "ts-orch-regional-control-fra",
                $"{root}.desired.gitops.gru",
                GlobalNatsAccountNames.GlobalAuthority),
        ]);
        await Assert.That(string.Join("; ", rogueImport.Imports
                .Where(import => import.Subject != GlobalNatsTopology.CellDirectorySubject)
                .SelectMany(import => NatsGatewayServiceCatalog.ValidateImport(rogueImport, import))))
            .Contains("global-authority subject");

        var unknownAccountImport = Rebuild(plan, imports:
        [
            .. plan.Imports,
            new NatsGatewayServiceImport(
                "ts-orch-regional-control-fra",
                GlobalNatsTopology.CellDirectorySubject,
                "ts-orch-not-declared"),
        ]);
        await Assert.That(string.Join("; ", unknownAccountImport.Imports
                .Where(import => import.SourceAccountName == "ts-orch-not-declared")
                .SelectMany(import => NatsGatewayServiceCatalog.ValidateImport(unknownAccountImport, import))))
            .Contains("is not declared in the plan");
    }

    [Test]
    public async Task AdmissionFailsClosedOnInvalidPlans()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();

        await Assert.That(() => new NatsGatewayCluster(
            NatsGatewayPlane.Control,
            "GRU",
            "orchestrator-control-gru",
            "ORCH_GRU",
            plan.OperatorName,
            plan.Cluster("gru")!.Servers,
            plan.Cluster("gru")!.Accounts,
            plan.Cluster("gru")!.JetStreamAssets,
            plan.Cluster("gru")!.CgroupSlice,
            1, 1)).Throws<ArgumentException>();

        var sharedServerIdentity = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers: plan.Cluster("gru")!.Servers.ToArray())
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(sharedServerIdentity)))
            .Contains("is shared by more than one cluster");

        var sharedEndpoint = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
        {
            if (cluster.Cell != "sfo")
                return cluster;
            var gru = plan.Cluster("gru")!;
            var target = gru.Servers[0];
            return Rebuild(cluster, servers: cluster.Servers.Select((server, index) =>
                index == 0
                    ? Rebuild(server,
                        client: target.Client,
                        route: server.Route,
                        gateway: server.Gateway)
                    : server).ToArray());
        }).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(sharedEndpoint)))
            .Contains("is shared by");

        var sharedStore = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers: cluster.Servers.Select(server => Rebuild(server,
                    storeDirectory: plan.Cluster("gru")!.Servers[0].StoreDirectory)).ToArray())
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(sharedStore)))
            .Contains("is shared by more than one server");

        var sharedFailureDomain = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers: cluster.Servers.Select(server =>
                    Rebuild(server, failureDomain: "seed-1.sfo.internal.terrascale.tech")).ToArray())
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(sharedFailureDomain)))
            .Contains("in one failure domain");

        var renamedCluster = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo" ? Rebuild(cluster, clusterName: "sfo-control") : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(renamedCluster)))
            .Contains("is not the canonical");

        var renamedDomain = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo" ? Rebuild(cluster, jetStreamDomain: "SFO") : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(renamedDomain)))
            .Contains("is not the canonical");

        var accountWithoutScope = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, accounts: [.. cluster.Accounts, "ts-orch-unknown"])
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(accountWithoutScope)))
            .Contains("without an account scope");

        var controlServerWithoutGateway = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers:
                [
                    .. cluster.Servers.Select(server => Rebuild(server,
                        clearGateway: true,
                        profiles:
                        [
                            .. server.CertificateProfiles.Where(static profile =>
                                profile.Transport != NatsGatewayTransport.Gateway),
                        ])),
                ])
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(controlServerWithoutGateway)))
            .Contains("has no gateway listener");

        var loopbackPlan = Rebuild(plan, clusters: plan.Clusters.Select(cluster =>
            cluster.Cell == "sfo"
                ? Rebuild(cluster, servers: cluster.Servers.Select((server, index) => Rebuild(server,
                    client: new NatsGatewayEndpoint("127.0.0.1", 14000 + index),
                    route: new NatsGatewayEndpoint("127.0.0.1", 15000 + index),
                    gateway: new NatsGatewayEndpoint("127.0.0.1", 16000 + index))).ToArray())
                : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(loopbackPlan)))
            .Contains("binds a loopback endpoint");
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(
                loopbackPlan,
                NatsGatewayValidationOptions.LocalConformance)))
            .DoesNotContain("loopback");

        var incompleteMesh = Rebuild(plan,
            relationships: plan.GatewayRelationships.Skip(1).ToArray());
        await Assert.That(() => NatsGatewayPlanValidation.EnsureValid(incompleteMesh))
            .Throws<InvalidOperationException>();

        var twoCertificateAuthorities = Rebuild(plan, clusters:
        [
            .. plan.Clusters.Select(cluster => cluster.Cell != "sfo"
                ? cluster
                : Rebuild(cluster, servers:
                [
                    .. cluster.Servers.Select(server => Rebuild(server, profiles:
                    [
                        .. server.CertificateProfiles.Select(profile => new NatsGatewayCertificateProfile(
                            profile.Transport,
                            profile.CertificateFile,
                            profile.KeyFile,
                            "/etc/terrascale/pki/nats/other/ca.pem",
                            profile.ExpectedPeerIdentities)),
                    ])),
                ])),
        ]);
        await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(twoCertificateAuthorities)))
            .Contains("more than one certificate authority");
    }

    [Test]
    public async Task RotationPlansRollOneServerAtATimeWithExplicitRollback()
    {
        var current = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var next = NatsGatewayPlaneTopology.CreateControlSupercluster(configurationGeneration: 2);
        var digests = current.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .ToDictionary(
                static server => server.ServerName,
                server => ($"before-{server.ServerName}", $"after-{server.ServerName}"),
                StringComparer.Ordinal);

        var steps = NatsGatewayRotation.Plan(current, next, digests);
        await Assert.That(steps).Count().IsEqualTo(9);
        await Assert.That(steps.Select(static step => step.Cell))
            .IsEquivalentTo(["fra", "fra", "fra", "gru", "gru", "gru", "sfo", "sfo", "sfo"]);
        await Assert.That(string.Join(",", steps.Select(static step => step.ServerName)))
            .IsEqualTo(
                "fra-control-nats-1,fra-control-nats-2,fra-control-nats-3," +
                "gru-control-nats-1,gru-control-nats-2,gru-control-nats-3," +
                "sfo-control-nats-1,sfo-control-nats-2,sfo-control-nats-3");
        await Assert.That(steps.All(static step => step.FromConfigurationGeneration == 1 &&
                                                    step.ToConfigurationGeneration == 2))
            .IsTrue();
        await Assert.That(steps.All(static step => step.FromTrustGeneration == 1 && step.ToTrustGeneration == 1))
            .IsTrue();
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(current, steps))).IsEmpty();

        var rollback = NatsGatewayRotation.Rollback(steps);
        await Assert.That(rollback).Count().IsEqualTo(9);
        await Assert.That(rollback[0].ServerName).IsEqualTo("sfo-control-nats-3");
        await Assert.That(rollback[0].ToConfigurationGeneration).IsEqualTo(1);
        await Assert.That(rollback[0].FromConfigurationGeneration).IsEqualTo(2);
        await Assert.That(rollback[0].RollbackTarget.Digest).IsEqualTo("after-sfo-control-nats-3");
        await Assert.That(NatsGatewayRotation.Rollback(rollback[0]).ToConfigurationGeneration).IsEqualTo(2);

        var trustRotation = NatsGatewayRotation.Plan(
            current,
            NatsGatewayPlaneTopology.CreateControlSupercluster(trustGeneration: 2, configurationGeneration: 2),
            digests);
        await Assert.That(trustRotation.All(static step => step.ToTrustGeneration == 2)).IsTrue();

        var partialTrust = Rebuild(next, clusters: next.Clusters.Select(cluster =>
            cluster.Cell == "fra" ? Rebuild(cluster, trustGeneration: 2) : cluster).ToArray());
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(current, partialTrust, digests)))
            .Contains("must advance every cluster");

        var missingDigest = digests.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value,
            StringComparer.Ordinal);
        missingDigest.Remove("gru-control-nats-2");
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(current, next, missingDigest)))
            .Contains("no pre/post configuration digest");

        var unchangedDigests = current.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .ToDictionary(
                static server => server.ServerName,
                static server => ("same", "same"),
                StringComparer.Ordinal);
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(current, next, unchangedDigests)))
            .Contains("digest is unchanged");

        var membershipChange = Rebuild(next, clusters: next.Clusters
            .Where(cluster => cluster.Cell != "sfo").ToArray());
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(current, membershipChange, digests)))
            .Contains("never adds or removes a cluster");

        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(
                current,
                NatsGatewayPlaneTopology.CreateProductPlane(),
                digests)))
            .Contains("exactly one plane");

        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(
                current,
                [.. steps.Reverse()])))
            .Contains("not ordered by cell then server ordinal");

        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(
                current,
                [.. steps, steps[0]])))
            .Contains("is rolled more than once");

        var wrongFailureDomain = steps.Select(step => step == steps[0]
            ? new NatsGatewayRotationStep(
                step.Plane, step.Cell, step.ServerName, "wrong-domain.internal",
                step.FromTrustGeneration, step.ToTrustGeneration,
                step.FromConfigurationGeneration, step.ToConfigurationGeneration,
                step.BeforeDigest, step.AfterDigest)
            : step).ToArray();
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(current, wrongFailureDomain)))
            .Contains("records the wrong failure domain");
    }

    [Test]
    public async Task RotationRejectsSilentContentDriftAndForgedPreState()
    {
        var current = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var next = NatsGatewayPlaneTopology.CreateControlSupercluster(configurationGeneration: 2);
        var digests = current.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .ToDictionary(
                static server => server.ServerName,
                server => ($"before-{server.ServerName}", $"after-{server.ServerName}"),
                StringComparer.Ordinal);

        // A next plan that changes cluster content without advancing a
        // generation is rejected: the rotation would otherwise silently
        // produce zero steps while the deployment diverges from the plan.
        var drifted = Rebuild(current, clusters:
        [
            .. current.Clusters.Select(cluster => cluster.Cell != "sfo"
                ? cluster
                : Rebuild(cluster, servers:
                [
                    .. cluster.Servers.Select(server => Rebuild(server,
                        storeDirectory: server.StoreDirectory + "-drift")),
                ])),
        ]);
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(current, drifted, digests)))
            .Contains("changed its content without advancing a generation");
        await Assert.That(() => NatsGatewayRotation.Plan(current, drifted, digests))
            .Throws<InvalidOperationException>();

        // An unchanged plan with no generation change is a valid empty rotation.
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateTransition(
                current,
                current,
                new Dictionary<string, (string Before, string After)>())))
            .IsEmpty();

        // A step whose recorded pre-state is not the current plan's state is
        // rejected, so a stale or forged step cannot be replayed.
        var steps = NatsGatewayRotation.Plan(current, next, digests);
        var forged = steps.Select(step => step == steps[0]
            ? new NatsGatewayRotationStep(
                step.Plane, step.Cell, step.ServerName, step.FailureDomain,
                step.FromTrustGeneration, step.ToTrustGeneration,
                step.FromConfigurationGeneration + 1, step.ToConfigurationGeneration + 1,
                step.BeforeDigest, step.AfterDigest)
            : step).ToArray();
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(current, forged)))
            .Contains("does not record the current plan's generations as its pre-state");
    }

    [Test]
    public async Task LoopbackClassificationCoversTheWhole127RangeAndCaseInsensitiveLocalhost()
    {
        await Assert.That(NatsGatewayEndpoint.Parse("127.0.0.1:4222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("127.8.8.8:4222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("127.0.0.254:6222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("localhost:4222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("LocalHost:4222").IsLoopback).IsTrue();
        await Assert.That(NatsGatewayEndpoint.Parse("LOCALHOST:4222").IsLoopback).IsTrue();

        // Loopback look-alikes that are not loopback must not be swept in.
        await Assert.That(NatsGatewayEndpoint.Parse("127.0.0.1.evil.example:4222").IsLoopback).IsFalse();
        await Assert.That(NatsGatewayEndpoint.Parse("256.1.1.1:4222").IsLoopback).IsFalse();
        await Assert.That(NatsGatewayEndpoint.Parse("seed-1.fra.internal.terrascale.tech:6222").IsLoopback)
            .IsFalse();
        await Assert.That(NatsGatewayEndpoint.Parse("a127.b.c.d:4222").IsLoopback).IsFalse();

        // The evading forms are rejected by production admission and admitted
        // only by the explicit loopback conformance profile.
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        foreach (var host in new[] { "127.8.8.8", "LocalHost" })
        {
            var loopback = Rebuild(plan, clusters:
            [
                .. plan.Clusters.Select(cluster => cluster.Cell != "sfo"
                    ? cluster
                    : Rebuild(cluster, servers:
                    [
                        .. cluster.Servers.Select((server, index) => Rebuild(server,
                            client: new NatsGatewayEndpoint(host, 14000 + index),
                            route: new NatsGatewayEndpoint(host, 15000 + index),
                            gateway: new NatsGatewayEndpoint(host, 16000 + index))),
                    ])),
            ]);
            await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(loopback)))
                .Contains("binds a loopback endpoint");
            await Assert.That(() => NatsGatewayPlanValidation.EnsureValid(loopback))
                .Throws<InvalidOperationException>();
            await Assert.That(string.Join("; ", NatsGatewayPlanValidation.Validate(
                    loopback,
                    NatsGatewayValidationOptions.LocalConformance)))
                .DoesNotContain("loopback");
        }
    }

    [Test]
    public async Task ProductPlaneExchangesAreRejectedBySinglePlanAdmissionAndDualPlaneGate()
    {
        var control = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var product = NatsGatewayPlaneTopology.CreateProductPlane();

        // A product plan carrying even the one approved control service is
        // rejected by single-plan Validate, not only by dual-plane composition.
        var withExchange = Rebuild(product,
            exports: [new NatsGatewayServiceExport(
                "terrascale-product-gru",
                GlobalNatsTopology.CellDirectorySubject)],
            imports: [new NatsGatewayServiceImport(
                "terrascale-product-gru",
                GlobalNatsTopology.CellDirectorySubject,
                GlobalNatsAccountNames.GlobalDirectory)]);
        var singlePlanErrors = string.Join("; ", NatsGatewayPlanValidation.Validate(withExchange));
        await Assert.That(singlePlanErrors).Contains("product plane must not declare any cross-account export");
        await Assert.That(singlePlanErrors).Contains("product plane must not declare any cross-account import");
        await Assert.That(() => NatsGatewayPlanValidation.EnsureValid(withExchange))
            .Throws<InvalidOperationException>();

        // The dual-plane startup gate throws on the same tampering and stays
        // silent for the clean pair.
        await Assert.That(() => NatsGatewayPlanValidation.EnsureValidDualPlane(control, withExchange))
            .Throws<InvalidOperationException>();
        NatsGatewayPlanValidation.EnsureValidDualPlane(control, product);
    }

    [Test]
    public async Task ApprovedServiceExportsArePinnedToTheirTypedExporter()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        await Assert.That(NatsGatewayServiceCatalog.ExpectedExporter(GlobalNatsTopology.CellDirectorySubject))
            .IsEqualTo(GlobalNatsAccountNames.GlobalDirectory);
        await Assert.That(string.Join("; ",
                NatsGatewayServiceCatalog.ValidateExport(plan, plan.Exports[0])))
            .IsEmpty();

        // Any other declared account standing in front of the approved service
        // is rejected, even though the subject and the account are both valid.
        var rogue = Rebuild(plan, exports: [new NatsGatewayServiceExport(
            GlobalNatsAccountNames.RegionalControl("fra"),
            GlobalNatsTopology.CellDirectorySubject)]);
        await Assert.That(string.Join("; ", NatsGatewayServiceCatalog.ValidateExport(rogue, rogue.Exports[0])))
            .Contains($"must be exported by the account '{GlobalNatsAccountNames.GlobalDirectory}'");
    }

    [Test]
    public async Task DuplicateCellsAggregateInsteadOfThrowingFromMeshGeneration()
    {
        var plan = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var duplicated = new NatsGatewayPlan(
            plan.Plane,
            plan.OperatorName,
            plan.TrustGeneration,
            plan.ConfigurationGeneration,
            [.. plan.Clusters, plan.Cluster("gru")!],
            plan.GatewayRelationships,
            plan.Accounts,
            plan.Exports,
            plan.Imports);

        // The complete failure list is returned: the duplicate cell and the
        // consequences of it, with no raw generator exception.
        var errors = string.Join("; ", NatsGatewayPlanValidation.Validate(duplicated));
        await Assert.That(errors).Contains("The cell 'gru' declares more than one cluster.");
        await Assert.That(errors).Contains("is shared by more than one cluster.");
        await Assert.That(() => NatsGatewayPlanValidation.EnsureValid(duplicated))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ProductPlaneStaysCellLocalWithItsOwnTrustRoot()
    {
        var product = NatsGatewayPlaneTopology.CreateProductPlane();

        await Assert.That(product.Plane).IsEqualTo(NatsGatewayPlane.Product);
        await Assert.That(product.OperatorName).IsEqualTo(NatsGatewayPlaneTopology.ProductOperatorName);
        await Assert.That(product.GatewayRelationships).IsEmpty();
        await Assert.That(product.Exports).IsEmpty();
        await Assert.That(product.Imports).IsEmpty();
        foreach (var cluster in product.Clusters)
        {
            await Assert.That(cluster.ClusterName).IsEqualTo($"terrascale-product-{cluster.Cell}");
            await Assert.That(cluster.JetStreamDomain)
                .IsEqualTo($"PRODUCT_{cluster.Cell.ToUpperInvariant()}");
            await Assert.That(cluster.Servers.All(static server => server.Gateway is null)).IsTrue();
            await Assert.That(cluster.Servers.Select(static server => server.Client.Port).Distinct())
                .IsEquivalentTo([NatsGatewayCluster.ProductClientPort]);
            await Assert.That(cluster.Accounts)
                .IsEquivalentTo([$"terrascale-product-{cluster.Cell}", "system"]);
            await Assert.That(cluster.CgroupSlice).IsEqualTo(NatsGatewayPlaneTopology.ProductCgroupSlice);
            await Assert.That(cluster.Servers.All(server => server.StoreDirectory.StartsWith(
                    NatsGatewayPlaneTopology.ProductStoreRoot, StringComparison.Ordinal)))
                .IsTrue();
            await Assert.That(cluster.JetStreamAssets).IsEmpty();
        }
        await Assert.That(product.Clusters.SelectMany(static cluster => cluster.Servers)
                .All(server => server.Process.Cgroup.StartsWith(
                    NatsGatewayPlaneTopology.ProductCgroupSlice + "/", StringComparison.Ordinal)))
            .IsTrue();
        await Assert.That(product.Clusters.SelectMany(static cluster => cluster.Servers)
                .All(static server => server.CertificateProfiles.Count == 2))
            .IsTrue();    }

    private static IReadOnlyList<string> ExpectedRegionalAssets(string cell)
    {
        var topology = new NatsTopology(cell, 3);
        return
        [
            .. topology.Streams.Select(static stream => stream.Name!),
            topology.Leaders.Bucket,
            topology.Runtime.Bucket,
            topology.Delivery.Bucket,
            topology.Operations.Bucket,
            topology.OperationProofConsumptions.Bucket,
            topology.Bundles.Bucket,
            topology.ProtocolPackage.Bucket,
            topology.StartupConsumer.Name!,
            .. Enumerable.Range(1, 3)
                .Select(index => new NatsTopology(cell, 3, $"controller-{index}").CellSpecConsumer.Name!),
        ];
    }

    private static NatsGatewayCluster Rebuild(
        NatsGatewayCluster cluster,
        string? clusterName = null,
        string? jetStreamDomain = null,
        IReadOnlyList<NatsGatewayServerIdentity>? servers = null,
        IReadOnlyList<string>? accounts = null,
        IReadOnlyList<string>? assets = null,
        string? operatorName = null,
        int? trustGeneration = null,
        int? configurationGeneration = null) => new(
        cluster.Plane,
        cluster.Cell,
        clusterName ?? cluster.ClusterName,
        jetStreamDomain ?? cluster.JetStreamDomain,
        operatorName ?? cluster.OperatorName,
        servers ?? cluster.Servers,
        accounts ?? cluster.Accounts,
        assets ?? cluster.JetStreamAssets,
        cluster.CgroupSlice,
        trustGeneration ?? cluster.TrustGeneration,
        configurationGeneration ?? cluster.ConfigurationGeneration);

    private static NatsGatewayServerIdentity Rebuild(
        NatsGatewayServerIdentity server,
        NatsGatewayEndpoint? client = null,
        NatsGatewayEndpoint? route = null,
        NatsGatewayEndpoint? gateway = null,
        bool clearGateway = false,
        IReadOnlyList<NatsGatewayCertificateProfile>? profiles = null,
        string? failureDomain = null,
        string? storeDirectory = null) => new(
        server.ServerName,
        failureDomain ?? server.FailureDomain,
        client ?? server.Client,
        route ?? server.Route,
        clearGateway ? null : gateway ?? server.Gateway,
        profiles ?? server.CertificateProfiles,
        server.Process,
        storeDirectory ?? server.StoreDirectory);

    private static NatsGatewayPlan Rebuild(
        NatsGatewayPlan plan,
        IReadOnlyList<NatsGatewayCluster>? clusters = null,
        IReadOnlyList<NatsGatewayRelationship>? relationships = null,
        IReadOnlyList<NatsGatewayAccountScope>? accounts = null,
        IReadOnlyList<NatsGatewayServiceExport>? exports = null,
        IReadOnlyList<NatsGatewayServiceImport>? imports = null,
        string? operatorName = null) => new(
        plan.Plane,
        operatorName ?? plan.OperatorName,
        plan.TrustGeneration,
        plan.ConfigurationGeneration,
        clusters ?? plan.Clusters,
        relationships ?? plan.GatewayRelationships,
        accounts ?? plan.Accounts,
        exports ?? plan.Exports,
        imports ?? plan.Imports);
}

