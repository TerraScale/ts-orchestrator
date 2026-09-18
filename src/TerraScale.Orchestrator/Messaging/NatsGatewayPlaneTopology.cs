namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Builds the typed production NATS plane plans for the GRU/SFO/FRA launch
/// topology: the control-plane gateway supercluster under one offline operator
/// trust root, and the cell-local product plane under its own distinct root.
/// Everything downstream — mesh validation, isolation checks, rotation plans,
/// and configuration rendering — consumes these typed plans; no production
/// path builds NATS configuration text by hand.
/// </summary>
internal static class NatsGatewayPlaneTopology
{
    /// <summary>The canonical launch regions in stable ordinal order.</summary>
    internal static readonly IReadOnlyList<string> Regions = ["fra", "gru", "sfo"];

    /// <summary>The launch topology runs three NATS servers per region per plane.</summary>
    internal const int ServersPerRegion = 3;

    internal const string ControlOperatorName = "ts-orch-control";
    internal const string ProductOperatorName = "ts-terrascale-product";

    internal const string ControlCgroupSlice = "/terrascale.slice/terrascale-nats-control.slice";
    internal const string ProductCgroupSlice = "/terrascale.slice/terrascale-nats-product.slice";
    internal const string ControlStoreRoot = "/var/lib/terrascale/nats/control";
    internal const string ProductStoreRoot = "/var/lib/terrascale/nats/product";
    internal const string ControlPkiRoot = "/etc/terrascale/pki/nats/control";
    internal const string ProductPkiRoot = "/etc/terrascale/pki/nats/product";

    /// <summary>GRU owns the global authority and directory scopes as an additional role.</summary>
    internal const string GlobalScopeCell = "gru";

    private const string SystemAccountName = "system";

    /// <summary>
    /// The production control-plane supercluster: one cluster per region, one
    /// shared control operator trust root, a full directed gateway mesh between
    /// every pair, separately scoped accounts per region, and the approved
    /// cross-account directory service exchange.
    /// </summary>
    internal static NatsGatewayPlan CreateControlSupercluster(
        int trustGeneration = 1,
        int configurationGeneration = 1)
    {
        var clusters = Regions
            .OrderBy(static cell => cell, StringComparer.Ordinal)
            .Select(cell => ControlCluster(cell, trustGeneration, configurationGeneration))
            .ToArray();
        return new NatsGatewayPlan(
            NatsGatewayPlane.Control,
            ControlOperatorName,
            trustGeneration,
            configurationGeneration,
            clusters,
            NatsGatewayMesh.FullMesh(Regions),
            [.. ControlAccounts(trustGeneration)],
            [new NatsGatewayServiceExport(
                GlobalNatsAccountNames.GlobalDirectory,
                GlobalNatsTopology.CellDirectorySubject)],
            [.. Regions
                .Where(cell => cell != GlobalScopeCell)
                .Select(cell => new NatsGatewayServiceImport(
                    GlobalNatsAccountNames.RegionalControl(cell),
                    GlobalNatsTopology.CellDirectorySubject,
                    GlobalNatsAccountNames.GlobalDirectory))]);
    }

    /// <summary>
    /// The production product plane: one cell-local cluster per region under a
    /// distinct product operator root, with no gateway listener, no gateway
    /// relationship, and no import/export path to any other cluster.
    /// </summary>
    internal static NatsGatewayPlan CreateProductPlane(
        int trustGeneration = 1,
        int configurationGeneration = 1)
    {
        var clusters = Regions
            .OrderBy(static cell => cell, StringComparer.Ordinal)
            .Select(cell => ProductCluster(cell, trustGeneration, configurationGeneration))
            .ToArray();
        return new NatsGatewayPlan(
            NatsGatewayPlane.Product,
            ProductOperatorName,
            trustGeneration,
            configurationGeneration,
            clusters,
            [],
            [.. ProductAccounts(trustGeneration)],
            [],
            []);
    }

    /// <summary>
    /// The JetStream asset names declared for one regional control cluster:
    /// the regional streams, KV buckets, Object Stores, and durable consumers
    /// from <see cref="NatsTopology"/> — plus, on GRU only, the global
    /// authority assets from <see cref="GlobalNatsTopology"/>. GlobalNatsTopology
    /// reuses the regional ORCH_LEADERS bucket name on the GRU domain by landed
    /// design, so that name appears once.
    /// </summary>
    internal static IReadOnlyList<string> ControlJetStreamAssets(string cell)
    {
        if (!Regions.Contains(cell))
            throw new ArgumentOutOfRangeException(nameof(cell), cell, "The control cluster cell is not a launch region.");
        var regional = new NatsTopology(cell, ServersPerRegion);
        List<string> assets =
        [
            .. regional.Streams.Select(static stream => stream.Name!),
            regional.Leaders.Bucket,
            regional.Runtime.Bucket,
            regional.Delivery.Bucket,
            regional.Operations.Bucket,
            regional.OperationProofConsumptions.Bucket,
            regional.Bundles.Bucket,
            regional.Artifacts.Bucket,
            regional.ProtocolPackage.Bucket,
            regional.StartupConsumer.Name!,
            .. Enumerable.Range(1, ServersPerRegion)
                .Select(index => new NatsTopology(cell, ServersPerRegion, $"controller-{index}").CellSpecConsumer.Name!),
        ];
        if (cell == GlobalScopeCell)
        {
            var global = new GlobalNatsTopology(ServersPerRegion);
            assets.AddRange(global.Streams.Select(static stream => stream.Name!));
            assets.Add(global.Cells.Bucket);
            assets.Add(global.Releases.Bucket);
            assets.Add(global.RunnerJobs.Bucket);
            assets.Add(global.Bundles.Bucket);
            assets.Add(global.RunnerBundles.Bucket);
        }
        return assets;
    }

    /// <summary>
    /// The JetStream asset names declared for one product cluster. No product
    /// JetStream asset is landed yet: the product-plane asset catalog belongs
    /// to the product admission path, and this topology deliberately declares
    /// none rather than inventing product stream names.
    /// </summary>
    internal static IReadOnlyList<string> ProductJetStreamAssets(string cell)
    {
        if (!Regions.Contains(cell))
            throw new ArgumentOutOfRangeException(nameof(cell), cell, "The product cluster cell is not a launch region.");
        return [];
    }

    internal static string ControlClusterName(string cell) => $"orchestrator-control-{cell}";

    internal static string ProductClusterName(string cell) => $"terrascale-product-{cell}";

    internal static string ControlJetStreamDomain(string cell) => $"ORCH_{cell.ToUpperInvariant()}";

    internal static string ProductJetStreamDomain(string cell) => $"PRODUCT_{cell.ToUpperInvariant()}";

    internal static string ControlServerSpiffeId(string serverName) =>
        $"spiffe://terrascale.tech/control/nats/server/{serverName}";

    internal static string ControlClientSpiffePrefix => "spiffe://terrascale.tech/control/nats/client/";

    internal static string ProductServerSpiffeId(string serverName) =>
        $"spiffe://terrascale.product.internal/nats/server/{serverName}";

    internal static string ProductClientSpiffePrefix => "spiffe://terrascale.product.internal/nats/client/";

    internal static string ControlServerName(string cell, int index) => $"{cell}-control-nats-{index}";

    internal static string ProductServerName(string cell, int index) => $"{cell}-product-nats-{index}";

    /// <summary>The seed-host failure domain; the compact profile co-locates both planes on it.</summary>
    internal static string SeedHost(string cell, int index) => $"seed-{index}.{cell}.internal.terrascale.tech";

    private static NatsGatewayCluster ControlCluster(
        string cell,
        int trustGeneration,
        int configurationGeneration)
    {
        var servers = Enumerable.Range(1, ServersPerRegion)
            .Select(index => ControlServer(cell, index))
            .ToArray();
        return new NatsGatewayCluster(
            NatsGatewayPlane.Control,
            cell,
            ControlClusterName(cell),
            ControlJetStreamDomain(cell),
            ControlOperatorName,
            servers,
            [
                SystemAccountName,
                GlobalNatsAccountNames.GlobalAuthority,
                GlobalNatsAccountNames.GlobalDirectory,
                .. Regions.Select(GlobalNatsAccountNames.RegionalControl),
            ],
            ControlJetStreamAssets(cell),
            ControlCgroupSlice,
            trustGeneration,
            configurationGeneration);
    }

    private static NatsGatewayCluster ProductCluster(
        string cell,
        int trustGeneration,
        int configurationGeneration)
    {
        var servers = Enumerable.Range(1, ServersPerRegion)
            .Select(index => ProductServer(cell, index))
            .ToArray();
        return new NatsGatewayCluster(
            NatsGatewayPlane.Product,
            cell,
            ProductClusterName(cell),
            ProductJetStreamDomain(cell),
            ProductOperatorName,
            servers,
            [
                SystemAccountName,
                $"terrascale-product-{cell}",
            ],
            ProductJetStreamAssets(cell),
            ProductCgroupSlice,
            trustGeneration,
            configurationGeneration);
    }

    private static NatsGatewayServerIdentity ControlServer(string cell, int index)
    {
        var name = ControlServerName(cell, index);
        var host = SeedHost(cell, index);
        var siblingSpiffeIds = Enumerable.Range(1, ServersPerRegion)
            .Where(peer => peer != index)
            .Select(peer => ControlServerSpiffeId(ControlServerName(cell, peer)));
        var gatewayPeers = Regions
            .Where(other => other != cell)
            .SelectMany(other => Enumerable.Range(1, ServersPerRegion)
                .Select(peer => ControlServerSpiffeId(ControlServerName(other, peer))));
        var unit = ControlUnitName(cell, index);
        return new NatsGatewayServerIdentity(
            name,
            host,
            new NatsGatewayEndpoint(host, NatsGatewayCluster.ControlClientPort),
            new NatsGatewayEndpoint(host, NatsGatewayCluster.ControlRoutePort),
            new NatsGatewayEndpoint(host, NatsGatewayCluster.ControlGatewayPort),
            CertificateProfiles(
                ControlPkiRoot,
                name,
                ControlClientSpiffePrefix,
                siblingSpiffeIds,
                gatewayPeers,
                includeGateway: true),
            new NatsGatewayProcessIdentity(unit, $"{ControlCgroupSlice}/{unit}"),
            $"{ControlStoreRoot}/{cell}/{name}");
    }

    private static NatsGatewayServerIdentity ProductServer(string cell, int index)
    {
        var name = ProductServerName(cell, index);
        var host = SeedHost(cell, index);
        var siblingSpiffeIds = Enumerable.Range(1, ServersPerRegion)
            .Where(peer => peer != index)
            .Select(peer => ProductServerSpiffeId(ProductServerName(cell, peer)));
        var unit = ProductUnitName(cell, index);
        return new NatsGatewayServerIdentity(
            name,
            host,
            new NatsGatewayEndpoint(host, NatsGatewayCluster.ProductClientPort),
            new NatsGatewayEndpoint(host, NatsGatewayCluster.ProductRoutePort),
            gateway: null,
            CertificateProfiles(
                ProductPkiRoot,
                name,
                ProductClientSpiffePrefix,
                siblingSpiffeIds,
                gatewayPeers: [],
                includeGateway: false),
            new NatsGatewayProcessIdentity(unit, $"{ProductCgroupSlice}/{unit}"),
            $"{ProductStoreRoot}/{cell}/{name}");
    }

    internal static string ControlUnitName(string cell, int index) =>
        $"terrascale-control-nats@{cell}-{index}.service";

    internal static string ProductUnitName(string cell, int index) =>
        $"terrascale-product-nats@{cell}-{index}.service";

    private static IReadOnlyList<NatsGatewayCertificateProfile> CertificateProfiles(
        string pkiRoot,
        string serverName,
        string clientPeerPrefix,
        IEnumerable<string> routePeers,
        IEnumerable<string> gatewayPeers,
        bool includeGateway)
    {
        var root = $"{pkiRoot}/{serverName}";
        var ca = $"{pkiRoot}/ca.pem";
        var profiles = new List<NatsGatewayCertificateProfile>
        {
            new(
                NatsGatewayTransport.Client,
                $"{root}-client.pem",
                $"{root}-client.key.pem",
                ca,
                [clientPeerPrefix]),
            new(
                NatsGatewayTransport.Route,
                $"{root}-route.pem",
                $"{root}-route.key.pem",
                ca,
                routePeers),
        };
        if (includeGateway)
        {
            profiles.Add(new(
                NatsGatewayTransport.Gateway,
                $"{root}-gateway.pem",
                $"{root}-gateway.key.pem",
                ca,
                gatewayPeers));
        }
        return profiles;
    }

    private static IReadOnlyList<NatsGatewayAccountScope> ControlAccounts(int trustGeneration)
    {
        var regionalLimits = new NatsGatewayAccountLimits(64, 1024, 1024 * 1024, 16, 64, 32L * 1024 * 1024 * 1024);
        var authorityLimits = new NatsGatewayAccountLimits(16, 1024, 1024 * 1024, 16, 64, 32L * 1024 * 1024 * 1024);
        var directoryLimits = new NatsGatewayAccountLimits(16, 256, 1024 * 1024, 4, 32, 2L * 1024 * 1024 * 1024);
        var systemLimits = new NatsGatewayAccountLimits(64, 4096, 1024 * 1024, 0, 0, 0);
        return
        [
            new NatsGatewayAccountScope(
                GlobalScopeCell,
                GlobalNatsAccountNames.GlobalAuthority,
                [SigningKeyName(GlobalNatsAccountNames.GlobalAuthority, trustGeneration)],
                ["global-authority"],
                authorityLimits),
            new NatsGatewayAccountScope(
                GlobalScopeCell,
                GlobalNatsAccountNames.GlobalDirectory,
                [SigningKeyName(GlobalNatsAccountNames.GlobalDirectory, trustGeneration)],
                [
                    "global-directory-infrastructure",
                    "cell-directory-service-gru",
                    .. Regions.Where(cell => cell != GlobalScopeCell)
                        .Select(cell => $"cell-directory-publisher-{cell}"),
                ],
                directoryLimits),
            .. Regions.Select(cell => new NatsGatewayAccountScope(
                cell,
                GlobalNatsAccountNames.RegionalControl(cell),
                [SigningKeyName(GlobalNatsAccountNames.RegionalControl(cell), trustGeneration)],
                [
                    "controller-1",
                    "controller-2",
                    "controller-3",
                    "infrastructure",
                    "journal-writer",
                    "operator-read",
                    .. cell == GlobalScopeCell
                        ? Array.Empty<string>()
                        : [$"cell-directory-reader-{cell}"],
                ],
                regionalLimits)),
            new NatsGatewayAccountScope(
                GlobalScopeCell,
                SystemAccountName,
                [SigningKeyName(SystemAccountName, trustGeneration)],
                ["system"],
                systemLimits),
        ];
    }

    private static IReadOnlyList<NatsGatewayAccountScope> ProductAccounts(int trustGeneration)
    {
        var limits = new NatsGatewayAccountLimits(512, 8192, 1024 * 1024, 256, 1024, 512L * 1024 * 1024 * 1024);
        var systemLimits = new NatsGatewayAccountLimits(64, 4096, 1024 * 1024, 0, 0, 0);
        return
        [
            .. Regions.Select(cell => new NatsGatewayAccountScope(
                cell,
                $"terrascale-product-{cell}",
                [SigningKeyName($"terrascale-product-{cell}", trustGeneration)],
                [$"product-{cell}-platform"],
                limits)),
            new NatsGatewayAccountScope(
                GlobalScopeCell,
                SystemAccountName,
                [SigningKeyName(SystemAccountName, trustGeneration)],
                ["system"],
                systemLimits),
        ];
    }

    private static string SigningKeyName(string accountName, int trustGeneration) =>
        $"{accountName}-signing-v{trustGeneration}";
}

