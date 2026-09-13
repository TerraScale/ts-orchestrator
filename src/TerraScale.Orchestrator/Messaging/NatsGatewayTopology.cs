using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// The NATS trust plane a cluster belongs to. The control and product planes
/// never share an operator, account, process, port, cgroup, or store path.
/// </summary>
internal enum NatsGatewayPlane
{
    Control = 0,
    Product = 1,
}

/// <summary>
/// One qualified transport endpoint: an explicit host and an explicit port.
/// A bare host, a wildcard, an empty port, or port zero is not a qualified
/// endpoint and fails closed before rendering or startup.
/// </summary>
internal sealed record NatsGatewayEndpoint
{
    internal NatsGatewayEndpoint(string host, int port)
    {
        if (!IsValidHost(host))
            throw new ArgumentException("The endpoint host is not a bounded DNS-style host.", nameof(host));
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "The endpoint port must be an explicit TCP port.");
        Host = host;
        Port = port;
    }

    internal string Host { get; }

    internal int Port { get; }

    /// <summary>The single canonical rendering used by configuration and evidence.</summary>
    internal string Qualified => string.Create(CultureInfo.InvariantCulture, $"{Host}:{Port}");

    /// <summary>
    /// True for the whole loopback surface the production profile rejects:
    /// <c>localhost</c> in any letter case and the entire 127/8 address range
    /// (any all-numeric dotted host whose first octet is 127), not only the
    /// single literal 127.0.0.1.
    /// </summary>
    internal bool IsLoopback
    {
        get
        {
            if (string.Equals(Host, "localhost", StringComparison.OrdinalIgnoreCase))
                return true;
            var labels = Host.Split('.');
            return labels.Length >= 1 &&
                   labels[0] == "127" &&
                   labels.All(static label =>
                       label.Length > 0 && label.All(static character => character is >= '0' and <= '9'));
        }
    }

    /// <summary>Parses <c>host:port</c>; anything else (including a bare host) is unqualified.</summary>
    internal static NatsGatewayEndpoint Parse(string? qualified)
    {
        if (TryParse(qualified, out var endpoint) && endpoint is not null)
            return endpoint;
        throw new ArgumentException(
            $"The endpoint '{qualified ?? "<null>"}' is not a qualified host:port endpoint.",
            nameof(qualified));
    }

    internal static bool TryParse([NotNullWhen(true)] string? qualified, [NotNullWhen(true)] out NatsGatewayEndpoint? endpoint)
    {
        endpoint = null;
        if (qualified is null)
            return false;
        var separator = qualified.LastIndexOf(':');
        if (separator <= 0 || separator == qualified.Length - 1)
            return false;
        var host = qualified[..separator];
        var portText = qualified[(separator + 1)..];
        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
            port is < 1 or > 65535)
            return false;
        if (!IsValidHost(host))
            return false;
        endpoint = new NatsGatewayEndpoint(host, port);
        return true;
    }

    internal static bool IsValidHost(string? host)
    {
        if (host is not { Length: >= 1 and <= 253 })
            return false;
        if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
            return false; // bracket literals are not part of the accepted host grammar
        foreach (var label in host.Split('.'))
        {
            if (label is not { Length: >= 1 and <= 63 })
                return false;
            if (label[0] == '-' || label[^1] == '-')
                return false;
            if (!label.All(static character =>
                    character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-'))
                return false;
        }
        return true;
    }
}

/// <summary>
/// Shared validation for paths that are eventually handed to nats-server or
/// systemd. These values are rendered inside quoted configuration strings, so
/// the grammar deliberately permits only the portable path characters used by
/// the topology and rejects traversal, quoting, escaping, whitespace, and
/// control characters at the typed boundary.
/// </summary>
internal static class NatsGatewayPathRules
{
    internal static bool IsSafeAbsolutePath(string? path, string? requiredSuffix = null)
    {
        if (path is not { Length: >= 2 and <= 4096 } ||
            !Path.IsPathRooted(path) ||
            !path.StartsWith("/", StringComparison.Ordinal) ||
            path.Contains('\\') ||
            (requiredSuffix is not null && !path.EndsWith(requiredSuffix, StringComparison.Ordinal)))
            return false;

        foreach (var character in path)
        {
            if (character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '/' or '.' or '_' or '-' or '@' or '%' or ':' or '+'))
                return false;
        }

        var segments = path.Split('/');
        return segments[0].Length == 0 &&
               segments[1..].All(static segment => segment.Length > 0 && segment is not ("." or ".."));
    }
}

/// <summary>Validation for certificate identities carried in URI or DNS SANs.</summary>
internal static class NatsGatewayPeerIdentityRules
{
    internal static bool IsValid(string? identity)
    {
        if (identity is not { Length: >= 1 and <= 512 } ||
            identity.Any(static character =>
                character is '"' or '\'' or '\\' || char.IsWhiteSpace(character) || char.IsControl(character)))
            return false;

        if (!identity.StartsWith("spiffe://", StringComparison.Ordinal))
            return NatsGatewayEndpoint.IsValidHost(identity);

        if (!Uri.TryCreate(identity, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "spiffe", StringComparison.Ordinal) ||
            string.IsNullOrEmpty(uri.Host) ||
            !NatsGatewayEndpoint.IsValidHost(uri.Host) ||
            uri.Port != -1 ||
            uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 ||
            uri.UserInfo.Length != 0 ||
            identity.Contains('%', StringComparison.Ordinal))
            return false;

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length > 0 &&
               segments.All(static segment =>
                   segment.Length > 0 &&
                   segment is not ("." or "..") &&
                   segment.All(static character =>
                       character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.'));
    }
}

/// <summary>
/// The transport a certificate profile protects. Client, route, and gateway
/// transports always use separate certificate profiles with explicit expected
/// peer identities; one certificate never spans two transports.
/// </summary>
internal enum NatsGatewayTransport
{
    Client = 0,
    Route = 1,
    Gateway = 2,
}

/// <summary>
/// One mTLS certificate profile: file references only, never key material.
/// Every profile requires and verifies peer certificates against its CA and
/// names the peer identities (SPIFFE IDs or DNS names) it expects to see.
/// </summary>
internal sealed record NatsGatewayCertificateProfile
{
    internal NatsGatewayCertificateProfile(
        NatsGatewayTransport transport,
        string certificateFile,
        string keyFile,
        string caFile,
        IEnumerable<string> expectedPeerIdentities)
    {
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(certificateFile, ".pem"))
            throw new ArgumentException("The certificate profile requires an absolute .pem certificate path.", nameof(certificateFile));
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(keyFile, ".pem"))
            throw new ArgumentException("The certificate profile requires an absolute .pem key path.", nameof(keyFile));
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(caFile, ".pem"))
            throw new ArgumentException("The certificate profile requires an absolute .pem CA path.", nameof(caFile));
        ArgumentNullException.ThrowIfNull(expectedPeerIdentities);
        var peers = expectedPeerIdentities.ToArray();
        if (peers.Length == 0 || peers.Any(static identity => !NatsGatewayPeerIdentityRules.IsValid(identity)))
            throw new ArgumentException("The certificate profile must name at least one expected peer identity.", nameof(expectedPeerIdentities));
        if (peers.Distinct(StringComparer.Ordinal).Count() != peers.Length)
            throw new ArgumentException("The certificate profile must not repeat an expected peer identity.", nameof(expectedPeerIdentities));
        Transport = transport;
        CertificateFile = certificateFile;
        KeyFile = keyFile;
        CaFile = caFile;
        ExpectedPeerIdentities = Array.AsReadOnly(peers.Order(StringComparer.Ordinal).ToArray());
    }

    internal NatsGatewayTransport Transport { get; }
    internal string CertificateFile { get; }
    internal string KeyFile { get; }
    internal string CaFile { get; }
    internal IReadOnlyList<string> ExpectedPeerIdentities { get; }
}

/// <summary>
/// One immutable nats-server identity inside a regional cluster: server name,
/// failure-domain host, its client/route/gateway listener endpoints, and its
/// three mTLS certificate profiles (one per transport). Server names are
/// unique across the whole supercluster; a name never moves between cells,
/// planes, or hosts, and one certificate never spans two transports.
/// </summary>
internal sealed record NatsGatewayServerIdentity
{
    internal NatsGatewayServerIdentity(
        string serverName,
        string failureDomain,
        NatsGatewayEndpoint client,
        NatsGatewayEndpoint route,
        NatsGatewayEndpoint? gateway,
        IReadOnlyList<NatsGatewayCertificateProfile> certificateProfiles,
        NatsGatewayProcessIdentity process,
        string storeDirectory)
    {
        if (string.IsNullOrWhiteSpace(serverName) || serverName.Length > 128 ||
            !serverName.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'))
            throw new ArgumentException("The server name is not a bounded lowercase DNS-style token.", nameof(serverName));
        if (string.IsNullOrWhiteSpace(failureDomain) || failureDomain.Length > 253)
            throw new ArgumentException("The failure domain is not a bounded host identity.", nameof(failureDomain));
        if (certificateProfiles.Count(static profile => profile.Transport == NatsGatewayTransport.Client) != 1 ||
            certificateProfiles.Count(static profile => profile.Transport == NatsGatewayTransport.Route) != 1)
            throw new ArgumentException(
                "The server must declare exactly one certificate profile for each of client and route.",
                nameof(certificateProfiles));
        if ((gateway is null &&
                certificateProfiles.Any(static profile => profile.Transport == NatsGatewayTransport.Gateway)) ||
            (gateway is not null &&
                certificateProfiles.Count(static profile => profile.Transport == NatsGatewayTransport.Gateway) != 1))
            throw new ArgumentException(
                "A gateway certificate profile exists exactly when the server opens a gateway listener.",
                nameof(certificateProfiles));
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(storeDirectory))
            throw new ArgumentException("The store directory must be an absolute path without traversal.", nameof(storeDirectory));
        ServerName = serverName;
        FailureDomain = failureDomain;
        Client = client;
        Route = route;
        Gateway = gateway;
        CertificateProfiles = Array.AsReadOnly(certificateProfiles.ToArray());
        Process = process;
        StoreDirectory = storeDirectory;
    }

    internal string ServerName { get; }
    internal string FailureDomain { get; }
    internal NatsGatewayEndpoint Client { get; }
    internal NatsGatewayEndpoint Route { get; }

    /// <summary>Null on the product plane, which never opens a gateway listener.</summary>
    internal NatsGatewayEndpoint? Gateway { get; }

    internal IReadOnlyList<NatsGatewayCertificateProfile> CertificateProfiles { get; }

    /// <summary>The dedicated unit and cgroup of this server's process.</summary>
    internal NatsGatewayProcessIdentity Process { get; }

    /// <summary>This server's dedicated JetStream store directory; never shared with another server or plane.</summary>
    internal string StoreDirectory { get; }

    internal NatsGatewayCertificateProfile Profile(NatsGatewayTransport transport) =>
        CertificateProfiles.Single(profile => profile.Transport == transport);

    internal IEnumerable<NatsGatewayEndpoint> Listeners
    {
        get
        {
            yield return Client;
            yield return Route;
            if (Gateway is not null)
                yield return Gateway;
        }
    }
}

/// <summary>
/// The process identity of one nats-server: its dedicated systemd unit and
/// cgroup. The two planes never share a unit, cgroup, or cgroup slice, even
/// when decision 8A lets them share a physical host.
/// </summary>
internal sealed record NatsGatewayProcessIdentity
{
    internal NatsGatewayProcessIdentity(string unitName, string cgroup)
    {
        if (unitName.Length is < 1 or > 256 ||
            !unitName.EndsWith(".service", StringComparison.Ordinal) ||
            unitName.Any(static character =>
                character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '@' or '%' or '.' or ':')))
            throw new ArgumentException("The NATS process unit must be a bounded systemd unit name.", nameof(unitName));
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(cgroup))
            throw new ArgumentException("The NATS cgroup must be a bounded absolute cgroup path.", nameof(cgroup));
        UnitName = unitName;
        Cgroup = cgroup;
    }

    internal string UnitName { get; }
    internal string Cgroup { get; }
}

/// <summary>
/// The account limits one account scope enforces. Limits are explicit and
/// finite: unmeasured production sizing blocks deployment qualification, not
/// the typed contract.
/// </summary>
internal sealed record NatsGatewayAccountLimits
{
    internal NatsGatewayAccountLimits(
        int maxConnections,
        int maxSubscriptions,
        long maxPayloadBytes,
        int maxStreams,
        int maxConsumers,
        long maxDiskStorageBytes)
    {
        if (maxConnections < 1)
            throw new ArgumentOutOfRangeException(nameof(maxConnections), maxConnections, "The account limit must be positive.");
        if (maxSubscriptions < 1)
            throw new ArgumentOutOfRangeException(nameof(maxSubscriptions), maxSubscriptions, "The account limit must be positive.");
        if (maxPayloadBytes < 1)
            throw new ArgumentOutOfRangeException(nameof(maxPayloadBytes), maxPayloadBytes, "The account limit must be positive.");
        if (maxStreams < 0 || maxConsumers < 0)
            throw new ArgumentOutOfRangeException(nameof(maxStreams), "The stream and consumer limits must not be negative.");
        if (maxDiskStorageBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(maxDiskStorageBytes), maxDiskStorageBytes, "The account limit must not be negative.");
        MaxConnections = maxConnections;
        MaxSubscriptions = maxSubscriptions;
        MaxPayloadBytes = maxPayloadBytes;
        MaxStreams = maxStreams;
        MaxConsumers = maxConsumers;
        MaxDiskStorageBytes = maxDiskStorageBytes;
    }

    internal int MaxConnections { get; }
    internal int MaxSubscriptions { get; }
    internal long MaxPayloadBytes { get; }
    internal int MaxStreams { get; }
    internal int MaxConsumers { get; }
    internal long MaxDiskStorageBytes { get; }
}

/// <summary>
/// One separately scoped account inside the plane trust model: the owning
/// cell, its signing-key references (public names only, never seeds), its
/// user names, its limits, and the cross-account service exchanges granted to
/// it. Signing keys and users are names; credential material never appears in
/// a typed plan.
/// </summary>
internal sealed record NatsGatewayAccountScope
{
    internal NatsGatewayAccountScope(
        string cell,
        string accountName,
        IEnumerable<string> signingKeyNames,
        IEnumerable<string> users,
        NatsGatewayAccountLimits limits)
    {
        if (string.IsNullOrWhiteSpace(cell) || cell.Length > 63 ||
            !cell.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'))
            throw new ArgumentException("The account scope cell is not a bounded lowercase token.", nameof(cell));
        if (!GlobalNatsAccountNames.IsValid(accountName))
            throw new ArgumentException("The account scope name is not a valid NATS account name.", nameof(accountName));
        var keys = signingKeyNames.ToArray();
        if (keys.Length == 0 || keys.Any(static key => string.IsNullOrWhiteSpace(key) || key.Length > 128))
            throw new ArgumentException("The account scope must reference at least one signing key name.", nameof(signingKeyNames));
        var userNames = users.ToArray();
        if (userNames.Length == 0 ||
            userNames.Any(static user => user.Length is < 1 or > 128 ||
                !user.All(static character =>
                    character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.')))
            throw new ArgumentException("The account scope must name at least one bounded user.", nameof(users));
        Cell = cell;
        AccountName = accountName;
        SigningKeyNames = Array.AsReadOnly(keys.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
        Users = Array.AsReadOnly(userNames.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
        Limits = limits;
    }

    internal string Cell { get; }
    internal string AccountName { get; }
    internal IReadOnlyList<string> SigningKeyNames { get; }
    internal IReadOnlyList<string> Users { get; }
    internal NatsGatewayAccountLimits Limits { get; }
}

/// <summary>
/// An approved cross-account service export: the exporting account and the
/// exact versioned subject it exposes. Stream exports are not granted by this
/// type; only versioned control services may cross accounts.
/// </summary>
internal sealed record NatsGatewayServiceExport
{
    internal NatsGatewayServiceExport(string accountName, string subject)
    {
        if (!GlobalNatsAccountNames.IsValid(accountName))
            throw new ArgumentException("The exporting account name is invalid.", nameof(accountName));
        if (string.IsNullOrWhiteSpace(subject))
            throw new ArgumentException("The exported subject must be a concrete subject.", nameof(subject));
        AccountName = accountName;
        Subject = subject;
    }

    internal string AccountName { get; }
    internal string Subject { get; }
}

/// <summary>
/// An approved cross-account service import: the importing account, the exact
/// subject, and the exporting account it binds to. The local subject equals
/// the exported subject; no remapping and no wildcards.
/// </summary>
internal sealed record NatsGatewayServiceImport
{
    internal NatsGatewayServiceImport(string accountName, string subject, string sourceAccountName)
    {
        if (!GlobalNatsAccountNames.IsValid(accountName))
            throw new ArgumentException("The importing account name is invalid.", nameof(accountName));
        if (string.IsNullOrWhiteSpace(subject))
            throw new ArgumentException("The imported subject must be a concrete subject.", nameof(subject));
        if (!GlobalNatsAccountNames.IsValid(sourceAccountName))
            throw new ArgumentException("The source account name is invalid.", nameof(sourceAccountName));
        AccountName = accountName;
        Subject = subject;
        SourceAccountName = sourceAccountName;
    }

    internal string AccountName { get; }
    internal string Subject { get; }
    internal string SourceAccountName { get; }
}

/// <summary>One directed gateway relationship from one cell's cluster to another's.</summary>
internal sealed record NatsGatewayRelationship(string FromCell, string ToCell);

/// <summary>
/// One immutable regional cluster of the plane: cell, cluster name, JetStream
/// domain, server identities, account set, JetStream assets, process and
/// store identity, trust and configuration generations, and certificate
/// profiles. Clusters are immutable; every change is a new generation.
/// </summary>
internal sealed record NatsGatewayCluster
{
    internal const int ControlClientPort = 4222;
    internal const int ControlRoutePort = 6222;
    internal const int ControlGatewayPort = 7222;
    internal const int ProductClientPort = 4223;
    internal const int ProductRoutePort = 6223;

    internal NatsGatewayCluster(
        NatsGatewayPlane plane,
        string cell,
        string clusterName,
        string jetStreamDomain,
        string operatorName,
        IReadOnlyList<NatsGatewayServerIdentity> servers,
        IReadOnlyList<string> accounts,
        IReadOnlyList<string> jetStreamAssets,
        string cgroupSlice,
        int trustGeneration,
        int configurationGeneration)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The cluster cell is not a lowercase DNS-style token.", nameof(cell));
        if (string.IsNullOrWhiteSpace(clusterName) || clusterName.Length > 256)
            throw new ArgumentException("The cluster name must be bounded.", nameof(clusterName));
        if (string.IsNullOrWhiteSpace(jetStreamDomain) || jetStreamDomain.Length > 64 ||
            !jetStreamDomain.All(static character =>
                character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_'))
            throw new ArgumentException("The JetStream domain must be a bounded uppercase token.", nameof(jetStreamDomain));
        if (string.IsNullOrWhiteSpace(operatorName) || operatorName.Length > 128)
            throw new ArgumentException("The operator name must be bounded.", nameof(operatorName));
        if (servers.Count == 0)
            throw new ArgumentException("The cluster must declare at least one server.", nameof(servers));
        if (accounts.Count == 0 || accounts.Any(static account => !GlobalNatsAccountNames.IsValid(account)))
            throw new ArgumentException("The cluster must declare a non-empty set of valid account names.", nameof(accounts));
        if (jetStreamAssets.Any(static asset => string.IsNullOrWhiteSpace(asset) || asset.Length > 256))
            throw new ArgumentException("The JetStream asset names must be bounded.", nameof(jetStreamAssets));
        if (!NatsGatewayPathRules.IsSafeAbsolutePath(cgroupSlice))
            throw new ArgumentException("The cgroup slice must be a bounded absolute cgroup path.", nameof(cgroupSlice));
        if (trustGeneration < 1 || configurationGeneration < 1)
            throw new ArgumentException("The trust and configuration generations must be positive.", nameof(trustGeneration));
        if (plane == NatsGatewayPlane.Product && servers.Any(static server => server.Gateway is not null))
            throw new ArgumentException("A product-plane cluster must not declare a gateway listener.", nameof(servers));
        if (servers.Any(server => !server.Process.Cgroup.StartsWith(cgroupSlice + "/", StringComparison.Ordinal)))
            throw new ArgumentException(
                "Every server process cgroup must live inside the cluster's cgroup slice.", nameof(servers));
        Plane = plane;
        Cell = cell;
        ClusterName = clusterName;
        JetStreamDomain = jetStreamDomain;
        OperatorName = operatorName;
        Servers = Array.AsReadOnly(servers.ToArray());
        Accounts = Array.AsReadOnly(accounts.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
        JetStreamAssets = Array.AsReadOnly(jetStreamAssets.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
        CgroupSlice = cgroupSlice;
        TrustGeneration = trustGeneration;
        ConfigurationGeneration = configurationGeneration;
    }

    internal NatsGatewayPlane Plane { get; }
    internal string Cell { get; }
    internal string ClusterName { get; }
    internal string JetStreamDomain { get; }
    internal string OperatorName { get; }
    internal IReadOnlyList<NatsGatewayServerIdentity> Servers { get; }
    internal IReadOnlyList<string> Accounts { get; }

    /// <summary>Stream, KV, Object Store, and consumer names local to this cluster's domain.</summary>
    internal IReadOnlyList<string> JetStreamAssets { get; }

    /// <summary>The plane-scoped cgroup slice every server process of this cluster lives in.</summary>
    internal string CgroupSlice { get; }
    internal int TrustGeneration { get; }
    internal int ConfigurationGeneration { get; }

    internal NatsGatewayCertificateProfile Profile(string serverName, NatsGatewayTransport transport) =>
        Server(serverName).Profile(transport);

    internal NatsGatewayServerIdentity Server(string serverName) =>
        Servers.SingleOrDefault(server => server.ServerName == serverName)
            ?? throw new ArgumentException(
                $"The server '{serverName}' is not part of cluster '{ClusterName}'.", nameof(serverName));
}

/// <summary>
/// The complete typed plan for one NATS plane: its operator trust root, its
/// clusters, the directed gateway relationships between them, the separately
/// scoped account model, and the approved cross-account service exchanges.
/// Rendering and startup consume this plan; nothing renders a string first.
/// </summary>
internal sealed record NatsGatewayPlan
{
    internal NatsGatewayPlan(
        NatsGatewayPlane plane,
        string operatorName,
        int trustGeneration,
        int configurationGeneration,
        IReadOnlyList<NatsGatewayCluster> clusters,
        IReadOnlyList<NatsGatewayRelationship> gatewayRelationships,
        IReadOnlyList<NatsGatewayAccountScope> accounts,
        IReadOnlyList<NatsGatewayServiceExport> exports,
        IReadOnlyList<NatsGatewayServiceImport> imports)
    {
        if (string.IsNullOrWhiteSpace(operatorName) || operatorName.Length > 128)
            throw new ArgumentException("The operator name must be bounded.", nameof(operatorName));
        if (trustGeneration < 1 || configurationGeneration < 1)
            throw new ArgumentException("The trust and configuration generations must be positive.", nameof(trustGeneration));
        if (clusters.Count == 0)
            throw new ArgumentException("The plan must declare at least one cluster.", nameof(clusters));
        if (clusters.Any(cluster => cluster.Plane != plane))
            throw new ArgumentException("Every cluster in the plan must belong to the plan's plane.", nameof(clusters));
        if (clusters.Any(cluster => cluster.OperatorName != operatorName))
            throw new ArgumentException("Every cluster in the plan must share the plan's operator trust root.", nameof(clusters));
        if (accounts.Count == 0)
            throw new ArgumentException("The plan must declare at least one account scope.", nameof(accounts));
        Plane = plane;
        OperatorName = operatorName;
        TrustGeneration = trustGeneration;
        ConfigurationGeneration = configurationGeneration;
        Clusters = Array.AsReadOnly(clusters.ToArray());
        GatewayRelationships = Array.AsReadOnly(gatewayRelationships.ToArray());
        Accounts = Array.AsReadOnly(accounts.ToArray());
        Exports = Array.AsReadOnly(exports.ToArray());
        Imports = Array.AsReadOnly(imports.ToArray());
    }

    internal NatsGatewayPlane Plane { get; }
    internal string OperatorName { get; }
    internal int TrustGeneration { get; }
    internal int ConfigurationGeneration { get; }
    internal IReadOnlyList<NatsGatewayCluster> Clusters { get; }
    internal IReadOnlyList<NatsGatewayRelationship> GatewayRelationships { get; }
    internal IReadOnlyList<NatsGatewayAccountScope> Accounts { get; }
    internal IReadOnlyList<NatsGatewayServiceExport> Exports { get; }
    internal IReadOnlyList<NatsGatewayServiceImport> Imports { get; }

    internal NatsGatewayCluster? Cluster(string cell) =>
        Clusters.SingleOrDefault(cluster => cluster.Cell == cell);
}
