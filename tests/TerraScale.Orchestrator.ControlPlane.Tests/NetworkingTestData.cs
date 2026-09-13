using TerraScale.Orchestrator.ControlPlane.Networking;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class NetworkingTestData
{
    private const int M = 64;
    public static NetworkCellId Cell(string v = "gru") { NetworkCellId.TryCreate(v, M, out var x); return x!; }
    public static NetworkId Net(string v = "net") { NetworkId.TryCreate(v, M, out var x); return x!; }
    public static NetworkSubnetId Subnet(string v = "subnet") { NetworkSubnetId.TryCreate(v, M, out var x); return x!; }
    public static NetworkNodeId Node(string v = "node") { NetworkNodeId.TryCreate(v, M, out var x); return x!; }
    public static NetworkWorkloadId Workload(string v = "platform") { NetworkWorkloadId.TryCreate(v, M, out var x); return x!; }
    public static NetworkServiceId Service(string v = "service") { NetworkServiceId.TryCreate(v, M, out var x); return x!; }
    public static NetworkEndpointId Endpoint(string v = "endpoint") { NetworkEndpointId.TryCreate(v, M, out var x); return x!; }
    public static NetworkRouteId Route(string v = "route") { NetworkRouteId.TryCreate(v, M, out var x); return x!; }
    public static NetworkPeerId Peer(string v = "peer") { NetworkPeerId.TryCreate(v, M, out var x); return x!; }
    public static NetworkTunnelId Tunnel(string v = "tunnel") { NetworkTunnelId.TryCreate(v, M, out var x); return x!; }
    public static NetworkDnsId Dns(string v = "dns") { NetworkDnsId.TryCreate(v, M, out var x); return x!; }
    public static NetworkLoadBalancerId Lb(string v = "lb") { NetworkLoadBalancerId.TryCreate(v, M, out var x); return x!; }
    public static NetworkBackendId Backend(string v = "backend") { NetworkBackendId.TryCreate(v, M, out var x); return x!; }
    public static NetworkCertificateRef Cert(string v = "cert-ref") { NetworkCertificateRef.TryCreate(v, M, out var x); return x!; }
    public static NetworkOperationId Op(string v = "op") { NetworkOperationId.TryCreate(v, M, out var x); return x!; }
    public static NetworkOrdinal O(ulong v) { NetworkOrdinal.TryCreate(v, out var x); return x; }
    public static NetworkPort Port(ushort v = 443) { NetworkPort.TryCreate(v, out var x); return x; }
    public static NetworkPrefix Prefix(byte a, byte b = 0, byte c = 0, byte d = 0, byte bits = 8) { NetworkAddress.TryCreate([a, b, c, d], out var address); NetworkPrefix.TryCreate(address, bits, out var prefix); return prefix!; }
    public static NetworkRouteScope RouteScope(NetworkPrefix? destination = null, NetworkTrustPlane plane = NetworkTrustPlane.Product,
        NetworkRouteKind kind = NetworkRouteKind.Peer, NetworkCellId? peerCell = null) =>
        new(Cell(), peerCell ?? Cell("sfo"), Net(), Subnet(), Route(), Peer(), Tunnel(), plane, destination ?? Prefix(10), kind, O(7), O(3), Op());
    public static NetworkRouteEvidence RouteEvidence(NetworkRouteScope? scope = null, IEnumerable<NetworkRouteObservation?>? routes = null,
        IEnumerable<NetworkPrefix?>? approved = null, IEnumerable<NetworkCellId?>? cellInventory = null, IEnumerable<NetworkPeerLink?>? links = null,
        NetworkTopologyShape shape = NetworkTopologyShape.HubAndSpoke, uint cells = 20,
        NetworkProof noMutation = NetworkProof.Proven, NetworkProof local = NetworkProof.Proven, NetworkProof configured = NetworkProof.Proven,
        NetworkProof traffic = NetworkProof.Proven, NetworkProof healthy = NetworkProof.Proven, NetworkProof routeConfigured = NetworkProof.Proven,
        bool partitioned = false, int maximumCells = 32) =>
        new(scope ?? RouteScope(), routes ?? [], approved ?? [Prefix(10)], cellInventory ?? Cells(cells), links ?? HubLinks(cells), shape, noMutation, local,
            configured, traffic, healthy, routeConfigured, partitioned, 32, 16, 64, maximumCells);
    private static NetworkCellId[] Cells(uint count) => Enumerable.Range(0, (int)count).Select(i => i switch { 0 => Cell(), 1 => Cell("sfo"), _ => Cell($"cell{i}") }).ToArray();
    private static NetworkPeerLink[] HubLinks(uint count) { var cells = Cells(count); return cells.Skip(1).SelectMany(cell => new[] { new NetworkPeerLink(cells[0], cell), new NetworkPeerLink(cell, cells[0]) }).ToArray(); }
    public static NetworkEndpointScope EndpointScope(NetworkExposure exposure = NetworkExposure.Public, NetworkServiceKind kind = NetworkServiceKind.Product,
        NetworkCertificateRef? cert = null, NetworkOrdinal? generation = null) => new(Cell(), Workload(), Service(), Endpoint(), Node(), Lb(), Backend(), Dns(), cert ?? Cert(), kind, exposure,
            NetworkProtocol.Https, Port(), generation ?? O(9), O(4), Op());
    public static NetworkEndpointEvidence EndpointEvidence(NetworkEndpointScope? scope = null, NetworkHealth health = NetworkHealth.Healthy,
        NetworkProof admitted = NetworkProof.Proven, NetworkProof processLive = NetworkProof.Proven, NetworkProof ready = NetworkProof.Proven, NetworkProof cert = NetworkProof.Proven,
        NetworkProof publicApproved = NetworkProof.Proven, NetworkProof gates = NetworkProof.Proven, NetworkProof withdrawalTested = NetworkProof.Proven,
        NetworkProof registered = NetworkProof.Proven, NetworkProof promoted = NetworkProof.Proven, NetworkProof dnsRequested = NetworkProof.Proven,
        NetworkProof dnsObserved = NetworkProof.Proven, NetworkProof deregistered = NetworkProof.Proven, NetworkProof drained = NetworkProof.Proven,
        NetworkProof dnsWithdrawalRequested = NetworkProof.Proven, NetworkProof dnsWithdrawn = NetworkProof.Proven,
        NetworkProof lbWithdrawalRequested = NetworkProof.Proven, NetworkProof lbWithdrawn = NetworkProof.Proven,
        NetworkProof deregistrationRequested = NetworkProof.Proven) =>
        new(scope ?? EndpointScope(), scope?.ServiceGeneration ?? O(9), scope?.Epoch ?? O(4), admitted, processLive, ready, health, cert, NetworkProof.Proven,
            publicApproved, gates, withdrawalTested, registered, promoted, dnsRequested, dnsObserved, deregistered, drained,
            dnsWithdrawalRequested, dnsWithdrawn, lbWithdrawalRequested, lbWithdrawn, deregistrationRequested);
}

