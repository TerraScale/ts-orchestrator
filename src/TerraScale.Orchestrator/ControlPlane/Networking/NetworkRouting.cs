namespace TerraScale.Orchestrator.ControlPlane.Networking;

public sealed record NetworkRouteScope(NetworkCellId Cell, NetworkCellId PeerCell, NetworkId Network, NetworkSubnetId Subnet, NetworkRouteId Route,
    NetworkPeerId Peer, NetworkTunnelId Tunnel, NetworkTrustPlane TrustPlane, NetworkPrefix Destination, NetworkRouteKind RouteKind,
    NetworkOrdinal Generation, NetworkOrdinal Epoch, NetworkOperationId Operation)
{
    internal bool Valid => Cell is not null && PeerCell is not null && Network is not null && Subnet is not null && Route is not null && Peer is not null && Tunnel is not null
    && Enum.IsDefined(TrustPlane) && TrustPlane != NetworkTrustPlane.Unknown && Destination is not null && Enum.IsDefined(RouteKind) && RouteKind != NetworkRouteKind.Unknown
    && Generation.IsValid && Epoch.IsValid && Operation is not null; public override string ToString() => "<network-route-scope>";
}

public sealed record NetworkRouteObservation(NetworkRouteId Route, NetworkCellId Owner, NetworkPeerId NextPeer,
    NetworkPeerId? LearnedFromPeer, NetworkTrustPlane TrustPlane, NetworkPrefix Destination);
public sealed record NetworkPeerLink(NetworkCellId From, NetworkCellId To);

public sealed class NetworkRouteEvidence : IEquatable<NetworkRouteEvidence>
{
    private readonly NetworkRouteObservation[] _routes; private readonly NetworkPrefix[] _approved; private readonly NetworkPeerLink[] _links; private readonly NetworkCellId[] _cells;
    public NetworkRouteEvidence(NetworkRouteScope scope, IEnumerable<NetworkRouteObservation?>? routes, IEnumerable<NetworkPrefix?>? approved,
        IEnumerable<NetworkCellId?>? cells, IEnumerable<NetworkPeerLink?>? links, NetworkTopologyShape shape, NetworkProof noOverlappingMutation, NetworkProof localPolicy,
        NetworkProof tunnelConfigured, NetworkProof trafficProven, NetworkProof tunnelHealthy, NetworkProof routeConfigured,
        bool partitioned, int maximumRoutes, int maximumPrefixes, int maximumLinks, int maximumCells)
    {
        Scope = scope; Shape = shape; NoOverlappingMutation = noOverlappingMutation; LocalPolicy = localPolicy;
        TunnelConfigured = tunnelConfigured; TrafficProven = trafficProven; TunnelHealthy = tunnelHealthy; RouteConfigured = routeConfigured; Partitioned = partitioned;
        var r = routes is null ? [] : NetworkInputSnapshot.Copy(routes, NetworkTechnicalLimits.MaximumCapturedItems, nameof(routes));
        var p = approved is null ? [] : NetworkInputSnapshot.Copy(approved, NetworkTechnicalLimits.MaximumCapturedItems, nameof(approved));
        var l = links is null ? [] : NetworkInputSnapshot.Copy(links, NetworkTechnicalLimits.MaximumCapturedItems, nameof(links));
        var c = cells is null ? [] : NetworkInputSnapshot.Copy(cells, NetworkTechnicalLimits.MaximumCapturedItems, nameof(cells));
        var validCells = c.Length > 0 && c.All(x => x is not null) && c.Distinct().Count() == c.Length;
        IsValid = scope is not null && scope.Valid && maximumRoutes > 0 && maximumPrefixes > 0 && maximumLinks > 0 && maximumCells > 0 && r.Length <= maximumRoutes && p.Length > 0 && p.Length <= maximumPrefixes && l.Length <= maximumLinks && c.Length <= maximumCells && validCells
            && c.Contains(scope.Cell) && c.Contains(scope.PeerCell)
            && r.All(x => x is not null && x.Route is not null && x.Owner is not null && x.NextPeer is not null && x.Destination is not null && Enum.IsDefined(x.TrustPlane) && x.TrustPlane != NetworkTrustPlane.Unknown)
            && p.All(x => x is not null) && l.All(x => x is not null && x.From is not null && x.To is not null && x.From != x.To && c.Contains(x.From) && c.Contains(x.To))
            && Enum.IsDefined(shape) && shape != NetworkTopologyShape.Unknown
            && Enum.IsDefined(noOverlappingMutation) && Enum.IsDefined(localPolicy) && Enum.IsDefined(tunnelConfigured) && Enum.IsDefined(trafficProven)
            && Enum.IsDefined(tunnelHealthy) && Enum.IsDefined(routeConfigured);
        _routes = r.Where(x => x is not null).Cast<NetworkRouteObservation>().ToArray(); _approved = p.Where(x => x is not null).Cast<NetworkPrefix>().ToArray(); _links = l.Where(x => x is not null).Cast<NetworkPeerLink>().ToArray(); _cells = c.Where(x => x is not null).Cast<NetworkCellId>().ToArray();
    }
    public NetworkRouteScope Scope { get; }
    public NetworkTopologyShape Shape { get; }
    public uint CellCount => (uint)_cells.Length; public NetworkProof NoOverlappingMutation { get; }
    public NetworkProof LocalPolicy { get; }
    public NetworkProof TunnelConfigured { get; }
    public NetworkProof TrafficProven { get; }
    public NetworkProof TunnelHealthy { get; }
    public NetworkProof RouteConfigured { get; }
    public bool Partitioned { get; }
    public bool IsValid { get; }
    public IReadOnlyList<NetworkRouteObservation> Routes => Array.AsReadOnly(_routes); public IReadOnlyList<NetworkPrefix> ApprovedPrefixes => Array.AsReadOnly(_approved);
    public IReadOnlyList<NetworkPeerLink> Links => Array.AsReadOnly(_links);
    public IReadOnlyList<NetworkCellId> Cells => Array.AsReadOnly(_cells);

    public bool Equals(NetworkRouteEvidence? other) => other is not null && Scope == other.Scope && Shape == other.Shape
        && NoOverlappingMutation == other.NoOverlappingMutation && LocalPolicy == other.LocalPolicy && TunnelConfigured == other.TunnelConfigured
        && TrafficProven == other.TrafficProven && TunnelHealthy == other.TunnelHealthy && RouteConfigured == other.RouteConfigured
        && Partitioned == other.Partitioned && IsValid == other.IsValid
        && Canonical(_routes, RouteKey).SequenceEqual(Canonical(other._routes, RouteKey), StringComparer.Ordinal)
        && Canonical(_approved, PrefixKey).SequenceEqual(Canonical(other._approved, PrefixKey), StringComparer.Ordinal)
        && Canonical(_links, LinkKey).SequenceEqual(Canonical(other._links, LinkKey), StringComparer.Ordinal)
        && Canonical(_cells, static value => IdentityKey(value)).SequenceEqual(Canonical(other._cells, static value => IdentityKey(value)), StringComparer.Ordinal);
    public override bool Equals(object? value) => Equals(value as NetworkRouteEvidence);
    public override int GetHashCode()
    {
        var hash = new HashCode(); hash.Add(Scope); hash.Add(Shape); hash.Add(NoOverlappingMutation); hash.Add(LocalPolicy); hash.Add(TunnelConfigured);
        hash.Add(TrafficProven); hash.Add(TunnelHealthy); hash.Add(RouteConfigured); hash.Add(Partitioned); hash.Add(IsValid);
        Add(ref hash, "routes", Canonical(_routes, RouteKey)); Add(ref hash, "prefixes", Canonical(_approved, PrefixKey));
        Add(ref hash, "links", Canonical(_links, LinkKey)); Add(ref hash, "cells", Canonical(_cells, static value => IdentityKey(value)));
        return hash.ToHashCode();
    }
    private static string[] Canonical<T>(IEnumerable<T> values, Func<T, string> key) => values.Select(key).Order(StringComparer.Ordinal).ToArray();
    private static void Add(ref HashCode hash, string type, IReadOnlyList<string> values)
    { hash.Add(type, StringComparer.Ordinal); hash.Add(values.Count); foreach (var value in values) hash.Add(value, StringComparer.Ordinal); }
    private static string Frame(string value) => $"{value.Length}:{value}";
    private static string IdentityKey(NetworkIdentity value) => $"identity:{Frame(value.GetType().FullName!)}:{Frame(value.Value)}";
    private static string PrefixKey(NetworkPrefix value) => $"prefix:{value.Address.BitLength}:{Convert.ToHexString(value.Address.Bytes)}:{value.Bits}";
    private static string RouteKey(NetworkRouteObservation value) => $"route:{IdentityKey(value.Route)}:{IdentityKey(value.Owner)}:{IdentityKey(value.NextPeer)}:{(value.LearnedFromPeer is null ? "null" : IdentityKey(value.LearnedFromPeer))}:{(int)value.TrustPlane}:{PrefixKey(value.Destination)}";
    private static string LinkKey(NetworkPeerLink value) => $"link:{IdentityKey(value.From)}:{IdentityKey(value.To)}";
}

public static class NetworkRoutePlanner
{
    public static NetworkDecision Plan(NetworkRouteScope? expected, NetworkOrdinal observedGeneration, NetworkOrdinal observedEpoch, NetworkRouteEvidence? e)
    {
        if (expected is null || !expected.Valid) return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope);
        var trace = new NetworkNumericTrace(expected.Generation, expected.Epoch, (uint)(e?.Routes.Count ?? 0), e is null ? 0 : (uint)e.Routes.Select(x => x.NextPeer).Distinct().Count());
        if (e is null || !e.IsValid || e.Scope != expected) return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope, trace);
        if (observedGeneration.Value < expected.Generation.Value || observedEpoch.Value < expected.Epoch.Value) return NetworkDecision.Hold(NetworkCode.StaleGeneration, trace);
        if (observedGeneration.Value > expected.Generation.Value || observedEpoch.Value > expected.Epoch.Value) return NetworkDecision.Hold(NetworkCode.FutureGeneration, trace);
        if (e.CellCount == 0 || e.Links.Select(x => (x.From, x.To)).Distinct().Count() != e.Links.Count) return NetworkDecision.Hold(NetworkCode.InvalidInput, trace);
        if (!TopologyMatchesDeclaredShape(e)) return NetworkDecision.Hold(NetworkCode.QuadraticMesh, trace);
        if (expected.RouteKind != NetworkRouteKind.Local && !e.Links.Any(x => x.From == expected.Cell && x.To == expected.PeerCell)) return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope, trace);
        if (e.NoOverlappingMutation != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.AmbiguousOwnership, trace);
        if (!e.ApprovedPrefixes.Any(prefix => prefix.Contains(expected.Destination))) return NetworkDecision.Hold(NetworkCode.RouteLeak, trace);
        if (e.Routes.Select(x => x.Route).Distinct().Count() != e.Routes.Count) return NetworkDecision.Hold(NetworkCode.Duplicate, trace);
        if (e.Routes.GroupBy(x => (x.Destination, x.NextPeer)).Any(group => group.Count() > 1)) return NetworkDecision.Hold(NetworkCode.Duplicate, trace);
        if (e.Routes.Any(route => route.Owner != expected.Cell)) return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope, trace);
        if (e.Routes.Any(route => route.TrustPlane != expected.TrustPlane)) return NetworkDecision.Hold(NetworkCode.TrustPlaneCrossover, trace);
        if (e.Routes.Any(route => !e.ApprovedPrefixes.Any(prefix => prefix.Contains(route.Destination)))) return NetworkDecision.Hold(NetworkCode.RouteLeak, trace);
        if (e.Routes.Any(route => route.LearnedFromPeer == expected.Peer && route.NextPeer == expected.Peer)) return NetworkDecision.Hold(NetworkCode.Reflection, trace);
        if (e.Routes.Any(route => route.Destination.Equals(expected.Destination) && route.NextPeer != expected.Peer)) return NetworkDecision.Hold(NetworkCode.AmbiguousOwnership, trace);
        if (e.Routes.Any(route => route.Destination.Overlaps(expected.Destination) && route.NextPeer != expected.Peer)) return NetworkDecision.Hold(NetworkCode.Overlap, trace);
        if (expected.RouteKind == NetworkRouteKind.Local && expected.PeerCell != expected.Cell)
        {
            if (e.Partitioned && e.LocalPolicy != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.LocalPolicyRequired, trace);
            return NetworkDecision.Hold(e.Partitioned ? NetworkCode.PartitionAuthorityDenied : NetworkCode.WrongEvidenceScope, trace);
        }
        var subject = new NetworkRouteIntentSubject(expected, observedGeneration, observedEpoch, e);
        if (e.Partitioned)
        {
            if (e.LocalPolicy != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.LocalPolicyRequired, trace);
            if (expected.TrustPlane != NetworkTrustPlane.Product || expected.RouteKind != NetworkRouteKind.Local) return NetworkDecision.Hold(NetworkCode.PartitionAuthorityDenied, trace);
        }
        if (e.TunnelConfigured != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.ConfigureTunnel, NetworkTarget.Tunnel, NetworkCode.NextStep, subject, trace);
        if (e.TunnelHealthy == NetworkProof.Contradicted || e.TrafficProven == NetworkProof.Contradicted)
            return NetworkDecision.Emit(NetworkAction.Rollback, NetworkTarget.Tunnel, NetworkCode.TunnelHealthRequired, subject, trace);
        if (e.TunnelHealthy != NetworkProof.Proven || e.TrafficProven != NetworkProof.Proven)
            return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.Tunnel, NetworkCode.TunnelHealthRequired, subject, trace);
        if (e.RouteConfigured != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.ConfigureRoute, NetworkTarget.Route, NetworkCode.NextStep, subject, trace);
        return NetworkDecision.Emit(NetworkAction.Verify, NetworkTarget.Route, NetworkCode.Completed, subject, trace);
    }

    private static bool TopologyMatchesDeclaredShape(NetworkRouteEvidence e)
    {
        var cells = (ulong)e.CellCount; var links = (ulong)e.Links.Count;
        if (e.Shape == NetworkTopologyShape.InitialThreeFullMesh)
            return cells == 3 && links == 6 && e.Cells.All(from => e.Cells.Where(to => to != from).All(to => e.Links.Any(link => link.From == from && link.To == to)));
        if (e.Shape == NetworkTopologyShape.ExplicitReplication) return links <= checked(cells * 2);
        if (e.Shape != NetworkTopologyShape.HubAndSpoke || cells < 3 || links != checked(2 * (cells - 1))) return false;
        return e.Cells.Count(hub => e.Links.All(link => link.From == hub || link.To == hub)
            && e.Cells.Where(spoke => spoke != hub).All(spoke => e.Links.Any(link => link.From == hub && link.To == spoke)
                && e.Links.Any(link => link.From == spoke && link.To == hub))) == 1;
    }
}
