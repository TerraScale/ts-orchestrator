namespace TerraScale.Orchestrator.ControlPlane.Networking;

public sealed record NetworkRouteScope(NetworkCellId Cell,NetworkCellId PeerCell,NetworkId Network,NetworkSubnetId Subnet,NetworkRouteId Route,
    NetworkPeerId Peer,NetworkTunnelId Tunnel,NetworkTrustPlane TrustPlane,NetworkPrefix Destination,NetworkRouteKind RouteKind,
    NetworkOrdinal Generation,NetworkOrdinal Epoch,NetworkOperationId Operation)
{internal bool Valid=>Cell is not null&&PeerCell is not null&&Network is not null&&Subnet is not null&&Route is not null&&Peer is not null&&Tunnel is not null
    &&Enum.IsDefined(TrustPlane)&&TrustPlane!=NetworkTrustPlane.Unknown&&Destination is not null&&Enum.IsDefined(RouteKind)&&RouteKind!=NetworkRouteKind.Unknown
    &&Generation.IsValid&&Epoch.IsValid&&Operation is not null;public override string ToString()=>"<network-route-scope>";}

public sealed record NetworkRouteObservation(NetworkRouteId Route,NetworkCellId Owner,NetworkPeerId NextPeer,
    NetworkPeerId? LearnedFromPeer,NetworkTrustPlane TrustPlane,NetworkPrefix Destination);
public sealed record NetworkPeerLink(NetworkCellId From,NetworkCellId To);

public sealed class NetworkRouteEvidence
{
    private readonly NetworkRouteObservation[] _routes;private readonly NetworkPrefix[] _approved;private readonly NetworkPeerLink[] _links;private readonly NetworkCellId[] _cells;
    public NetworkRouteEvidence(NetworkRouteScope scope,IEnumerable<NetworkRouteObservation?>? routes,IEnumerable<NetworkPrefix?>? approved,
        IEnumerable<NetworkCellId?>? cells,IEnumerable<NetworkPeerLink?>? links,NetworkTopologyShape shape,NetworkProof noOverlappingMutation,NetworkProof localPolicy,
        NetworkProof tunnelConfigured,NetworkProof trafficProven,NetworkProof tunnelHealthy,NetworkProof routeConfigured,
        bool partitioned,int maximumRoutes,int maximumPrefixes,int maximumLinks,int maximumCells)
    {
        Scope=scope;Shape=shape;NoOverlappingMutation=noOverlappingMutation;LocalPolicy=localPolicy;
        TunnelConfigured=tunnelConfigured;TrafficProven=trafficProven;TunnelHealthy=tunnelHealthy;RouteConfigured=routeConfigured;Partitioned=partitioned;
        var r=routes?.ToArray()??[];var p=approved?.ToArray()??[];var l=links?.ToArray()??[];var c=cells?.ToArray()??[];
        var validCells=c.Length>0&&c.All(x=>x is not null)&&c.Distinct().Count()==c.Length;
        IsValid=scope is not null&&scope.Valid&&maximumRoutes>0&&maximumPrefixes>0&&maximumLinks>0&&maximumCells>0&&r.Length<=maximumRoutes&&p.Length>0&&p.Length<=maximumPrefixes&&l.Length<=maximumLinks&&c.Length<=maximumCells&&validCells
            &&c.Contains(scope.Cell)&&c.Contains(scope.PeerCell)
            &&r.All(x=>x is not null&&x.Route is not null&&x.Owner is not null&&x.NextPeer is not null&&x.Destination is not null&&Enum.IsDefined(x.TrustPlane)&&x.TrustPlane!=NetworkTrustPlane.Unknown)
            &&p.All(x=>x is not null)&&l.All(x=>x is not null&&x.From is not null&&x.To is not null&&x.From!=x.To&&c.Contains(x.From)&&c.Contains(x.To))
            &&Enum.IsDefined(shape)&&shape!=NetworkTopologyShape.Unknown
            &&Enum.IsDefined(noOverlappingMutation)&&Enum.IsDefined(localPolicy)&&Enum.IsDefined(tunnelConfigured)&&Enum.IsDefined(trafficProven)
            &&Enum.IsDefined(tunnelHealthy)&&Enum.IsDefined(routeConfigured);
        _routes=r.Where(x=>x is not null).Cast<NetworkRouteObservation>().ToArray();_approved=p.Where(x=>x is not null).Cast<NetworkPrefix>().ToArray();_links=l.Where(x=>x is not null).Cast<NetworkPeerLink>().ToArray();_cells=c.Where(x=>x is not null).Cast<NetworkCellId>().ToArray();
    }
    public NetworkRouteScope Scope{get;}public NetworkTopologyShape Shape{get;}public uint CellCount=>(uint)_cells.Length;public NetworkProof NoOverlappingMutation{get;}public NetworkProof LocalPolicy{get;}
    public NetworkProof TunnelConfigured{get;}public NetworkProof TrafficProven{get;}public NetworkProof TunnelHealthy{get;}public NetworkProof RouteConfigured{get;}public bool Partitioned{get;}public bool IsValid{get;}
    public IReadOnlyList<NetworkRouteObservation> Routes=>Array.AsReadOnly(_routes);public IReadOnlyList<NetworkPrefix> ApprovedPrefixes=>Array.AsReadOnly(_approved);
    public IReadOnlyList<NetworkPeerLink> Links=>Array.AsReadOnly(_links);
    public IReadOnlyList<NetworkCellId> Cells=>Array.AsReadOnly(_cells);
}

public static class NetworkRoutePlanner
{
    public static NetworkDecision Plan(NetworkRouteScope? expected,NetworkOrdinal observedGeneration,NetworkOrdinal observedEpoch,NetworkRouteEvidence? e)
    {
        if(expected is null||!expected.Valid)return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope);
        var trace=new NetworkNumericTrace(expected.Generation,expected.Epoch,(uint)(e?.Routes.Count??0),e is null?0:(uint)e.Routes.Select(x=>x.NextPeer).Distinct().Count());
        if(e is null||!e.IsValid||e.Scope!=expected)return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope,trace);
        if(observedGeneration.Value<expected.Generation.Value||observedEpoch.Value<expected.Epoch.Value)return NetworkDecision.Hold(NetworkCode.StaleGeneration,trace);
        if(observedGeneration.Value>expected.Generation.Value||observedEpoch.Value>expected.Epoch.Value)return NetworkDecision.Hold(NetworkCode.FutureGeneration,trace);
        if(e.CellCount==0||e.Links.Select(x=>(x.From,x.To)).Distinct().Count()!=e.Links.Count)return NetworkDecision.Hold(NetworkCode.InvalidInput,trace);
        if(!TopologyMatchesDeclaredShape(e))return NetworkDecision.Hold(NetworkCode.QuadraticMesh,trace);
        if(expected.RouteKind!=NetworkRouteKind.Local&&!e.Links.Any(x=>x.From==expected.Cell&&x.To==expected.PeerCell))return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope,trace);
        if(e.NoOverlappingMutation!=NetworkProof.Proven)return NetworkDecision.Hold(NetworkCode.AmbiguousOwnership,trace);
        if(!e.ApprovedPrefixes.Any(prefix=>prefix.Contains(expected.Destination)))return NetworkDecision.Hold(NetworkCode.RouteLeak,trace);
        if(e.Routes.Select(x=>x.Route).Distinct().Count()!=e.Routes.Count)return NetworkDecision.Hold(NetworkCode.Duplicate,trace);
        if(e.Routes.GroupBy(x=>(x.Destination,x.NextPeer)).Any(group=>group.Count()>1))return NetworkDecision.Hold(NetworkCode.Duplicate,trace);
        foreach(var route in e.Routes)
        {
            if(route.Owner!=expected.Cell)return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope,trace);
            if(route.TrustPlane!=expected.TrustPlane)return NetworkDecision.Hold(NetworkCode.TrustPlaneCrossover,trace);
            if(!e.ApprovedPrefixes.Any(prefix=>prefix.Contains(route.Destination)))return NetworkDecision.Hold(NetworkCode.RouteLeak,trace);
            if(route.LearnedFromPeer==expected.Peer&&route.NextPeer==expected.Peer)return NetworkDecision.Hold(NetworkCode.Reflection,trace);
            if(route.Destination.Equals(expected.Destination)&&route.NextPeer!=expected.Peer)return NetworkDecision.Hold(NetworkCode.AmbiguousOwnership,trace);
            if(route.Destination.Overlaps(expected.Destination)&&route.NextPeer!=expected.Peer)return NetworkDecision.Hold(NetworkCode.Overlap,trace);
        }
        var subject=new NetworkRouteIntentSubject(expected.Cell,expected.PeerCell,expected.Network,expected.Subnet,expected.Route,expected.Peer,expected.Tunnel,
            expected.TrustPlane,expected.RouteKind,expected.Destination,expected.Generation,expected.Epoch,expected.Operation);
        if(e.Partitioned)
        {
            if(e.LocalPolicy!=NetworkProof.Proven)return NetworkDecision.Hold(NetworkCode.LocalPolicyRequired,trace);
            if(expected.TrustPlane!=NetworkTrustPlane.Product||expected.RouteKind!=NetworkRouteKind.Local)return NetworkDecision.Hold(NetworkCode.PartitionAuthorityDenied,trace);
        }
        if(e.TunnelConfigured!=NetworkProof.Proven)return NetworkDecision.Emit(NetworkAction.ConfigureTunnel,NetworkTarget.Tunnel,NetworkCode.NextStep,subject,trace);
        if(e.TunnelHealthy==NetworkProof.Contradicted||e.TrafficProven==NetworkProof.Contradicted)
            return NetworkDecision.Emit(NetworkAction.Rollback,NetworkTarget.Tunnel,NetworkCode.TunnelHealthRequired,subject,trace);
        if(e.TunnelHealthy!=NetworkProof.Proven||e.TrafficProven!=NetworkProof.Proven)
            return NetworkDecision.Emit(NetworkAction.Observe,NetworkTarget.Tunnel,NetworkCode.TunnelHealthRequired,subject,trace);
        if(e.RouteConfigured!=NetworkProof.Proven)return NetworkDecision.Emit(NetworkAction.ConfigureRoute,NetworkTarget.Route,NetworkCode.NextStep,subject,trace);
        return NetworkDecision.Emit(NetworkAction.Verify,NetworkTarget.Route,NetworkCode.Completed,subject,trace);
    }

    private static bool TopologyMatchesDeclaredShape(NetworkRouteEvidence e)
    {
        var cells=(ulong)e.CellCount;var links=(ulong)e.Links.Count;
        if(e.Shape==NetworkTopologyShape.InitialThreeFullMesh)
            return cells==3&&links==6&&e.Cells.All(from=>e.Cells.Where(to=>to!=from).All(to=>e.Links.Any(link=>link.From==from&&link.To==to)));
        if(e.Shape==NetworkTopologyShape.ExplicitReplication)return links<=checked(cells*2);
        if(e.Shape!=NetworkTopologyShape.HubAndSpoke||cells<3||links!=checked(2*(cells-1)))return false;
        return e.Cells.Count(hub=>e.Links.All(link=>link.From==hub||link.To==hub)
            &&e.Cells.Where(spoke=>spoke!=hub).All(spoke=>e.Links.Any(link=>link.From==hub&&link.To==spoke)
                &&e.Links.Any(link=>link.From==spoke&&link.To==hub)))==1;
    }
}
