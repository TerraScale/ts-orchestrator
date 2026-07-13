namespace TerraScale.Orchestrator.ControlPlane.Networking;

public sealed record NetworkRouteScope(NetworkCellId Cell,NetworkId Network,NetworkSubnetId Subnet,NetworkRouteId Route,
    NetworkPeerId Peer,NetworkTunnelId Tunnel,NetworkTrustPlane TrustPlane,NetworkPrefix Destination,NetworkRouteKind RouteKind,
    NetworkOrdinal Generation,NetworkOrdinal Epoch,NetworkOperationId Operation)
{internal bool Valid=>Cell is not null&&Network is not null&&Subnet is not null&&Route is not null&&Peer is not null&&Tunnel is not null
    &&TrustPlane!=NetworkTrustPlane.Unknown&&Destination is not null&&RouteKind!=NetworkRouteKind.Unknown&&Generation.IsValid&&Epoch.IsValid&&Operation is not null;public override string ToString()=>"<network-route-scope>";}

public sealed record NetworkRouteObservation(NetworkRouteId Route,NetworkCellId Owner,NetworkPeerId NextPeer,
    NetworkPeerId? LearnedFromPeer,NetworkTrustPlane TrustPlane,NetworkPrefix Destination);

public sealed class NetworkRouteEvidence
{
    private readonly NetworkRouteObservation[] _routes;private readonly NetworkPrefix[] _approved;
    public NetworkRouteEvidence(NetworkRouteScope scope,IEnumerable<NetworkRouteObservation?>? routes,IEnumerable<NetworkPrefix?>? approved,
        NetworkTopologyShape shape,uint cellCount,NetworkProof noOverlappingMutation,NetworkProof localPolicy,
        NetworkProof tunnelConfigured,NetworkProof trafficProven,NetworkProof tunnelHealthy,NetworkProof routeConfigured,
        bool partitioned,int maximumRoutes,int maximumPrefixes)
    {
        Scope=scope;Shape=shape;CellCount=cellCount;NoOverlappingMutation=noOverlappingMutation;LocalPolicy=localPolicy;
        TunnelConfigured=tunnelConfigured;TrafficProven=trafficProven;TunnelHealthy=tunnelHealthy;RouteConfigured=routeConfigured;Partitioned=partitioned;
        var r=routes?.ToArray()??[];var p=approved?.ToArray()??[];IsValid=scope is not null&&scope.Valid&&maximumRoutes>0&&maximumPrefixes>0&&r.Length<=maximumRoutes&&p.Length>0&&p.Length<=maximumPrefixes&&r.All(x=>x is not null)&&p.All(x=>x is not null);
        _routes=r.Where(x=>x is not null).Cast<NetworkRouteObservation>().ToArray();_approved=p.Where(x=>x is not null).Cast<NetworkPrefix>().ToArray();
    }
    public NetworkRouteScope Scope{get;}public NetworkTopologyShape Shape{get;}public uint CellCount{get;}public NetworkProof NoOverlappingMutation{get;}public NetworkProof LocalPolicy{get;}
    public NetworkProof TunnelConfigured{get;}public NetworkProof TrafficProven{get;}public NetworkProof TunnelHealthy{get;}public NetworkProof RouteConfigured{get;}public bool Partitioned{get;}public bool IsValid{get;}
    public IReadOnlyList<NetworkRouteObservation> Routes=>Array.AsReadOnly(_routes);public IReadOnlyList<NetworkPrefix> ApprovedPrefixes=>Array.AsReadOnly(_approved);
}

public static class NetworkRoutePlanner
{
    public static NetworkDecision Plan(NetworkRouteScope expected,NetworkOrdinal observedGeneration,NetworkOrdinal observedEpoch,NetworkRouteEvidence? e)
    {
        var trace=new NetworkNumericTrace(expected.Generation,expected.Epoch,(uint)(e?.Routes.Count??0),e is null?0:(uint)e.Routes.Select(x=>x.NextPeer).Distinct().Count());
        if(e is null||!e.IsValid||e.Scope!=expected)return NetworkDecision.Hold(NetworkCode.WrongEvidenceScope,trace);
        if(observedGeneration.Value<expected.Generation.Value||observedEpoch.Value<expected.Epoch.Value)return NetworkDecision.Hold(NetworkCode.StaleGeneration,trace);
        if(observedGeneration.Value>expected.Generation.Value||observedEpoch.Value>expected.Epoch.Value)return NetworkDecision.Hold(NetworkCode.FutureGeneration,trace);
        if(e.Shape==NetworkTopologyShape.Unknown||e.CellCount==0)return NetworkDecision.Hold(NetworkCode.InvalidInput,trace);
        if(e.Shape==NetworkTopologyShape.InitialThreeFullMesh&&e.CellCount>3)return NetworkDecision.Hold(NetworkCode.QuadraticMesh,trace);
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
        var subject=new NetworkRouteIntentSubject(expected.Cell,expected.Network,expected.Subnet,expected.Route,expected.Peer,expected.Tunnel,
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
}
