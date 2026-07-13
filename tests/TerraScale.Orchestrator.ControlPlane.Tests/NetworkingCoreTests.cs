using TerraScale.Orchestrator.ControlPlane.Networking;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class NetworkingCoreTests
{
    [Test]
    public async Task Addresses_prefixes_ports_and_identities_are_canonical_and_bounded()
    {
        await Assert.That(NetworkAddress.TryCreate([10,0,0],out _)).IsFalse();
        byte[] bytes=[10,0,0,0];NetworkAddress.TryCreate(bytes,out var copied);bytes[0]=11;
        await Assert.That(copied).IsEqualTo(NetworkingTestData.Prefix(10).Address);
        NetworkAddress.TryCreate([10,1,0,0],out var host);await Assert.That(NetworkPrefix.TryCreate(host,8,out _)).IsFalse();
        await Assert.That(NetworkPort.TryCreate(0,out _)).IsFalse();
        await Assert.That(NetworkServiceId.TryCreate("two words",64,out _)).IsFalse();
        await Assert.That(typeof(NetworkIdentity).GetProperty(nameof(NetworkIdentity.Value))!.SetMethod is null).IsTrue();
    }

    [Test]
    public async Task Route_scope_replay_stale_future_overlap_leak_crossover_and_reflection_fail_closed()
    {
        var s=NetworkingTestData.RouteScope();
        NetworkDecision Plan(NetworkRouteEvidence e,ulong generation=7,ulong epoch=3)=>NetworkRoutePlanner.Plan(s,NetworkingTestData.O(generation),NetworkingTestData.O(epoch),e);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(scope:s with{Operation=NetworkingTestData.Op("other")})).Code).IsEqualTo(NetworkCode.WrongEvidenceScope);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(),6).Code).IsEqualTo(NetworkCode.StaleGeneration);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(),8).Code).IsEqualTo(NetworkCode.FutureGeneration);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(approved:[NetworkingTestData.Prefix(11)])).Code).IsEqualTo(NetworkCode.RouteLeak);
        var crossover=new NetworkRouteObservation(NetworkingTestData.Route("other"),s.Cell,s.Peer,null,NetworkTrustPlane.Control,NetworkingTestData.Prefix(11));
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[crossover])).Code).IsEqualTo(NetworkCode.TrustPlaneCrossover);
        var reflection=new NetworkRouteObservation(NetworkingTestData.Route("other"),s.Cell,s.Peer,s.Peer,s.TrustPlane,NetworkingTestData.Prefix(10,1,bits:16));
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[reflection])).Code).IsEqualTo(NetworkCode.Reflection);
        var ambiguous=new NetworkRouteObservation(NetworkingTestData.Route("other"),s.Cell,NetworkingTestData.Peer("other"),null,s.TrustPlane,s.Destination);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[ambiguous])).Code).IsEqualTo(NetworkCode.AmbiguousOwnership);
        var overlap=new NetworkRouteObservation(NetworkingTestData.Route("overlap"),s.Cell,NetworkingTestData.Peer("other"),null,s.TrustPlane,NetworkingTestData.Prefix(10,1,bits:16));
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[overlap])).Code).IsEqualTo(NetworkCode.Overlap);
        var forgedOwner=crossover with{Owner=NetworkingTestData.Cell("other"),TrustPlane=s.TrustPlane,Destination=NetworkingTestData.Prefix(10,2,bits:16)};
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[forgedOwner])).Code).IsEqualTo(NetworkCode.WrongEvidenceScope);
        var duplicate=new NetworkRouteObservation(NetworkingTestData.Route("dup"),s.Cell,s.Peer,null,s.TrustPlane,NetworkingTestData.Prefix(10,2,bits:16));
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[duplicate,duplicate])).Code).IsEqualTo(NetworkCode.Duplicate);
        var malformed=new NetworkRouteObservation(null!,s.Cell,s.Peer,null,s.TrustPlane,null!);
        await Assert.That(Plan(NetworkingTestData.RouteEvidence(routes:[malformed])).IsMutationAuthorized).IsFalse();
        await Assert.That(NetworkRoutePlanner.Plan(null,s.Generation,s.Epoch,null).Code).IsEqualTo(NetworkCode.WrongEvidenceScope);
        var invalidScope=s with{TrustPlane=(NetworkTrustPlane)99};
        await Assert.That(NetworkRoutePlanner.Plan(invalidScope,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(scope:invalidScope)).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Scalable_topology_and_partition_local_authority_are_explicit()
    {
        var s=NetworkingTestData.RouteScope();
        var mesh=NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(shape:NetworkTopologyShape.InitialThreeFullMesh,cells:20));
        var partitionHold=NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(partitioned:true,local:NetworkProof.Unknown));
        var localScope=NetworkingTestData.RouteScope(kind:NetworkRouteKind.Local);
        var local=NetworkRoutePlanner.Plan(localScope,localScope.Generation,localScope.Epoch,NetworkingTestData.RouteEvidence(scope:localScope,partitioned:true));
        await Assert.That(mesh.Code).IsEqualTo(NetworkCode.QuadraticMesh);
        await Assert.That(partitionHold.Code).IsEqualTo(NetworkCode.LocalPolicyRequired);
        await Assert.That(local.Code).IsEqualTo(NetworkCode.Completed);
        var cells=new[]{NetworkingTestData.Cell(),NetworkingTestData.Cell("sfo"),NetworkingTestData.Cell("fra"),NetworkingTestData.Cell("iad")};
        var disguised=cells.SelectMany(source=>cells.Where(target=>target!=source).Select(target=>new NetworkPeerLink(source,target))).ToArray();
        var hiddenMesh=NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(cellInventory:cells,links:disguised,cells:4));
        await Assert.That(hiddenMesh.Code).IsEqualTo(NetworkCode.QuadraticMesh);
        var threeCells=cells.Take(3).ToArray();
        var fullMesh=threeCells.SelectMany(source=>threeCells.Where(target=>target!=source).Select(target=>new NetworkPeerLink(source,target))).ToArray();
        await Assert.That(NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(
            cellInventory:threeCells,links:fullMesh,shape:NetworkTopologyShape.InitialThreeFullMesh,cells:3)).Code).IsEqualTo(NetworkCode.Completed);
        await Assert.That(NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(
            cellInventory:threeCells,links:fullMesh[..^1],shape:NetworkTopologyShape.InitialThreeFullMesh,cells:3)).Code).IsEqualTo(NetworkCode.QuadraticMesh);
        var missingInventoryCell=new[]{new NetworkPeerLink(cells[0],cells[1]),new NetworkPeerLink(cells[1],cells[0]),
            new NetworkPeerLink(cells[0],cells[2]),new NetworkPeerLink(cells[2],cells[0])};
        await Assert.That(NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(
            cellInventory:cells,links:missingInventoryCell,cells:4)).Code).IsEqualTo(NetworkCode.QuadraticMesh);
        var oneWaySpokes=cells.Skip(1).Select(cell=>new NetworkPeerLink(cells[0],cell)).ToArray();
        await Assert.That(NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,NetworkingTestData.RouteEvidence(
            cellInventory:cells,links:oneWaySpokes,cells:4)).Code).IsEqualTo(NetworkCode.QuadraticMesh);
        var absentScope=NetworkingTestData.RouteScope(kind:NetworkRouteKind.Local,peerCell:NetworkingTestData.Cell("absent"));
        await Assert.That(NetworkRoutePlanner.Plan(absentScope,absentScope.Generation,absentScope.Epoch,
            NetworkingTestData.RouteEvidence(scope:absentScope,cellInventory:cells,cells:4,partitioned:true)).IsMutationAuthorized).IsFalse();
        await Assert.That(NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,
            NetworkingTestData.RouteEvidence(cellInventory:cells,cells:4,maximumCells:3)).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Tunnel_is_staged_health_proven_and_rollback_safe()
    {
        var s=NetworkingTestData.RouteScope();NetworkDecision P(NetworkRouteEvidence e)=>NetworkRoutePlanner.Plan(s,s.Generation,s.Epoch,e);
        var configure=P(NetworkingTestData.RouteEvidence(configured:NetworkProof.Unknown));
        var observe=P(NetworkingTestData.RouteEvidence(traffic:NetworkProof.Unknown));
        var rollback=P(NetworkingTestData.RouteEvidence(healthy:NetworkProof.Contradicted));
        var route=P(NetworkingTestData.RouteEvidence(routeConfigured:NetworkProof.Unknown));
        await Assert.That(configure.Action).IsEqualTo(NetworkAction.ConfigureTunnel);
        await Assert.That(observe.Action).IsEqualTo(NetworkAction.Observe);
        await Assert.That(rollback.Action).IsEqualTo(NetworkAction.Rollback);
        await Assert.That(route.Action).IsEqualTo(NetworkAction.ConfigureRoute);
        await Assert.That(((NetworkRouteIntentSubject)route.Subject!).Route).IsEqualTo(s.Route);
    }

    [Test]
    public async Task Public_ingress_is_default_deny_exact_and_health_gated()
    {
        var s=NetworkingTestData.EndpointScope();
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(admitted:NetworkProof.Unknown)).Code).IsEqualTo(NetworkCode.DefaultDeny);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(publicApproved:NetworkProof.Unknown)).Code).IsEqualTo(NetworkCode.PublicApprovalRequired);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(gates:NetworkProof.Unknown)).Code).IsEqualTo(NetworkCode.PublicApprovalRequired);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(health:NetworkHealth.Stale)).Code).IsEqualTo(NetworkCode.BackendHealthRequired);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(processLive:NetworkProof.Unknown)).Code).IsEqualTo(NetworkCode.ReadinessRequired);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(processLive:NetworkProof.Contradicted)).Code).IsEqualTo(NetworkCode.ReadinessRequired);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(cert:NetworkProof.Unknown)).Code).IsEqualTo(NetworkCode.CertificateMismatch);
        var wrong=NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(scope:s with{Certificate=NetworkingTestData.Cert("forged")}));
        await Assert.That(wrong.Code).IsEqualTo(NetworkCode.WrongEvidenceScope);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence() with{ObservedGeneration=NetworkingTestData.O(8)}).Code).IsEqualTo(NetworkCode.StaleGeneration);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence()).ToString()).DoesNotContain("cert-ref");
        await Assert.That(NetworkEndpointPlanner.PlanRegister(null,null).Code).IsEqualTo(NetworkCode.WrongEvidenceScope);
        var invalid=s with{Exposure=(NetworkExposure)99};
        await Assert.That(NetworkEndpointPlanner.PlanRegister(invalid,NetworkingTestData.EndpointEvidence(scope:invalid)).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Admin_monitoring_public_exposure_is_forbidden_and_registration_is_restartable()
    {
        foreach(var kind in new[]{NetworkServiceKind.Administration,NetworkServiceKind.Monitoring})
        {
            var s=NetworkingTestData.EndpointScope(kind:kind);await Assert.That(NetworkEndpointPlanner.PlanRegister(s,NetworkingTestData.EndpointEvidence(scope:s)).Code).IsEqualTo(NetworkCode.ForbiddenExposure);
        }
        var service=NetworkingTestData.EndpointScope();
        await Assert.That(NetworkEndpointPlanner.PlanRegister(service,NetworkingTestData.EndpointEvidence(registered:NetworkProof.Unknown)).Action).IsEqualTo(NetworkAction.Register);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(service,NetworkingTestData.EndpointEvidence(promoted:NetworkProof.Unknown)).Action).IsEqualTo(NetworkAction.Promote);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(service,NetworkingTestData.EndpointEvidence(dnsRequested:NetworkProof.Unknown)).Action).IsEqualTo(NetworkAction.DnsUpdate);
        await Assert.That(NetworkEndpointPlanner.PlanRegister(service,NetworkingTestData.EndpointEvidence(dnsObserved:NetworkProof.Unknown)).Action).IsEqualTo(NetworkAction.Observe);
    }

    [Test]
    public async Task Deregistration_precedes_drain_and_emergency_withdrawal_is_deterministic()
    {
        var s=NetworkingTestData.EndpointScope();
        var deregister=NetworkEndpointPlanner.PlanRemoval(s,NetworkingTestData.EndpointEvidence(deregistered:NetworkProof.Unknown,drained:NetworkProof.Unknown,deregistrationRequested:NetworkProof.Unknown));
        var drain=NetworkEndpointPlanner.PlanRemoval(s,NetworkingTestData.EndpointEvidence(drained:NetworkProof.Unknown));
        var stale=NetworkEndpointPlanner.PlanRemoval(s,NetworkingTestData.EndpointEvidence(health:NetworkHealth.Stale,deregistrationRequested:NetworkProof.Unknown));
        var dns=NetworkEndpointPlanner.PlanEmergencyWithdrawal(s,NetworkingTestData.EndpointEvidence(dnsWithdrawalRequested:NetworkProof.Unknown,dnsWithdrawn:NetworkProof.Unknown,lbWithdrawn:NetworkProof.Unknown));
        var dnsLost=NetworkEndpointPlanner.PlanEmergencyWithdrawal(s,NetworkingTestData.EndpointEvidence(dnsWithdrawn:NetworkProof.Unknown,lbWithdrawn:NetworkProof.Unknown));
        var lb=NetworkEndpointPlanner.PlanEmergencyWithdrawal(s,NetworkingTestData.EndpointEvidence(lbWithdrawalRequested:NetworkProof.Unknown,lbWithdrawn:NetworkProof.Unknown));
        await Assert.That(deregister.Action).IsEqualTo(NetworkAction.Deregister);
        await Assert.That(drain.Action).IsEqualTo(NetworkAction.Observe);
        await Assert.That(stale.Code).IsEqualTo(NetworkCode.BackendHealthRequired);
        await Assert.That(dns.Target).IsEqualTo(NetworkTarget.Dns);
        await Assert.That(dnsLost.Action).IsEqualTo(NetworkAction.Observe);
        await Assert.That(lb.Target).IsEqualTo(NetworkTarget.LoadBalancer);
    }
}
