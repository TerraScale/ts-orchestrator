using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Networking;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class NetworkingFourthAuditCounterexampleTests
{
    [Test]
    public async Task Route_intent_must_bind_the_exact_accepted_evidence_snapshot()
    {
        var scope = NetworkingTestData.RouteScope();
        var firstEvidence = NetworkingTestData.RouteEvidence(scope,
            configured: NetworkProof.Unknown,
            traffic: NetworkProof.Unknown,
            healthy: NetworkProof.Unknown,
            routeConfigured: NetworkProof.Unknown);
        var secondEvidence = NetworkingTestData.RouteEvidence(scope,
            configured: NetworkProof.Unknown,
            traffic: NetworkProof.Proven,
            healthy: NetworkProof.Proven,
            routeConfigured: NetworkProof.Proven);

        var first = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, firstEvidence);
        var second = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, secondEvidence);

        await Assert.That(first.Action).IsEqualTo(NetworkAction.ConfigureTunnel);
        await Assert.That(second.Action).IsEqualTo(NetworkAction.ConfigureTunnel);
        await Assert.That(first).IsNotEqualTo(second);
    }

    [Test]
    public async Task Endpoint_intent_must_bind_the_exact_accepted_evidence_snapshot()
    {
        var scope = NetworkingTestData.EndpointScope();
        var firstEvidence = NetworkingTestData.EndpointEvidence(scope,
            registered: NetworkProof.Unknown,
            promoted: NetworkProof.Unknown,
            dnsRequested: NetworkProof.Unknown,
            dnsObserved: NetworkProof.Unknown);
        var secondEvidence = NetworkingTestData.EndpointEvidence(scope,
            registered: NetworkProof.Unknown,
            promoted: NetworkProof.Proven,
            dnsRequested: NetworkProof.Proven,
            dnsObserved: NetworkProof.Proven);

        var first = NetworkEndpointPlanner.PlanRegister(scope, firstEvidence);
        var second = NetworkEndpointPlanner.PlanRegister(scope, secondEvidence);

        await Assert.That(first.Action).IsEqualTo(NetworkAction.Register);
        await Assert.That(second.Action).IsEqualTo(NetworkAction.Register);
        await Assert.That(first).IsNotEqualTo(second);
    }

    [Test]
    public async Task Endpoint_subject_must_bind_the_semantic_planner_route()
    {
        var scope = NetworkingTestData.EndpointScope();
        var evidence = NetworkingTestData.EndpointEvidence(scope);

        var registration = NetworkEndpointPlanner.PlanRegister(scope, evidence);
        var removal = NetworkEndpointPlanner.PlanRemoval(scope, evidence);

        await Assert.That(registration.Code).IsEqualTo(NetworkCode.Completed);
        await Assert.That(removal.Code).IsEqualTo(NetworkCode.Completed);
        await Assert.That(registration.Subject).IsNotEqualTo(removal.Subject);
    }

    [Test]
    public async Task Every_successful_route_branch_retains_the_exact_accepted_basis()
    {
        var scope = NetworkingTestData.RouteScope();
        var evidence = new[]
        {
            NetworkingTestData.RouteEvidence(scope, configured: NetworkProof.Unknown),
            NetworkingTestData.RouteEvidence(scope, healthy: NetworkProof.Contradicted),
            NetworkingTestData.RouteEvidence(scope, healthy: NetworkProof.Unknown),
            NetworkingTestData.RouteEvidence(scope, routeConfigured: NetworkProof.Unknown),
            NetworkingTestData.RouteEvidence(scope),
        };
        var actions = new[] { NetworkAction.ConfigureTunnel, NetworkAction.Rollback, NetworkAction.Observe,
            NetworkAction.ConfigureRoute, NetworkAction.Verify };

        for (var index = 0; index < evidence.Length; index++)
        {
            var decision = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, evidence[index]);
            await Assert.That(decision.Action).IsEqualTo(actions[index]);
            var subject = (NetworkRouteIntentSubject)decision.Subject!;
            await Assert.That(ReferenceEquals(subject.Scope, scope)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Evidence, evidence[index])).IsTrue();
            await Assert.That(subject.ObservedGeneration).IsEqualTo(scope.Generation);
            await Assert.That(subject.ObservedEpoch).IsEqualTo(scope.Epoch);
            await AssertLegacyRouteProjection(subject, scope);
        }
    }

    [Test]
    public async Task Every_successful_endpoint_branch_retains_the_exact_accepted_basis_and_plan_kind()
    {
        var scope = NetworkingTestData.EndpointScope();
        var registration = new[]
        {
            NetworkingTestData.EndpointEvidence(scope, registered: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, promoted: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, dnsRequested: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, dnsObserved: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope),
        };
        var removal = new[]
        {
            NetworkingTestData.EndpointEvidence(scope, deregistrationRequested: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, deregistered: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, drained: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope),
        };
        var emergency = new[]
        {
            NetworkingTestData.EndpointEvidence(scope, dnsWithdrawalRequested: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, dnsWithdrawn: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, lbWithdrawalRequested: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope, lbWithdrawn: NetworkProof.Unknown),
            NetworkingTestData.EndpointEvidence(scope),
        };

        await AssertEndpointBranches(scope, registration, NetworkEndpointPlanKind.Register,
            NetworkEndpointPlanner.PlanRegister);
        await AssertEndpointBranches(scope, removal, NetworkEndpointPlanKind.Removal,
            NetworkEndpointPlanner.PlanRemoval);
        await AssertEndpointBranches(scope, emergency, NetworkEndpointPlanKind.EmergencyWithdrawal,
            NetworkEndpointPlanner.PlanEmergencyWithdrawal);
    }

    [Test]
    public async Task Reconstructed_route_evidence_has_order_independent_multiset_equality_and_hashing()
    {
        var scope = NetworkingTestData.RouteScope();
        var topology = NetworkingTestData.RouteEvidence(scope);
        NetworkRouteObservation[] routes =
        [
            new(NetworkingTestData.Route("route-a"), scope.Cell, NetworkingTestData.Peer("peer-a"), null,
                scope.TrustPlane, NetworkingTestData.Prefix(11, bits: 8)),
            new(NetworkingTestData.Route("route-b"), scope.Cell, NetworkingTestData.Peer("peer-b"),
                NetworkingTestData.Peer("learned-b"), scope.TrustPlane, NetworkingTestData.Prefix(12, bits: 8)),
        ];
        NetworkPrefix[] prefixes = [NetworkingTestData.Prefix(10), NetworkingTestData.Prefix(11), NetworkingTestData.Prefix(12)];
        var first = RichEvidence(scope, routes, prefixes, topology.Cells, topology.Links,
            configured: NetworkProof.Unknown);
        var second = RichEvidence(scope, routes.Reverse(), prefixes.Reverse(), topology.Cells.Reverse(),
            topology.Links.Reverse(), configured: NetworkProof.Unknown);

        await Assert.That(ReferenceEquals(first, second)).IsFalse();
        await Assert.That(first).IsEqualTo(second);
        await Assert.That(first.GetHashCode()).IsEqualTo(second.GetHashCode());
        var firstDecision = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, first);
        var secondDecision = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, second);
        await Assert.That(firstDecision).IsEqualTo(secondDecision);
        await Assert.That(ReferenceEquals(((NetworkRouteIntentSubject)firstDecision.Subject!).Evidence, first)).IsTrue();
        await Assert.That(ReferenceEquals(((NetworkRouteIntentSubject)secondDecision.Subject!).Evidence, second)).IsTrue();
    }

    [Test]
    public async Task Route_evidence_equality_is_sensitive_to_every_scalar_leaf_member_and_count()
    {
        var scope = NetworkingTestData.RouteScope();
        var topology = NetworkingTestData.RouteEvidence(scope);
        var route = new NetworkRouteObservation(NetworkingTestData.Route("route-a"), scope.Cell,
            NetworkingTestData.Peer("peer-a"), NetworkingTestData.Peer("learned-a"), scope.TrustPlane,
            NetworkingTestData.Prefix(11));
        var prefixes = new[] { NetworkingTestData.Prefix(10), NetworkingTestData.Prefix(11) };
        var baseline = RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links);
        var mutations = new List<NetworkRouteEvidence>
        {
            RichEvidence(scope with { Operation = NetworkingTestData.Op("other-operation") }, [route], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, shape: NetworkTopologyShape.ExplicitReplication),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, noMutation: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, local: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, configured: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, traffic: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, healthy: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, routeConfigured: NetworkProof.Contradicted),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links, partitioned: true),
            RichEvidence(scope, [], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route, route], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { Route = NetworkingTestData.Route("route-b") }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { Owner = NetworkingTestData.Cell("sfo") }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { NextPeer = NetworkingTestData.Peer("peer-b") }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { LearnedFromPeer = null }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { TrustPlane = NetworkTrustPlane.Control }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route with { Destination = NetworkingTestData.Prefix(12) }], prefixes, topology.Cells, topology.Links),
            RichEvidence(scope, [route], [NetworkingTestData.Prefix(10)], topology.Cells, topology.Links),
            RichEvidence(scope, [route], [.. prefixes, NetworkingTestData.Prefix(12)], topology.Cells, topology.Links),
            RichEvidence(scope, [route], prefixes, topology.Cells, topology.Links.Skip(1)),
            RichEvidence(scope, [route], prefixes, topology.Cells,
                topology.Links.Select((link,index)=>index==0?link with { To = NetworkingTestData.Cell("other") }:link)),
            RichEvidence(scope, [route], prefixes, topology.Cells.Skip(1), topology.Links),
            RichEvidence(scope, [route], prefixes,
                topology.Cells.Select((cell,index)=>index==0?NetworkingTestData.Cell("other"):cell), topology.Links),
        };

        foreach (var mutation in mutations) await Assert.That(mutation).IsNotEqualTo(baseline);
        await Assert.That(mutations.Count).IsEqualTo(23);
    }

    [Test]
    public async Task Endpoint_scope_and_evidence_records_are_independently_field_sensitive()
    {
        var scope = NetworkingTestData.EndpointScope();
        object[] scopeMutations =
        [
            scope with { Cell = NetworkingTestData.Cell("sfo") }, scope with { Workload = NetworkingTestData.Workload("auth") },
            scope with { Service = NetworkingTestData.Service("service-b") }, scope with { Endpoint = NetworkingTestData.Endpoint("endpoint-b") },
            scope with { Node = NetworkingTestData.Node("node-b") }, scope with { LoadBalancer = NetworkingTestData.Lb("lb-b") },
            scope with { Backend = NetworkingTestData.Backend("backend-b") }, scope with { Dns = NetworkingTestData.Dns("dns-b") },
            scope with { Certificate = NetworkingTestData.Cert("cert-b") }, scope with { ServiceKind = NetworkServiceKind.Monitoring },
            scope with { Exposure = NetworkExposure.Private }, scope with { Protocol = NetworkProtocol.Tcp },
            scope with { Port = NetworkingTestData.Port(8443) }, scope with { ServiceGeneration = NetworkingTestData.O(10) },
            scope with { Epoch = NetworkingTestData.O(5) }, scope with { Operation = NetworkingTestData.Op("op-b") },
        ];
        foreach (var mutation in scopeMutations) await Assert.That(mutation).IsNotEqualTo(scope);

        var evidence = NetworkingTestData.EndpointEvidence(scope);
        NetworkEndpointEvidence[] evidenceMutations =
        [
            evidence with { Scope = scope with { Operation = NetworkingTestData.Op("op-b") } },
            evidence with { ObservedGeneration = NetworkingTestData.O(10) }, evidence with { ObservedEpoch = NetworkingTestData.O(5) },
            evidence with { RegistryAdmitted = NetworkProof.Contradicted }, evidence with { ProcessLive = NetworkProof.Contradicted },
            evidence with { Ready = NetworkProof.Contradicted }, evidence with { BackendHealth = NetworkHealth.Unhealthy },
            evidence with { CertificateMatches = NetworkProof.Contradicted }, evidence with { TrustProven = NetworkProof.Contradicted },
            evidence with { PublicApproved = NetworkProof.Contradicted }, evidence with { ProductionGates = NetworkProof.Contradicted },
            evidence with { WithdrawalTested = NetworkProof.Contradicted }, evidence with { BackendRegistered = NetworkProof.Contradicted },
            evidence with { BackendPromoted = NetworkProof.Contradicted }, evidence with { DnsRequestRecorded = NetworkProof.Contradicted },
            evidence with { DnsObserved = NetworkProof.Contradicted }, evidence with { Deregistered = NetworkProof.Contradicted },
            evidence with { Drained = NetworkProof.Contradicted }, evidence with { DnsWithdrawalRequested = NetworkProof.Contradicted },
            evidence with { DnsWithdrawn = NetworkProof.Contradicted }, evidence with { LoadBalancerWithdrawalRequested = NetworkProof.Contradicted },
            evidence with { LoadBalancerWithdrawn = NetworkProof.Contradicted }, evidence with { DeregistrationRequested = NetworkProof.Contradicted },
        ];
        foreach (var mutation in evidenceMutations) await Assert.That(mutation).IsNotEqualTo(evidence);
        await Assert.That(scopeMutations.Length).IsEqualTo(16);
        await Assert.That(evidenceMutations.Length).IsEqualTo(23);
    }

    [Test]
    public async Task Every_held_network_decision_has_no_accepted_subject()
    {
        var routeScope = NetworkingTestData.RouteScope();
        var heldRoute = NetworkRoutePlanner.Plan(routeScope, NetworkingTestData.O(6), routeScope.Epoch,
            NetworkingTestData.RouteEvidence(routeScope));
        await AssertHeld(heldRoute);

        var endpointScope = NetworkingTestData.EndpointScope();
        var stale = NetworkingTestData.EndpointEvidence(endpointScope) with { ObservedEpoch = NetworkingTestData.O(3) };
        await AssertHeld(NetworkEndpointPlanner.PlanRegister(endpointScope, stale));
        await AssertHeld(NetworkEndpointPlanner.PlanRemoval(endpointScope,
            NetworkingTestData.EndpointEvidence(endpointScope, health: NetworkHealth.Stale)));
        await AssertHeld(NetworkEndpointPlanner.PlanEmergencyWithdrawal(endpointScope, stale));
    }

    [Test]
    public async Task Provenance_replay_is_deterministic_for_1000_cases_and_cultures()
    {
        var first = UnderCulture("tr-TR", ReplayCases);
        var second = UnderCulture("ar-SA", ReplayCases);
        await Assert.That(first).IsEquivalentTo(second);
        await Assert.That(first.Count).IsEqualTo(1_000);
        await Assert.That(first.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(1_000);
    }

    [Test]
    public async Task Network_output_factory_accessor_default_copy_and_clone_routes_are_closed()
    {
        var assembly = typeof(NetworkDecision).Assembly;
        var factories = assembly.GetExportedTypes().SelectMany(static type => type.GetMethods(
                BindingFlags.Public|BindingFlags.Static|BindingFlags.DeclaredOnly))
            .Where(static method => method.ReturnType == typeof(NetworkDecision))
            .Select(static method => $"{method.DeclaringType!.Name}.{method.Name}").ToArray();
        await Assert.That(factories).IsEquivalentTo(new[]
        {
            "NetworkRoutePlanner.Plan", "NetworkEndpointPlanner.PlanRegister",
            "NetworkEndpointPlanner.PlanRemoval", "NetworkEndpointPlanner.PlanEmergencyWithdrawal",
        });
        await Assert.That(typeof(NetworkDecision).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(NetworkDecision).GetProperties(BindingFlags.Public|BindingFlags.Instance)
            .Any(static property => property.SetMethod?.IsPublic == true)).IsFalse();
        var empty = default(NetworkDecision);
        await Assert.That(empty.Action).IsEqualTo(NetworkAction.Uninitialized);
        await Assert.That(empty.Target).IsEqualTo(NetworkTarget.None);
        await Assert.That(empty.Code).IsEqualTo(NetworkCode.Uninitialized);
        await Assert.That(empty.Subject).IsNull();
        await Assert.That(empty.Trace).IsNull();
        await Assert.That(empty.IsMutationAuthorized).IsFalse();
        var valueCopy = empty with { };
        await Assert.That(valueCopy).IsEqualTo(empty);

        var routeScope = NetworkingTestData.RouteScope();
        var routeEvidence = NetworkingTestData.RouteEvidence(routeScope);
        var route = (NetworkRouteIntentSubject)NetworkRoutePlanner.Plan(routeScope, routeScope.Generation,
            routeScope.Epoch, routeEvidence).Subject!;
        var endpointScope = NetworkingTestData.EndpointScope();
        var endpointEvidence = NetworkingTestData.EndpointEvidence(endpointScope);
        var endpoint = (NetworkEndpointIntentSubject)NetworkEndpointPlanner.PlanRegister(endpointScope,
            endpointEvidence).Subject!;
        foreach (var value in new NetworkIntentSubject[] { route, endpoint })
        {
            var type = value.GetType();
            await Assert.That(type.GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
            await Assert.That(type.GetProperties(BindingFlags.Public|BindingFlags.Instance)
                .Any(static property => property.SetMethod?.IsPublic == true)).IsFalse();
            await Assert.That(type.GetMethods(BindingFlags.Public|BindingFlags.Instance)
                .Any(static method => method.Name == "Deconstruct")).IsFalse();
            var cloneMethod = type.GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.DeclaredOnly)
                .Single(static method => method.Name == "<Clone>$");
            var clone = (NetworkIntentSubject)cloneMethod.Invoke(value, null)!;
            await Assert.That(clone).IsEqualTo(value);
            await Assert.That(ReferenceEquals(clone, value)).IsFalse();
        }
        var routeClone = (NetworkRouteIntentSubject)typeof(NetworkRouteIntentSubject)
            .GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.DeclaredOnly)
            .Single(static method => method.Name == "<Clone>$").Invoke(route, null)!;
        await Assert.That(ReferenceEquals(routeClone.Scope, routeScope)).IsTrue();
        await Assert.That(ReferenceEquals(routeClone.Evidence, routeEvidence)).IsTrue();
        var endpointClone = (NetworkEndpointIntentSubject)typeof(NetworkEndpointIntentSubject)
            .GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.DeclaredOnly)
            .Single(static method => method.Name == "<Clone>$").Invoke(endpoint, null)!;
        await Assert.That(ReferenceEquals(endpointClone.Scope, endpointScope)).IsTrue();
        await Assert.That(ReferenceEquals(endpointClone.Evidence, endpointEvidence)).IsTrue();
        await Assert.That(typeof(NetworkNumericTrace).GetConstructors(BindingFlags.Public|BindingFlags.Instance).Length).IsEqualTo(1);
        await Assert.That(assembly.GetExportedTypes().SelectMany(static type => type.GetMethods(
                BindingFlags.Public|BindingFlags.Static|BindingFlags.Instance|BindingFlags.DeclaredOnly))
            .Where(static method => method.ReturnType == typeof(NetworkIntentSubject))
            .Select(static method => $"{method.DeclaringType!.Name}.{method.Name}"))
            .IsEquivalentTo(["NetworkDecision.get_Subject", "NetworkIntentSubject.<Clone>$"]);
    }

    private static async Task AssertEndpointBranches(NetworkEndpointScope scope,
        IReadOnlyList<NetworkEndpointEvidence> evidence,NetworkEndpointPlanKind planKind,
        Func<NetworkEndpointScope,NetworkEndpointEvidence,NetworkDecision> planner)
    {
        foreach (var item in evidence)
        {
            var subject = (NetworkEndpointIntentSubject)planner(scope, item).Subject!;
            await Assert.That(subject.PlanKind).IsEqualTo(planKind);
            await Assert.That(ReferenceEquals(subject.Scope, scope)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Evidence, item)).IsTrue();
            await AssertLegacyEndpointProjection(subject, scope);
        }
    }

    private static async Task AssertLegacyRouteProjection(NetworkRouteIntentSubject subject,NetworkRouteScope scope)
    {
        await Assert.That(subject.Cell).IsEqualTo(scope.Cell);await Assert.That(subject.PeerCell).IsEqualTo(scope.PeerCell);
        await Assert.That(subject.Network).IsEqualTo(scope.Network);await Assert.That(subject.Subnet).IsEqualTo(scope.Subnet);
        await Assert.That(subject.Route).IsEqualTo(scope.Route);await Assert.That(subject.Peer).IsEqualTo(scope.Peer);
        await Assert.That(subject.Tunnel).IsEqualTo(scope.Tunnel);await Assert.That(subject.TrustPlane).IsEqualTo(scope.TrustPlane);
        await Assert.That(subject.RouteKind).IsEqualTo(scope.RouteKind);await Assert.That(subject.Destination).IsEqualTo(scope.Destination);
        await Assert.That(subject.Generation).IsEqualTo(scope.Generation);await Assert.That(subject.Epoch).IsEqualTo(scope.Epoch);
        await Assert.That(subject.Operation).IsEqualTo(scope.Operation);
    }

    private static async Task AssertLegacyEndpointProjection(NetworkEndpointIntentSubject subject,NetworkEndpointScope scope)
    {
        await Assert.That(subject.Cell).IsEqualTo(scope.Cell);await Assert.That(subject.Workload).IsEqualTo(scope.Workload);
        await Assert.That(subject.Service).IsEqualTo(scope.Service);await Assert.That(subject.Endpoint).IsEqualTo(scope.Endpoint);
        await Assert.That(subject.Node).IsEqualTo(scope.Node);await Assert.That(subject.LoadBalancer).IsEqualTo(scope.LoadBalancer);
        await Assert.That(subject.Backend).IsEqualTo(scope.Backend);await Assert.That(subject.Dns).IsEqualTo(scope.Dns);
        await Assert.That(subject.Certificate).IsEqualTo(scope.Certificate);await Assert.That(subject.ServiceKind).IsEqualTo(scope.ServiceKind);
        await Assert.That(subject.Exposure).IsEqualTo(scope.Exposure);await Assert.That(subject.Protocol).IsEqualTo(scope.Protocol);
        await Assert.That(subject.Port).IsEqualTo(scope.Port);await Assert.That(subject.ServiceGeneration).IsEqualTo(scope.ServiceGeneration);
        await Assert.That(subject.Epoch).IsEqualTo(scope.Epoch);await Assert.That(subject.Operation).IsEqualTo(scope.Operation);
    }

    private static NetworkRouteEvidence RichEvidence(NetworkRouteScope scope,IEnumerable<NetworkRouteObservation?> routes,
        IEnumerable<NetworkPrefix?> prefixes,IEnumerable<NetworkCellId?> cells,IEnumerable<NetworkPeerLink?> links,
        NetworkTopologyShape shape=NetworkTopologyShape.HubAndSpoke,NetworkProof noMutation=NetworkProof.Proven,
        NetworkProof local=NetworkProof.Proven,NetworkProof configured=NetworkProof.Proven,NetworkProof traffic=NetworkProof.Proven,
        NetworkProof healthy=NetworkProof.Proven,NetworkProof routeConfigured=NetworkProof.Proven,bool partitioned=false)=>
        new(scope,routes,prefixes,cells,links,shape,noMutation,local,configured,traffic,healthy,routeConfigured,
            partitioned,64,64,64,32);

    private static async Task AssertHeld(NetworkDecision decision)
    {
        await Assert.That(decision.Action).IsEqualTo(NetworkAction.Hold);
        await Assert.That(decision.Subject).IsNull();
        await Assert.That(decision.IsMutationAuthorized).IsFalse();
    }

    private static IReadOnlyList<string> ReplayCases()
    {
        var values = new string[1_000];
        for (var index = 0; index < values.Length; index++)
        {
            var scope = NetworkingTestData.EndpointScope(generation: NetworkingTestData.O((ulong)index+1)) with
            { Operation = NetworkingTestData.Op($"operation-{index}") };
            var evidence = NetworkingTestData.EndpointEvidence(scope,registered:NetworkProof.Unknown,
                promoted:index%2==0?NetworkProof.Unknown:NetworkProof.Proven);
            var subject = (NetworkEndpointIntentSubject)NetworkEndpointPlanner.PlanRegister(scope,evidence).Subject!;
            values[index] = string.Join('|',subject.PlanKind,subject.Operation.Value,subject.ServiceGeneration.Value,
                subject.Evidence.BackendRegistered,subject.Evidence.BackendPromoted);
        }
        return values;
    }

    private static T UnderCulture<T>(string name,Func<T> action)
    {
        var previous=CultureInfo.CurrentCulture;var previousUi=CultureInfo.CurrentUICulture;
        try{CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo(name);CultureInfo.CurrentUICulture=CultureInfo.GetCultureInfo(name);return action();}
        finally{CultureInfo.CurrentCulture=previous;CultureInfo.CurrentUICulture=previousUi;}
    }
}
