using System.Collections;
using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Networking;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class NetworkingPolicyCompletenessPropertyTests
{
    private const int Cases = 1000;
    private const int CaptureLimit = NetworkTechnicalLimits.MaximumCapturedItems;

    internal static string ReplayPublicHttp(ulong seed)
    {
        var scope = EndpointScope(checked((int)seed)) with { Protocol = NetworkProtocol.Http };
        return NetworkEndpointPlanner.PlanRegister(scope, NetworkingTestData.EndpointEvidence(scope)).Code.ToString();
    }

    internal static string ReplayRoutePermutation(ulong seed)
    {
        var intSeed = checked((int)seed);
        var scope = RouteScope(intSeed);
        var first = RouteViolation(scope, 0, 0, intSeed);
        var second = RouteViolation(scope, 1, 1, intSeed);
        var forward = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, RouteEvidence(scope, routes: [first, second]));
        var reverse = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, RouteEvidence(scope, routes: [second, first]));
        return forward == reverse ? forward.Code.ToString() : "OrderDependent";
    }

    internal static string ReplayRouteProvenance(ulong seed)
    {
        var scope = NetworkingTestData.RouteScope() with
        {
            Operation = NetworkingTestData.Op($"route-provenance-{seed}"),
        };
        var first = NetworkingTestData.RouteEvidence(scope, configured: NetworkProof.Unknown,
            traffic: NetworkProof.Unknown, healthy: NetworkProof.Unknown, routeConfigured: NetworkProof.Unknown);
        var second = NetworkingTestData.RouteEvidence(scope, configured: NetworkProof.Unknown,
            traffic: NetworkProof.Proven, healthy: NetworkProof.Proven, routeConfigured: NetworkProof.Proven);
        return NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, first) ==
            NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, second) ? "Collision" : "Distinct";
    }

    internal static string ReplayEndpointPlanProvenance(ulong seed)
    {
        var scope = NetworkingTestData.EndpointScope() with
        {
            Operation = NetworkingTestData.Op($"endpoint-provenance-{seed}"),
        };
        var evidence = NetworkingTestData.EndpointEvidence(scope);
        return NetworkEndpointPlanner.PlanRegister(scope, evidence).Subject ==
            NetworkEndpointPlanner.PlanRemoval(scope, evidence).Subject ? "Collision" : "Distinct";
    }

    [Test]
    public async Task Route_lifecycle_matches_an_independent_exact_oracle_for_1000_cases()
    {
        var actions = new[] { NetworkAction.ConfigureTunnel, NetworkAction.Rollback, NetworkAction.Observe, NetworkAction.ConfigureRoute, NetworkAction.Verify };
        var targets = new[] { NetworkTarget.Tunnel, NetworkTarget.Tunnel, NetworkTarget.Tunnel, NetworkTarget.Route, NetworkTarget.Route };
        var codes = new[] { NetworkCode.NextStep, NetworkCode.TunnelHealthRequired, NetworkCode.TunnelHealthRequired, NetworkCode.NextStep, NetworkCode.Completed };
        var operations = new HashSet<string>(StringComparer.Ordinal);

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % actions.Length;
            var scope = RouteScope(seed);
            var evidence = RouteEvidence(scope,
                configured: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
                traffic: variant == 2 ? NetworkProof.Unknown : variant == 1 ? NetworkProof.Contradicted : NetworkProof.Proven,
                healthy: variant == 1 ? NetworkProof.Contradicted : NetworkProof.Proven,
                routeConfigured: variant == 3 ? NetworkProof.Unknown : NetworkProof.Proven);

            var decision = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, evidence);
            ExactDecision(decision, actions[variant], targets[variant], codes[variant], scope, routeCount: 0, peerCount: 0, seed);
            Require(decision == NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, evidence), seed, "route replay");
            operations.Add(scope.Operation.Value);
        }

        await Assert.That(operations.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Route_denials_preserve_documented_precedence_for_1000_cases()
    {
        var executed = 0;
        var expectedCodes = new[]
        {
            NetworkCode.WrongEvidenceScope, NetworkCode.WrongEvidenceScope, NetworkCode.WrongEvidenceScope,
            NetworkCode.StaleGeneration, NetworkCode.StaleGeneration, NetworkCode.FutureGeneration,
            NetworkCode.InvalidInput, NetworkCode.QuadraticMesh, NetworkCode.WrongEvidenceScope,
            NetworkCode.AmbiguousOwnership, NetworkCode.RouteLeak, NetworkCode.Duplicate,
            NetworkCode.WrongEvidenceScope, NetworkCode.TrustPlaneCrossover, NetworkCode.Reflection,
            NetworkCode.AmbiguousOwnership, NetworkCode.Overlap, NetworkCode.LocalPolicyRequired,
            NetworkCode.PartitionAuthorityDenied,
        };

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % expectedCodes.Length;
            var scope = RouteScope(seed);
            var (expected, generation, epoch, evidence) = DeniedRouteCase(scope, variant);
            var decision = NetworkRoutePlanner.Plan(expected, generation, epoch, evidence);
            Require(decision.Action == NetworkAction.Hold && decision.Target == NetworkTarget.None, seed, "route denial action");
            Require(decision.Code == expectedCodes[variant] && decision.Subject is null && !decision.IsMutationAuthorized, seed, "route denial code");
            if (expected is null) Require(decision.Trace is null, seed, "null route trace");
            else
            {
                var trace = decision.Trace!;
                Require(trace.Generation == expected.Generation && trace.Epoch == expected.Epoch, seed, "route denial trace authority");
                Require(trace.RouteCount == (uint)(evidence?.Routes.Count ?? 0), seed, "route denial trace routes");
                Require(trace.PeerCount == (uint)(evidence?.Routes.Select(route => route.NextPeer).Distinct().Count() ?? 0), seed, "route denial trace peers");
            }
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Registration_lifecycle_matches_an_independent_exact_oracle_for_1000_cases()
    {
        var executed = 0;
        var actions = new[] { NetworkAction.Register, NetworkAction.Promote, NetworkAction.DnsUpdate, NetworkAction.Observe, NetworkAction.Verify };
        var targets = new[] { NetworkTarget.Backend, NetworkTarget.LoadBalancer, NetworkTarget.Dns, NetworkTarget.Dns, NetworkTarget.Ingress };
        var codes = new[] { NetworkCode.NextStep, NetworkCode.NextStep, NetworkCode.NextStep, NetworkCode.DnsConvergencePending, NetworkCode.Completed };

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % actions.Length;
            var scope = EndpointScope(seed);
            var evidence = NetworkingTestData.EndpointEvidence(scope,
                registered: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
                promoted: variant <= 1 ? NetworkProof.Unknown : NetworkProof.Proven,
                dnsRequested: variant <= 2 ? NetworkProof.Unknown : NetworkProof.Proven,
                dnsObserved: variant <= 3 ? NetworkProof.Unknown : NetworkProof.Proven);

            var decision = NetworkEndpointPlanner.PlanRegister(scope, evidence);
            ExactDecision(decision, actions[variant], targets[variant], codes[variant], scope, seed);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Registration_denials_bind_scope_authority_transport_and_gate_precedence_for_1000_cases()
    {
        var executed = 0;
        var expectedCodes = new[]
        {
            NetworkCode.WrongEvidenceScope, NetworkCode.InvalidInput, NetworkCode.StaleGeneration, NetworkCode.FutureGeneration,
            NetworkCode.ForbiddenExposure, NetworkCode.ForbiddenExposure, NetworkCode.DefaultDeny,
            NetworkCode.ReadinessRequired, NetworkCode.ReadinessRequired, NetworkCode.BackendHealthRequired,
            NetworkCode.CertificateMismatch, NetworkCode.PublicApprovalRequired, NetworkCode.PublicApprovalRequired,
            NetworkCode.PublicApprovalRequired,
        };

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % expectedCodes.Length;
            var scope = EndpointScope(seed);
            var evidence = NetworkingTestData.EndpointEvidence(scope);
            (scope, evidence) = DeniedEndpointCase(scope, evidence, variant);
            var decision = NetworkEndpointPlanner.PlanRegister(scope, evidence);
            Require(decision.Action == NetworkAction.Hold && decision.Target == NetworkTarget.None, seed, "registration denial action");
            Require(decision.Code == expectedCodes[variant] && decision.Subject is null && !decision.IsMutationAuthorized, seed, "registration denial code");
            Require(decision.Trace is { RouteCount: 0, PeerCount: 0 } trace && trace.Generation == scope.ServiceGeneration && trace.Epoch == scope.Epoch,
                seed, "registration denial trace");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Insecure_public_http_is_denied_without_selecting_other_transport_policy()
    {
        var baseScope = EndpointScope(0);
        foreach (var exposure in new[] { NetworkExposure.Private, NetworkExposure.Workload })
        {
            var scope = baseScope with { Exposure = exposure, Protocol = NetworkProtocol.Http };
            var decision = NetworkEndpointPlanner.PlanRegister(scope, NetworkingTestData.EndpointEvidence(scope));
            await Assert.That(decision.Action).IsEqualTo(NetworkAction.Verify);
            await Assert.That(decision.Code).IsEqualTo(NetworkCode.Completed);
        }

        foreach (var protocol in new[] { NetworkProtocol.Https, NetworkProtocol.Tcp, NetworkProtocol.Udp })
        {
            var scope = baseScope with { Protocol = protocol };
            var decision = NetworkEndpointPlanner.PlanRegister(scope, NetworkingTestData.EndpointEvidence(scope));
            await Assert.That(decision.Action).IsEqualTo(NetworkAction.Verify);
            await Assert.That(decision.Code).IsEqualTo(NetworkCode.Completed);
        }

        var insecure = baseScope with { Protocol = NetworkProtocol.Http };
        var denied = NetworkEndpointPlanner.PlanRegister(insecure, NetworkingTestData.EndpointEvidence(insecure));
        await Assert.That(denied.Action).IsEqualTo(NetworkAction.Hold);
        await Assert.That(denied.Code).IsEqualTo(NetworkCode.ForbiddenExposure);
        await Assert.That(denied.IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Removal_lifecycle_and_stale_health_hold_match_an_independent_exact_oracle_for_1000_cases()
    {
        var executed = 0;
        var actions = new[] { NetworkAction.Deregister, NetworkAction.Observe, NetworkAction.Observe, NetworkAction.Verify, NetworkAction.Hold };
        var targets = new[] { NetworkTarget.Backend, NetworkTarget.Backend, NetworkTarget.Backend, NetworkTarget.Backend, NetworkTarget.None };
        var codes = new[] { NetworkCode.DeregisterBeforeDrain, NetworkCode.DeregisterBeforeDrain, NetworkCode.DeregisterBeforeDrain, NetworkCode.Completed, NetworkCode.BackendHealthRequired };

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % actions.Length;
            var scope = EndpointScope(seed);
            var evidence = NetworkingTestData.EndpointEvidence(scope,
                health: variant == 4 ? NetworkHealth.Stale : NetworkHealth.Healthy,
                deregistered: variant <= 1 ? NetworkProof.Unknown : NetworkProof.Proven,
                drained: variant <= 2 ? NetworkProof.Unknown : NetworkProof.Proven,
                deregistrationRequested: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven);
            var decision = NetworkEndpointPlanner.PlanRemoval(scope, evidence);
            if (variant == 4) ExactHold(decision, codes[variant], scope, seed);
            else ExactDecision(decision, actions[variant], targets[variant], codes[variant], scope, seed);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Emergency_withdrawal_lifecycle_matches_an_independent_exact_oracle_for_1000_cases()
    {
        var executed = 0;
        var actions = new[] { NetworkAction.DnsUpdate, NetworkAction.Observe, NetworkAction.Deregister, NetworkAction.Observe, NetworkAction.Verify };
        var targets = new[] { NetworkTarget.Dns, NetworkTarget.Dns, NetworkTarget.LoadBalancer, NetworkTarget.LoadBalancer, NetworkTarget.Ingress };

        for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % actions.Length;
            var scope = EndpointScope(seed);
            var evidence = NetworkingTestData.EndpointEvidence(scope,
                dnsWithdrawalRequested: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
                dnsWithdrawn: variant <= 1 ? NetworkProof.Unknown : NetworkProof.Proven,
                lbWithdrawalRequested: variant <= 2 ? NetworkProof.Unknown : NetworkProof.Proven,
                lbWithdrawn: variant <= 3 ? NetworkProof.Unknown : NetworkProof.Proven);
            var decision = NetworkEndpointPlanner.PlanEmergencyWithdrawal(scope, evidence);
            ExactDecision(decision, actions[variant], targets[variant], variant == 4 ? NetworkCode.Completed : NetworkCode.EmergencyWithdrawal, scope, seed);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Full_decision_rendering_is_identical_between_en_us_and_non_english_cultures_for_1000_cases()
    {
        var executed = 0;
        var alternateCultures = new[] { "tr-TR", "ar-SA", "ja-JP" };
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            for (var seed = 0; seed < Cases; seed++)
            {
                var routeScope = RouteScope(seed);
                var endpointScope = EndpointScope(seed);
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
                var baseline = Signature(NetworkRoutePlanner.Plan(routeScope, routeScope.Generation, routeScope.Epoch, RouteEvidence(routeScope))) + "|" +
                    Signature(NetworkEndpointPlanner.PlanRegister(endpointScope, NetworkingTestData.EndpointEvidence(endpointScope)));

                var alternate = CultureInfo.GetCultureInfo(alternateCultures[seed % alternateCultures.Length]);
                CultureInfo.CurrentCulture = alternate;
                CultureInfo.CurrentUICulture = alternate;
                var actual = Signature(NetworkRoutePlanner.Plan(routeScope, routeScope.Generation, routeScope.Epoch, RouteEvidence(routeScope))) + "|" +
                    Signature(NetworkEndpointPlanner.PlanRegister(endpointScope, NetworkingTestData.EndpointEvidence(endpointScope)));
                Require(StringComparer.Ordinal.Equals(actual, baseline), seed, "cross-culture decision signature");
                executed++;
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Every_pair_of_route_denials_has_stable_precedence_under_both_permutations_for_1000_cases()
    {
        var pairs = Enumerable.Range(0, 6).SelectMany(left => Enumerable.Range(left + 1, 5 - left).Select(right => (Left: left, Right: right))).ToArray();
        var codes = new[] { NetworkCode.WrongEvidenceScope, NetworkCode.TrustPlaneCrossover, NetworkCode.RouteLeak,
            NetworkCode.Reflection, NetworkCode.AmbiguousOwnership, NetworkCode.Overlap };
        var executed = 0;
        for (var seed = 0; seed < Cases; seed++)
        {
            var scope = RouteScope(seed);
            var pair = pairs[seed % pairs.Length];
            var left = RouteViolation(scope, pair.Left, 0, seed);
            var right = RouteViolation(scope, pair.Right, 1, seed);
            var forwardEvidence = RouteEvidence(scope, routes: [left, right]);
            var reverseEvidence = RouteEvidence(scope, routes: [right, left]);
            var forward = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, forwardEvidence);
            var reverse = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, reverseEvidence);
            ExactRouteHold(forward, codes[pair.Left], scope, forwardEvidence, seed);
            ExactRouteHold(reverse, codes[pair.Left], scope, reverseEvidence, seed);
            Require(forward == reverse, seed, "pairwise route evidence permutation");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Every_single_route_denial_preserves_its_exact_code_for_1000_cases()
    {
        var codes = new[] { NetworkCode.WrongEvidenceScope, NetworkCode.TrustPlaneCrossover, NetworkCode.RouteLeak,
            NetworkCode.Reflection, NetworkCode.AmbiguousOwnership, NetworkCode.Overlap };
        var executed = 0;
        for (var seed = 0; seed < Cases; seed++)
        {
            var scope = RouteScope(seed);
            var variant = seed % codes.Length;
            var evidence = RouteEvidence(scope, routes: [RouteViolation(scope, variant, 0, seed)]);
            ExactRouteHold(NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, evidence), codes[variant], scope, evidence, seed);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Valid_route_observation_order_cannot_change_success_for_1000_cases()
    {
        var executed = 0;
        for (var seed = 0; seed < Cases; seed++)
        {
            var scope = RouteScope(seed);
            var first = SafeObservedRoute(scope, 0, seed);
            var second = SafeObservedRoute(scope, 1, seed);
            var forward = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, RouteEvidence(scope, routes: [first, second]));
            var reverse = NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, RouteEvidence(scope, routes: [second, first]));
            ExactDecision(forward, NetworkAction.Verify, NetworkTarget.Route, NetworkCode.Completed, scope, 2, 1, seed);
            ExactDecision(reverse, NetworkAction.Verify, NetworkTarget.Route, NetworkCode.Completed, scope, 2, 1, seed);
            Require(forward == reverse, seed, "valid route evidence permutation");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Accepted_network_outputs_have_only_the_reviewed_planner_construction_surface()
    {
        var assembly = typeof(NetworkDecision).Assembly;
        await Assert.That(typeof(NetworkDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(NetworkDecision).GetMethods(BindingFlags.Public | BindingFlags.Instance).Any(method => method.Name == "Deconstruct")).IsFalse();
        await Assert.That(typeof(NetworkDecision).GetProperties(BindingFlags.Public | BindingFlags.Instance).Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
        await Assert.That(assembly.GetTypes().Where(type => typeof(NetworkIntentSubject).IsAssignableFrom(type))
            .SelectMany(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))).IsEmpty();
        await Assert.That(assembly.GetTypes().Where(type => typeof(NetworkIntentSubject).IsAssignableFrom(type))
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance)).Any(method => method.Name == "Deconstruct")).IsFalse();

        var factories = assembly.GetTypes().SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(method => method.ReturnType == typeof(NetworkDecision))
                .Select(method => $"{type.FullName}.{method.Name}"))
            .Order(StringComparer.Ordinal)
            .ToArray();
        await Assert.That(factories).IsEquivalentTo(new[]
        {
            "TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanEmergencyWithdrawal",
            "TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanRegister",
            "TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanRemoval",
            "TerraScale.Orchestrator.ControlPlane.Networking.NetworkRoutePlanner.Plan",
        });
    }

    [Test]
    public async Task Every_network_enumerable_stops_at_the_shared_technical_limit_before_extra_Current()
    {
        var scope = RouteScope(1);
        var route = new NetworkRouteObservation(NetworkingTestData.Route("observed"), scope.Cell, scope.Peer, null, scope.TrustPlane, NetworkingTestData.Prefix(11));
        var link = new NetworkPeerLink(scope.Cell, scope.PeerCell);
        var cells = new[] { scope.Cell, scope.PeerCell };
        var links = new[] { link };
        var sources = new IBoundarySource[]
        {
            new BoundarySource<NetworkRouteObservation?>(() => route, probe => NewEvidence(scope, probe, [NetworkingTestData.Prefix(10)], cells, links)),
            new BoundarySource<NetworkPrefix?>(() => NetworkingTestData.Prefix(10), probe => NewEvidence(scope, [], probe, cells, links)),
            new BoundarySource<NetworkCellId?>(() => scope.Cell, probe => NewEvidence(scope, [], [NetworkingTestData.Prefix(10)], probe, links)),
            new BoundarySource<NetworkPeerLink?>(() => link, probe => NewEvidence(scope, [], [NetworkingTestData.Prefix(10)], cells, probe)),
        };

        foreach (var source in sources)
        {
            source.CaptureExact();
            await Assert.That(source.CurrentCalls).IsEqualTo(CaptureLimit);
            await Assert.That(source.CaptureMaxPlusOneThrows()).IsTrue();
            await Assert.That(source.CurrentCalls).IsEqualTo(CaptureLimit);
        }
    }

    private static (NetworkRouteScope? Expected, NetworkOrdinal Generation, NetworkOrdinal Epoch, NetworkRouteEvidence? Evidence) DeniedRouteCase(NetworkRouteScope scope, int variant)
    {
        var currentGeneration = scope.Generation;
        var currentEpoch = scope.Epoch;
        if (variant == 0) return (null, currentGeneration, currentEpoch, null);
        if (variant == 1) return (scope, currentGeneration, currentEpoch, null);
        if (variant == 2) return (scope, NetworkingTestData.O(scope.Generation.Value - 1), currentEpoch,
            RouteEvidence(scope with { Operation = NetworkingTestData.Op("wrong-operation") }));
        if (variant == 3) return (scope, NetworkingTestData.O(scope.Generation.Value - 1), NetworkingTestData.O(scope.Epoch.Value + 1), RouteEvidence(scope));
        if (variant == 4) return (scope, NetworkingTestData.O(scope.Generation.Value + 1), NetworkingTestData.O(scope.Epoch.Value - 1), RouteEvidence(scope));
        if (variant == 5) return (scope, NetworkingTestData.O(scope.Generation.Value + 1), currentEpoch, RouteEvidence(scope));
        if (variant == 6)
        {
            var duplicateLink = new NetworkPeerLink(scope.Cell, scope.PeerCell);
            return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, links: [duplicateLink, duplicateLink], shape: NetworkTopologyShape.ExplicitReplication));
        }
        if (variant == 7) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, shape: NetworkTopologyShape.InitialThreeFullMesh, noMutation: NetworkProof.Unknown));
        if (variant == 8) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, links: [], noMutation: NetworkProof.Unknown));
        if (variant == 9) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, noMutation: NetworkProof.Unknown, approved: [NetworkingTestData.Prefix(11)]));
        var observed = new NetworkRouteObservation(NetworkingTestData.Route($"observed-{variant}"), scope.Cell, scope.Peer, null, scope.TrustPlane, NetworkingTestData.Prefix(11));
        if (variant == 10) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed], approved: [NetworkingTestData.Prefix(11)]));
        if (variant == 11) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed, observed]));
        if (variant == 12) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed with { Owner = NetworkingTestData.Cell("wrong"), TrustPlane = NetworkTrustPlane.Control }]));
        if (variant == 13) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed with { TrustPlane = NetworkTrustPlane.Control }]));
        if (variant == 14) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed with { LearnedFromPeer = scope.Peer, Destination = scope.Destination }]));
        if (variant == 15) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed with { NextPeer = NetworkingTestData.Peer("wrong-peer"), Destination = scope.Destination }]));
        if (variant == 16)
        {
            NetworkPrefix.TryCreate(scope.Destination.Address, 24, out var child);
            return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, routes: [observed with { NextPeer = NetworkingTestData.Peer("wrong-peer"), Destination = child! }]));
        }
        if (variant == 17) return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, partitioned: true, local: NetworkProof.Unknown));
        return (scope, currentGeneration, currentEpoch, RouteEvidence(scope, partitioned: true, local: NetworkProof.Proven));
    }

    private static NetworkRouteObservation RouteViolation(NetworkRouteScope scope, int violation, int slot, int seed)
    {
        var safe = SafeObservedRoute(scope, slot, seed);
        return violation switch
        {
            0 => safe with { Owner = NetworkingTestData.Cell("wrong-cell") },
            1 => safe with { TrustPlane = NetworkTrustPlane.Control },
            2 => safe with { Destination = NetworkingTestData.Prefix(11, (byte)(slot + 1), bits: 16) },
            3 => safe with { LearnedFromPeer = scope.Peer },
            4 => safe with { Destination = scope.Destination, NextPeer = NetworkingTestData.Peer($"ambiguous-peer-{slot}") },
            5 => safe with
            {
                Destination = NetworkingTestData.Prefix(10, (byte)(seed % 250 + 1), (byte)(slot + 1), bits: 24),
                NextPeer = NetworkingTestData.Peer($"overlap-peer-{slot}"),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(violation)),
        };
    }

    private static NetworkRouteObservation SafeObservedRoute(NetworkRouteScope scope, int slot, int seed)
    {
        var expectedSecondOctet = seed % 250 + 1;
        var safeSecondOctet = expectedSecondOctet == 250 ? 1 : expectedSecondOctet + 1;
        return new(NetworkingTestData.Route($"observed-{seed}-{slot}"), scope.Cell, scope.Peer, null, scope.TrustPlane,
            NetworkingTestData.Prefix(10, (byte)safeSecondOctet, (byte)(slot + 1), bits: 24));
    }

    private static (NetworkEndpointScope Scope, NetworkEndpointEvidence Evidence) DeniedEndpointCase(NetworkEndpointScope scope, NetworkEndpointEvidence evidence, int variant) => variant switch
    {
        0 => (scope, evidence with { Scope = scope with { Operation = NetworkingTestData.Op("wrong-operation") }, BackendHealth = (NetworkHealth)99 }),
        1 => (scope, evidence with { BackendHealth = (NetworkHealth)99, ObservedGeneration = NetworkingTestData.O(scope.ServiceGeneration.Value - 1) }),
        2 => (scope, evidence with { ObservedGeneration = NetworkingTestData.O(scope.ServiceGeneration.Value - 1), ObservedEpoch = NetworkingTestData.O(scope.Epoch.Value + 1) }),
        3 => (scope, evidence with { ObservedGeneration = NetworkingTestData.O(scope.ServiceGeneration.Value + 1) }),
        4 => (scope with { ServiceKind = NetworkServiceKind.Administration }, evidence with { Scope = scope with { ServiceKind = NetworkServiceKind.Administration }, RegistryAdmitted = NetworkProof.Unknown }),
        5 => (scope with { Protocol = NetworkProtocol.Http }, evidence with { Scope = scope with { Protocol = NetworkProtocol.Http }, RegistryAdmitted = NetworkProof.Unknown }),
        6 => (scope, evidence with { RegistryAdmitted = NetworkProof.Unknown, ProcessLive = NetworkProof.Unknown }),
        7 => (scope, evidence with { ProcessLive = NetworkProof.Unknown, Ready = NetworkProof.Unknown }),
        8 => (scope, evidence with { Ready = NetworkProof.Unknown, BackendHealth = NetworkHealth.Stale }),
        9 => (scope, evidence with { BackendHealth = NetworkHealth.Stale, CertificateMatches = NetworkProof.Unknown }),
        10 => (scope, evidence with { CertificateMatches = NetworkProof.Unknown, PublicApproved = NetworkProof.Unknown }),
        11 => (scope, evidence with { PublicApproved = NetworkProof.Unknown, ProductionGates = NetworkProof.Unknown }),
        12 => (scope, evidence with { ProductionGates = NetworkProof.Unknown, WithdrawalTested = NetworkProof.Unknown }),
        _ => (scope, evidence with { WithdrawalTested = NetworkProof.Unknown }),
    };

    private static NetworkRouteScope RouteScope(int seed)
    {
        var suffix = (seed + 1).ToString(CultureInfo.InvariantCulture);
        return new(NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo"), NetworkingTestData.Net($"network-{suffix}"),
            NetworkingTestData.Subnet($"subnet-{suffix}"), NetworkingTestData.Route($"route-{suffix}"), NetworkingTestData.Peer($"peer-{suffix}"),
            NetworkingTestData.Tunnel($"tunnel-{suffix}"), NetworkTrustPlane.Product,
            NetworkingTestData.Prefix(10, (byte)(seed % 250 + 1), bits: 16), NetworkRouteKind.Peer,
            NetworkingTestData.O((ulong)seed + 11), NetworkingTestData.O((ulong)seed + 7), NetworkingTestData.Op($"network-operation-{suffix}"));
    }

    private static NetworkRouteEvidence RouteEvidence(NetworkRouteScope scope, IEnumerable<NetworkRouteObservation?>? routes = null,
        IEnumerable<NetworkPrefix?>? approved = null, IEnumerable<NetworkPeerLink?>? links = null,
        NetworkTopologyShape shape = NetworkTopologyShape.ExplicitReplication, NetworkProof noMutation = NetworkProof.Proven,
        NetworkProof local = NetworkProof.Proven, NetworkProof configured = NetworkProof.Proven,
        NetworkProof traffic = NetworkProof.Proven, NetworkProof healthy = NetworkProof.Proven,
        NetworkProof routeConfigured = NetworkProof.Proven, bool partitioned = false)
    {
        var cells = new[] { scope.Cell, scope.PeerCell };
        return new(scope, routes ?? [], approved ?? [NetworkingTestData.Prefix(10)], cells,
            links ?? [new(scope.Cell, scope.PeerCell), new(scope.PeerCell, scope.Cell)], shape, noMutation, local,
            configured, traffic, healthy, routeConfigured, partitioned, 32, 16, 16, 8);
    }

    private static NetworkEndpointScope EndpointScope(int seed)
    {
        var suffix = (seed + 1).ToString(CultureInfo.InvariantCulture);
        return new(NetworkingTestData.Cell(), NetworkingTestData.Workload($"workload-{suffix}"), NetworkingTestData.Service($"service-{suffix}"),
            NetworkingTestData.Endpoint($"endpoint-{suffix}"), NetworkingTestData.Node($"node-{suffix}"), NetworkingTestData.Lb($"lb-{suffix}"),
            NetworkingTestData.Backend($"backend-{suffix}"), NetworkingTestData.Dns($"dns-{suffix}"), NetworkingTestData.Cert($"certificate-{suffix}"),
            NetworkServiceKind.Product, NetworkExposure.Public, NetworkProtocol.Https, NetworkingTestData.Port(),
            NetworkingTestData.O((ulong)seed + 23), NetworkingTestData.O((ulong)seed + 19), NetworkingTestData.Op($"endpoint-operation-{suffix}"));
    }

    private static void ExactDecision(NetworkDecision decision, NetworkAction action, NetworkTarget target, NetworkCode code,
        NetworkRouteScope scope, uint routeCount, uint peerCount, int seed)
    {
        Require(decision.Action == action && decision.Target == target && decision.Code == code, seed, "route tuple");
        Require(decision.IsMutationAuthorized == (action is NetworkAction.ConfigureRoute or NetworkAction.ConfigureTunnel or NetworkAction.Rollback), seed, "route mutation authorization");
        var subject = decision.Subject as NetworkRouteIntentSubject;
        Require(subject is not null && subject.Cell == scope.Cell && subject.PeerCell == scope.PeerCell && subject.Network == scope.Network &&
            subject.Subnet == scope.Subnet && subject.Route == scope.Route && subject.Peer == scope.Peer && subject.Tunnel == scope.Tunnel &&
            subject.TrustPlane == scope.TrustPlane && subject.RouteKind == scope.RouteKind && subject.Destination.Equals(scope.Destination) &&
            subject.Generation == scope.Generation && subject.Epoch == scope.Epoch && subject.Operation == scope.Operation, seed, "route subject");
        Require(decision.Trace is { } trace && trace.Generation == scope.Generation && trace.Epoch == scope.Epoch && trace.RouteCount == routeCount && trace.PeerCount == peerCount,
            seed, "route trace");
    }

    private static void ExactDecision(NetworkDecision decision, NetworkAction action, NetworkTarget target, NetworkCode code,
        NetworkEndpointScope scope, int seed)
    {
        Require(decision.Action == action && decision.Target == target && decision.Code == code, seed, "endpoint tuple");
        Require(decision.IsMutationAuthorized == (action is NetworkAction.Register or NetworkAction.Deregister or NetworkAction.Promote or NetworkAction.DnsUpdate), seed, "endpoint mutation authorization");
        var subject = decision.Subject as NetworkEndpointIntentSubject;
        Require(subject is not null && subject.Cell == scope.Cell && subject.Workload == scope.Workload && subject.Service == scope.Service &&
            subject.Endpoint == scope.Endpoint && subject.Node == scope.Node && subject.LoadBalancer == scope.LoadBalancer && subject.Backend == scope.Backend &&
            subject.Dns == scope.Dns && subject.Certificate == scope.Certificate && subject.ServiceKind == scope.ServiceKind && subject.Exposure == scope.Exposure &&
            subject.Protocol == scope.Protocol && subject.Port == scope.Port && subject.ServiceGeneration == scope.ServiceGeneration && subject.Epoch == scope.Epoch &&
            subject.Operation == scope.Operation, seed, "endpoint subject");
        Require(decision.Trace is { RouteCount: 0, PeerCount: 0 } trace && trace.Generation == scope.ServiceGeneration && trace.Epoch == scope.Epoch,
            seed, "endpoint trace");
    }

    private static void ExactHold(NetworkDecision decision, NetworkCode code, NetworkEndpointScope scope, int seed)
    {
        Require(decision.Action == NetworkAction.Hold && decision.Target == NetworkTarget.None && decision.Code == code && decision.Subject is null && !decision.IsMutationAuthorized,
            seed, "endpoint hold tuple");
        Require(decision.Trace is { RouteCount: 0, PeerCount: 0 } trace && trace.Generation == scope.ServiceGeneration && trace.Epoch == scope.Epoch,
            seed, "endpoint hold trace");
    }

    private static void ExactRouteHold(NetworkDecision decision, NetworkCode code, NetworkRouteScope scope, NetworkRouteEvidence evidence, int seed)
    {
        Require(decision.Action == NetworkAction.Hold && decision.Target == NetworkTarget.None && decision.Code == code && decision.Subject is null && !decision.IsMutationAuthorized,
            seed, "route hold tuple");
        Require(decision.Trace is { } trace && trace.Generation == scope.Generation && trace.Epoch == scope.Epoch &&
            trace.RouteCount == (uint)evidence.Routes.Count && trace.PeerCount == (uint)evidence.Routes.Select(route => route.NextPeer).Distinct().Count(),
            seed, "route hold trace");
    }

    private static string Signature(NetworkDecision decision)
    {
        var subject = decision.Subject switch
        {
            NetworkRouteIntentSubject route => string.Join('|', route.Cell.Value, route.PeerCell.Value, route.Network.Value, route.Subnet.Value,
                route.Route.Value, route.Peer.Value, route.Tunnel.Value, route.TrustPlane, route.RouteKind, route.Destination.ToString(),
                route.Generation.ToString(), route.Epoch.ToString(), route.Operation.Value),
            NetworkEndpointIntentSubject endpoint => string.Join('|', endpoint.Cell.Value, endpoint.Workload.Value, endpoint.Service.Value,
                endpoint.Endpoint.Value, endpoint.Node.Value, endpoint.LoadBalancer.Value, endpoint.Backend.Value, endpoint.Dns.Value,
                endpoint.Certificate.Value, endpoint.ServiceKind, endpoint.Exposure, endpoint.Protocol, endpoint.Port.Value,
                endpoint.ServiceGeneration.ToString(), endpoint.Epoch.ToString(), endpoint.Operation.Value),
            null => "<none>",
            _ => throw new InvalidOperationException("Unexpected network subject."),
        };
        return string.Join('|', decision.Action, decision.Target, decision.Code, decision.IsMutationAuthorized, subject, decision.Trace?.ToString() ?? "<none>");
    }

    private static NetworkRouteEvidence NewEvidence(NetworkRouteScope scope, IEnumerable<NetworkRouteObservation?> routes,
        IEnumerable<NetworkPrefix?> approved, IEnumerable<NetworkCellId?> cells, IEnumerable<NetworkPeerLink?> links) =>
        new(scope, routes, approved, cells, links, NetworkTopologyShape.ExplicitReplication, NetworkProof.Proven, NetworkProof.Proven,
            NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, false,
            CaptureLimit, CaptureLimit, CaptureLimit, CaptureLimit);

    private static void Require(bool condition, int seed, string property)
    {
        if (!condition) throw new InvalidOperationException($"Property {property} failed at seed {seed}.");
    }

    private interface IBoundarySource
    {
        int CurrentCalls { get; }
        void CaptureExact();
        bool CaptureMaxPlusOneThrows();
    }

    private sealed class BoundarySource<T>(Func<T> factory, Action<IEnumerable<T>> capture) : IBoundarySource
    {
        private BoundaryEnumerable<T>? _probe;
        public int CurrentCalls => _probe?.CurrentCalls ?? 0;
        public void CaptureExact()
        {
            _probe = new(CaptureLimit, factory);
            capture(_probe);
        }
        public bool CaptureMaxPlusOneThrows()
        {
            _probe = new(CaptureLimit + 1, factory, CaptureLimit);
            try { capture(_probe); return false; }
            catch (ArgumentException) { return true; }
        }
    }

    private sealed class BoundaryEnumerable<T> : IEnumerable<T>
    {
        private readonly int _count;
        private readonly Func<T> _factory;
        private readonly int _throwOnCurrent;

        public BoundaryEnumerable(int count, Func<T> factory, int throwOnCurrent = -1)
        {
            _count = count;
            _factory = factory;
            _throwOnCurrent = throwOnCurrent;
        }

        public int CurrentCalls { get; private set; }
        public IEnumerator<T> GetEnumerator() => new Iterator(this);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Iterator(BoundaryEnumerable<T> owner) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current
            {
                get
                {
                    owner.CurrentCalls++;
                    if (_index == owner._throwOnCurrent) throw new InvalidOperationException("extra Current must not be read");
                    return owner._factory();
                }
            }
            object? IEnumerator.Current => Current;
            public bool MoveNext() => ++_index < owner._count;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { }
        }
    }
}
