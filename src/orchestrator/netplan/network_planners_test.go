package netplan

import "testing"

func testEndpointScope(t *testing.T) NetworkEndpointScope {
	t.Helper()
	cell, _ := NetworkCellIdTryCreate("gru", 32)
	workload, _ := NetworkWorkloadIdTryCreate("api-1", 32)
	service, _ := NetworkServiceIdTryCreate("database-api", 32)
	endpoint, _ := NetworkEndpointIdTryCreate("https", 32)
	node, _ := NetworkNodeIdTryCreate("node-1", 32)
	loadBalancer, _ := NetworkLoadBalancerIdTryCreate("lb-1", 32)
	backend, _ := NetworkBackendIdTryCreate("backend-1", 32)
	dns, _ := NetworkDnsIdTryCreate("api.terrascale.tech", 64)
	certificate, _ := NetworkCertificateRefTryCreate("origin-cert-1", 32)
	port, _ := NetworkPortTryCreate(443)
	generation, _ := NetworkOrdinalTryCreate(7)
	epoch, _ := NetworkOrdinalTryCreate(11)
	operation, _ := NetworkOperationIdTryCreate("op-endpoint-1", 32)
	return NetworkEndpointScope{
		Cell:              cell,
		Workload:          workload,
		Service:           service,
		Endpoint:          endpoint,
		Node:              node,
		LoadBalancer:      loadBalancer,
		Backend:           backend,
		Dns:               dns,
		Certificate:       certificate,
		ServiceKind:       NetworkServiceKindProduct,
		Exposure:          NetworkExposurePrivate,
		Protocol:          NetworkProtocolHttps,
		Port:              port,
		ServiceGeneration: generation,
		Epoch:             epoch,
		Operation:         operation,
	}
}

func testEndpointEvidence(scope NetworkEndpointScope) NetworkEndpointEvidence {
	return NetworkEndpointEvidence{
		Scope:                           scope,
		ObservedGeneration:              scope.ServiceGeneration,
		ObservedEpoch:                   scope.Epoch,
		RegistryAdmitted:                NetworkProofProven,
		ProcessLive:                     NetworkProofProven,
		Ready:                           NetworkProofProven,
		BackendHealth:                   NetworkHealthHealthy,
		CertificateMatches:              NetworkProofProven,
		TrustProven:                     NetworkProofProven,
		PublicApproved:                  NetworkProofProven,
		ProductionGates:                 NetworkProofProven,
		WithdrawalTested:                NetworkProofProven,
		BackendRegistered:               NetworkProofProven,
		BackendPromoted:                 NetworkProofProven,
		DnsRequestRecorded:              NetworkProofProven,
		DnsObserved:                     NetworkProofProven,
		Deregistered:                    NetworkProofProven,
		Drained:                         NetworkProofProven,
		DnsWithdrawalRequested:          NetworkProofProven,
		DnsWithdrawn:                    NetworkProofProven,
		LoadBalancerWithdrawalRequested: NetworkProofProven,
		LoadBalancerWithdrawn:           NetworkProofProven,
		DeregistrationRequested:         NetworkProofProven,
	}
}

func assertNetworkDecision(t *testing.T, decision NetworkDecision, action NetworkAction, target NetworkTarget, code NetworkCode) {
	t.Helper()
	if decision.Action != action || decision.Target != target || decision.Code != code {
		t.Fatalf("decision = action %d target %d code %d, want action %d target %d code %d",
			decision.Action, decision.Target, decision.Code, action, target, code)
	}
}

func TestEndpointRegistrationReconcilesOneMutationAtATime(t *testing.T) {
	t.Parallel()

	scope := testEndpointScope(t)
	evidence := testEndpointEvidence(scope)
	tests := []struct {
		name   string
		change func(*NetworkEndpointEvidence)
		action NetworkAction
		target NetworkTarget
		code   NetworkCode
	}{
		{name: "admission", change: func(e *NetworkEndpointEvidence) { e.RegistryAdmitted = NetworkProofUnknown }, action: NetworkActionHold, target: NetworkTargetNone, code: NetworkCodeDefaultDeny},
		{name: "process live", change: func(e *NetworkEndpointEvidence) { e.ProcessLive = NetworkProofUnknown }, action: NetworkActionHold, target: NetworkTargetNone, code: NetworkCodeReadinessRequired},
		{name: "ready", change: func(e *NetworkEndpointEvidence) { e.Ready = NetworkProofUnknown }, action: NetworkActionHold, target: NetworkTargetNone, code: NetworkCodeReadinessRequired},
		{name: "backend health", change: func(e *NetworkEndpointEvidence) { e.BackendHealth = NetworkHealthStale }, action: NetworkActionHold, target: NetworkTargetNone, code: NetworkCodeBackendHealthRequired},
		{name: "certificate", change: func(e *NetworkEndpointEvidence) { e.CertificateMatches = NetworkProofContradicted }, action: NetworkActionHold, target: NetworkTargetNone, code: NetworkCodeCertificateMismatch},
		{name: "register", change: func(e *NetworkEndpointEvidence) { e.BackendRegistered = NetworkProofUnknown }, action: NetworkActionRegister, target: NetworkTargetBackend, code: NetworkCodeNextStep},
		{name: "promote", change: func(e *NetworkEndpointEvidence) { e.BackendPromoted = NetworkProofUnknown }, action: NetworkActionPromote, target: NetworkTargetLoadBalancer, code: NetworkCodeNextStep},
		{name: "request dns", change: func(e *NetworkEndpointEvidence) { e.DnsRequestRecorded = NetworkProofUnknown }, action: NetworkActionDnsUpdate, target: NetworkTargetDns, code: NetworkCodeNextStep},
		{name: "observe dns", change: func(e *NetworkEndpointEvidence) { e.DnsObserved = NetworkProofUnknown }, action: NetworkActionObserve, target: NetworkTargetDns, code: NetworkCodeDnsConvergencePending},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := evidence
			test.change(&candidate)
			assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&scope, &candidate), test.action, test.target, test.code)
		})
	}
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&scope, &evidence), NetworkActionVerify, NetworkTargetIngress, NetworkCodeCompleted)
}

func TestEndpointRegistrationFailsClosedOnScopeAndExposure(t *testing.T) {
	t.Parallel()

	scope := testEndpointScope(t)
	evidence := testEndpointEvidence(scope)
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(nil, &evidence), NetworkActionHold, NetworkTargetNone, NetworkCodeWrongEvidenceScope)

	stale := evidence
	stale.ObservedGeneration.Value--
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&scope, &stale), NetworkActionHold, NetworkTargetNone, NetworkCodeStaleGeneration)
	future := evidence
	future.ObservedEpoch.Value++
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&scope, &future), NetworkActionHold, NetworkTargetNone, NetworkCodeFutureGeneration)

	publicHTTP := scope
	publicHTTP.Exposure = NetworkExposurePublic
	publicHTTP.Protocol = NetworkProtocolHttp
	publicEvidence := testEndpointEvidence(publicHTTP)
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&publicHTTP, &publicEvidence), NetworkActionHold, NetworkTargetNone, NetworkCodeForbiddenExposure)

	adminPublic := publicHTTP
	adminPublic.Protocol = NetworkProtocolHttps
	adminPublic.ServiceKind = NetworkServiceKindAdministration
	adminEvidence := testEndpointEvidence(adminPublic)
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&adminPublic, &adminEvidence), NetworkActionHold, NetworkTargetNone, NetworkCodeForbiddenExposure)

	publicProduct := publicHTTP
	publicProduct.Protocol = NetworkProtocolHttps
	publicProduct.ServiceKind = NetworkServiceKindProduct
	approvalMissing := testEndpointEvidence(publicProduct)
	approvalMissing.PublicApproved = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRegister(&publicProduct, &approvalMissing), NetworkActionHold, NetworkTargetNone, NetworkCodePublicApprovalRequired)
}

func TestEndpointRemovalAndEmergencyWithdrawalOrder(t *testing.T) {
	t.Parallel()

	scope := testEndpointScope(t)
	evidence := testEndpointEvidence(scope)

	removal := evidence
	removal.DeregistrationRequested = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRemoval(&scope, &removal), NetworkActionDeregister, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain)
	removal.DeregistrationRequested = NetworkProofProven
	removal.Deregistered = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRemoval(&scope, &removal), NetworkActionObserve, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain)
	removal.Deregistered = NetworkProofProven
	removal.Drained = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRemoval(&scope, &removal), NetworkActionObserve, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain)
	removal.Drained = NetworkProofProven
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanRemoval(&scope, &removal), NetworkActionVerify, NetworkTargetBackend, NetworkCodeCompleted)

	withdrawal := evidence
	withdrawal.DnsWithdrawalRequested = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanEmergencyWithdrawal(&scope, &withdrawal), NetworkActionDnsUpdate, NetworkTargetDns, NetworkCodeEmergencyWithdrawal)
	withdrawal.DnsWithdrawalRequested = NetworkProofProven
	withdrawal.DnsWithdrawn = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanEmergencyWithdrawal(&scope, &withdrawal), NetworkActionObserve, NetworkTargetDns, NetworkCodeEmergencyWithdrawal)
	withdrawal.DnsWithdrawn = NetworkProofProven
	withdrawal.LoadBalancerWithdrawalRequested = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanEmergencyWithdrawal(&scope, &withdrawal), NetworkActionDeregister, NetworkTargetLoadBalancer, NetworkCodeEmergencyWithdrawal)
	withdrawal.LoadBalancerWithdrawalRequested = NetworkProofProven
	withdrawal.LoadBalancerWithdrawn = NetworkProofUnknown
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanEmergencyWithdrawal(&scope, &withdrawal), NetworkActionObserve, NetworkTargetLoadBalancer, NetworkCodeEmergencyWithdrawal)
	withdrawal.LoadBalancerWithdrawn = NetworkProofProven
	assertNetworkDecision(t, NetworkEndpointPlanner.PlanEmergencyWithdrawal(&scope, &withdrawal), NetworkActionVerify, NetworkTargetIngress, NetworkCodeCompleted)
}

func testRouteFixture(t *testing.T) (NetworkRouteScope, []NetworkCellId, []NetworkPeerLink, []NetworkPrefix) {
	t.Helper()
	gru, _ := NetworkCellIdTryCreate("gru", 32)
	sfo, _ := NetworkCellIdTryCreate("sfo", 32)
	fra, _ := NetworkCellIdTryCreate("fra", 32)
	network, _ := NetworkIdTryCreate("product", 32)
	subnet, _ := NetworkSubnetIdTryCreate("gru-product", 32)
	route, _ := NetworkRouteIdTryCreate("gru-to-sfo", 32)
	peer, _ := NetworkPeerIdTryCreate("sfo-peer", 32)
	tunnel, _ := NetworkTunnelIdTryCreate("gru-sfo", 32)
	address, _ := NetworkAddressTryCreate([]byte{10, 20, 0, 0})
	destination, _ := NetworkPrefixTryCreate(address, 16)
	approvedAddress, _ := NetworkAddressTryCreate([]byte{10, 0, 0, 0})
	approved, _ := NetworkPrefixTryCreate(approvedAddress, 8)
	generation, _ := NetworkOrdinalTryCreate(4)
	epoch, _ := NetworkOrdinalTryCreate(9)
	operation, _ := NetworkOperationIdTryCreate("op-route-1", 32)
	scope := NetworkRouteScope{Cell: gru, PeerCell: sfo, Network: network, Subnet: subnet, Route: route,
		Peer: peer, Tunnel: tunnel, TrustPlane: NetworkTrustPlaneProduct, Destination: destination,
		RouteKind: NetworkRouteKindPeer, Generation: generation, Epoch: epoch, Operation: operation}
	return scope, []NetworkCellId{gru, sfo, fra}, []NetworkPeerLink{{From: gru, To: sfo}}, []NetworkPrefix{approved}
}

func testRouteEvidence(t *testing.T, scope NetworkRouteScope, cells []NetworkCellId, links []NetworkPeerLink, approved []NetworkPrefix, routes []NetworkRouteObservation) *NetworkRouteEvidence {
	t.Helper()
	return NewNetworkRouteEvidence(scope, routes, approved, cells, links,
		NetworkTopologyShapeExplicitReplication, NetworkProofProven, NetworkProofProven,
		NetworkProofProven, NetworkProofProven, NetworkProofProven, NetworkProofProven,
		false, 32, 32, 32, 32)
}

func TestRoutePlannerReconcilesTunnelThenRoute(t *testing.T) {
	t.Parallel()

	scope, cells, links, approved := testRouteFixture(t)
	evidence := testRouteEvidence(t, scope, cells, links, approved, nil)
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionVerify, NetworkTargetRoute, NetworkCodeCompleted)

	evidence.TunnelConfigured = NetworkProofUnknown
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionConfigureTunnel, NetworkTargetTunnel, NetworkCodeNextStep)
	evidence.TunnelConfigured = NetworkProofProven
	evidence.TunnelHealthy = NetworkProofContradicted
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionRollback, NetworkTargetTunnel, NetworkCodeTunnelHealthRequired)
	evidence.TunnelHealthy = NetworkProofUnknown
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionObserve, NetworkTargetTunnel, NetworkCodeTunnelHealthRequired)
	evidence.TunnelHealthy = NetworkProofProven
	evidence.RouteConfigured = NetworkProofUnknown
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionConfigureRoute, NetworkTargetRoute, NetworkCodeNextStep)
}

func TestRoutePlannerFencesStaleAndFutureObservations(t *testing.T) {
	t.Parallel()

	scope, cells, links, approved := testRouteFixture(t)
	evidence := testRouteEvidence(t, scope, cells, links, approved, nil)
	stale, _ := NetworkOrdinalTryCreate(scope.Generation.Value - 1)
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, stale, scope.Epoch, evidence), NetworkActionHold, NetworkTargetNone, NetworkCodeStaleGeneration)
	future, _ := NetworkOrdinalTryCreate(scope.Epoch.Value + 1)
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, future, evidence), NetworkActionHold, NetworkTargetNone, NetworkCodeFutureGeneration)
	wrongScope := scope
	wrongScope.Operation, _ = NetworkOperationIdTryCreate("other-operation", 32)
	assertNetworkDecision(t, NetworkRoutePlanner.Plan(&wrongScope, wrongScope.Generation, wrongScope.Epoch, evidence), NetworkActionHold, NetworkTargetNone, NetworkCodeWrongEvidenceScope)
}

func TestRouteEvidenceOwnsInputAndOutputSlices(t *testing.T) {
	t.Parallel()

	scope, cells, links, approved := testRouteFixture(t)
	evidence := testRouteEvidence(t, scope, cells, links, approved, nil)
	if !evidence.IsValid {
		t.Fatal("valid evidence rejected")
	}
	originalCell := evidence.Cells()[0]
	cells[0], _ = NetworkCellIdTryCreate("changed", 32)
	if evidence.Cells()[0] != originalCell {
		t.Fatal("constructor retained caller cells slice")
	}
	exposed := evidence.Cells()
	exposed[0], _ = NetworkCellIdTryCreate("also-changed", 32)
	if evidence.Cells()[0] != originalCell {
		t.Fatal("Cells exposed mutable internal storage")
	}

	originalPrefix := evidence.ApprovedPrefixes()[0]
	approved[0] = NetworkPrefix{}
	if !evidence.ApprovedPrefixes()[0].Equal(originalPrefix) {
		t.Fatal("constructor retained caller prefixes slice")
	}
	exposedPrefixes := evidence.ApprovedPrefixes()
	exposedPrefixes[0] = NetworkPrefix{}
	if !evidence.ApprovedPrefixes()[0].Equal(originalPrefix) {
		t.Fatal("ApprovedPrefixes exposed mutable internal storage")
	}
}

func TestRouteEvidenceEqualityIncludesAddressBytes(t *testing.T) {
	t.Parallel()

	scope, cells, links, approved := testRouteFixture(t)
	left := testRouteEvidence(t, scope, cells, links, approved, nil)
	right := testRouteEvidence(t, scope, cells, links, approved, nil)
	if !left.Equal(right) {
		t.Fatal("equivalent evidence compared unequal")
	}

	differentAddress, _ := NetworkAddressTryCreate([]byte{11, 0, 0, 0})
	differentPrefix, _ := NetworkPrefixTryCreate(differentAddress, 8)
	right = testRouteEvidence(t, scope, cells, links, []NetworkPrefix{differentPrefix}, nil)
	if left.Equal(right) {
		t.Fatal("evidence with different approved prefix bytes compared equal")
	}
}

func TestRoutePlannerRejectsUnsafeRouteSets(t *testing.T) {
	t.Parallel()

	scope, cells, links, approved := testRouteFixture(t)
	otherPeer, _ := NetworkPeerIdTryCreate("fra-peer", 32)
	otherRoute, _ := NetworkRouteIdTryCreate("route-other", 32)
	observation := NetworkRouteObservation{Route: otherRoute, Owner: scope.Cell, NextPeer: otherPeer,
		TrustPlane: scope.TrustPlane, Destination: scope.Destination}

	tests := []struct {
		name   string
		change func(*NetworkRouteEvidence)
		code   NetworkCode
	}{
		{name: "ambiguous destination owner", change: func(e *NetworkRouteEvidence) { e.routes = []NetworkRouteObservation{observation} }, code: NetworkCodeAmbiguousOwnership},
		{name: "route leak", change: func(e *NetworkRouteEvidence) { e.approved = nil }, code: NetworkCodeRouteLeak},
		{name: "ownership not proven", change: func(e *NetworkRouteEvidence) { e.NoOverlappingMutation = NetworkProofUnknown }, code: NetworkCodeAmbiguousOwnership},
		{name: "topology mismatch", change: func(e *NetworkRouteEvidence) { e.Shape = NetworkTopologyShapeInitialThreeFullMesh }, code: NetworkCodeQuadraticMesh},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evidence := testRouteEvidence(t, scope, cells, links, approved, nil)
			test.change(evidence)
			assertNetworkDecision(t, NetworkRoutePlanner.Plan(&scope, scope.Generation, scope.Epoch, evidence), NetworkActionHold, NetworkTargetNone, test.code)
		})
	}
}
