package netplan

import (
	"encoding/hex"
	"sort"
	"strconv"
)

// NetworkTechnicalLimits ports the technical denial-of-service safety limits;
// these are not route, topology, or exposure policy.
const NetworkTechnicalLimitsMaximumCapturedItems = 4096

// networkInputSnapshotCopy ports the internal NetworkInputSnapshot.Copy.
func networkInputSnapshotCopy[T any](source []T, maximum int, parameterName string) ([]T, error) {
	if source == nil {
		return nil, argumentNil(parameterName)
	}
	if len(source) > maximum {
		return nil, invalidArgument(parameterName, "Network input exceeds the technical item limit.")
	}
	result := make([]T, len(source))
	copy(result, source)
	return result, nil
}

type NetworkEndpointScope struct {
	Cell              NetworkCellId
	Workload          NetworkWorkloadId
	Service           NetworkServiceId
	Endpoint          NetworkEndpointId
	Node              NetworkNodeId
	LoadBalancer      NetworkLoadBalancerId
	Backend           NetworkBackendId
	Dns               NetworkDnsId
	Certificate       NetworkCertificateRef
	ServiceKind       NetworkServiceKind
	Exposure          NetworkExposure
	Protocol          NetworkProtocol
	Port              NetworkPort
	ServiceGeneration NetworkOrdinal
	Epoch             NetworkOrdinal
	Operation         NetworkOperationId
}

func (s NetworkEndpointScope) Valid() bool {
	return s.Cell.IsValid() && s.Workload.IsValid() && s.Service.IsValid() && s.Endpoint.IsValid() &&
		s.Node.IsValid() && s.LoadBalancer.IsValid() && s.Backend.IsValid() && s.Dns.IsValid() &&
		s.Certificate.IsValid() && networkServiceKindIsDefined(s.ServiceKind) &&
		s.ServiceKind != NetworkServiceKindUnknown && networkExposureIsDefined(s.Exposure) &&
		s.Exposure != NetworkExposureUnknown && networkProtocolIsDefined(s.Protocol) &&
		s.Protocol != NetworkProtocolUnknown && s.Port.IsValid() && s.ServiceGeneration.IsValid() &&
		s.Epoch.IsValid() && s.Operation.IsValid()
}

type NetworkEndpointEvidence struct {
	Scope                           NetworkEndpointScope
	ObservedGeneration              NetworkOrdinal
	ObservedEpoch                   NetworkOrdinal
	RegistryAdmitted                NetworkProof
	ProcessLive                     NetworkProof
	Ready                           NetworkProof
	BackendHealth                   NetworkHealth
	CertificateMatches              NetworkProof
	TrustProven                     NetworkProof
	PublicApproved                  NetworkProof
	ProductionGates                 NetworkProof
	WithdrawalTested                NetworkProof
	BackendRegistered               NetworkProof
	BackendPromoted                 NetworkProof
	DnsRequestRecorded              NetworkProof
	DnsObserved                     NetworkProof
	Deregistered                    NetworkProof
	Drained                         NetworkProof
	DnsWithdrawalRequested          NetworkProof
	DnsWithdrawn                    NetworkProof
	LoadBalancerWithdrawalRequested NetworkProof
	LoadBalancerWithdrawn           NetworkProof
	DeregistrationRequested         NetworkProof
}

var NetworkEndpointPlanner networkEndpointPlanner

type networkEndpointPlanner struct{}

func (networkEndpointPlanner) PlanRegister(expected *NetworkEndpointScope, e *NetworkEndpointEvidence) NetworkDecision {
	var trace *NetworkNumericTrace
	if expected != nil {
		trace = &NetworkNumericTrace{Generation: expected.ServiceGeneration, Epoch: expected.Epoch}
	}
	code := networkEndpointValidate(expected, e)
	if code != NetworkCodeCompleted || expected == nil || e == nil || trace == nil {
		return networkDecisionHold(code, trace)
	}
	scope := *expected
	if (scope.ServiceKind == NetworkServiceKindAdministration || scope.ServiceKind == NetworkServiceKindMonitoring) &&
		scope.Exposure != NetworkExposurePrivate {
		return networkDecisionHold(NetworkCodeForbiddenExposure, trace)
	}
	if scope.Exposure == NetworkExposurePublic && scope.Protocol == NetworkProtocolHttp {
		return networkDecisionHold(NetworkCodeForbiddenExposure, trace)
	}
	if e.RegistryAdmitted != NetworkProofProven {
		return networkDecisionHold(NetworkCodeDefaultDeny, trace)
	}
	if e.ProcessLive != NetworkProofProven {
		return networkDecisionHold(NetworkCodeReadinessRequired, trace)
	}
	if e.Ready != NetworkProofProven {
		return networkDecisionHold(NetworkCodeReadinessRequired, trace)
	}
	if e.BackendHealth != NetworkHealthHealthy {
		return networkDecisionHold(NetworkCodeBackendHealthRequired, trace)
	}
	if e.CertificateMatches != NetworkProofProven || e.TrustProven != NetworkProofProven {
		return networkDecisionHold(NetworkCodeCertificateMismatch, trace)
	}
	if scope.Exposure == NetworkExposurePublic && (e.PublicApproved != NetworkProofProven ||
		e.ProductionGates != NetworkProofProven || e.WithdrawalTested != NetworkProofProven) {
		return networkDecisionHold(NetworkCodePublicApprovalRequired, trace)
	}
	subject := &NetworkEndpointIntentSubject{PlanKind: NetworkEndpointPlanKindRegister, Scope: scope, Evidence: *e}
	if e.BackendRegistered != NetworkProofProven {
		return networkDecisionEmit(NetworkActionRegister, NetworkTargetBackend, NetworkCodeNextStep, subject, *trace)
	}
	if e.BackendPromoted != NetworkProofProven {
		return networkDecisionEmit(NetworkActionPromote, NetworkTargetLoadBalancer, NetworkCodeNextStep, subject, *trace)
	}
	if e.DnsRequestRecorded != NetworkProofProven {
		return networkDecisionEmit(NetworkActionDnsUpdate, NetworkTargetDns, NetworkCodeNextStep, subject, *trace)
	}
	if e.DnsObserved != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetDns, NetworkCodeDnsConvergencePending, subject, *trace)
	}
	return networkDecisionEmit(NetworkActionVerify, NetworkTargetIngress, NetworkCodeCompleted, subject, *trace)
}

func (networkEndpointPlanner) PlanRemoval(expected *NetworkEndpointScope, e *NetworkEndpointEvidence) NetworkDecision {
	var trace *NetworkNumericTrace
	if expected != nil {
		trace = &NetworkNumericTrace{Generation: expected.ServiceGeneration, Epoch: expected.Epoch}
	}
	code := networkEndpointValidate(expected, e)
	if code != NetworkCodeCompleted || expected == nil || e == nil || trace == nil {
		return networkDecisionHold(code, trace)
	}
	scope := *expected
	subject := &NetworkEndpointIntentSubject{PlanKind: NetworkEndpointPlanKindRemoval, Scope: scope, Evidence: *e}
	if e.BackendHealth == NetworkHealthUnknown || e.BackendHealth == NetworkHealthStale {
		return networkDecisionHold(NetworkCodeBackendHealthRequired, trace)
	}
	if e.DeregistrationRequested != NetworkProofProven {
		return networkDecisionEmit(NetworkActionDeregister, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain, subject, *trace)
	}
	if e.Deregistered != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain, subject, *trace)
	}
	if e.Drained != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetBackend, NetworkCodeDeregisterBeforeDrain, subject, *trace)
	}
	return networkDecisionEmit(NetworkActionVerify, NetworkTargetBackend, NetworkCodeCompleted, subject, *trace)
}

func (networkEndpointPlanner) PlanEmergencyWithdrawal(expected *NetworkEndpointScope, e *NetworkEndpointEvidence) NetworkDecision {
	var trace *NetworkNumericTrace
	if expected != nil {
		trace = &NetworkNumericTrace{Generation: expected.ServiceGeneration, Epoch: expected.Epoch}
	}
	code := networkEndpointValidate(expected, e)
	if code != NetworkCodeCompleted || expected == nil || e == nil || trace == nil {
		return networkDecisionHold(code, trace)
	}
	scope := *expected
	subject := &NetworkEndpointIntentSubject{PlanKind: NetworkEndpointPlanKindEmergencyWithdrawal, Scope: scope, Evidence: *e}
	if e.DnsWithdrawalRequested != NetworkProofProven {
		return networkDecisionEmit(NetworkActionDnsUpdate, NetworkTargetDns, NetworkCodeEmergencyWithdrawal, subject, *trace)
	}
	if e.DnsWithdrawn != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetDns, NetworkCodeEmergencyWithdrawal, subject, *trace)
	}
	if e.LoadBalancerWithdrawalRequested != NetworkProofProven {
		return networkDecisionEmit(NetworkActionDeregister, NetworkTargetLoadBalancer, NetworkCodeEmergencyWithdrawal, subject, *trace)
	}
	if e.LoadBalancerWithdrawn != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetLoadBalancer, NetworkCodeEmergencyWithdrawal, subject, *trace)
	}
	return networkDecisionEmit(NetworkActionVerify, NetworkTargetIngress, NetworkCodeCompleted, subject, *trace)
}

func networkEndpointValidate(expected *NetworkEndpointScope, e *NetworkEndpointEvidence) NetworkCode {
	if expected == nil || !expected.Valid() || e == nil || e.Scope != *expected {
		return NetworkCodeWrongEvidenceScope
	}
	for _, proof := range []NetworkProof{e.RegistryAdmitted, e.ProcessLive, e.Ready, e.CertificateMatches,
		e.TrustProven, e.PublicApproved, e.ProductionGates, e.WithdrawalTested, e.BackendRegistered,
		e.BackendPromoted, e.DnsRequestRecorded, e.DnsObserved, e.Deregistered, e.Drained,
		e.DnsWithdrawalRequested, e.DnsWithdrawn, e.LoadBalancerWithdrawalRequested,
		e.LoadBalancerWithdrawn, e.DeregistrationRequested} {
		if !networkProofIsDefined(proof) {
			return NetworkCodeInvalidInput
		}
	}
	if !networkHealthIsDefined(e.BackendHealth) {
		return NetworkCodeInvalidInput
	}
	if e.ObservedGeneration.Value < expected.ServiceGeneration.Value || e.ObservedEpoch.Value < expected.Epoch.Value {
		return NetworkCodeStaleGeneration
	}
	if e.ObservedGeneration.Value > expected.ServiceGeneration.Value || e.ObservedEpoch.Value > expected.Epoch.Value {
		return NetworkCodeFutureGeneration
	}
	return NetworkCodeCompleted
}

type NetworkRouteScope struct {
	Cell        NetworkCellId
	PeerCell    NetworkCellId
	Network     NetworkId
	Subnet      NetworkSubnetId
	Route       NetworkRouteId
	Peer        NetworkPeerId
	Tunnel      NetworkTunnelId
	TrustPlane  NetworkTrustPlane
	Destination NetworkPrefix
	RouteKind   NetworkRouteKind
	Generation  NetworkOrdinal
	Epoch       NetworkOrdinal
	Operation   NetworkOperationId
}

func (s NetworkRouteScope) Valid() bool {
	return s.Cell.IsValid() && s.PeerCell.IsValid() && s.Network.IsValid() && s.Subnet.IsValid() &&
		s.Route.IsValid() && s.Peer.IsValid() && s.Tunnel.IsValid() &&
		networkTrustPlaneIsDefined(s.TrustPlane) && s.TrustPlane != NetworkTrustPlaneUnknown &&
		len(s.Destination.Address.bytes) > 0 && networkRouteKindIsDefined(s.RouteKind) &&
		s.RouteKind != NetworkRouteKindUnknown && s.Generation.IsValid() && s.Epoch.IsValid() &&
		s.Operation.IsValid()
}

type NetworkRouteObservation struct {
	Route           NetworkRouteId
	Owner           NetworkCellId
	NextPeer        NetworkPeerId
	LearnedFromPeer *NetworkPeerId
	TrustPlane      NetworkTrustPlane
	Destination     NetworkPrefix
}

type NetworkPeerLink struct {
	From NetworkCellId
	To   NetworkCellId
}

type NetworkRouteEvidence struct {
	Scope                 NetworkRouteScope
	Shape                 NetworkTopologyShape
	NoOverlappingMutation NetworkProof
	LocalPolicy           NetworkProof
	TunnelConfigured      NetworkProof
	TrafficProven         NetworkProof
	TunnelHealthy         NetworkProof
	RouteConfigured       NetworkProof
	Partitioned           bool
	IsValid               bool
	routes                []NetworkRouteObservation
	approved              []NetworkPrefix
	links                 []NetworkPeerLink
	cells                 []NetworkCellId
}

func NewNetworkRouteEvidence(scope NetworkRouteScope, routes []NetworkRouteObservation, approved []NetworkPrefix,
	cells []NetworkCellId, links []NetworkPeerLink, shape NetworkTopologyShape, noOverlappingMutation,
	localPolicy, tunnelConfigured, trafficProven, tunnelHealthy, routeConfigured NetworkProof, partitioned bool,
	maximumRoutes, maximumPrefixes, maximumLinks, maximumCells int) *NetworkRouteEvidence {
	evidence := &NetworkRouteEvidence{Scope: scope, Shape: shape, NoOverlappingMutation: noOverlappingMutation,
		LocalPolicy: localPolicy, TunnelConfigured: tunnelConfigured, TrafficProven: trafficProven,
		TunnelHealthy: tunnelHealthy, RouteConfigured: routeConfigured, Partitioned: partitioned,
		routes:   append([]NetworkRouteObservation{}, routes...),
		approved: append([]NetworkPrefix{}, approved...),
		links:    append([]NetworkPeerLink{}, links...),
		cells:    append([]NetworkCellId{}, cells...)}
	validCells := len(evidence.cells) > 0
	distinctCells := map[NetworkCellId]struct{}{}
	for _, cell := range evidence.cells {
		distinctCells[cell] = struct{}{}
	}
	validCells = validCells && len(distinctCells) == len(evidence.cells)
	containsScopeCells := false
	containsPeerCell := false
	for _, cell := range evidence.cells {
		if cell == scope.Cell {
			containsScopeCells = true
		}
		if cell == scope.PeerCell {
			containsPeerCell = true
		}
	}
	routesValid := true
	for _, route := range evidence.routes {
		if !route.Route.IsValid() || !route.Owner.IsValid() || !route.NextPeer.IsValid() ||
			len(route.Destination.Address.bytes) == 0 || !networkTrustPlaneIsDefined(route.TrustPlane) ||
			route.TrustPlane == NetworkTrustPlaneUnknown {
			routesValid = false
			break
		}
	}
	linksValid := true
	for _, link := range evidence.links {
		if !link.From.IsValid() || !link.To.IsValid() || link.From == link.To {
			linksValid = false
			break
		}
		fromKnown, toKnown := false, false
		for _, cell := range evidence.cells {
			if cell == link.From {
				fromKnown = true
			}
			if cell == link.To {
				toKnown = true
			}
		}
		if !fromKnown || !toKnown {
			linksValid = false
			break
		}
	}
	evidence.IsValid = scope.Valid() && maximumRoutes > 0 && maximumPrefixes > 0 && maximumLinks > 0 &&
		maximumCells > 0 && len(evidence.routes) <= maximumRoutes && len(evidence.approved) > 0 &&
		len(evidence.approved) <= maximumPrefixes && len(evidence.links) <= maximumLinks &&
		len(evidence.cells) <= maximumCells && validCells && containsScopeCells && containsPeerCell &&
		routesValid && linksValid &&
		networkTopologyShapeIsDefined(shape) && shape != NetworkTopologyShapeUnknown &&
		networkProofIsDefined(noOverlappingMutation) && networkProofIsDefined(localPolicy) &&
		networkProofIsDefined(tunnelConfigured) && networkProofIsDefined(trafficProven) &&
		networkProofIsDefined(tunnelHealthy) && networkProofIsDefined(routeConfigured)
	return evidence
}

func (s NetworkRouteScope) Equal(other NetworkRouteScope) bool {
	return s.Cell == other.Cell && s.PeerCell == other.PeerCell && s.Network == other.Network &&
		s.Subnet == other.Subnet && s.Route == other.Route && s.Peer == other.Peer &&
		s.Tunnel == other.Tunnel && s.TrustPlane == other.TrustPlane &&
		s.Destination.Equal(other.Destination) && s.RouteKind == other.RouteKind &&
		s.Generation == other.Generation && s.Epoch == other.Epoch && s.Operation == other.Operation
}

func (e *NetworkRouteEvidence) Routes() []NetworkRouteObservation {
	return append([]NetworkRouteObservation{}, e.routes...)
}

func (e *NetworkRouteEvidence) ApprovedPrefixes() []NetworkPrefix {
	return append([]NetworkPrefix{}, e.approved...)
}

func (e *NetworkRouteEvidence) Links() []NetworkPeerLink {
	return append([]NetworkPeerLink{}, e.links...)
}

func (e *NetworkRouteEvidence) Cells() []NetworkCellId {
	return append([]NetworkCellId{}, e.cells...)
}

func (e *NetworkRouteEvidence) CellCount() uint32 { return uint32(len(e.cells)) }

func (e *NetworkRouteEvidence) Equal(other *NetworkRouteEvidence) bool {
	if other == nil || !e.Scope.Equal(other.Scope) || e.Shape != other.Shape ||
		e.NoOverlappingMutation != other.NoOverlappingMutation || e.LocalPolicy != other.LocalPolicy ||
		e.TunnelConfigured != other.TunnelConfigured || e.TrafficProven != other.TrafficProven ||
		e.TunnelHealthy != other.TunnelHealthy || e.RouteConfigured != other.RouteConfigured ||
		e.Partitioned != other.Partitioned || e.IsValid != other.IsValid {
		return false
	}
	leftRoutes, rightRoutes := networkCanonicalRoutes(e.routes), networkCanonicalRoutes(other.routes)
	leftPrefixes, rightPrefixes := networkCanonicalPrefixes(e.approved), networkCanonicalPrefixes(other.approved)
	leftLinks, rightLinks := networkCanonicalLinks(e.links), networkCanonicalLinks(other.links)
	leftCells, rightCells := networkCanonicalCells(e.cells), networkCanonicalCells(other.cells)
	return stringSlicesEqualOrdinal(leftRoutes, rightRoutes) &&
		stringSlicesEqualOrdinal(leftPrefixes, rightPrefixes) &&
		stringSlicesEqualOrdinal(leftLinks, rightLinks) &&
		stringSlicesEqualOrdinal(leftCells, rightCells)
}

func stringSlicesEqualOrdinal(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func networkCanonicalSorted(values []string) []string {
	sorted := make([]string, len(values))
	copy(sorted, values)
	sort.Strings(sorted)
	return sorted
}

func networkCanonicalRoutes(routes []NetworkRouteObservation) []string {
	keys := make([]string, 0, len(routes))
	for _, route := range routes {
		learned := "null"
		if route.LearnedFromPeer != nil {
			learned = "identity:" + route.LearnedFromPeer.Value
		}
		keys = append(keys, "route:identity:"+route.Route.Value+":identity:"+route.Owner.Value+
			":identity:"+route.NextPeer.Value+":"+learned+":"+strconv.Itoa(int(route.TrustPlane))+
			":prefix:"+hex.EncodeToString(route.Destination.Address.bytes)+":"+
			strconv.Itoa(int(route.Destination.Bits)))
	}
	return networkCanonicalSorted(keys)
}

func networkCanonicalPrefixes(prefixes []NetworkPrefix) []string {
	keys := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		keys = append(keys, "prefix:"+hex.EncodeToString(prefix.Address.bytes)+":"+
			strconv.Itoa(int(prefix.Bits)))
	}
	return networkCanonicalSorted(keys)
}

func networkCanonicalLinks(links []NetworkPeerLink) []string {
	keys := make([]string, 0, len(links))
	for _, link := range links {
		keys = append(keys, "link:identity:"+link.From.Value+":identity:"+link.To.Value)
	}
	return networkCanonicalSorted(keys)
}

func networkCanonicalCells(cells []NetworkCellId) []string {
	keys := make([]string, 0, len(cells))
	for _, cell := range cells {
		keys = append(keys, "identity:"+cell.Value)
	}
	return networkCanonicalSorted(keys)
}

var NetworkRoutePlanner networkRoutePlanner

type networkRoutePlanner struct{}

func (networkRoutePlanner) Plan(expected *NetworkRouteScope, observedGeneration, observedEpoch NetworkOrdinal,
	e *NetworkRouteEvidence) NetworkDecision {
	if expected == nil || !expected.Valid() {
		return networkDecisionHold(NetworkCodeWrongEvidenceScope, nil)
	}
	routeCount := uint32(0)
	distinctPeers := uint32(0)
	if e != nil {
		routeCount = uint32(len(e.routes))
		peers := map[NetworkPeerId]struct{}{}
		for _, route := range e.routes {
			peers[route.NextPeer] = struct{}{}
		}
		distinctPeers = uint32(len(peers))
	}
	trace := NetworkNumericTrace{Generation: expected.Generation, Epoch: expected.Epoch,
		RouteCount: routeCount, PeerCount: distinctPeers}
	if e == nil || !e.IsValid || !e.Scope.Equal(*expected) {
		return networkDecisionHold(NetworkCodeWrongEvidenceScope, &trace)
	}
	if observedGeneration.Value < expected.Generation.Value || observedEpoch.Value < expected.Epoch.Value {
		return networkDecisionHold(NetworkCodeStaleGeneration, &trace)
	}
	if observedGeneration.Value > expected.Generation.Value || observedEpoch.Value > expected.Epoch.Value {
		return networkDecisionHold(NetworkCodeFutureGeneration, &trace)
	}
	if e.CellCount() == 0 {
		return networkDecisionHold(NetworkCodeInvalidInput, &trace)
	}
	distinctLinks := map[NetworkPeerLink]struct{}{}
	for _, link := range e.links {
		distinctLinks[link] = struct{}{}
	}
	if len(distinctLinks) != len(e.links) {
		return networkDecisionHold(NetworkCodeInvalidInput, &trace)
	}
	if !networkTopologyMatchesDeclaredShape(e) {
		return networkDecisionHold(NetworkCodeQuadraticMesh, &trace)
	}
	if expected.RouteKind != NetworkRouteKindLocal {
		linked := false
		for _, link := range e.links {
			if link.From == expected.Cell && link.To == expected.PeerCell {
				linked = true
				break
			}
		}
		if !linked {
			return networkDecisionHold(NetworkCodeWrongEvidenceScope, &trace)
		}
	}
	if e.NoOverlappingMutation != NetworkProofProven {
		return networkDecisionHold(NetworkCodeAmbiguousOwnership, &trace)
	}
	covered := false
	for _, prefix := range e.approved {
		if prefix.Contains(expected.Destination) {
			covered = true
			break
		}
	}
	if !covered {
		return networkDecisionHold(NetworkCodeRouteLeak, &trace)
	}
	distinctRouteIds := map[NetworkRouteId]struct{}{}
	for _, route := range e.routes {
		distinctRouteIds[route.Route] = struct{}{}
	}
	if len(distinctRouteIds) != len(e.routes) {
		return networkDecisionHold(NetworkCodeDuplicate, &trace)
	}
	routePairs := map[string]int{}
	for _, route := range e.routes {
		key := hex.EncodeToString(route.Destination.Address.bytes) + "|" +
			strconv.Itoa(int(route.Destination.Bits)) + "|" + route.NextPeer.Value
		routePairs[key]++
	}
	for _, count := range routePairs {
		if count > 1 {
			return networkDecisionHold(NetworkCodeDuplicate, &trace)
		}
	}
	for _, route := range e.routes {
		if route.Owner != expected.Cell {
			return networkDecisionHold(NetworkCodeWrongEvidenceScope, &trace)
		}
	}
	for _, route := range e.routes {
		if route.TrustPlane != expected.TrustPlane {
			return networkDecisionHold(NetworkCodeTrustPlaneCrossover, &trace)
		}
	}
	for _, route := range e.routes {
		allowed := false
		for _, prefix := range e.approved {
			if prefix.Contains(route.Destination) {
				allowed = true
				break
			}
		}
		if !allowed {
			return networkDecisionHold(NetworkCodeRouteLeak, &trace)
		}
	}
	for _, route := range e.routes {
		if route.LearnedFromPeer != nil && *route.LearnedFromPeer == expected.Peer &&
			route.NextPeer == expected.Peer {
			return networkDecisionHold(NetworkCodeReflection, &trace)
		}
	}
	for _, route := range e.routes {
		if route.Destination.Equal(expected.Destination) && route.NextPeer != expected.Peer {
			return networkDecisionHold(NetworkCodeAmbiguousOwnership, &trace)
		}
	}
	for _, route := range e.routes {
		if route.Destination.Overlaps(expected.Destination) && route.NextPeer != expected.Peer {
			return networkDecisionHold(NetworkCodeOverlap, &trace)
		}
	}
	if expected.RouteKind == NetworkRouteKindLocal && expected.PeerCell != expected.Cell {
		if e.Partitioned && e.LocalPolicy != NetworkProofProven {
			return networkDecisionHold(NetworkCodeLocalPolicyRequired, &trace)
		}
		if e.Partitioned {
			return networkDecisionHold(NetworkCodePartitionAuthorityDenied, &trace)
		}
		return networkDecisionHold(NetworkCodeWrongEvidenceScope, &trace)
	}
	subject := &NetworkRouteIntentSubject{Scope: *expected, ObservedGeneration: observedGeneration,
		ObservedEpoch: observedEpoch, Evidence: e}
	if e.Partitioned {
		if e.LocalPolicy != NetworkProofProven {
			return networkDecisionHold(NetworkCodeLocalPolicyRequired, &trace)
		}
		if expected.TrustPlane != NetworkTrustPlaneProduct || expected.RouteKind != NetworkRouteKindLocal {
			return networkDecisionHold(NetworkCodePartitionAuthorityDenied, &trace)
		}
	}
	if e.TunnelConfigured != NetworkProofProven {
		return networkDecisionEmit(NetworkActionConfigureTunnel, NetworkTargetTunnel, NetworkCodeNextStep, subject, trace)
	}
	if e.TunnelHealthy == NetworkProofContradicted || e.TrafficProven == NetworkProofContradicted {
		return networkDecisionEmit(NetworkActionRollback, NetworkTargetTunnel, NetworkCodeTunnelHealthRequired, subject, trace)
	}
	if e.TunnelHealthy != NetworkProofProven || e.TrafficProven != NetworkProofProven {
		return networkDecisionEmit(NetworkActionObserve, NetworkTargetTunnel, NetworkCodeTunnelHealthRequired, subject, trace)
	}
	if e.RouteConfigured != NetworkProofProven {
		return networkDecisionEmit(NetworkActionConfigureRoute, NetworkTargetRoute, NetworkCodeNextStep, subject, trace)
	}
	return networkDecisionEmit(NetworkActionVerify, NetworkTargetRoute, NetworkCodeCompleted, subject, trace)
}

func networkTopologyMatchesDeclaredShape(e *NetworkRouteEvidence) bool {
	cells := uint64(e.CellCount())
	links := uint64(len(e.links))
	if e.Shape == NetworkTopologyShapeInitialThreeFullMesh {
		if cells != 3 || links != 6 {
			return false
		}
		for _, from := range e.cells {
			for _, to := range e.cells {
				if from == to {
					continue
				}
				found := false
				for _, link := range e.links {
					if link.From == from && link.To == to {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
		return true
	}
	if e.Shape == NetworkTopologyShapeExplicitReplication {
		return links <= cells*2
	}
	if e.Shape != NetworkTopologyShapeHubAndSpoke || cells < 3 || links != 2*(cells-1) {
		return false
	}
	hubCount := 0
	for _, hub := range e.cells {
		allThroughHub := true
		for _, link := range e.links {
			if link.From != hub && link.To != hub {
				allThroughHub = false
				break
			}
		}
		if !allThroughHub {
			continue
		}
		spokesComplete := true
		for _, spoke := range e.cells {
			if spoke == hub {
				continue
			}
			outbound, inbound := false, false
			for _, link := range e.links {
				if link.From == hub && link.To == spoke {
					outbound = true
				}
				if link.From == spoke && link.To == hub {
					inbound = true
				}
			}
			if !outbound || !inbound {
				spokesComplete = false
				break
			}
		}
		if spokesComplete {
			hubCount++
		}
	}
	return hubCount == 1
}
