// Port of src/TerraScale.Orchestrator/ControlPlane/Networking/NetworkingPrimitives.cs
package control

func networkValueRulesValid(value string, maximum int) bool {
	if maximum <= 0 || len(value) == 0 || len(value) > maximum {
		return false
	}
	runes := []rune(value)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if isSpaceRune(c) || isControlRune(c) {
			return false
		}
		if c >= 0xD800 && c <= 0xDBFF {
			if i+1 >= len(runes) || !(runes[i+1] >= 0xDC00 && runes[i+1] <= 0xDFFF) {
				return false
			}
			i++
		} else if c >= 0xDC00 && c <= 0xDFFF {
			return false
		}
	}
	return true
}

// networkIdentity is the Go form of the abstract NetworkIdentity record.
type networkIdentity struct {
	Value string
	valid bool
}

func (i networkIdentity) IsValid() bool { return i.valid }

type NetworkCellId struct{ networkIdentity }

func NetworkCellIdTryCreate(v string, m int) (NetworkCellId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkCellId{}, false
	}
	return NetworkCellId{networkIdentity{v, true}}, true
}

type NetworkId struct{ networkIdentity }

func NetworkIdTryCreate(v string, m int) (NetworkId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkId{}, false
	}
	return NetworkId{networkIdentity{v, true}}, true
}

type NetworkSubnetId struct{ networkIdentity }

func NetworkSubnetIdTryCreate(v string, m int) (NetworkSubnetId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkSubnetId{}, false
	}
	return NetworkSubnetId{networkIdentity{v, true}}, true
}

type NetworkNodeId struct{ networkIdentity }

func NetworkNodeIdTryCreate(v string, m int) (NetworkNodeId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkNodeId{}, false
	}
	return NetworkNodeId{networkIdentity{v, true}}, true
}

type NetworkWorkloadId struct{ networkIdentity }

func NetworkWorkloadIdTryCreate(v string, m int) (NetworkWorkloadId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkWorkloadId{}, false
	}
	return NetworkWorkloadId{networkIdentity{v, true}}, true
}

type NetworkServiceId struct{ networkIdentity }

func NetworkServiceIdTryCreate(v string, m int) (NetworkServiceId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkServiceId{}, false
	}
	return NetworkServiceId{networkIdentity{v, true}}, true
}

type NetworkEndpointId struct{ networkIdentity }

func NetworkEndpointIdTryCreate(v string, m int) (NetworkEndpointId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkEndpointId{}, false
	}
	return NetworkEndpointId{networkIdentity{v, true}}, true
}

type NetworkRouteId struct{ networkIdentity }

func NetworkRouteIdTryCreate(v string, m int) (NetworkRouteId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkRouteId{}, false
	}
	return NetworkRouteId{networkIdentity{v, true}}, true
}

type NetworkPeerId struct{ networkIdentity }

func NetworkPeerIdTryCreate(v string, m int) (NetworkPeerId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkPeerId{}, false
	}
	return NetworkPeerId{networkIdentity{v, true}}, true
}

type NetworkTunnelId struct{ networkIdentity }

func NetworkTunnelIdTryCreate(v string, m int) (NetworkTunnelId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkTunnelId{}, false
	}
	return NetworkTunnelId{networkIdentity{v, true}}, true
}

type NetworkDnsId struct{ networkIdentity }

func NetworkDnsIdTryCreate(v string, m int) (NetworkDnsId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkDnsId{}, false
	}
	return NetworkDnsId{networkIdentity{v, true}}, true
}

type NetworkLoadBalancerId struct{ networkIdentity }

func NetworkLoadBalancerIdTryCreate(v string, m int) (NetworkLoadBalancerId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkLoadBalancerId{}, false
	}
	return NetworkLoadBalancerId{networkIdentity{v, true}}, true
}

type NetworkBackendId struct{ networkIdentity }

func NetworkBackendIdTryCreate(v string, m int) (NetworkBackendId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkBackendId{}, false
	}
	return NetworkBackendId{networkIdentity{v, true}}, true
}

type NetworkCertificateRef struct{ networkIdentity }

func NetworkCertificateRefTryCreate(v string, m int) (NetworkCertificateRef, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkCertificateRef{}, false
	}
	return NetworkCertificateRef{networkIdentity{v, true}}, true
}

type NetworkOperationId struct{ networkIdentity }

func NetworkOperationIdTryCreate(v string, m int) (NetworkOperationId, bool) {
	if !networkValueRulesValid(v, m) {
		return NetworkOperationId{}, false
	}
	return NetworkOperationId{networkIdentity{v, true}}, true
}

type NetworkOrdinal struct{ Value uint64 }

func (o NetworkOrdinal) IsValid() bool { return o.Value > 0 }

func NetworkOrdinalTryCreate(v uint64) (NetworkOrdinal, bool) {
	if v > 0 {
		return NetworkOrdinal{v}, true
	}
	return NetworkOrdinal{}, false
}

type NetworkPort struct{ Value uint16 }

func (p NetworkPort) IsValid() bool { return p.Value > 0 }

func NetworkPortTryCreate(v uint16) (NetworkPort, bool) {
	if v > 0 {
		return NetworkPort{v}, true
	}
	return NetworkPort{}, false
}

type NetworkAddress struct {
	bytes []byte
}

func NetworkAddressTryCreate(bytes []byte) (NetworkAddress, bool) {
	if len(bytes) != 4 && len(bytes) != 16 {
		return NetworkAddress{}, false
	}
	copied := make([]byte, len(bytes))
	copy(copied, bytes)
	return NetworkAddress{bytes: copied}, true
}

func (a NetworkAddress) BitLength() int { return len(a.bytes) * 8 }
func (a NetworkAddress) Bytes() []byte  { return a.bytes }
func (a NetworkAddress) Equal(other NetworkAddress) bool {
	if len(a.bytes) != len(other.bytes) {
		return false
	}
	for index := range a.bytes {
		if a.bytes[index] != other.bytes[index] {
			return false
		}
	}
	return true
}

type NetworkPrefix struct {
	Address NetworkAddress
	Bits    byte
}

func NetworkPrefixTryCreate(address NetworkAddress, bits byte) (NetworkPrefix, bool) {
	if len(address.bytes) == 0 || bits > byte(address.BitLength()) {
		return NetworkPrefix{}, false
	}
	bytes := address.bytes
	for bit := int(bits); bit < address.BitLength(); bit++ {
		if bytes[bit/8]&(1<<(7-bit%8)) != 0 {
			return NetworkPrefix{}, false
		}
	}
	return NetworkPrefix{Address: address, Bits: bits}, true
}

func (p NetworkPrefix) Contains(other NetworkPrefix) bool {
	if p.Address.BitLength() != other.Address.BitLength() || p.Bits > other.Bits {
		return false
	}
	for bit := 0; bit < int(p.Bits); bit++ {
		if (p.Address.bytes[bit/8] & (1 << (7 - bit%8))) != (other.Address.bytes[bit/8] & (1 << (7 - bit%8))) {
			return false
		}
	}
	return true
}

func (p NetworkPrefix) Overlaps(other NetworkPrefix) bool {
	return p.Contains(other) || other.Contains(p)
}

func (p NetworkPrefix) Equal(other NetworkPrefix) bool {
	return p.Bits == other.Bits && p.Address.Equal(other.Address)
}

type NetworkExposure int

const (
	NetworkExposureUnknown  NetworkExposure = 0
	NetworkExposurePrivate  NetworkExposure = 1
	NetworkExposureWorkload NetworkExposure = 2
	NetworkExposurePublic   NetworkExposure = 3
)

func networkExposureIsDefined(v NetworkExposure) bool {
	return v >= NetworkExposureUnknown && v <= NetworkExposurePublic
}

type NetworkProtocol int

const (
	NetworkProtocolUnknown NetworkProtocol = 0
	NetworkProtocolTcp     NetworkProtocol = 1
	NetworkProtocolUdp     NetworkProtocol = 2
	NetworkProtocolHttp    NetworkProtocol = 3
	NetworkProtocolHttps   NetworkProtocol = 4
)

func networkProtocolIsDefined(v NetworkProtocol) bool {
	return v >= NetworkProtocolUnknown && v <= NetworkProtocolHttps
}

type NetworkTrustPlane int

const (
	NetworkTrustPlaneUnknown   NetworkTrustPlane = 0
	NetworkTrustPlaneControl   NetworkTrustPlane = 1
	NetworkTrustPlaneProduct   NetworkTrustPlane = 2
	NetworkTrustPlaneTelemetry NetworkTrustPlane = 3
)

func networkTrustPlaneIsDefined(v NetworkTrustPlane) bool {
	return v >= NetworkTrustPlaneUnknown && v <= NetworkTrustPlaneTelemetry
}

type NetworkRouteKind int

const (
	NetworkRouteKindUnknown             NetworkRouteKind = 0
	NetworkRouteKindLocal               NetworkRouteKind = 1
	NetworkRouteKindPeer                NetworkRouteKind = 2
	NetworkRouteKindExplicitReplication NetworkRouteKind = 3
	NetworkRouteKindEmergencyWithdrawal NetworkRouteKind = 4
)

func networkRouteKindIsDefined(v NetworkRouteKind) bool {
	return v >= NetworkRouteKindUnknown && v <= NetworkRouteKindEmergencyWithdrawal
}

type NetworkTunnelState int

const (
	NetworkTunnelStateUnknown NetworkTunnelState = 0
	NetworkTunnelStateStaged  NetworkTunnelState = 1
	NetworkTunnelStateHealthy NetworkTunnelState = 2
	NetworkTunnelStateFailed  NetworkTunnelState = 3
)

type NetworkBackendState int

const (
	NetworkBackendStateUnknown      NetworkBackendState = 0
	NetworkBackendStateAdmitted     NetworkBackendState = 1
	NetworkBackendStateRegistered   NetworkBackendState = 2
	NetworkBackendStatePromoted     NetworkBackendState = 3
	NetworkBackendStateDeregistered NetworkBackendState = 4
	NetworkBackendStateDrained      NetworkBackendState = 5
)

type NetworkHealth int

const (
	NetworkHealthUnknown   NetworkHealth = 0
	NetworkHealthHealthy   NetworkHealth = 1
	NetworkHealthUnhealthy NetworkHealth = 2
	NetworkHealthStale     NetworkHealth = 3
)

func networkHealthIsDefined(v NetworkHealth) bool {
	return v >= NetworkHealthUnknown && v <= NetworkHealthStale
}

type NetworkServiceKind int

const (
	NetworkServiceKindUnknown        NetworkServiceKind = 0
	NetworkServiceKindProduct        NetworkServiceKind = 1
	NetworkServiceKindMonitoring     NetworkServiceKind = 2
	NetworkServiceKindAdministration NetworkServiceKind = 3
)

func networkServiceKindIsDefined(v NetworkServiceKind) bool {
	return v >= NetworkServiceKindUnknown && v <= NetworkServiceKindAdministration
}

type NetworkTopologyShape int

const (
	NetworkTopologyShapeUnknown              NetworkTopologyShape = 0
	NetworkTopologyShapeInitialThreeFullMesh NetworkTopologyShape = 1
	NetworkTopologyShapeHubAndSpoke          NetworkTopologyShape = 2
	NetworkTopologyShapeExplicitReplication  NetworkTopologyShape = 3
)

func networkTopologyShapeIsDefined(v NetworkTopologyShape) bool {
	return v >= NetworkTopologyShapeUnknown && v <= NetworkTopologyShapeExplicitReplication
}

type NetworkProof int

const (
	NetworkProofUnknown      NetworkProof = 0
	NetworkProofProven       NetworkProof = 1
	NetworkProofContradicted NetworkProof = 2
)

func networkProofIsDefined(v NetworkProof) bool {
	return v >= NetworkProofUnknown && v <= NetworkProofContradicted
}

type NetworkEndpointPlanKind int

const (
	NetworkEndpointPlanKindUnknown             NetworkEndpointPlanKind = 0
	NetworkEndpointPlanKindRegister            NetworkEndpointPlanKind = 1
	NetworkEndpointPlanKindRemoval             NetworkEndpointPlanKind = 2
	NetworkEndpointPlanKindEmergencyWithdrawal NetworkEndpointPlanKind = 3
)

func networkEndpointPlanKindIsDefined(v NetworkEndpointPlanKind) bool {
	return v >= NetworkEndpointPlanKindUnknown && v <= NetworkEndpointPlanKindEmergencyWithdrawal
}

type NetworkAction int

const (
	NetworkActionUninitialized   NetworkAction = 0
	NetworkActionObserve         NetworkAction = 1
	NetworkActionConfigureRoute  NetworkAction = 2
	NetworkActionConfigureTunnel NetworkAction = 3
	NetworkActionRegister        NetworkAction = 4
	NetworkActionDeregister      NetworkAction = 5
	NetworkActionPromote         NetworkAction = 6
	NetworkActionDnsUpdate       NetworkAction = 7
	NetworkActionRollback        NetworkAction = 8
	NetworkActionHold            NetworkAction = 9
	NetworkActionVerify          NetworkAction = 10
)

type NetworkTarget int

const (
	NetworkTargetNone         NetworkTarget = 0
	NetworkTargetRoute        NetworkTarget = 1
	NetworkTargetTunnel       NetworkTarget = 2
	NetworkTargetBackend      NetworkTarget = 3
	NetworkTargetLoadBalancer NetworkTarget = 4
	NetworkTargetDns          NetworkTarget = 5
	NetworkTargetIngress      NetworkTarget = 6
	NetworkTargetLocalService NetworkTarget = 7
)

type NetworkCode int

const (
	NetworkCodeUninitialized            NetworkCode = 0
	NetworkCodeNextStep                 NetworkCode = 1
	NetworkCodeCompleted                NetworkCode = 2
	NetworkCodeInvalidInput             NetworkCode = 3
	NetworkCodeWrongEvidenceScope       NetworkCode = 4
	NetworkCodeStaleGeneration          NetworkCode = 5
	NetworkCodeFutureGeneration         NetworkCode = 6
	NetworkCodeOverlap                  NetworkCode = 7
	NetworkCodeAmbiguousOwnership       NetworkCode = 8
	NetworkCodeDuplicate                NetworkCode = 9
	NetworkCodeRouteLeak                NetworkCode = 10
	NetworkCodeTrustPlaneCrossover      NetworkCode = 11
	NetworkCodeReflection               NetworkCode = 12
	NetworkCodeQuadraticMesh            NetworkCode = 13
	NetworkCodePartitionAuthorityDenied NetworkCode = 14
	NetworkCodeLocalPolicyRequired      NetworkCode = 15
	NetworkCodeTunnelHealthRequired     NetworkCode = 16
	NetworkCodeDefaultDeny              NetworkCode = 17
	NetworkCodePublicApprovalRequired   NetworkCode = 18
	NetworkCodeForbiddenExposure        NetworkCode = 19
	NetworkCodeCertificateMismatch      NetworkCode = 20
	NetworkCodeReadinessRequired        NetworkCode = 21
	NetworkCodeBackendHealthRequired    NetworkCode = 22
	NetworkCodeDnsConvergencePending    NetworkCode = 23
	NetworkCodeDeregisterBeforeDrain    NetworkCode = 24
	NetworkCodeEmergencyWithdrawal      NetworkCode = 25
)

type NetworkNumericTrace struct {
	Generation NetworkOrdinal
	Epoch      NetworkOrdinal
	RouteCount uint32
	PeerCount  uint32
}

// NetworkIntentSubject is the Go form of the abstract intent subject.
type NetworkIntentSubject interface {
	networkIntentSubject()
}

type NetworkRouteIntentSubject struct {
	Scope              NetworkRouteScope
	ObservedGeneration NetworkOrdinal
	ObservedEpoch      NetworkOrdinal
	Evidence           *NetworkRouteEvidence
}

func (*NetworkRouteIntentSubject) networkIntentSubject() {}

type NetworkEndpointIntentSubject struct {
	PlanKind NetworkEndpointPlanKind
	Scope    NetworkEndpointScope
	Evidence NetworkEndpointEvidence
}

func (*NetworkEndpointIntentSubject) networkIntentSubject() {}

type NetworkDecision struct {
	Action  NetworkAction
	Target  NetworkTarget
	Code    NetworkCode
	Subject NetworkIntentSubject
	Trace   *NetworkNumericTrace
}

func (d NetworkDecision) IsMutationAuthorized() bool {
	switch d.Action {
	case NetworkActionConfigureRoute, NetworkActionConfigureTunnel, NetworkActionRegister,
		NetworkActionDeregister, NetworkActionPromote, NetworkActionDnsUpdate, NetworkActionRollback:
		return true
	default:
		return false
	}
}

func networkDecisionEmit(a NetworkAction, t NetworkTarget, c NetworkCode, s NetworkIntentSubject,
	x NetworkNumericTrace) NetworkDecision {
	return NetworkDecision{Action: a, Target: t, Code: c, Subject: s, Trace: &x}
}

func networkDecisionHold(c NetworkCode, x *NetworkNumericTrace) NetworkDecision {
	return NetworkDecision{Action: NetworkActionHold, Target: NetworkTargetNone, Code: c, Subject: nil, Trace: x}
}
