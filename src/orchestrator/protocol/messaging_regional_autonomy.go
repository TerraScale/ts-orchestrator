package protocol

// MessagingConnectivity is the connectivity class for regional autonomy. The
// values align one-to-one with the ConnectivityState consumed by
// MessagingPolicyEngine.DecidePartition in the executable decision core.
type MessagingConnectivity int

const (
	MessagingConnectivityUnspecified MessagingConnectivity = 0
	MessagingConnectivityConnected   MessagingConnectivity = 1
	// MessagingConnectivityGlobalIsolated: the cell is isolated from the global
	// plane but its regional quorum is healthy.
	MessagingConnectivityGlobalIsolated MessagingConnectivity = 2
	// MessagingConnectivityRegionalQuorumLost: the cell lost its own regional
	// NATS quorum.
	MessagingConnectivityRegionalQuorumLost MessagingConnectivity = 3
)

// RegionalAutonomyOperationClass names the mutation classes the autonomy rules
// freeze or permit.
type RegionalAutonomyOperationClass int

const (
	RegionalAutonomyOperationClassUnspecified RegionalAutonomyOperationClass = 0
	// RegionalAutonomyOperationClassPreAuthorizedRegionalOperation: regional
	// work already authorized before isolation: keep running and reconciling it.
	RegionalAutonomyOperationClassPreAuthorizedRegionalOperation RegionalAutonomyOperationClass = 1
	// RegionalAutonomyOperationClassNewGlobalGeneration: starting a new global
	// desired-state generation.
	RegionalAutonomyOperationClassNewGlobalGeneration RegionalAutonomyOperationClass = 2
	// RegionalAutonomyOperationClassNewGlobalPolicy: changing global policy or
	// trust.
	RegionalAutonomyOperationClassNewGlobalPolicy RegionalAutonomyOperationClass = 3
	// RegionalAutonomyOperationClassNewGlobalRelease: publishing or activating
	// a new global release.
	RegionalAutonomyOperationClassNewGlobalRelease RegionalAutonomyOperationClass = 4
	// RegionalAutonomyOperationClassGlobalAuthorityClaim: claiming or renewing
	// the global authority lease from an isolated cell.
	RegionalAutonomyOperationClassGlobalAuthorityClaim RegionalAutonomyOperationClass = 5
	// RegionalAutonomyOperationClassRegionalObservation: read-only observation
	// and reporting: always permitted.
	RegionalAutonomyOperationClassRegionalObservation RegionalAutonomyOperationClass = 6
)

// RegionalAutonomyDecision is the autonomy decision for one operation class.
type RegionalAutonomyDecision int

const (
	RegionalAutonomyDecisionUnspecified RegionalAutonomyDecision = 0
	RegionalAutonomyDecisionPermitted   RegionalAutonomyDecision = 1
	// RegionalAutonomyDecisionFrozenGlobalMutation: frozen; hold the mutation;
	// it requires reconnection and a current global epoch.
	RegionalAutonomyDecisionFrozenGlobalMutation RegionalAutonomyDecision = 2
	// RegionalAutonomyDecisionHeldUntilRegionalQuorum: held; regional mutations
	// stop until the regional quorum returns; read-only work continues.
	RegionalAutonomyDecisionHeldUntilRegionalQuorum RegionalAutonomyDecision = 3
	// RegionalAutonomyDecisionFrozenGlobalAuthorityClaim: frozen; an isolated
	// cell may never claim global authority.
	RegionalAutonomyDecisionFrozenGlobalAuthorityClaim RegionalAutonomyDecision = 4
)

// RegionalAutonomyRules freezes the regional autonomy rules: an isolated cell
// keeps its pre-authorized regional work and freezes new global generations,
// policy, and releases. When the regional quorum itself is lost, running
// workloads continue on their last committed allocation but new mutations are
// held. The epoch/generation comparison logic lives in
// MessagingPolicyEngine.DecidePartition; these rules freeze the operation
// classes.
var RegionalAutonomyRules regionalAutonomyRules

type regionalAutonomyRules struct{}

// Decide returns the autonomy decision for one connectivity and operation
// class.
func (regionalAutonomyRules) Decide(
	connectivity MessagingConnectivity,
	operationClass RegionalAutonomyOperationClass,
) RegionalAutonomyDecision {
	if connectivity == MessagingConnectivityUnspecified ||
		operationClass == RegionalAutonomyOperationClassUnspecified {
		return RegionalAutonomyDecisionUnspecified
	}

	if operationClass == RegionalAutonomyOperationClassRegionalObservation {
		return RegionalAutonomyDecisionPermitted
	}

	switch connectivity {
	case MessagingConnectivityConnected:
		return RegionalAutonomyDecisionPermitted
	case MessagingConnectivityGlobalIsolated:
		switch operationClass {
		case RegionalAutonomyOperationClassPreAuthorizedRegionalOperation:
			return RegionalAutonomyDecisionPermitted
		case RegionalAutonomyOperationClassGlobalAuthorityClaim:
			return RegionalAutonomyDecisionFrozenGlobalAuthorityClaim
		case RegionalAutonomyOperationClassNewGlobalGeneration,
			RegionalAutonomyOperationClassNewGlobalPolicy,
			RegionalAutonomyOperationClassNewGlobalRelease:
			return RegionalAutonomyDecisionFrozenGlobalMutation
		default:
			return RegionalAutonomyDecisionUnspecified
		}
	case MessagingConnectivityRegionalQuorumLost:
		if operationClass == RegionalAutonomyOperationClassGlobalAuthorityClaim {
			return RegionalAutonomyDecisionFrozenGlobalAuthorityClaim
		}

		return RegionalAutonomyDecisionHeldUntilRegionalQuorum
	default:
		return RegionalAutonomyDecisionUnspecified
	}
}
