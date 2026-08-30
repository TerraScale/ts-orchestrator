// This file ports Runtime/Mcp/McpWorkloadReconciliation.cs.
package runtime

import (
	"fmt"
	"regexp"
)

// McpChangeKind records why a new desired state exists, so an upgrade, a
// rollback, and a plain restart are distinguishable in the operator view.
type McpChangeKind int

const (
	McpChangeKindInitialCreation McpChangeKind = iota
	McpChangeKindUpgrade
	McpChangeKindRollback
	McpChangeKindRestart
)

func (k McpChangeKind) defined() bool {
	return k >= McpChangeKindInitialCreation && k <= McpChangeKindRestart
}

var mcpFailureDomainTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// McpDesiredWorkload is the desired MCP workload state: one generation, one
// admitted manifest, and the exact failure-domain placement.
type McpDesiredWorkload struct {
	Generation     int64
	Manifest       McpWorkloadManifest
	FailureDomains []string
	ChangeKind     McpChangeKind
}

// NewMcpDesiredWorkload validates the desired state.
func NewMcpDesiredWorkload(
	generation int64,
	manifest McpWorkloadManifest,
	failureDomains []string,
	changeKind McpChangeKind,
) (McpDesiredWorkload, error) {
	if generation < 1 {
		return McpDesiredWorkload{}, &ArgumentOutOfRangeError{
			Param:   "generation",
			Message: "The desired generation must be positive.",
		}
	}
	if len(failureDomains) != McpPlacementContractMinimumInstances {
		return McpDesiredWorkload{}, &ArgumentError{
			Param: "failureDomains",
			Message: fmt.Sprintf("The MCP workload requires exactly %d failure domains.",
				McpPlacementContractMinimumInstances),
		}
	}
	distinct := make(map[string]bool, len(failureDomains))
	for _, domain := range failureDomains {
		if domain == "" || !mcpFailureDomainTokenPattern.MatchString(domain) {
			return McpDesiredWorkload{}, &ArgumentError{
				Param:   "failureDomains",
				Message: "A failure domain must be a bounded lowercase token.",
			}
		}
		distinct[domain] = true
	}
	if len(distinct) != len(failureDomains) {
		return McpDesiredWorkload{}, &ArgumentError{
			Param:   "failureDomains",
			Message: "The two MCP instances must run in independent failure domains.",
		}
	}
	if !changeKind.defined() {
		return McpDesiredWorkload{}, &ArgumentOutOfRangeError{Param: "changeKind"}
	}
	return McpDesiredWorkload{
		Generation:     generation,
		Manifest:       manifest,
		FailureDomains: failureDomains,
		ChangeKind:     changeKind,
	}, nil
}

// ArtifactDigest returns the manifest digest.
func (w McpDesiredWorkload) ArtifactDigest() string { return w.Manifest.ArtifactDigest }

// McpInstanceCondition is the observed condition of one MCP instance.
type McpInstanceCondition int

const (
	// McpInstanceConditionAbsent means the domain holds no instance
	// observation at all (crash removal or first deployment).
	McpInstanceConditionAbsent McpInstanceCondition = iota
	McpInstanceConditionStarting
	McpInstanceConditionReady
	McpInstanceConditionFailed
)

func (c McpInstanceCondition) String() string {
	names := [...]string{"Absent", "Starting", "Ready", "Failed"}
	if c >= 0 && int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("McpInstanceCondition(%d)", int(c))
}

// McpInstanceObservation is what one MCP instance actually runs, as last
// observed.
type McpInstanceObservation struct {
	FailureDomain  string
	Generation     int64
	ArtifactDigest string
	Condition      McpInstanceCondition
}

// McpInstanceActionKind is the reconciler's instance action vocabulary.
type McpInstanceActionKind int

const (
	// McpInstanceActionKindCreate means the failure domain has never run an
	// instance of this workload.
	McpInstanceActionKindCreate McpInstanceActionKind = iota
	// McpInstanceActionKindRestart means the domain already holds the right
	// artifact; start it again after loss or crash.
	McpInstanceActionKindRestart
	// McpInstanceActionKindReplace means the observed instance failed; replace
	// it with the desired artifact.
	McpInstanceActionKindReplace
	// McpInstanceActionKindConverge moves the domain onto the desired artifact
	// (upgrade, rollback, or drift repair).
	McpInstanceActionKindConverge
	// McpInstanceActionKindAwaitHealth means the right artifact is starting;
	// wait for its health evidence.
	McpInstanceActionKindAwaitHealth
)

func (k McpInstanceActionKind) String() string {
	names := [...]string{"Create", "Restart", "Replace", "Converge", "AwaitHealth"}
	if k >= 0 && int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("McpInstanceActionKind(%d)", int(k))
}

// McpInstanceAction is one typed instance action for one failure domain.
type McpInstanceAction struct {
	FailureDomain  string
	Kind           McpInstanceActionKind
	ArtifactDigest string
	ChangeKind     McpChangeKind
	Reason         string
}

// McpRouteDecisionCode is the route decision after one reconciliation pass.
type McpRouteDecisionCode int

const (
	McpRouteDecisionCodeOpen McpRouteDecisionCode = iota
	// McpRouteDecisionCodeOpenDegraded means at least one healthy backend
	// serves stateless traffic, but fewer than the placement floor.
	McpRouteDecisionCodeOpenDegraded
	McpRouteDecisionCodeClosedNoHealthyBackend
	// McpRouteDecisionCodeClosedIngressNotProven means live Authentication,
	// scope-denial, isolation, health, and rollback evidence has not passed.
	McpRouteDecisionCodeClosedIngressNotProven
	McpRouteDecisionCodeClosedByEmergencyWithdrawal
	// McpRouteDecisionCodeClosedDesiredStale means the desired generation is
	// behind an observed generation; a fenced writer must not regress it.
	McpRouteDecisionCodeClosedDesiredStale
)

func (c McpRouteDecisionCode) String() string {
	names := [...]string{
		"Open", "OpenDegraded", "ClosedNoHealthyBackend", "ClosedIngressNotProven",
		"ClosedByEmergencyWithdrawal", "ClosedDesiredStale",
	}
	if c >= 0 && int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("McpRouteDecisionCode(%d)", int(c))
}

// McpBackendSelection is the backend selected for one stateless request.
type McpBackendSelection struct {
	RequestSequence int64
	FailureDomain   string
}

// McpReconciliationPlan is the typed reconciliation plan for the MCP workload.
// Pure: it decides instance actions, the route decision, and stateless backend
// selection from desired state, observations, the route table, and the ingress
// evidence gate.
type McpReconciliationPlan struct {
	Route                 McpRouteDecisionCode
	InstanceActions       []McpInstanceAction
	HealthyFailureDomains []string
	Holds                 []string
}

// StickySessions is the stateless contract: no session affinity ever exists
// (issue #9, ADR 0032).
func (p McpReconciliationPlan) StickySessions() bool {
	return McpPlacementContractStickySessions
}

// SelectBackend selects the backend for one request deterministically from the
// request sequence alone: selection carries no session, cookie, or affinity
// state, so consecutive requests may be served by different failure domains
// and any healthy backend may replace a lost one.
func (p McpReconciliationPlan) SelectBackend(requestSequence int64) (McpBackendSelection, error) {
	if requestSequence < 0 {
		return McpBackendSelection{}, &ArgumentOutOfRangeError{
			Param:   "requestSequence",
			Message: "The request sequence must be non-negative.",
		}
	}
	if len(p.HealthyFailureDomains) == 0 {
		return McpBackendSelection{}, &InvalidOperationError{
			Message: "No healthy MCP backend is available for routing.",
		}
	}
	remainder := int(uint64(requestSequence) % uint64(len(p.HealthyFailureDomains)))
	return McpBackendSelection{
		RequestSequence: requestSequence,
		FailureDomain:   p.HealthyFailureDomains[remainder],
	}, nil
}

// McpWorkloadReconciler produces create, restart, converge, route, and
// withdraw decisions.
var McpWorkloadReconciler mcpWorkloadReconciler

type mcpWorkloadReconciler struct{}

// Plan runs one pure reconciliation pass.
func (mcpWorkloadReconciler) Plan(
	desired McpDesiredWorkload,
	observations []McpInstanceObservation,
	routeTable McpProductRouteTable,
	ingressEvidence *McpIngressEvidence,
) (McpReconciliationPlan, error) {
	observed := make(map[string]McpInstanceObservation)
	var observationOrder []string
	for _, observation := range observations {
		if _, seen := observed[observation.FailureDomain]; !seen {
			observationOrder = append(observationOrder, observation.FailureDomain)
		}
		observed[observation.FailureDomain] = observation
	}

	actions := make([]McpInstanceAction, 0, len(desired.FailureDomains))
	healthy := make([]string, 0, len(desired.FailureDomains))
	var holds []string

	for _, domain := range desired.FailureDomains {
		observation, hasObservation := observed[domain]
		if !hasObservation {
			actions = append(actions, McpInstanceAction{
				FailureDomain:  domain,
				Kind:           McpInstanceActionKindCreate,
				ArtifactDigest: desired.ArtifactDigest(),
				ChangeKind:     desired.ChangeKind,
				Reason:         "the failure domain holds no observation",
			})
			continue
		}

		// The generation fence runs before every condition branch — including
		// crash-removed (Absent) observations — so a stale writer's older
		// generation can never restart, regress, or act on a domain a newer
		// fenced writer already advanced.
		if observation.Generation > desired.Generation {
			holds = append(holds, fmt.Sprintf("%s:observed-generation-%d-exceeds-desired-%d",
				domain, observation.Generation, desired.Generation))
			continue
		}

		if observation.Condition == McpInstanceConditionAbsent {
			// The domain ran an instance of this workload and lost it (crash
			// removal): restart, which is idempotent at the same generation
			// and digest.
			actions = append(actions, McpInstanceAction{
				FailureDomain:  domain,
				Kind:           McpInstanceActionKindRestart,
				ArtifactDigest: desired.ArtifactDigest(),
				ChangeKind:     McpChangeKindRestart,
				Reason:         "the domain lost its instance and restarts the same artifact",
			})
			continue
		}

		runsDesiredArtifact := observation.ArtifactDigest == desired.ArtifactDigest()
		if observation.Generation == desired.Generation {
			if !runsDesiredArtifact {
				actions = append(actions, McpInstanceAction{
					FailureDomain:  domain,
					Kind:           McpInstanceActionKindConverge,
					ArtifactDigest: desired.ArtifactDigest(),
					ChangeKind:     desired.ChangeKind,
					Reason:         "the observed artifact drifted from the desired digest",
				})
				continue
			}
			switch observation.Condition {
			case McpInstanceConditionReady:
				healthy = append(healthy, domain)
			case McpInstanceConditionStarting:
				actions = append(actions, McpInstanceAction{
					FailureDomain:  domain,
					Kind:           McpInstanceActionKindAwaitHealth,
					ArtifactDigest: desired.ArtifactDigest(),
					ChangeKind:     desired.ChangeKind,
					Reason:         "the desired artifact is starting",
				})
			case McpInstanceConditionFailed:
				actions = append(actions, McpInstanceAction{
					FailureDomain:  domain,
					Kind:           McpInstanceActionKindReplace,
					ArtifactDigest: desired.ArtifactDigest(),
					ChangeKind:     McpChangeKindRestart,
					Reason:         "the instance failed and is replaced on the same artifact",
				})
			}
			continue
		}

		// The observation trails the desired generation.
		kind := McpInstanceActionKindConverge
		reason := "the desired artifact differs from the observed one"
		if runsDesiredArtifact {
			kind = McpInstanceActionKindRestart
			reason = "the generation advanced without an artifact change"
		}
		actions = append(actions, McpInstanceAction{
			FailureDomain:  domain,
			Kind:           kind,
			ArtifactDigest: desired.ArtifactDigest(),
			ChangeKind:     desired.ChangeKind,
			Reason:         reason,
		})
	}

	route := decideMcpRoute(desired, routeTable, ingressEvidence, healthy, holds)
	return McpReconciliationPlan{
		Route:                 route,
		InstanceActions:       actions,
		HealthyFailureDomains: healthy,
		Holds:                 holds,
	}, nil
}

func decideMcpRoute(
	desired McpDesiredWorkload,
	routeTable McpProductRouteTable,
	ingressEvidence *McpIngressEvidence,
	healthy []string,
	holds []string,
) McpRouteDecisionCode {
	if !routeTable.IsOpen(McpProductRouteTableMcpRouteName) {
		return McpRouteDecisionCodeClosedByEmergencyWithdrawal
	}
	if McpIngressGate.Evaluate(ingressEvidence) != McpIngressStateOpen {
		return McpRouteDecisionCodeClosedIngressNotProven
	}
	if len(holds) > 0 {
		return McpRouteDecisionCodeClosedDesiredStale
	}
	if len(healthy) == 0 {
		return McpRouteDecisionCodeClosedNoHealthyBackend
	}
	if len(healthy) < McpPlacementContractMinimumInstances {
		return McpRouteDecisionCodeOpenDegraded
	}
	return McpRouteDecisionCodeOpen
}
