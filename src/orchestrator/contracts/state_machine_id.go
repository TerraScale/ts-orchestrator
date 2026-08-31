// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/StateMachineId.cs.
package contracts

import "fmt"

// StateMachineId is a permanent state-machine identifier from the GOAL.md
// "Stable contract identifiers" table. Identifiers form a closed set: only
// values registered in StableIdentifierRegistry construct successfully, the
// canonical text of a live identifier never changes in place, and a
// replacement decision marks the retired identifier superseded and adds a new
// identifier instead of editing either one.
type StateMachineId struct {
	Value string
}

// IsRegistered reports whether this value is one of the registered state machines.
func (i StateMachineId) IsRegistered() bool {
	_, ok := StableIdentifierRegistry.tryGetStateMachineText(i)
	return ok
}

// CanonicalText returns the verbatim GOAL.md text.
func (i StateMachineId) CanonicalText() (string, error) {
	if text, ok := StableIdentifierRegistry.tryGetStateMachineText(i); ok {
		return text, nil
	}
	return "", fmt.Errorf("state machine %q is not registered", i.Value)
}

// TryGetText mirrors StableIdentifierRegistry.TryGetText(StateMachineId, out text).
func (i StateMachineId) TryGetText() (string, bool) {
	return StableIdentifierRegistry.tryGetStateMachineText(i)
}

// StateMachineIdTryCreate mirrors StateMachineId.TryCreate: only registered values pass.
func StateMachineIdTryCreate(value string) (StateMachineId, bool) {
	if _, ok := StableIdentifierRegistry.tryGetStateMachineText(StateMachineId{Value: value}); ok {
		return StateMachineId{Value: value}, true
	}

	return StateMachineId{}, false
}

// SupersededBy mirrors StableIdentifierRegistry.SupersededBy(StateMachineId).
func (i StateMachineId) SupersededBy() (StateMachineId, bool) {
	return StableIdentifierRegistry.supersededStateMachine(i)
}

func (i StateMachineId) String() string { return i.Value }

// The registered state-machine identifiers (C# static properties).
var (
	StateMachineIdBootstrap         = StateMachineId{Value: "SM-ORCH-BOOTSTRAP"}
	StateMachineIdGlobalAuthority   = StateMachineId{Value: "SM-ORCH-GLOBAL-AUTHORITY"}
	StateMachineIdRegionalAuthority = StateMachineId{Value: "SM-ORCH-REGIONAL-AUTHORITY"}
	StateMachineIdRegionAdmission   = StateMachineId{Value: "SM-ORCH-REGION-ADMISSION"}
	StateMachineIdRegionRemoval     = StateMachineId{Value: "SM-ORCH-REGION-REMOVAL"}
	StateMachineIdProviderOperation = StateMachineId{Value: "SM-ORCH-PROVIDER-OPERATION"}
	StateMachineIdHostLifecycle     = StateMachineId{Value: "SM-ORCH-HOST-LIFECYCLE"}
	StateMachineIdWorkloadLifecycle = StateMachineId{Value: "SM-ORCH-WORKLOAD-LIFECYCLE"}
	StateMachineIdMemberAdd         = StateMachineId{Value: "SM-ORCH-MEMBER-ADD"}
	StateMachineIdMemberReplace     = StateMachineId{Value: "SM-ORCH-MEMBER-REPLACE"}
	StateMachineIdCapacity          = StateMachineId{Value: "SM-ORCH-CAPACITY"}
	StateMachineIdRelease           = StateMachineId{Value: "SM-ORCH-RELEASE"}
	StateMachineIdReconnect         = StateMachineId{Value: "SM-ORCH-RECONNECT"}
	StateMachineIdTrustRotation     = StateMachineId{Value: "SM-ORCH-TRUST-ROTATION"}
	StateMachineIdControlRestore    = StateMachineId{Value: "SM-ORCH-CONTROL-RESTORE"}
	StateMachineIdNodePressure      = StateMachineId{Value: "SM-ORCH-NODE-PRESSURE"}
	StateMachineIdWorkloadRestart   = StateMachineId{Value: "SM-ORCH-WORKLOAD-RESTART"}
	StateMachineIdResourceDeletion  = StateMachineId{Value: "SM-ORCH-RESOURCE-DELETION"}
)
