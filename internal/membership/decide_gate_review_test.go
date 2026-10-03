package membership

import (
	"strings"
	"testing"
	"time"
)

// An admitted successor HEAD reserves the single replacement slot from the
// ledger alone: losing the evidence file that would let this term resume it
// must not let a second slot start a concurrent replacement (#127 11993).
func TestDecideAdmittedSuccessorReservesTheGateWithoutEvidence(t *testing.T) {
	topology := testTopology()
	topology.Slots = append(topology.Slots, "controller-d", "controller-e")
	observation := lostB(testEpoch)
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, Retirement: evidenceID}
	delete(observation.Lifecycle, "controller-b")
	observation = withPeer(observation, "gru-controller-c", false)
	observation.Lifecycle["controller-c"] = LifecycleTerminated
	observation.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
	observation.Meta.Peers = append(observation.Meta.Peers, Peer{Name: "gru-controller-d", Online: true},
		Peer{Name: "gru-controller-e", Online: true})
	for name, evidence := range map[string]*Evidence{
		"absent": nil,
		"foreign": {Slot: "controller-b", PreviousAttempt: 1, PriorInstanceOCID: instanceB,
			Digest: strings.Repeat("3", 64), Wire: []byte("other")},
	} {
		delete(observation.Evidence, "controller-b")
		if evidence != nil {
			observation.Evidence["controller-b"] = *evidence
		}
		state, actions := Decide(testConfig(), topology, State{}, observation)
		if len(actions) != 0 {
			t.Fatalf("%s: concurrent replacement started = %+v", name, actions)
		}
		if status := state.Slots["controller-c"]; status.Phase != PhaseHeld || status.Reason != ReasonOtherReplacement {
			t.Fatalf("%s: second slot = %+v", name, status)
		}
	}
}

// A remembered replacement whose successor the ledger never admitted, and
// whose evidence was removed, returns to a held state and releases the gate
// (#127 12001).
func TestDecideAbandonedUnadmittedReplacementReleasesTheGate(t *testing.T) {
	topology := testTopology()
	topology.Slots = append(topology.Slots, "controller-d", "controller-e")
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	observation.Meta.Peers = append(observation.Meta.Peers, Peer{Name: "gru-controller-d", Online: true},
		Peer{Name: "gru-controller-e", Online: true})
	state, actions := Decide(testConfig(), topology, State{}, observation)
	if len(actions) != 1 || state.Slots["controller-b"].Phase != PhaseReplacing {
		t.Fatalf("start = %+v %+v", state.Slots["controller-b"], actions)
	}
	remembered := state
	// AdvanceSlot rejected the envelope and the operator removed it. The
	// ledger still holds the completed attempt 1.
	delete(observation.Evidence, "controller-b")
	observation = withPeer(observation, "gru-controller-c", false)
	observation.Lifecycle["controller-c"] = LifecycleTerminated
	observation.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
	observation.At = observation.At.Add(time.Minute)
	state, actions = Decide(testConfig(), topology, remembered, observation)
	if status := state.Slots["controller-b"]; status.Phase != PhaseHeld || status.PendingAttempt != 0 ||
		!strings.HasPrefix(status.Reason, ReasonAwaitingEvidence) {
		t.Fatalf("abandoned slot = %+v", status)
	}
	if len(actions) != 1 || actions[0].Slot != "controller-c" {
		t.Fatalf("gate not released = %+v", actions)
	}
	// While usable evidence is still on hand the retry stays reserved.
	withEvidenceB(&observation)
	state, actions = Decide(testConfig(), topology, remembered, observation)
	if state.Slots["controller-b"].Phase != PhaseReplacing || len(actions) != 1 || actions[0].Slot != "controller-b" {
		t.Fatalf("actionable retry dropped = %+v %+v", state.Slots["controller-b"], actions)
	}
}
