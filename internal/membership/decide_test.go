package membership

import (
	"strings"
	"testing"
	"time"
)

var testEpoch = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func testTopology() Topology {
	return Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
		SeedSlot: "controller-a", SelfSlot: "controller-a"}
}

func TestAcceptedControllerWithoutLaunchHistoryRemainsObservedAndHeld(t *testing.T) {
	observation := healthyObservation(testEpoch)
	observation.Ledger["controller-b"] = LedgerSlot{InstanceOCID: instanceB, Complete: true}
	state, actions := Decide(testTopology(), State{}, observation)
	if state.Slots["controller-b"].Phase != PhaseHealthy || len(actions) != 0 {
		t.Fatal("accepted online controller was not observed as healthy")
	}
	observation = withPeer(observation, "gru-1-ctl-2", false)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	observation.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
	state, actions = Decide(testTopology(), state, observation)
	if state.Slots["controller-b"].Phase != PhaseHeld ||
		state.Slots["controller-b"].Reason != "accepted controller has no current replacement launch authority" || len(actions) != 0 {
		t.Fatalf("accepted installation invented launch history: %+v, %+v", state.Slots["controller-b"], actions)
	}
}

const (
	instanceB  = "ocid1.instance.oc1.sa-saopaulo-1.controller-b"
	instanceC  = "ocid1.instance.oc1.sa-saopaulo-1.controller-c"
	instanceA  = "ocid1.instance.oc1.sa-saopaulo-1.controller-a"
	evidenceID = "2222222222222222222222222222222222222222222222222222222222222222"
)

// healthyObservation is a full three-slot cell with every peer online.
func healthyObservation(at time.Time) Observation {
	return Observation{At: at,
		Meta: Meta{Leader: "gru-1-ctl-1", Size: 3, Peers: []Peer{
			{Name: "gru-1-ctl-2", Online: true, Current: true},
			{Name: "gru-1-ctl-3", Online: true, Current: true}}},
		Ledger: map[string]LedgerSlot{
			"controller-a": {Attempt: 1, InstanceOCID: instanceA, Complete: true},
			"controller-b": {Attempt: 1, InstanceOCID: instanceB, Complete: true},
			"controller-c": {Attempt: 1, InstanceOCID: instanceC, Complete: true}},
		Lifecycle: map[string]string{"controller-b": LifecycleRunning, "controller-c": LifecycleRunning},
		Evidence:  map[string]Evidence{},
	}
}

func withPeer(observation Observation, name string, online bool) Observation {
	peers := make([]Peer, 0, len(observation.Meta.Peers))
	for _, peer := range observation.Meta.Peers {
		if peer.Name == name {
			peer.Online = online
		}
		peers = append(peers, peer)
	}
	observation.Meta.Peers = peers
	return observation
}

func evidenceFor(slot string, attempt uint64, instance string) Evidence {
	return Evidence{Slot: slot, PreviousAttempt: attempt, PriorInstanceOCID: instance, Digest: evidenceID,
		Wire: []byte("signed")}
}

func lostB(at time.Time) Observation {
	observation := withPeer(healthyObservation(at), "gru-1-ctl-2", false)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	return observation
}

func TestDecideHealthyCellTakesNoAction(t *testing.T) {
	state, actions := Decide(testTopology(), State{}, healthyObservation(testEpoch))
	if len(actions) != 0 {
		t.Fatalf("healthy cell actions = %+v", actions)
	}
	for _, slot := range testTopology().Slots {
		if state.Slots[slot].Phase != PhaseHealthy {
			t.Fatalf("%s = %+v", slot, state.Slots[slot])
		}
	}
	if state.Slots["controller-a"].Reason != ReasonLocal {
		t.Fatalf("local slot = %+v", state.Slots["controller-a"])
	}
}

func TestDecideOfflinePeerWaitsForGraceThenRequiresTermination(t *testing.T) {
	observation := withPeer(healthyObservation(testEpoch), "gru-1-ctl-2", false)
	observation.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
	state, actions := Decide(testTopology(), State{}, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect ||
		!state.Slots["controller-b"].OfflineSince.Equal(testEpoch) {
		t.Fatalf("first offline pass = %+v %+v", state.Slots["controller-b"], actions)
	}
	observation.At = testEpoch.Add(DefaultOfflineGrace - time.Second)
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect {
		t.Fatalf("within grace = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Past the grace the slot is lost, but a RUNNING instance may still come
	// back under the same server name, so it is never relaunched.
	observation.At = testEpoch.Add(DefaultOfflineGrace)
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseHeld ||
		!strings.HasPrefix(state.Slots["controller-b"].Reason, ReasonInstanceAlive) {
		t.Fatalf("lost running instance = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Once the operator terminates it the matching evidence replaces it.
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 1 || actions[0].Slot != "controller-b" || actions[0].PreviousAttempt != 1 ||
		state.Slots["controller-b"].Phase != PhaseReplacing || state.Slots["controller-b"].PendingAttempt != 2 {
		t.Fatalf("terminated instance = %+v %+v", state.Slots["controller-b"], actions)
	}
}

func TestDecideTerminatedInstanceSkipsGrace(t *testing.T) {
	observation := lostB(testEpoch)
	observation.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
	_, actions := Decide(testTopology(), State{}, observation)
	if len(actions) != 1 || actions[0].PriorInstanceOCID != instanceB || string(actions[0].Retirement.Wire) != "signed" {
		t.Fatalf("terminated instance actions = %+v", actions)
	}
}

func TestDecideHoldReasons(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Observation)
		prior  func(*State)
		want   string
	}{
		{name: "missing evidence", want: ReasonAwaitingEvidence},
		{name: "evidence for older attempt", want: ReasonAwaitingEvidence, mutate: func(o *Observation) {
			o.Evidence["controller-b"] = evidenceFor("controller-b", 0, instanceB)
		}},
		{name: "evidence for other instance", want: ReasonAwaitingEvidence, mutate: func(o *Observation) {
			o.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceC)
		}},
		{name: "quorum lost", want: ReasonQuorumLost, mutate: func(o *Observation) {
			withEvidenceB(o)
			*o = withPeer(*o, "gru-1-ctl-3", false)
		}},
		{name: "no metadata leader", want: ReasonQuorumLost, mutate: func(o *Observation) {
			withEvidenceB(o)
			o.Meta.Leader = ""
		}},
		{name: "unobservable instance", want: ReasonInstanceUnobserved, mutate: func(o *Observation) {
			withEvidenceB(o)
			delete(o.Lifecycle, "controller-b")
			o.At = o.At.Add(time.Hour)
		}, prior: func(s *State) {
			s.Slots["controller-b"] = SlotStatus{Slot: "controller-b", Phase: PhaseSuspect, OfflineSince: testEpoch}
		}},
		{name: "incomplete ledger", want: ReasonLedgerIncomplete, mutate: func(o *Observation) {
			withEvidenceB(o)
			o.Ledger["controller-b"] = LedgerSlot{Attempt: 2}
		}},
		{name: "retry backoff", want: ReasonRetryBackoff, mutate: withEvidenceB, prior: func(s *State) {
			s.Slots["controller-b"] = SlotStatus{Slot: "controller-b", Phase: PhaseHeld, OfflineSince: testEpoch,
				LastFailure: testEpoch.Add(-time.Minute)}
		}},
		{name: "another replacement", want: ReasonOtherReplacement, mutate: func(o *Observation) {
			withEvidenceB(o)
			// The remembered replacement is still actionable: its evidence
			// is on hand (an abandoned one releases the gate).
			o.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
		}, prior: func(s *State) {
			s.Slots["controller-c"] = SlotStatus{Slot: "controller-c", Phase: PhaseReplacing, PendingAttempt: 2}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := lostB(testEpoch)
			if test.mutate != nil {
				test.mutate(&observation)
			}
			prior := State{Slots: map[string]SlotStatus{}}
			if test.prior != nil {
				test.prior(&prior)
			}
			state, actions := Decide(testTopology(), prior, observation)
			for _, action := range actions {
				if action.Slot == "controller-b" {
					t.Fatalf("held slot produced action %+v", action)
				}
			}
			status := state.Slots["controller-b"]
			if status.Phase != PhaseHeld || !strings.HasPrefix(status.Reason, test.want) {
				t.Fatalf("status = %+v, want held %q", status, test.want)
			}
		})
	}
}

func withEvidenceB(o *Observation) {
	o.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
}

func TestDecideNeverReplacesSeedOrSelf(t *testing.T) {
	topology := testTopology()
	topology.SelfSlot = "controller-b"
	observation := healthyObservation(testEpoch)
	observation.Meta.Peers = []Peer{{Name: "gru-1-ctl-1", Online: false}, {Name: "gru-1-ctl-3", Online: true}}
	observation.Lifecycle = map[string]string{"controller-a": LifecycleTerminated, "controller-c": LifecycleRunning}
	observation.Evidence["controller-a"] = evidenceFor("controller-a", 1, instanceA)
	state, actions := Decide(topology, State{}, observation)
	if len(actions) != 0 || state.Slots["controller-a"].Reason != ReasonSeedSlot ||
		state.Slots["controller-b"].Reason != ReasonLocal {
		t.Fatalf("seed/self = %+v %+v %+v", state.Slots["controller-a"], state.Slots["controller-b"], actions)
	}
}

func TestDecideTerminatedButOnlineIsHeld(t *testing.T) {
	observation := healthyObservation(testEpoch)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	withEvidenceB(&observation)
	state, actions := Decide(testTopology(), State{}, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonTerminatedButOnline {
		t.Fatalf("terminated but online = %+v %+v", state.Slots["controller-b"], actions)
	}
}

func TestDecideReplacesOneSlotAtATime(t *testing.T) {
	topology := Topology{Cell: "gru", SeedSlot: "controller-a", SelfSlot: "controller-a",
		Slots: []string{"controller-a", "controller-b", "controller-c", "controller-d", "controller-e"}}
	observation := lostB(testEpoch)
	observation.Meta.Peers = append(observation.Meta.Peers,
		Peer{Name: "gru-1-ctl-4", Online: true}, Peer{Name: "gru-1-ctl-5", Online: true})
	observation = withPeer(observation, "gru-1-ctl-3", false)
	observation.Ledger["controller-c"] = LedgerSlot{Attempt: 1, InstanceOCID: instanceC, Complete: true}
	observation.Ledger["controller-d"] = LedgerSlot{Attempt: 1, InstanceOCID: instanceC + "d", Complete: true}
	observation.Lifecycle["controller-c"] = LifecycleTerminated
	withEvidenceB(&observation)
	observation.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
	state, actions := Decide(topology, State{}, observation)
	if len(actions) != 1 || actions[0].Slot != "controller-b" ||
		state.Slots["controller-c"].Reason != ReasonOtherReplacement {
		t.Fatalf("concurrent losses = %+v c=%+v", actions, state.Slots["controller-c"])
	}
}

func TestDecideReplacementLifecycle(t *testing.T) {
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	state, actions := Decide(testTopology(), State{}, observation)
	if len(actions) != 1 {
		t.Fatalf("actions = %+v", actions)
	}
	// The actuator failed: the same evidence is retried only after backoff.
	status := state.Slots["controller-b"]
	status.LastFailure = observation.At
	state.Slots["controller-b"] = status
	observation.At = observation.At.Add(time.Minute)
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonRetryBackoff ||
		state.Slots["controller-b"].Phase != PhaseReplacing {
		t.Fatalf("backoff = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The ledger advanced but the successor has not completed: resume.
	observation.At = observation.At.Add(DefaultRetryBackoff)
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, Retirement: evidenceID}
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 1 || actions[0].PreviousAttempt != 1 || actions[0].Reason != "resume replacement" {
		t.Fatalf("resume = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Completed but not yet online: a fresh grace for the new instance.
	observation.At = observation.At.Add(time.Minute)
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, InstanceOCID: instanceB + "-a2", Complete: true}
	observation.Lifecycle["controller-b"] = LifecycleRunning
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect ||
		state.Slots["controller-b"].Reason != ReasonRejoining ||
		!state.Slots["controller-b"].OfflineSince.Equal(observation.At) {
		t.Fatalf("rejoining = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The old evidence can never retire the successor attempt.
	observation.At = observation.At.Add(DefaultOfflineGrace)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	state, actions = Decide(testTopology(), state, observation)
	if len(actions) != 0 || !strings.HasPrefix(state.Slots["controller-b"].Reason, ReasonAwaitingEvidence) {
		t.Fatalf("stale evidence = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The rejoined successor is healthy again.
	observation = withPeer(observation, "gru-1-ctl-2", true)
	observation.Lifecycle["controller-b"] = LifecycleRunning
	state, _ = Decide(testTopology(), state, observation)
	if state.Slots["controller-b"].Phase != PhaseHealthy || !state.Slots["controller-b"].OfflineSince.IsZero() {
		t.Fatalf("rejoined = %+v", state.Slots["controller-b"])
	}
}

func TestDecideReplacingHoldsWithoutQuorum(t *testing.T) {
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	state, _ := Decide(testTopology(), State{}, observation)
	observation = withPeer(observation, "gru-1-ctl-3", false)
	state, actions := Decide(testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonQuorumLost {
		t.Fatalf("replacing without quorum = %+v %+v", state.Slots["controller-b"], actions)
	}
}

// A new authority term has no memory of a replacement an earlier term
// admitted. The incomplete successor HEAD bound to the on-hand evidence must
// be resumed, and must still block a second concurrent replacement.
func TestDecideNewTermResumesAdmittedSuccessor(t *testing.T) {
	topology := testTopology()
	topology.Slots = append(topology.Slots, "controller-d", "controller-e")
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, Retirement: evidenceID}
	delete(observation.Lifecycle, "controller-b")
	observation = withPeer(observation, "gru-1-ctl-3", false)
	observation.Lifecycle["controller-c"] = LifecycleTerminated
	observation.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
	observation.Meta.Peers = append(observation.Meta.Peers, Peer{Name: "gru-1-ctl-4", Online: true},
		Peer{Name: "gru-1-ctl-5", Online: true})
	state, actions := Decide(topology, State{}, observation)
	if len(actions) != 1 || actions[0].Slot != "controller-b" || actions[0].PreviousAttempt != 1 ||
		actions[0].Reason != "resume replacement" {
		t.Fatalf("new term actions = %+v", actions)
	}
	if status := state.Slots["controller-b"]; status.Phase != PhaseReplacing || status.PendingAttempt != 2 {
		t.Fatalf("adopted successor = %+v", status)
	}
	if status := state.Slots["controller-c"]; status.Phase != PhaseHeld || status.Reason != ReasonOtherReplacement {
		t.Fatalf("second slot = %+v", status)
	}
	// Evidence that did not advance this HEAD is never adopted.
	observation.Evidence["controller-b"] = Evidence{Slot: "controller-b", PreviousAttempt: 1,
		PriorInstanceOCID: instanceB, Digest: strings.Repeat("3", 64), Wire: []byte("other")}
	state, _ = Decide(topology, State{}, observation)
	if state.Slots["controller-b"].Phase == PhaseReplacing {
		t.Fatalf("foreign evidence adopted = %+v", state.Slots["controller-b"])
	}
}
