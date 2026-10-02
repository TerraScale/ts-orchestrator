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

func testConfig() Config { return Config{Enabled: true, Replace: true} }

const (
	instanceB  = "ocid1.instance.oc1.sa-saopaulo-1.controller-b"
	instanceC  = "ocid1.instance.oc1.sa-saopaulo-1.controller-c"
	instanceA  = "ocid1.instance.oc1.sa-saopaulo-1.controller-a"
	evidenceID = "2222222222222222222222222222222222222222222222222222222222222222"
)

// healthyObservation is a full three-slot cell with every peer online.
func healthyObservation(at time.Time) Observation {
	return Observation{At: at,
		Meta: Meta{Leader: "gru-controller-a", Size: 3, Peers: []Peer{
			{Name: "gru-controller-b", Online: true, Current: true},
			{Name: "gru-controller-c", Online: true, Current: true}}},
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
	observation := withPeer(healthyObservation(at), "gru-controller-b", false)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	return observation
}

func TestDecideHealthyCellTakesNoAction(t *testing.T) {
	state, actions := Decide(testConfig(), testTopology(), State{}, healthyObservation(testEpoch))
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
	cfg := testConfig()
	observation := withPeer(healthyObservation(testEpoch), "gru-controller-b", false)
	observation.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
	state, actions := Decide(cfg, testTopology(), State{}, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect ||
		!state.Slots["controller-b"].OfflineSince.Equal(testEpoch) {
		t.Fatalf("first offline pass = %+v %+v", state.Slots["controller-b"], actions)
	}
	observation.At = testEpoch.Add(cfg.OfflineGrace() - time.Second)
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect {
		t.Fatalf("within grace = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Past the grace the slot is lost, but a RUNNING instance may still come
	// back under the same server name, so it is never relaunched.
	observation.At = testEpoch.Add(cfg.OfflineGrace())
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseHeld ||
		!strings.HasPrefix(state.Slots["controller-b"].Reason, ReasonInstanceAlive) {
		t.Fatalf("lost running instance = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Once the operator terminates it the matching evidence replaces it.
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 1 || actions[0].Slot != "controller-b" || actions[0].PreviousAttempt != 1 ||
		state.Slots["controller-b"].Phase != PhaseReplacing || state.Slots["controller-b"].PendingAttempt != 2 {
		t.Fatalf("terminated instance = %+v %+v", state.Slots["controller-b"], actions)
	}
}

func TestDecideTerminatedInstanceSkipsGrace(t *testing.T) {
	observation := lostB(testEpoch)
	observation.Evidence["controller-b"] = evidenceFor("controller-b", 1, instanceB)
	_, actions := Decide(testConfig(), testTopology(), State{}, observation)
	if len(actions) != 1 || actions[0].PriorInstanceOCID != instanceB || string(actions[0].Retirement.Wire) != "signed" {
		t.Fatalf("terminated instance actions = %+v", actions)
	}
}

func TestDecideHoldReasons(t *testing.T) {
	for _, test := range []struct {
		name   string
		cfg    func(*Config)
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
		{name: "observe only", want: ReasonObserveOnly, cfg: func(c *Config) { c.Replace = false },
			mutate: withEvidenceB},
		{name: "quorum lost", want: ReasonQuorumLost, mutate: func(o *Observation) {
			withEvidenceB(o)
			*o = withPeer(*o, "gru-controller-c", false)
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
		{name: "another replacement", want: ReasonOtherReplacement, mutate: withEvidenceB, prior: func(s *State) {
			s.Slots["controller-c"] = SlotStatus{Slot: "controller-c", Phase: PhaseReplacing, PendingAttempt: 2}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			if test.cfg != nil {
				test.cfg(&cfg)
			}
			observation := lostB(testEpoch)
			if test.mutate != nil {
				test.mutate(&observation)
			}
			prior := State{Slots: map[string]SlotStatus{}}
			if test.prior != nil {
				test.prior(&prior)
			}
			state, actions := Decide(cfg, testTopology(), prior, observation)
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
	observation.Meta.Peers = []Peer{{Name: "gru-controller-a", Online: false}, {Name: "gru-controller-c", Online: true}}
	observation.Lifecycle = map[string]string{"controller-a": LifecycleTerminated, "controller-c": LifecycleRunning}
	observation.Evidence["controller-a"] = evidenceFor("controller-a", 1, instanceA)
	state, actions := Decide(testConfig(), topology, State{}, observation)
	if len(actions) != 0 || state.Slots["controller-a"].Reason != ReasonSeedSlot ||
		state.Slots["controller-b"].Reason != ReasonLocal {
		t.Fatalf("seed/self = %+v %+v %+v", state.Slots["controller-a"], state.Slots["controller-b"], actions)
	}
}

func TestDecideTerminatedButOnlineIsHeld(t *testing.T) {
	observation := healthyObservation(testEpoch)
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	withEvidenceB(&observation)
	state, actions := Decide(testConfig(), testTopology(), State{}, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonTerminatedButOnline {
		t.Fatalf("terminated but online = %+v %+v", state.Slots["controller-b"], actions)
	}
}

func TestDecideReplacesOneSlotAtATime(t *testing.T) {
	topology := Topology{Cell: "gru", SeedSlot: "controller-a", SelfSlot: "controller-a",
		Slots: []string{"controller-a", "controller-b", "controller-c", "controller-d", "controller-e"}}
	observation := lostB(testEpoch)
	observation.Meta.Peers = append(observation.Meta.Peers,
		Peer{Name: "gru-controller-d", Online: true}, Peer{Name: "gru-controller-e", Online: true})
	observation = withPeer(observation, "gru-controller-c", false)
	observation.Ledger["controller-c"] = LedgerSlot{Attempt: 1, InstanceOCID: instanceC, Complete: true}
	observation.Ledger["controller-d"] = LedgerSlot{Attempt: 1, InstanceOCID: instanceC + "d", Complete: true}
	observation.Lifecycle["controller-c"] = LifecycleTerminated
	withEvidenceB(&observation)
	observation.Evidence["controller-c"] = evidenceFor("controller-c", 1, instanceC)
	state, actions := Decide(testConfig(), topology, State{}, observation)
	if len(actions) != 1 || actions[0].Slot != "controller-b" ||
		state.Slots["controller-c"].Reason != ReasonOtherReplacement {
		t.Fatalf("concurrent losses = %+v c=%+v", actions, state.Slots["controller-c"])
	}
}

func TestDecideReplacementLifecycle(t *testing.T) {
	cfg := testConfig()
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	state, actions := Decide(cfg, testTopology(), State{}, observation)
	if len(actions) != 1 {
		t.Fatalf("actions = %+v", actions)
	}
	// The actuator failed: the same evidence is retried only after backoff.
	status := state.Slots["controller-b"]
	status.LastFailure = observation.At
	state.Slots["controller-b"] = status
	observation.At = observation.At.Add(time.Minute)
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonRetryBackoff ||
		state.Slots["controller-b"].Phase != PhaseReplacing {
		t.Fatalf("backoff = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The ledger advanced but the successor has not completed: resume.
	observation.At = observation.At.Add(cfg.RetryBackoff())
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, Retirement: evidenceID}
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 1 || actions[0].PreviousAttempt != 1 || actions[0].Reason != "resume replacement" {
		t.Fatalf("resume = %+v %+v", state.Slots["controller-b"], actions)
	}
	// Completed but not yet online: a fresh grace for the new instance.
	observation.At = observation.At.Add(time.Minute)
	observation.Ledger["controller-b"] = LedgerSlot{Attempt: 2, InstanceOCID: instanceB + "-a2", Complete: true}
	observation.Lifecycle["controller-b"] = LifecycleRunning
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Phase != PhaseSuspect ||
		state.Slots["controller-b"].Reason != ReasonRejoining ||
		!state.Slots["controller-b"].OfflineSince.Equal(observation.At) {
		t.Fatalf("rejoining = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The old evidence can never retire the successor attempt.
	observation.At = observation.At.Add(cfg.OfflineGrace())
	observation.Lifecycle["controller-b"] = LifecycleTerminated
	state, actions = Decide(cfg, testTopology(), state, observation)
	if len(actions) != 0 || !strings.HasPrefix(state.Slots["controller-b"].Reason, ReasonAwaitingEvidence) {
		t.Fatalf("stale evidence = %+v %+v", state.Slots["controller-b"], actions)
	}
	// The rejoined successor is healthy again.
	observation = withPeer(observation, "gru-controller-b", true)
	observation.Lifecycle["controller-b"] = LifecycleRunning
	state, _ = Decide(cfg, testTopology(), state, observation)
	if state.Slots["controller-b"].Phase != PhaseHealthy || !state.Slots["controller-b"].OfflineSince.IsZero() {
		t.Fatalf("rejoined = %+v", state.Slots["controller-b"])
	}
}

func TestDecideReplacingHoldsWithoutQuorum(t *testing.T) {
	observation := lostB(testEpoch)
	withEvidenceB(&observation)
	state, _ := Decide(testConfig(), testTopology(), State{}, observation)
	observation = withPeer(observation, "gru-controller-c", false)
	state, actions := Decide(testConfig(), testTopology(), state, observation)
	if len(actions) != 0 || state.Slots["controller-b"].Reason != ReasonQuorumLost {
		t.Fatalf("replacing without quorum = %+v %+v", state.Slots["controller-b"], actions)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, test := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{Enabled: true, OfflineGraceSeconds: 600, IntervalSeconds: 10}, true},
		{Config{Replace: true}, false},
		{Config{Enabled: true, OfflineGraceSeconds: 30}, false},
		{Config{Enabled: true, IntervalSeconds: 3600}, false},
		{Config{Enabled: true, RetirementEvidenceDir: "relative"}, false},
		{Config{Enabled: true, RetryBackoffSeconds: -1}, false},
	} {
		if err := test.cfg.Validate(); (err == nil) != test.ok {
			t.Fatalf("Validate(%+v) = %v", test.cfg, err)
		}
	}
	if (Config{}).OfflineGrace() != DefaultOfflineGrace || (Config{}).Interval() != DefaultInterval {
		t.Fatal("defaults changed")
	}
}
