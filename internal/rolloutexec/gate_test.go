package rolloutexec

import (
	"context"
	"errors"
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

type fakeCluster struct {
	observation natscell.ClusterObservation
	err         error
	streams     []natscell.StreamState
}

func (c fakeCluster) ObserveCluster() (natscell.ClusterObservation, error) {
	return c.observation, c.err
}

func (c fakeCluster) StreamHealth(context.Context) ([]natscell.StreamState, error) {
	return c.streams, nil
}

func healthyCluster() natscell.ClusterObservation {
	return natscell.ClusterObservation{ServerName: "a", Running: true, ExpectedPeers: []string{"a", "b", "c"},
		MetaLeader: "b", MetaSize: 3, MetaQuorum: 2,
		MetaPeers: []natscell.MetaReplica{{Name: "b", Current: true}, {Name: "c", Current: true}}}
}

func r3(name string) natscell.StreamState {
	return natscell.StreamState{Name: name, Peers: []string{"a", "b", "c"}}
}

func TestClusterGateHoldsUnlessJetStreamKeepsQuorumAndStreamsAreCurrent(t *testing.T) {
	controllers := rollout.Record{Kind: rollout.KindController}
	hosts := rollout.Record{Kind: rollout.KindHost}
	healthy := fakeCluster{observation: healthyCluster(), streams: []natscell.StreamState{r3("TS_ROLLOUTS")}}
	if err := (ClusterGate{Cluster: healthy}).Check(t.Context(), controllers, "ctl-b"); err != nil {
		t.Fatalf("healthy cluster held: %v", err)
	}
	peerDown := healthyCluster()
	peerDown.MetaPeers[1].Offline = true
	noLeader := healthyCluster()
	noLeader.MetaLeader = ""
	lagging := r3("TS_ROLLOUTS")
	lagging.Lagging = true
	for name, gate := range map[string]ClusterGate{
		"no cluster view":     {},
		"observe failure":     {Cluster: fakeCluster{err: errors.New("down")}},
		"no metadata leader":  {Cluster: fakeCluster{observation: noLeader}},
		"a broker is offline": {Cluster: fakeCluster{observation: peerDown}},
		"lagging stream":      {Cluster: fakeCluster{observation: healthyCluster(), streams: []natscell.StreamState{lagging}}},
	} {
		if err := gate.Check(t.Context(), hosts, "h1"); !errors.Is(err, ErrGateHeld) {
			t.Errorf("%s: gate = %v", name, err)
		}
	}
	// Without expected peers (a lab), a controller step still needs the
	// metadata group to survive the restart of one more broker.
	twoOfThree := healthyCluster()
	twoOfThree.ExpectedPeers = nil
	twoOfThree.MetaPeers = slices.Delete(twoOfThree.MetaPeers, 1, 2)
	gate := ClusterGate{Cluster: fakeCluster{observation: twoOfThree}}
	if err := gate.Check(t.Context(), controllers, "ctl-b"); !errors.Is(err, ErrGateHeld) {
		t.Fatalf("controller step that would lose quorum = %v", err)
	}
	if err := gate.Check(t.Context(), hosts, "h1"); err != nil {
		t.Fatalf("host step does not restart a broker: %v", err)
	}
}

// A controller restart must not take a stream below its quorum: R1 and R2
// streams on the restarting broker hold the step, streams elsewhere do not,
// and an unknown broker is judged as hosting every stream.
func TestClusterGateHoldsAControllerWhoseStreamsLackRedundancy(t *testing.T) {
	controllers := rollout.Record{Kind: rollout.KindController}
	streams := []natscell.StreamState{r3("TS_ROLLOUTS"), {Name: "R2_ON_A_B", Peers: []string{"a", "b"}},
		{Name: "R1_ON_C", Peers: []string{"c"}}}
	servers := map[string]string{"ctl-a": "a", "ctl-b": "b", "ctl-c": "c", "ctl-x": "x"}
	gate := ClusterGate{Cluster: fakeCluster{observation: healthyCluster(), streams: streams},
		ServerOf: func(unit string) (string, bool) { server, ok := servers[unit]; return server, ok }}
	for unit, held := range map[string]bool{"ctl-a": true, "ctl-b": true, "ctl-c": true, "ctl-x": false, "ctl-z": true} {
		err := gate.Check(t.Context(), controllers, unit)
		if held != errors.Is(err, ErrGateHeld) {
			t.Errorf("%s: gate = %v, want held %v", unit, err, held)
		}
	}
	if err := gate.Check(t.Context(), rollout.Record{Kind: rollout.KindHost}, "h1"); err != nil {
		t.Fatalf("a host step was held by stream redundancy: %v", err)
	}
	// Preflight restarts no broker: a controller subset whose brokers host
	// no R1 or R2 stream must not be held before its first step.
	if err := gate.Check(t.Context(), controllers, ""); err != nil {
		t.Fatalf("preflight was held by stream redundancy: %v", err)
	}
	gate.Cluster = fakeCluster{observation: healthyCluster(), streams: []natscell.StreamState{r3("TS_ROLLOUTS")}}
	gate.ServerOf = nil
	if err := gate.Check(t.Context(), controllers, "ctl-a"); err != nil {
		t.Fatalf("R3 streams held a controller step: %v", err)
	}
}
