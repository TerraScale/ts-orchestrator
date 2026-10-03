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
	lagging     []string
}

func (c fakeCluster) ObserveCluster() (natscell.ClusterObservation, error) {
	return c.observation, c.err
}
func (c fakeCluster) LaggingStreams(context.Context) ([]string, error) { return c.lagging, nil }

func healthyCluster() natscell.ClusterObservation {
	return natscell.ClusterObservation{ServerName: "a", Running: true, ExpectedPeers: []string{"a", "b", "c"},
		MetaLeader: "b", MetaSize: 3, MetaQuorum: 2,
		MetaPeers: []natscell.MetaReplica{{Name: "b", Current: true}, {Name: "c", Current: true}}}
}

func TestClusterGateHoldsUnlessJetStreamKeepsQuorumAndStreamsAreCurrent(t *testing.T) {
	controllers := rollout.Record{Kind: rollout.KindController}
	hosts := rollout.Record{Kind: rollout.KindHost}
	if err := (ClusterGate{Cluster: fakeCluster{observation: healthyCluster()}}).Check(t.Context(), controllers, "ctl-b"); err != nil {
		t.Fatalf("healthy cluster held: %v", err)
	}
	peerDown := healthyCluster()
	peerDown.MetaPeers[1].Offline = true
	noLeader := healthyCluster()
	noLeader.MetaLeader = ""
	for name, gate := range map[string]ClusterGate{
		"no cluster view":     {},
		"observe failure":     {Cluster: fakeCluster{err: errors.New("down")}},
		"no metadata leader":  {Cluster: fakeCluster{observation: noLeader}},
		"a broker is offline": {Cluster: fakeCluster{observation: peerDown}},
		"lagging stream":      {Cluster: fakeCluster{observation: healthyCluster(), lagging: []string{"TS_ROLLOUTS"}}},
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
