package clusterhealth

import (
	"slices"
	"testing"
	"time"
)

var expectedBrokers = []string{"cell-controller-a", "cell-controller-b", "cell-controller-c"}

func healthyObservation() Observation {
	return Observation{ServerName: "cell-controller-a", Running: true, Expected: expectedBrokers,
		Routes:     []string{"cell-controller-b", "cell-controller-c"},
		MetaLeader: "cell-controller-b", MetaSize: 3, MetaQuorum: 2,
		Peers: []Peer{{Name: "cell-controller-c", Current: true}, {Name: "cell-controller-b", Current: true}}}
}

func TestEvaluateClassifiesClusterStates(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*Observation)
		check  func(*testing.T, Status)
	}{
		{"healthy", func(*Observation) {}, func(t *testing.T, status Status) {
			if status.Phase != PhaseHealthy || !slices.Equal(status.Online, expectedBrokers) ||
				status.Offline != nil || status.Missing != nil || status.Unknown != nil {
				t.Fatalf("status = %+v", status)
			}
		}},

		// A NATS follower always reports other followers as not current with
		// zero lag; it has no progress data for them.

	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := healthyObservation()
			observation.Peers = slices.Clone(observation.Peers)
			test.mutate(&observation)
			status := Evaluate(observation, DefaultLagThreshold, now)
			if !status.ObservedAt.Equal(now) {
				t.Fatalf("observed at = %s", status.ObservedAt)
			}
			test.check(t, status)
		})
	}
}
