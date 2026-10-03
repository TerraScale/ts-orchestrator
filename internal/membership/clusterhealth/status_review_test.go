package clusterhealth

import (
	"testing"
	"time"
)

// On the metadata leader, a peer whose lag is within the tolerated threshold
// but whose last contact is older than the lost-quorum interval is out of
// contact, even while Offline has not been set yet.
func TestLeaderTreatsStaleContactAsLaggingWithinLagThreshold(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	observation := healthyObservation()
	observation.MetaLeader = observation.ServerName
	observation.Peers = []Peer{
		{Name: "cell-controller-b", Current: true},
		{Name: "cell-controller-c", Current: false, Lag: 500, Active: StaleContact + time.Second},
	}
	status := Evaluate(observation, DefaultLagThreshold, now)
	if status.Phase != PhaseDegraded || len(status.Lagging) != 1 || status.Lagging[0].Name != "cell-controller-c" {
		t.Fatalf("status = %+v", status)
	}
	// The same lag with recent contact is tolerated catch-up.
	observation.Peers[1].Active = time.Second
	if status := Evaluate(observation, DefaultLagThreshold, now); status.Phase != PhaseHealthy {
		t.Fatalf("recently contacted peer within the lag threshold: %+v", status)
	}
}
