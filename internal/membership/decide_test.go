package membership

import (
	"time"
)

var testEpoch = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func testTopology() Topology {
	return Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
		SeedSlot: "controller-a", SelfSlot: "controller-a"}
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
