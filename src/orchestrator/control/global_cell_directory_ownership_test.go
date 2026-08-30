package control

import (
	"testing"
	"time"
)

func TestGlobalCellDirectoryOwnsAdvertisementSlices(t *testing.T) {
	now := time.Now().UTC()
	advertisement := GlobalCellAdvertisement{
		SchemaVersion:     1,
		Cell:              "gru",
		Cluster:           "orchestrator-control-gru",
		AuthorityId:       "gru-regional",
		AuthorityEpoch:    1,
		AuthorityRevision: 1,
		Sequence:          1,
		Capabilities:      []string{"runtime"},
		Membership: RegionalRuntimeMembershipHealth{
			ExpectedControllers: 1, ActiveControllers: 1, QuorumAvailable: true,
			AuthorityLeaders: 1, Condition: RegionalRuntimeMembershipConditionHealthy,
			ObservedAt: now,
		},
		ObservedAt:     now,
		LeaseExpiresAt: now.Add(GlobalCellAdvertisementSemanticLease),
		Endpoints:      []string{"tls://nats.example:4222"},
	}
	directory := NewGlobalCellDirectory()
	if got := directory.ApplyAdvertisement(advertisement, &now); got != GlobalCellAdvertisementDispositionAccepted {
		t.Fatalf("ApplyAdvertisement = %v", got)
	}
	advertisement.Capabilities[0] = "caller-mutated"
	advertisement.Endpoints[0] = "tls://caller-mutated:4222"
	snapshot := directory.Snapshot(&now)
	if len(snapshot.Cells) != 1 || snapshot.Cells[0].Capabilities[0] != "runtime" || snapshot.Cells[0].Endpoints[0] != "tls://nats.example:4222" {
		t.Fatalf("caller mutation changed stored advertisement: %#v", snapshot)
	}
	snapshot.Cells[0].Capabilities[0] = "snapshot-mutated"
	snapshot.Cells[0].Endpoints[0] = "tls://snapshot-mutated:4222"
	next := directory.Snapshot(&now)
	if next.Cells[0].Capabilities[0] != "runtime" || next.Cells[0].Endpoints[0] != "tls://nats.example:4222" {
		t.Fatalf("snapshot mutation changed stored advertisement: %#v", next)
	}
}
