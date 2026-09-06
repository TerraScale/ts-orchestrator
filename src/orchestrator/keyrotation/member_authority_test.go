package keyrotation

import (
	"errors"
	"strings"
	"testing"
)

func TestMemberPeerAuthorityBindsCandidateEpochAndLease(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, t.Context(), connection, true)
	lease := rotationTestLease(9, "global-controller-gru-member-proof")
	putRotationTestLease(t, t.Context(), kv, lease)
	pin := strings.Repeat("a", 64)
	check, err := NewMemberPeerAuthority(connection, map[string]string{pin: lease.CandidateId})
	if err != nil {
		t.Fatal(err)
	}
	if err := check(t.Context(), pin, uint64(lease.Epoch), lease.LeaseId); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		pin     string
		epoch   uint64
		leaseID string
	}{{strings.Repeat("b", 64), uint64(lease.Epoch), lease.LeaseId}, {pin, uint64(lease.Epoch - 1), lease.LeaseId}, {pin, uint64(lease.Epoch), "old-lease"}} {
		if err := check(t.Context(), input.pin, input.epoch, input.leaseID); !errors.Is(err, ErrStateFenced) {
			t.Fatalf("accepted stale owner proof: %v", err)
		}
	}
	lease.Epoch++
	lease.LeaseId = "new-lease-same-candidate"
	putRotationTestLease(t, t.Context(), kv, lease)
	if err := check(t.Context(), pin, uint64(lease.Epoch-1), lease.LeaseId); !errors.Is(err, ErrStateFenced) {
		t.Fatal("same candidate prior epoch accepted")
	}
}
