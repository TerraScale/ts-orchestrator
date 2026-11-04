package app

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func TestNetBirdRolloutPersistsProgressAndRejectsFencedLeader(t *testing.T) {
	kv := fenceKV(t)
	lease := &fenceLease{}
	r := netbirdRollout{fence: &releaseFence{kv: kv, fencer: lease}}
	before := network.Record{ID: "4845ZN4B5KA6F2FCQQZE93Y54S", Node: "node-a", Previous: "0.79.0", Phase: "check"}
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, before); err != nil {
		t.Fatal(err)
	}
	restarted := netbirdRollout{fence: &releaseFence{kv: kv, fencer: lease}}
	var after network.Record
	if err := restarted.load(t.Context(), netbirdRecordKey, &after); err != nil || after.ID != before.ID || after.Node != before.Node || after.Phase != before.Phase {
		t.Fatalf("leader did not resume: %+v %v", after, err)
	}
	lease.lost = true
	before.Node = "node-b"
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, before); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("deposed leader saved another node: %v", err)
	}
	if err := restarted.load(t.Context(), netbirdRecordKey, &after); err != nil || after.Node != "node-a" {
		t.Fatal("deposed leader changed active node")
	}
}
