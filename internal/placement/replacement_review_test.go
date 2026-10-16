package placement

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// A host OCI still lists but positively reports TERMINATED is lost: its
// loss is recorded and its grace starts. When the host is observed live
// again the record clears, so a later loss gets a full grace.
func TestTerminatedListedHostIsLostAndARecoveredHostClearsTheLoss(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	memberID := permanentMember(oci.RegionGRU)
	instances := attachedInstances(t, intent)
	index := -1
	for i, instance := range instances {
		if instance.ID == store.members[memberID].State.InstanceID {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("fixture has no instance for the permanent member")
	}
	instances[index].State = "TERMINATED"
	fleet := &placementTestFleet{instances: instances}
	controller := startTestPlacementController(t, store, fleet, &placementTestHosts{}, nil)
	now := time.Now().UTC()
	controller.now = func() time.Time { return now }
	controller.config.LostMemberEvidence = func(context.Context, MemberState) (RetirementEvidence, bool, error) {
		return RetirementEvidence{}, false, nil
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state := store.members[memberID].State; !state.HostLostAt.Equal(now) {
		t.Fatalf("a TERMINATED listed host was not treated as lost: %+v", state)
	}
	fleet.instances[index].State = "RUNNING"
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state := store.members[memberID].State; !state.HostLostAt.IsZero() {
		t.Fatalf("a recovered host kept its loss time: %+v", state)
	}
}
