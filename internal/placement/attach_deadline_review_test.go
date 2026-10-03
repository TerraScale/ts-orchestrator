package placement

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// The production fleet fails an attach whose settle wait expires and
// withholds an instance whose volume is ATTACHING, so the member never
// reaches the stage that observes ATTACHING. The attach deadline therefore
// runs from the durable attach request and is reported from the prepared
// stage too (#127 12106).
func TestControllerReportsAStalledAttachRequestWhileTheAttachmentIsUnobservable(t *testing.T) {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	store := newPlacementMemoryStore(t, intent)
	for memberID, member := range store.members {
		member.State.Stage = StagePreparedAttach
		member.State.AttachmentID, member.State.AttachmentDevice, member.State.AttachmentETag = "", "", ""
		store.members[memberID] = member
	}
	instances := attachedInstances(t, intent)
	for index := range instances {
		instances[index].Attachments = nil
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })
	start := time.Now()
	controller.now = func() time.Time { return start }

	// The first attach (whose settle wait fails in this fleet) records when
	// it was requested.
	_ = controller.Tick(t.Context())
	if fleet.attachCalls == 0 {
		t.Fatal("no attach was requested")
	}
	recorded := 0
	for _, member := range store.members {
		if !member.State.AttachRequestedAt.IsZero() {
			recorded++
		}
	}
	if recorded != fleet.attachCalls {
		t.Fatalf("%d attach requests but %d recorded", fleet.attachCalls, recorded)
	}
	for _, reason := range holds {
		if strings.Contains(reason, "stuck ATTACHING") {
			t.Fatalf("attach within its deadline was reported stuck: %s", reason)
		}
	}

	// Past the deadline, with the instance withheld from observation.
	fleet.instances = nil
	controller.now = func() time.Time { return start.Add(11 * time.Minute) }
	holds = nil
	_ = controller.Tick(t.Context())
	stuck := false
	for _, reason := range holds {
		stuck = stuck || strings.Contains(reason, "stuck ATTACHING") && strings.Contains(reason, "force-detach-retry")
	}
	if !stuck {
		t.Fatalf("stalled attach request was not reported: %q", holds)
	}
}
