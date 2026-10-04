package oci

import (
	"strings"
	"testing"
	"time"
)

func fleetView(t *testing.T, region Region) (instances, volumes, attachments map[string]int, observed time.Time) {
	t.Helper()
	for _, view := range FleetInventory() {
		if view.Region == string(region) {
			return view.Instances, view.Volumes, view.Attachments, view.ObservedAt
		}
	}
	t.Fatalf("no inventory for %s", region)
	return nil, nil, nil, time.Time{}
}

func TestCompleteObserveSweepPublishesTheFleetByLifecycleState(t *testing.T) {
	ctx := t.Context()
	_, _, _, subject, host, volume := newAttachTestState(t)
	if _, err := subject.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "db-main", PartitionID: "partition-main",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: "attach-inventory",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := subject.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	instances, volumes, attachments, observed := fleetView(t, host.Region)
	if observed.IsZero() || sum(instances) != 1 || instances[host.State] != 1 || sum(volumes) != 1 ||
		attachments["ATTACHED"] != 1 || sum(attachments) != 1 {
		t.Fatalf("inventory = instances %v volumes %v attachments %v", instances, volumes, attachments)
	}
	view := APIView()
	if len(view.Fleet) == 0 {
		t.Fatal("the OCI view lacks the fleet inventory")
	}
	var exposition strings.Builder
	Metrics.WritePrometheus(&exposition)
	if !strings.Contains(exposition.String(), `oci_fleet_resources{region="`+string(host.Region)+`",kind="attachment",state="ATTACHED"} 1`) {
		t.Fatalf("fleet gauges missing from /metrics:\n%s", exposition.String())
	}

	// A selective observation never replaces the complete inventory.
	before := observed
	if _, err := subject.(*fleet).ObserveSelected(ctx, func(string, string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, after := fleetView(t, host.Region); !after.Equal(before) {
		t.Fatal("a selective observation replaced the complete inventory")
	}
}

func TestInventoryZeroesStatesThatEmptied(t *testing.T) {
	region := Region("inventory-test")
	first := newInventoryTally()
	first.instance("RUNNING")
	first.instance("")
	publishInventory(region, first, time.Unix(1, 0))
	second := newInventoryTally()
	second.instance("STOPPED")
	publishInventory(region, second, time.Unix(2, 0))
	instances, _, _, _ := fleetView(t, region)
	if len(instances) != 1 || instances["STOPPED"] != 1 {
		t.Fatalf("instances = %v", instances)
	}
	var exposition strings.Builder
	Metrics.WritePrometheus(&exposition)
	if !strings.Contains(exposition.String(), `oci_fleet_resources{region="inventory-test",kind="instance",state="RUNNING"} 0`) {
		t.Fatal("an emptied state kept its last count")
	}
	var nilTally *inventoryTally
	nilTally.volume("AVAILABLE") // outside a sweep: no tally, no panic
	bounded := newInventoryTally()
	for index := range maxInventoryStates + 4 {
		bounded.attachment(strings.Repeat("S", index+1))
	}
	if len(bounded.attachments) != maxInventoryStates+1 || bounded.attachments["OTHER"] != 4 {
		t.Fatalf("states are not bounded: %v", bounded.attachments)
	}
}

func sum(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

// TestInventoryCountsOnlyVerifiedHosts pins that a host withheld partway
// through its attachments contributes no volume or attachment, whichever
// order OCI lists them in.
func TestInventoryCountsOnlyVerifiedHosts(t *testing.T) {
	ctx := t.Context()
	_, provider, _, subject, host, volume := newAttachTestState(t)
	if _, err := subject.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "db-main", PartitionID: "partition-main",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: "attach-inventory-partial",
	}); err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-unconfirmed"] = observeTestAttachment("attachment-unconfirmed", volume.ID, host.ID)
	for range 8 {
		observed, err := subject.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(observed) != 0 {
			t.Fatalf("observed %d hosts, want the host withheld", len(observed))
		}
		instances, volumes, attachments, _ := fleetView(t, host.Region)
		if sum(instances) != 1 || sum(volumes) != 0 || sum(attachments) != 0 {
			t.Fatalf("inventory = instances %v volumes %v attachments %v", instances, volumes, attachments)
		}
	}
}
