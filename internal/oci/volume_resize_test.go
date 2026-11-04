package oci

import (
	"testing"
)

type resizeProvider struct {
	*fakeProvider
	updates            int
	updateErr          error
	updateApplies      bool
	volumeAttachLists  int
	compartmentListing int
}

func resizeFixture(t *testing.T) (*fleet, *resizeProvider, *fakeJournal, *fakeFencer, RetainedVolume) {
	t.Helper()
	config, intent := testRegionConfig()
	provider := &resizeProvider{fakeProvider: newFakeProvider(config)}
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	built, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := built.CreateRetainedVolume(t.Context(), VolumeCreateRequest{
		Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000007ZA298B7HFNPARDE", SizeGB: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	volume := provider.volumes[created.ID]
	volume.LifecycleState = "AVAILABLE"
	provider.volumes[created.ID] = volume
	return built.(*fleet), provider, journal, fencer, created
}

func resizeRequest(volumeID string, sizeGB int64) VolumeResizeRequest {
	return VolumeResizeRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volumeID, SizeGB: sizeGB}
}

func TestResizeRetainedVolumeGrowsAndKeepsDurableOwnership(t *testing.T) {
	ctx := t.Context()
	fleet, provider, journal, _, created := resizeFixture(t)
	var _ VolumeResizer = fleet

	resized, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 100))
	if err != nil || resized.SizeGB != 100 || provider.updates != 1 {
		t.Fatalf("resize = %+v, %v (updates %d)", resized, err, provider.updates)
	}
	cloud := provider.volumes[created.ID]
	if cloud.SizeGB != 100 || cloud.FreeformTags[tagVolumeSize] != "100" {
		t.Fatalf("size and size tag were not updated together: %+v", cloud)
	}
	if got := journal.volumes[created.ID].SizeGB; got != 100 {
		t.Fatalf("ownership record was not advanced: size %d", got)
	}
	// The grown volume is still owned: attach scope checks and re-ensure work.
	if _, err := fleet.ownedVolume(ctx, created.ID); err != nil {
		t.Fatalf("resized volume looks foreign: %v", err)
	}
	again, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{
		Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000007ZA298B7HFNPARDE", SizeGB: 50,
	})
	if err != nil || again.ID != created.ID || again.SizeGB != 100 {
		t.Fatalf("re-ensure of resized volume failed: %+v, %v", again, err)
	}
	// A raised desired size never issues a second create for the same key.
	raised, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{
		Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000007ZA298B7HFNPARDE", SizeGB: 200,
	})
	if err != nil || raised.ID != created.ID || provider.volumeCreates != 1 {
		t.Fatalf("raised desired size broke re-ensure: %+v, %v creates=%d", raised, err, provider.volumeCreates)
	}
	// Grow-only and idempotent: equal or smaller targets are no-ops.
	for _, size := range []int64{100, 60} {
		if same, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, size)); err != nil || same.SizeGB != 100 {
			t.Fatalf("resize to %d = %+v, %v", size, same, err)
		}
	}
	if provider.updates != 1 {
		t.Fatalf("no-op resizes reached OCI: %d updates", provider.updates)
	}
	// A second step grows from the advanced ownership record.
	if grown, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 150)); err != nil || grown.SizeGB != 150 {
		t.Fatalf("second resize = %+v, %v", grown, err)
	}
}
