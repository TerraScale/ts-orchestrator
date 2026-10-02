package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

// resizeProvider adds the optional UpdateVolume and VolumeId-filtered
// attachment seams to the shared fake provider.
type resizeProvider struct {
	*fakeProvider
	updates            int
	updateErr          error
	updateApplies      bool
	volumeAttachLists  int
	compartmentListing int
}

func (p *resizeProvider) UpdateVolumeSize(_ context.Context, id, etag string, sizeGB int64, tags map[string]string) (CloudVolume, error) {
	p.updates++
	volume, ok := p.volumes[id]
	if !ok {
		return CloudVolume{}, fakeNotFound{}
	}
	if volume.ETag != etag {
		return CloudVolume{}, ErrStaleETag
	}
	if p.updateErr != nil && !p.updateApplies {
		return CloudVolume{}, p.updateErr
	}
	volume.SizeGB = sizeGB
	volume.FreeformTags = maps.Clone(tags)
	volume.ETag = fmt.Sprintf("%s-resized-%d", etag, sizeGB)
	p.volumes[id] = volume
	return volume, p.updateErr
}

func (p *resizeProvider) ListVolumeAttachments(ctx context.Context, compartmentID, instanceID string) ([]CloudAttachment, error) {
	if instanceID == "" {
		p.compartmentListing++
	}
	return p.fakeProvider.ListVolumeAttachments(ctx, compartmentID, instanceID)
}

func (p *resizeProvider) ListVolumeAttachmentsByVolume(_ context.Context, compartmentID, availabilityDomain, volumeID string) ([]CloudAttachment, error) {
	if compartmentID != p.config.CompartmentID || availabilityDomain != p.config.AvailabilityDomain {
		return nil, ErrForeignResource
	}
	p.volumeAttachLists++
	var found []CloudAttachment
	for _, attachment := range p.attachments {
		if attachment.VolumeID == volumeID {
			found = append(found, attachment)
		}
	}
	// A foreign record proves the fleet still filters client-side.
	found = append(found, CloudAttachment{ID: "foreign", VolumeID: "ocid1.volume.other"})
	return found, nil
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
		DatabaseID: "db-main", PartitionID: "partition-main", CreateKey: "resize-volume", SizeGB: 50,
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
	return VolumeResizeRequest{DatabaseID: "db-main", PartitionID: "partition-main", VolumeID: volumeID, SizeGB: sizeGB}
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
		DatabaseID: "db-main", PartitionID: "partition-main", CreateKey: "resize-volume", SizeGB: 50,
	})
	if err != nil || again.ID != created.ID || again.SizeGB != 100 {
		t.Fatalf("re-ensure of resized volume failed: %+v, %v", again, err)
	}
	// A raised desired size never issues a second create for the same key.
	raised, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{
		DatabaseID: "db-main", PartitionID: "partition-main", CreateKey: "resize-volume", SizeGB: 200,
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

func TestResizeRetainedVolumeRecoversLostResponseAndHoldsStaleState(t *testing.T) {
	ctx := t.Context()
	fleet, provider, journal, _, created := resizeFixture(t)
	provider.updateErr, provider.updateApplies = errors.New("response dropped"), true
	if resized, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 80)); err != nil || resized.SizeGB != 80 {
		t.Fatalf("applied update with lost response was not confirmed: %+v, %v", resized, err)
	}
	if journal.volumes[created.ID].SizeGB != 80 {
		t.Fatal("confirmed resize did not advance ownership")
	}

	// An update that did not apply records Unknown and keeps the old owner.
	provider.updateErr, provider.updateApplies = errors.New("service unavailable"), false
	if _, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 120)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("failed update was not unknown: %v", err)
	}
	if journal.volumes[created.ID].SizeGB != 80 {
		t.Fatal("unknown resize changed ownership")
	}
	// The immutable intent pinned the ETag; a concurrent change holds.
	volume := provider.volumes[created.ID]
	volume.ETag = "changed-elsewhere"
	provider.volumes[created.ID] = volume
	provider.updateErr = nil
	updates := provider.updates
	if _, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 120)); !errors.Is(err, ErrStaleETag) || provider.updates != updates {
		t.Fatalf("stale resize was retried: %v updates=%d", err, provider.updates)
	}
}

func TestResizeRetainedVolumeRefusesUnownedFencedAndOutOfBoundRequests(t *testing.T) {
	ctx := t.Context()
	fleet, provider, journal, fencer, created := resizeFixture(t)
	if _, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, fleet.config.MaxDataVolumeGB+1)); err == nil {
		t.Fatal("resize above the fleet bound was accepted")
	}
	delete(journal.volumes, created.ID)
	if _, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 90)); !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("unowned volume was resized: %v", err)
	}
	journal.volumes[created.ID] = ResourceIdentity{ID: created.ID, Region: created.Region, Generation: created.Generation,
		Owner: created.Owner, CreateKey: created.CreateKey, AvailabilityDomain: created.AvailabilityDomain, SizeGB: 50}
	fencer.guardErr = authority.ErrFenced
	if _, err := fleet.ResizeRetainedVolume(ctx, resizeRequest(created.ID, 90)); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced controller resized: %v", err)
	}
	if provider.updates != 0 {
		t.Fatalf("refused resizes reached OCI: %d", provider.updates)
	}
	fencer.guardErr = nil
	_, regionIntent := testRegionConfig()
	plain, err := newTestFleet(fleet.config, regionIntent, provider.fakeProvider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.(VolumeResizer).ResizeRetainedVolume(ctx, resizeRequest(created.ID, 90)); !errors.Is(err, ErrVolumeResizeUnsupported) {
		t.Fatalf("provider without UpdateVolume did not refuse: %v", err)
	}
}

func TestVolumeAttachmentLookupUsesVolumeFilter(t *testing.T) {
	fleet, provider, _, _, created := resizeFixture(t)
	provider.attachments["attachment-x"] = CloudAttachment{ID: "attachment-x", VolumeID: created.ID, InstanceID: "ocid1.instance.x"}
	found, err := fleet.findVolumeAttachments(t.Context(), created.ID)
	if err != nil || len(found) != 1 || found[0].ID != "attachment-x" {
		t.Fatalf("filtered attachments = %+v, %v", found, err)
	}
	if provider.volumeAttachLists != 1 || provider.compartmentListing != 0 {
		t.Fatalf("lookup scanned the compartment: filtered=%d scans=%d", provider.volumeAttachLists, provider.compartmentListing)
	}
}

func TestKVJournalAdvancesAndRepairsResizedVolumeOwnership(t *testing.T) {
	ctx := t.Context()
	kv := testJournalBucket(t)
	journal, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := testRegionConfig()
	volumeID := "ocid1.volume.kv-resize"
	create := OperationIntent{Action: actionVolumeCreate, Key: "kv-resize", Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreateKey: "kv-resize",
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, CreatedAt: time.Now().UTC()}
	if err := journal.RecordIntent(ctx, create); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: create, ResourceID: volumeID}); err != nil {
		t.Fatal(err)
	}
	identity := ResourceIdentity{ID: volumeID, Region: config.Region, Generation: config.Generation,
		Owner: config.Owner, CreateKey: "kv-resize", AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50}
	resize := OperationIntent{Action: actionVolumeResize, Key: volumeResizeKey(volumeID, 100), Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, ResourceID: volumeID, VolumeID: volumeID,
		CreateKey: "kv-resize", ExpectedETag: "etag-50", AvailabilityDomain: config.AvailabilityDomain,
		SizeGB: 100, PreviousSizeGB: 50, CreatedAt: time.Now().UTC()}
	bad := resize
	bad.Key = volumeResizeKey(volumeID, 90)
	if err := journal.RecordIntent(ctx, bad); err == nil {
		t.Fatal("resize intent with a mismatched key was accepted")
	}
	shrink := resize
	shrink.Key, shrink.SizeGB = volumeResizeKey(volumeID, 40), 40
	if err := journal.RecordIntent(ctx, shrink); err == nil {
		t.Fatal("shrinking resize intent was accepted")
	}
	if err := journal.RecordIntent(ctx, resize); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: resize, ResourceID: "ocid1.volume.other"}); err == nil {
		t.Fatal("resize result for another volume was accepted")
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: resize, ResourceID: volumeID, ETag: "etag-100"}); err != nil {
		t.Fatal(err)
	}
	grown := identity
	grown.SizeGB = 100
	if owned, err := journal.IsOwnedVolume(ctx, grown); err != nil || !owned {
		t.Fatalf("resized volume not owned: %v %v", owned, err)
	}
	if owned, _ := journal.IsOwnedVolume(ctx, identity); owned {
		t.Fatal("predecessor size is still owned after resize")
	}
	// Replaying the confirmed receipt is idempotent.
	if err := journal.RecordResult(ctx, OperationResult{Intent: resize, ResourceID: volumeID, ETag: "etag-100"}); err != nil {
		t.Fatalf("idempotent resize result failed: %v", err)
	}
	// A lost ownership projection is rebuilt from the create and resize.
	if err := kv.Delete(ctx, ownershipKey("volume", volumeID)); err != nil {
		t.Fatal(err)
	}
	if owned, err := journal.IsOwnedVolume(ctx, grown); err != nil || !owned {
		t.Fatalf("resized ownership was not repaired: %v %v", owned, err)
	}
	unconfirmed := grown
	unconfirmed.SizeGB = 200
	if owned, _ := journal.IsOwnedVolume(ctx, unconfirmed); owned {
		t.Fatal("size without a confirmed resize was owned")
	}
}
