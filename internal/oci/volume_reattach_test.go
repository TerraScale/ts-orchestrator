package oci

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// newReattachFixture returns the volume-init fixture plus a running
// replacement host. The original host still holds its ATTACHED attachment.
func newReattachFixture(t *testing.T) (*fleet, *fakeProvider, *KVJournal, VolumeInitializationPins, Instance) {
	t.Helper()
	fleet, provider, journal, pins, _ := newVolumeInitFixture(t)
	fleet.attachmentSettle = 50 * time.Millisecond
	request := testEnsureRequest(entityid.Derive("test-operation", "volume-init-replacement"))
	request.PrivateIP = "10.251.0.22"
	request.BootPins.HostAttempt = 2
	replacement, err := fleet.EnsureHost(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	cloud := provider.instances[replacement.ID]
	cloud.LifecycleState = "RUNNING"
	provider.instances[replacement.ID] = cloud
	return fleet, provider, journal, pins, replacement
}

func setInstanceState(provider *fakeProvider, id, state string) {
	instance := provider.instances[id]
	instance.LifecycleState = state
	provider.instances[id] = instance
}

func TestFencedDetachRequiresATerminatedInstanceAndIsJournaled(t *testing.T) {
	fleet, provider, journal, pins, _ := newReattachFixture(t)
	ctx := t.Context()
	request := FencedDetachRequest{DatabaseID: pins.DatabaseID, PartitionID: pins.PartitionID,
		AttachmentID: pins.AttachmentID, ExpectedETag: pins.AttachmentETag, InstanceID: pins.InstanceID}
	for _, state := range []string{"RUNNING", "STOPPED", "TERMINATING"} {
		setInstanceState(provider, pins.InstanceID, state)
		if got, err := fleet.FencedInstanceState(ctx, pins.InstanceID); err != nil || got != state {
			t.Fatalf("FencedInstanceState = %q, %v", got, err)
		}
		if err := fleet.DetachFencedAttachment(ctx, request); !errors.Is(err, ErrWriterStopUnverified) {
			t.Fatalf("%s instance was detached without fence proof: %v", state, err)
		}
	}
	if _, exists := provider.attachments[pins.AttachmentID]; !exists {
		t.Fatal("an unproven fence detached the attachment")
	}
	setInstanceState(provider, pins.InstanceID, "TERMINATED")
	stale := request
	stale.ExpectedETag = "0000000000RNVXNPAX5Y5BB8RY"
	if err := fleet.DetachFencedAttachment(ctx, stale); !errors.Is(err, ErrStaleETag) {
		t.Fatalf("stale attachment fence detached: %v", err)
	}
	other := request
	other.InstanceID = "ocid1.instance.other"
	if err := fleet.DetachFencedAttachment(ctx, other); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("attachment of another instance detached: %v", err)
	}
	if err := fleet.DetachFencedAttachment(ctx, request); err != nil {
		t.Fatalf("fenced detach of a TERMINATED instance failed: %v", err)
	}
	if _, exists := provider.attachments[pins.AttachmentID]; exists {
		t.Fatal("fenced detach did not reach OCI")
	}
	operations, err := journal.ListOperations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := 0
	for _, operation := range operations {
		if operation.Intent.Action == actionVolumeDetach && operation.Intent.ResourceID == pins.AttachmentID &&
			!operation.Result.RecordedAt.IsZero() && !operation.Result.Unknown {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("fenced detach has %d confirmed journal receipts, want 1", confirmed)
	}
	// A retry once the attachment is gone is a no-op.
	if err := fleet.DetachFencedAttachment(ctx, request); err != nil {
		t.Fatalf("fenced detach retry: %v", err)
	}
}

func TestFencedDetachThatNeverSettlesIsRecordedUnknown(t *testing.T) {
	fleet, provider, journal, pins, _ := newReattachFixture(t)
	setInstanceState(provider, pins.InstanceID, "TERMINATED")
	stuck := &stuckDetachProvider{fakeProvider: provider}
	fleet.provider = stuck
	err := fleet.DetachFencedAttachment(t.Context(), FencedDetachRequest{DatabaseID: pins.DatabaseID,
		PartitionID: pins.PartitionID, AttachmentID: pins.AttachmentID, ExpectedETag: pins.AttachmentETag,
		InstanceID: pins.InstanceID})
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("an unsettled detach was confirmed: %v", err)
	}
	operations, err := journal.ListOperations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range operations {
		if operation.Intent.Action == actionVolumeDetach && !operation.Result.Unknown {
			t.Fatalf("unsettled detach recorded %+v", operation.Result)
		}
		if operation.Intent.Action == actionVolumeDetach && fleet.detachSettled(t.Context(), operation.Intent) {
			t.Fatal("a DETACHING attachment settled its detach")
		}
	}
	attachment := provider.attachments[pins.AttachmentID]
	attachment.LifecycleState = attachmentStateDetached
	provider.attachments[pins.AttachmentID] = attachment
	settled := false
	for _, operation := range operations {
		settled = settled || operation.Intent.Action == actionVolumeDetach && fleet.detachSettled(t.Context(), operation.Intent)
	}
	if !settled {
		t.Fatal("a DETACHED attachment did not settle its unknown detach")
	}
}

type stuckDetachProvider struct {
	*fakeProvider
}

// DetachVolume accepts the detach, which then stays DETACHING.
func (provider *stuckDetachProvider) DetachVolume(_ context.Context, id, etag string) error {
	attachment, ok := provider.attachments[id]
	if !ok || attachment.ETag != etag {
		return ErrStaleETag
	}
	attachment.LifecycleState, attachment.ETag = attachmentStateDetaching, etag+"-detaching"
	provider.attachments[id] = attachment
	return nil
}

func TestReattachAttachesOverDetachedHistoryAndGrantsOnlyAMount(t *testing.T) {
	fleet, provider, _, pins, replacement := newReattachFixture(t)
	ctx := t.Context()
	setInstanceState(provider, pins.InstanceID, "TERMINATED")
	// OCI keeps the terminated host's attachment as DETACHED history.
	history := provider.attachments[pins.AttachmentID]
	history.LifecycleState, history.ETag = attachmentStateDetached, "detached-etag"
	provider.attachments[pins.AttachmentID] = history

	request := VolumeAttachRequest{DatabaseID: pins.DatabaseID, PartitionID: pins.PartitionID,
		VolumeID: pins.VolumeID, InstanceID: replacement.ID, IdempotencyKey: entityid.Derive("test-attach", "volume-init-reattach")}
	if _, err := fleet.AttachRetainedVolume(ctx, request); !errors.Is(err, ErrAttachmentRecoveryHold) {
		t.Fatalf("a regular attach adopted a volume with attachment history: %v", err)
	}
	request.AllowDetachedHistory = true
	attached, err := fleet.AttachRetainedVolume(ctx, request)
	if err != nil || attached.InstanceID != replacement.ID || attached.State != "ATTACHED" {
		t.Fatalf("reattach over DETACHED history = %+v, %v", attached, err)
	}
	listed, err := fleet.RetainedVolumeAttachments(ctx, pins.VolumeID)
	if err != nil || len(listed) != 2 {
		t.Fatalf("attachment history = %+v, %v", listed, err)
	}

	replacementPins := pins
	replacementPins.InstanceID, replacementPins.HostCreateKey = replacement.ID, replacement.CreateKey
	replacementPins.AttachmentID, replacementPins.AttachmentETag = attached.ID, attached.ETag
	replacementPins.Device = attached.Device
	if proof, err := fleet.InspectVolumeInitialization(ctx, replacementPins); !errors.Is(err, ErrForeignResource) || proof.AllowFormat {
		t.Fatalf("history without a mount permit was inspected: proof=%+v err=%v", proof, err)
	}
	permit := VolumeMountPermit{DatabaseID: pins.DatabaseID, PartitionID: pins.PartitionID, VolumeID: pins.VolumeID,
		AttachmentID: attached.ID, ReplacementInstanceID: replacement.ID, FencedInstanceID: pins.InstanceID}
	wrong := permit
	wrong.AttachmentID = pins.AttachmentID
	if err := fleet.GrantVolumeMountExisting(ctx, wrong); err == nil {
		t.Fatal("a mount permit was granted for the detached attachment")
	}
	setInstanceState(provider, pins.InstanceID, "STOPPED")
	if err := fleet.GrantVolumeMountExisting(ctx, permit); !errors.Is(err, ErrWriterStopUnverified) {
		t.Fatalf("a mount permit was granted without fence proof: %v", err)
	}
	setInstanceState(provider, pins.InstanceID, "TERMINATED")
	if has, err := fleet.HasVolumeMountExisting(ctx, permit); err != nil || has {
		t.Fatalf("HasVolumeMountExisting before grant = %v, %v", has, err)
	}
	for range 2 {
		if err := fleet.GrantVolumeMountExisting(ctx, permit); err != nil {
			t.Fatalf("mount permit grant: %v", err)
		}
	}
	if has, err := fleet.HasVolumeMountExisting(ctx, permit); err != nil || !has {
		t.Fatalf("HasVolumeMountExisting after grant = %v, %v", has, err)
	}
	proof, err := fleet.InspectVolumeInitialization(ctx, replacementPins)
	if err != nil || proof.AllowFormat || proof.BootDescriptorSHA256 != replacement.BootDescriptorSHA256 {
		t.Fatalf("reattached volume inspection = %+v, %v; want mount-only", proof, err)
	}
	// A live attachment anywhere else voids the permit's admission.
	live := history
	live.ID, live.LifecycleState = "attachment-live-elsewhere", "ATTACHED"
	provider.attachments[live.ID] = live
	if proof, err := fleet.InspectVolumeInitialization(ctx, replacementPins); err == nil || proof.AllowFormat {
		t.Fatalf("a second live attachment was admitted: proof=%+v err=%v", proof, err)
	}
}
