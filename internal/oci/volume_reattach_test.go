package oci

import (
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

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
