package bootstrapstart

import (
	"bytes"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func initialFounderPublicationFixture(t *testing.T) (*founderSelectionFixture, bootstrap.VerifiedBootstrapAnchor, []byte, *founderLedgerObjects) {
	t.Helper()
	fixture := newFounderSelectionFixture(t)
	envelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, fixture.baked.Roots,
		fixture.baked.Identity.AnchorExpectation(), fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	selectionWire := fixture.signSelection(t, fixture.selection, fixture.now.Add(time.Hour))
	store := &founderLedgerObjects{objects: make(map[string]founderStoredObject), now: fixture.now}
	return fixture, anchor, selectionWire, store
}

func TestPublishInitialFounderSelectionCreatesOnlyAndReplaysExactBytes(t *testing.T) {
	fixture, anchor, selectionWire, store := initialFounderPublicationFixture(t)
	for range 2 {
		if err := PublishInitialFounderSelection(t.Context(), anchor, fixture.baked.Identity,
			fixture.baked.Roots, selectionWire, fixture.planWire, fixture.manifests, store, fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	if store.writes != 6 || len(store.objects) != 6 {
		t.Fatalf("matching replay wrote %d times across %d objects, want five immutable and one selector", store.writes, len(store.objects))
	}
	selectorKey := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
		fixture.baked.Identity.DeploymentID, string(fixture.baked.Identity.Cell), fixture.baked.Identity.Environment)
	if !bytes.Equal(store.objects[selectorKey].wire, selectionWire) {
		t.Fatal("generation-one selector was not stored exactly")
	}
}

func TestPublishInitialFounderSelectionRejectsConflictingExistingSelector(t *testing.T) {
	fixture, anchor, selectionWire, store := initialFounderPublicationFixture(t)
	conflict := fixture.selection
	conflict.Generation = 2
	conflictingWire := fixture.signSelection(t, conflict, fixture.now.Add(time.Hour))
	selectorKey := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
		fixture.baked.Identity.DeploymentID, string(fixture.baked.Identity.Cell), fixture.baked.Identity.Environment)
	store.objects[selectorKey] = founderStoredObject{wire: conflictingWire, etag: "existing", modified: fixture.now}
	if err := PublishInitialFounderSelection(t.Context(), anchor, fixture.baked.Identity,
		fixture.baked.Roots, selectionWire, fixture.planWire, fixture.manifests, store, fixture.now); err == nil {
		t.Fatal("conflicting existing selector was treated as matching genesis replay")
	}
	if !bytes.Equal(store.objects[selectorKey].wire, conflictingWire) || store.writes != 5 {
		t.Fatal("conflicting selector was overwritten")
	}
}

func TestPublishInitialFounderSelectionReconcilesAmbiguousCreate(t *testing.T) {
	fixture, anchor, selectionWire, store := initialFounderPublicationFixture(t)
	if err := PublishInitialFounderSelection(t.Context(), anchor, fixture.baked.Identity,
		fixture.baked.Roots, selectionWire, fixture.planWire, fixture.manifests,
		ambiguousFounderPublisher{store: store}, fixture.now); err != nil {
		t.Fatalf("exact readback did not reconcile lost create response: %v", err)
	}
	if store.writes != 6 {
		t.Fatalf("ambiguous create made %d writes, want six", store.writes)
	}
}

func TestPublishInitialFounderSelectionRejectsBadPinBeforeAnyWrite(t *testing.T) {
	fixture, anchor, _, store := initialFounderPublicationFixture(t)
	bad := fixture.selection
	bad.Manifests[0].SHA256 = digestWire([]byte("different manifest"))
	selectionWire := fixture.signSelection(t, bad, fixture.now.Add(time.Hour))
	if err := PublishInitialFounderSelection(t.Context(), anchor, fixture.baked.Identity,
		fixture.baked.Roots, selectionWire, fixture.planWire, fixture.manifests, store, fixture.now); err == nil {
		t.Fatal("mismatched manifest pin was published")
	}
	if store.writes != 0 {
		t.Fatalf("invalid signed selector wrote %d objects", store.writes)
	}
}
