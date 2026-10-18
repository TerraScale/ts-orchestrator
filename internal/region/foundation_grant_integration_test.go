package region

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestFoundationGrantDocumentBoundsSDK(t *testing.T) {
	f := newOriginalCompartmentSDKFixture(t, "")
	t.Cleanup(func() {
		f.cloud.mu.Lock()
		defer f.cloud.mu.Unlock()
		if f.cloud.creates != 0 || f.cloud.launchPosts != 0 || f.cloud.materialPosts != 0 {
			t.Errorf("grant boundary verification performed effects: creates=%d launches=%d material=%d", f.cloud.creates, f.cloud.launchPosts, f.cloud.materialPosts)
		}
	})
	if len(f.bundle.GrantWire) <= foundationRecordLimit || len(f.bundle.GrantWire) > foundationGrantLimit {
		t.Fatalf("genuine schema3 grant does not exercise the larger grant bound: bytes=%d", len(f.bundle.GrantWire))
	}
	original, err := json.Marshal(f.bundle, json.Deterministic(true))
	if err != nil || len(original) > MaxWorkloadGenesisEvidenceBytes {
		t.Fatalf("genuine schema3 retained evidence exceeds its aggregate bound: bytes=%d err=%v", len(original), err)
	}
	if _, err := verifyRetainedFoundation(t.Context(), f.bundle, f.roots); err != nil {
		t.Fatalf("genuine schema3 retained grant was refused: %v", err)
	}
	anchor, err := verifyDiscoveryAnchor(f.bundle.AnchorWire, f.roots, f.bundle.TenancyID, f.bundle.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := f.factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewSignedFootprint(&objects, anchor, f.roots, f.bundle.TenancyID)
	if err != nil {
		t.Fatal(err)
	}
	object := reader.storage.HeadBucket + "/" + strings.TrimSuffix(reader.storage.Prefix, "/") + "/" + foundationGrantObject
	f.cloud.writeObject(object, f.bundle.GrantWire)
	f.cloud.mu.Lock()
	requests := f.cloud.requests
	f.cloud.mu.Unlock()
	wire, err := reader.readGrant(t.Context())
	if err != nil || !bytes.Equal(wire, f.bundle.GrantWire) {
		t.Fatalf("actual SDK reader lost the complete signed schema3 grant: %v", err)
	}
	grant, _, err := reader.verifyOriginalDocument(wire)
	if err != nil || grant.SchemaVersion != 3 || len(grant.Regions) != 3 {
		t.Fatalf("actual SDK grant failed original signature/scope verification: %v", err)
	}
	oversized := append(bytes.Clone(f.bundle.GrantWire), bytes.Repeat([]byte{' '}, foundationGrantLimit+1-len(f.bundle.GrantWire))...)
	f.cloud.writeObject(object, oversized)
	if _, err := reader.readGrant(t.Context()); err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Fatalf("actual SDK reader did not reject a grant one byte over its bound: %v", err)
	}
	f.cloud.mu.Lock()
	observedRequests := f.cloud.requests - requests
	f.cloud.mu.Unlock()
	if observedRequests != 2 {
		t.Fatalf("grant boundary checks crossed %d authenticated SDK requests; want two", observedRequests)
	}
	for _, candidate := range []struct {
		name string
		wire []byte
	}{{"empty", []byte{}}, {"oversized", oversized}} {
		t.Run(candidate.name, func(t *testing.T) {
			reader.retainedGrant = candidate.wire
			defer func() { reader.retainedGrant = nil }()
			if _, err := reader.readGrant(t.Context()); err == nil || !strings.Contains(err.Error(), "oversized") {
				t.Fatalf("retained reader returned an empty or oversized grant: %v", err)
			}
			if _, _, err := reader.verifyOriginalDocument(candidate.wire); err == nil || !strings.Contains(err.Error(), "empty or oversized") {
				t.Fatalf("direct grant verification reached parsing instead of the document bound: %v", err)
			}
			bundle := f.bundle.clone()
			bundle.GrantWire = candidate.wire
			if _, err := verifyRetainedFoundation(t.Context(), bundle, f.roots); err == nil || !strings.Contains(err.Error(), "document bounds") {
				t.Fatalf("retained bundle did not enforce grant document bounds: %v", err)
			}
		})
	}
}
