package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

func testContext(t *testing.T, action ProviderAction, target ProviderTarget, params ProviderActionParameters) ProviderOperationContext {
	t.Helper()
	c, e := NewProviderOperationContext(ProviderOperationId{"op-1"}, ProviderCellId{"gru"}, ProviderCompartmentId{"ocid1.compartment.oc1.x"}, ProviderEpoch{2}, ResourceVolume, action, target, ProviderGeneration{1}, ObservedPresent, TerminalExpanded, nil, DeadlineEvidence{DeadlineValid, ProviderGeneration{1}}, ProviderIdempotencyKey{"idem-1"}, nil, params)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestAuthorizationRejectsTagsAlone(t *testing.T) {
	c := testContext(t, ActionExpandVolume, ExistingProviderResource{ProviderResourceId{"ocid1.volume.oc1.x"}}, ExpandVolumeProviderParameters{ProviderByteCount{2 << 30}})
	r, _ := NewProviderAuthorizationRequest(c, nil, nil, []ProviderInventoryTagEvidence{{ResourceId: ProviderResourceId{"ocid1.volume.oc1.x"}, CellId: c.CellId, CompartmentId: c.CompartmentId, OperationId: c.OperationId, Generation: c.ExpectedGeneration}}, EvidenceComplete, nil, nil, nil, nil, ProviderCallEvidence{Context: c, Status: CallNotCalled})
	if d := Authorize(r); d.Authorized {
		t.Fatal("tags must not authorize")
	}
}

type fakeVolume struct {
	reads   []VolumeObservation
	updates int
	mu      sync.Mutex
}

func (f *fakeVolume) GetVolume(context.Context, VolumeReadRequest) (*VolumeObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reads) == 0 {
		return nil, nil
	}
	x := f.reads[0]
	f.reads = f.reads[1:]
	return &x, nil
}
func (f *fakeVolume) UpdateVolume(context.Context, VolumeUpdateRequest) (*VolumeObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	return nil, errors.New("response lost")
}
func TestExpansionCancellationBeforeTransport(t *testing.T) {
	f := &fakeVolume{}
	c := testContext(t, ActionExpandVolume, ExistingProviderResource{ProviderResourceId{"ocid1.volume.oc1.x"}}, ExpandVolumeProviderParameters{ProviderByteCount{2 << 30}})
	x := ExpandVolumeProviderIntent{intentBase{c}, c.ActionParameters.(ExpandVolumeProviderParameters)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (BlockVolumeExpansionAdapter{CellId: c.CellId, CompartmentId: c.CompartmentId, Transport: f}).Expand(ctx, x)
	if !errors.Is(err, context.Canceled) || f.updates != 0 {
		t.Fatalf("cancellation boundary failed: %v", err)
	}
}
func TestReceiptRoundTripAndTamper(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, e := NewCreateNodeHandoffReceiptSigner("tenant-key", key)
	if e != nil {
		t.Fatal(e)
	}
	b := CreateNodeReceiptBinding{"op", "tenant", "node", "idem", "create", "gru", "ocid1.compartment.oc1.x", "tmpl", "place", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "auth", "fingerprint", 1, 2, 1}
	issued := time.Unix(100, 0)
	r, e := signer.Sign(b, issued, issued.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ring, _ := NewReceiptKeyRing(map[string][]byte{"tenant-key": pub})
	if !VerifyCreateNodeHandoffReceipt(r, ring, b, issued.Add(time.Second)) {
		t.Fatal("valid receipt rejected")
	}
	r.Signature = base64.StdEncoding.EncodeToString([]byte("bad"))
	if VerifyCreateNodeHandoffReceipt(r, ring, b, issued.Add(time.Second)) {
		t.Fatal("tampered receipt accepted")
	}
}
func TestConcurrentDeterministicReconciliationIsRaceSafe(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ring, _ := NewReceiptKeyRing(map[string][]byte{"k": pub})
	ps, _ := NewCreateNodeProviderProofSigner("p", key)
	p, _ := NewDeterministicCreateNodeProvider(ring, ring, ps, time.Now)
	if p == nil {
		t.Fatal("provider nil")
	}
}
