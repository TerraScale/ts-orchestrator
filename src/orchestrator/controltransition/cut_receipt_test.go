package controltransition

import (
	"bytes"
	"testing"
)

func TestCutReceiptBindsOriginalCopyAndSourceEvidence(t *testing.T) {
	v, _, signers := pinReceiptFixture(t, false)
	p, err := v.Plan()
	if err != nil {
		t.Fatal(err)
	}
	r := CutReceipt{Version: 1, Phase: "source-store-copied", PlanSHA256: v.Digest(), NodeID: p.Source.NodeID, BootstrapGrantSHA256: p.Source.BootstrapGrantSHA256, StoreScopeSHA256: p.Source.StoreScopeSHA256, StoreSHA256: Digest([]byte("store")), CopySHA256: Digest([]byte("store")), SourceDevice: 2, SourceInode: 3, Files: 1, Bytes: 8, StoppedAt: p.IssuedAt, CopiedAt: p.IssuedAt, SourceStateReceiptSHA256: Digest([]byte("signed-state")), RetirementSHA256: Digest([]byte("durable-retirement"))}
	raw, err := SignCutReceipt(signers[0], v, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCutReceipt(v, raw)
	if err != nil || got != r {
		t.Fatalf("receipt %v: %v", got, err)
	}
	changed := bytes.Replace(raw, []byte("source-store-copied"), []byte("source-store-forged"), 1)
	if _, err := VerifyCutReceipt(v, changed); err == nil {
		t.Fatal("accepted changed signed phase")
	}
	for _, change := range []func(*CutReceipt){func(r *CutReceipt) { r.CopySHA256 = Digest([]byte("other")) }, func(r *CutReceipt) { r.SourceStateReceiptSHA256 = "" }, func(r *CutReceipt) { r.RetirementSHA256 = "" }, func(r *CutReceipt) { r.Files = p.Limits.MaxStoreFiles + 1 }, func(r *CutReceipt) { r.CopiedAt = p.ExpiresAt }, func(r *CutReceipt) { r.NodeID = "gru-other" }} {
		other := r
		change(&other)
		if _, err := SignCutReceipt(signers[0], v, other); err == nil {
			t.Fatal("signed invalid copy scope")
		}
	}
	if _, err := SignCutReceipt(signers[1], v, r); err == nil {
		t.Fatal("destination signer certified source copy")
	}
}
