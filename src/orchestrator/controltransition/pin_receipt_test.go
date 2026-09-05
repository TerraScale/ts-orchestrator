package controltransition

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func pinReceiptFixture(t testing.TB, separateGRU bool) (VerifiedPlan, []PinReceipt, []*security.CommandSignatureSigner) {
	t.Helper()
	p := testPlan(t)
	owner, public := testKey(t)
	source, sourcePublic := testKey(t)
	p.Source.ReceiptPublicKeyPEM = string(sourcePublic)
	if separateGRU {
		p.Destinations[0].NodeID = "gru-other"
	}
	signers := []*security.CommandSignatureSigner{source}
	receipts := []PinReceipt{{Version: 1, Phase: "plan-pinned", NodeID: p.Source.NodeID, Role: "source", PinSHA256: Digest([]byte(p.Source.NodeID)), BootstrapGrantSHA256: p.Source.BootstrapGrantSHA256, ManifestSHA256: p.Source.InitialManifestSHA256, CommandID: "capture-one", CommandSHA256: strings.Repeat("c", 64), AuthorityID: "gru-regional", Epoch: 7, CandidateID: "gru-controller-" + strings.Repeat("a", 63), LeaseID: "lease-one", AdmittedAt: p.IssuedAt, PublishedAt: p.IssuedAt.Add(time.Minute)}}
	for i, d := range p.Destinations {
		if d.NodeID == p.Source.NodeID {
			continue
		}
		signer, key := testKey(t)
		p.Destinations[i].ReceiptPublicKeyPEM = string(key)
		signers = append(signers, signer)
		receipts = append(receipts, PinReceipt{Version: 1, Phase: "plan-pinned", NodeID: d.NodeID, Role: "destination", PinSHA256: Digest([]byte(d.NodeID)), BootstrapGrantSHA256: d.BootstrapGrantSHA256, ManifestSHA256: d.PreparedManifestSHA256, AdmittedAt: p.IssuedAt, PublishedAt: p.IssuedAt.Add(time.Minute)})
	}
	raw, err := SignPlan(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyPlan(public, raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range receipts {
		receipts[i].PlanSHA256 = v.Digest()
	}
	return v, receipts, signers
}

func FuzzVerifyPinReceipt(f *testing.F) {
	v, receipts, signers := pinReceiptFixture(f, false)
	p, err := v.Plan()
	if err != nil {
		f.Fatal(err)
	}
	owner, public := testKey(f)
	planRaw, err := SignPlan(owner, p)
	if err != nil {
		f.Fatal(err)
	}
	v, err = VerifyPlan(public, planRaw)
	if err != nil {
		f.Fatal(err)
	}
	receipt := receipts[0]
	receipt.PlanSHA256 = v.Digest()
	raw, err := SignPinReceipt(signers[0], v, receipt)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(public, planRaw, raw)
	f.Add(public, planRaw, []byte(`{}`))
	f.Fuzz(func(t *testing.T, public, planRaw, raw []byte) {
		v, err := VerifyPlan(public, planRaw)
		if err != nil {
			return
		}
		r, err := VerifyPinReceipt(v, raw)
		if err == nil && (r.PlanSHA256 != v.Digest() || r.Phase != "plan-pinned" || len(raw) > PinReceiptMaximumBytes) {
			t.Fatal("invalid acknowledgement verified")
		}
	})
}

func TestPinReceiptAgreementRequiresEveryDistinctHost(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(map[bool]string{false: "cohosted", true: "separate-gru"}[separate], func(t *testing.T) {
			v, receipts, signers := pinReceiptFixture(t, separate)
			var signed [][]byte
			for i, r := range receipts {
				raw, err := SignPinReceipt(signers[i], v, r)
				if err != nil {
					t.Fatal(err)
				}
				observed, err := VerifyPinReceipt(v, raw)
				if err != nil || observed != r {
					t.Fatal("pin attribution changed", err)
				}
				signed = append(signed, raw)
			}
			now := receipts[0].PublishedAt
			pins, err := VerifyPlanPins(v, signed, now)
			if err != nil {
				t.Fatal(err)
			}
			digests, err := pins.ReceiptDigests(now)
			if err != nil || len(digests) != len(receipts) {
				t.Fatal(err)
			}
			for i, digest := range digests {
				if digest != Digest(signed[i]) {
					t.Fatal("signed receipt digest changed")
				}
			}
			digests[0] = "changed"
			again, err := pins.ReceiptDigests(now)
			if err != nil || again[0] != Digest(signed[0]) {
				t.Fatal("caller changed verified receipt inventory")
			}
			p, err := v.Plan()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pins.ReceiptDigests(p.ExpiresAt); err == nil {
				t.Fatal("expired agreement used")
			}
			if _, err := (VerifiedPlanPins{}).ReceiptDigests(now); err == nil {
				t.Fatal("zero agreement used")
			}
			if _, err := VerifyPlanPins(v, signed, now.Add(-time.Second)); err == nil {
				t.Fatal("future acknowledgement used")
			}
			for _, bad := range [][][]byte{signed[:len(signed)-1], append(signed, signed[0]), {signed[0], signed[0], signed[0]}} {
				if _, err := VerifyPlanPins(v, bad, now); err == nil {
					t.Fatal("incomplete or duplicate host agreement accepted")
				}
			}
			signed[0], signed[1] = signed[1], signed[0]
			if _, err := VerifyPlanPins(v, signed, now); err == nil {
				t.Fatal("reordered host agreement accepted")
			}
		})
	}
}

func TestPinReceiptScopeAndSignatureDomain(t *testing.T) {
	v, receipts, signers := pinReceiptFixture(t, false)
	for name, mutate := range map[string]func(*PinReceipt){
		"phase":                  func(r *PinReceipt) { r.Phase = "source-retired" },
		"plan":                   func(r *PinReceipt) { r.PlanSHA256 = strings.Repeat("f", 64) },
		"host":                   func(r *PinReceipt) { r.NodeID = "gru-foreign" },
		"role":                   func(r *PinReceipt) { r.Role = "destination" },
		"manifest":               func(r *PinReceipt) { r.ManifestSHA256 = strings.Repeat("f", 64) },
		"grant":                  func(r *PinReceipt) { r.BootstrapGrantSHA256 = strings.Repeat("f", 64) },
		"pin":                    func(r *PinReceipt) { r.PinSHA256 = "" },
		"command":                func(r *PinReceipt) { r.CommandSHA256 = "" },
		"authority":              func(r *PinReceipt) { r.AuthorityID = "global" },
		"epoch":                  func(r *PinReceipt) { r.Epoch = 0 },
		"lease":                  func(r *PinReceipt) { r.LeaseID = "" },
		"unbounded authority":    func(r *PinReceipt) { r.CandidateID = strings.Repeat("a", 129) },
		"publication before pin": func(r *PinReceipt) { r.PublishedAt = r.AdmittedAt.Add(-time.Nanosecond) },
		"expired publication":    func(r *PinReceipt) { p, _ := v.Plan(); r.PublishedAt = p.ExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			r := receipts[0]
			mutate(&r)
			if _, err := SignPinReceipt(signers[0], v, r); err == nil {
				t.Fatal("invalid claim signed")
			}
		})
	}
	destination := receipts[1]
	destination.Epoch = 1
	if _, err := SignPinReceipt(signers[1], v, destination); err == nil {
		t.Fatal("destination acknowledgement minted authority")
	}
	if _, err := SignPinReceipt(signers[1], v, receipts[0]); err == nil {
		t.Fatal("foreign host signer used")
	}
	raw, err := SignPinReceipt(signers[0], v, receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Repeat([]byte("x"), PinReceiptMaximumBytes+1)} {
		if _, err := VerifyPinReceipt(v, bad); err == nil {
			t.Fatal("noncanonical receipt accepted")
		}
	}
	payload, err := json.Marshal(receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"", signatureDomain, "TS-CANDIDATE-PRELIMINARY-VERIFICATION-V1\x00"} {
		sig, err := signers[0].SignCanonicalMaterial(append([]byte(domain), payload...))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(signedPlan{Payload: payload, Signature: sig.Bytes()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPinReceipt(v, wire); err == nil {
			t.Fatal("foreign signature domain accepted")
		}
	}
}
