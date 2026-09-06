package nodeauthority

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

func TestStorageTransitionAcknowledgementRecoversBothRenames(t *testing.T) {
	f := newInitialR1Fixture(t)
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	p := storagePlanFixture(t)
	owner, public := storagePlanKey(t)
	host, key := storagePlanKey(t)
	p.Source.ReceiptPublicKeyPEM = string(key)
	signed, err := controltransition.SignPlan(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	digest := controltransition.Digest(signed)
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, host, f.uid, nil); !os.IsNotExist(err) {
		t.Fatal("acknowledged absent pin", err)
	}
	c := f.command(t)
	fault := errors.New("directory fsync interrupted")
	if _, err := f.store.admitStorageTransitionPlan(t.Context(), public, signed, &c, f.uid, func() error { return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	directory := filepath.Dir(f.store.path)
	path := filepath.Join(directory, storageTransitionReceiptName)
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, nil, f.uid, nil); !errors.Is(err, ErrStorageTransitionReceiptSignerRequired) {
		t.Fatal("missing signer not distinguished", err)
	}
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, owner, f.uid, nil); err == nil {
		t.Fatal("off-host owner used for acknowledgement")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("wrong signer wrote acknowledgement", err)
	}
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, host, f.uid, func() error { return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(directory, storageTransitionRecordName))
	if err != nil {
		t.Fatal(err)
	}
	v, err := controltransition.VerifyPlan(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controltransition.VerifyPinReceipt(v, before)
	if err != nil || receipt.PinSHA256 != controltransition.Digest(pin) || receipt.Epoch != c.Epoch || receipt.CommandSHA256 != controltransition.Digest(c.Command) {
		t.Fatal("acknowledgement lost durable provenance", err)
	}
	if err := f.guard.Check(t.Context()); err != nil {
		t.Fatal("acknowledgement retired R1", err)
	}
	f.store.Close()
	f.store, err = NewEpochStore(directory, f.identity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	replayed, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, nil, f.uid, nil)
	if err != nil || !bytes.Equal(before, replayed) {
		t.Fatal("restart rewrote signed acknowledgement", err)
	}
	// Recovery after retirement neither needs the original signing key nor
	// renews the old command or source launch.
	c = f.command(t)
	if err := f.retire(t.Context(), c, nil); err != nil {
		t.Fatal(err)
	}
	replayed, err = f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, nil, f.uid, nil)
	if err != nil || !bytes.Equal(before, replayed) {
		t.Fatal("retirement lost agreement evidence", err)
	}
	if err := f.guard.Check(t.Context()); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatal("receipt recovery reactivated R1", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.store.acknowledgeStorageTransitionPlan(ctx, digest, nil, f.uid, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), strings.Repeat("f", 64), nil, f.uid, nil); err == nil {
		t.Fatal("foreign plan acknowledged")
	}
	// A correctly signed receipt for another private pin must be retained as
	// a conflict, never silently replaced by a new signature.
	receipt.PinSHA256 = strings.Repeat("f", 64)
	conflict, err := controltransition.SignPinReceipt(host, v, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, conflict, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.acknowledgeStorageTransitionPlan(t.Context(), digest, host, f.uid, nil); err == nil {
		t.Fatal("conflicting pin evidence replaced")
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, conflict) {
		t.Fatal("conflicting evidence not retained", err)
	}
}

func TestStorageTransitionAcknowledgementRefusesUnsafeFilesAndRuntimeDestination(t *testing.T) {
	p := storagePlanFixture(t)
	owner, public := storagePlanKey(t)
	host, key := storagePlanKey(t)
	p.Destinations[1].ReceiptPublicKeyPEM = string(key)
	signed, err := controltransition.SignPlan(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewEpochStore(private, "sfo-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d := p.Destinations[1]
	if err := s.AdmitBootstrap(d.BootstrapGrantSHA256, d.PreparedManifestSHA256); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	v, err := s.admitStorageTransitionPlan(t.Context(), public, signed, nil, uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, cancel := context.WithCancel(t.Context())
	if _, err := s.acknowledgeStorageTransitionPlan(interrupted, v.Digest(), host, uid, func() error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("acknowledgement reported success after cancellation", err)
	}
	raw, err := s.acknowledgeStorageTransitionPlan(t.Context(), v.Digest(), nil, uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, storageTransitionReceiptName)
	for _, name := range []string{"corrupt", "writable", "symlink", "hardlink", "oversized"} {
		t.Run(name, func(t *testing.T) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			aux := filepath.Join(private, "receipt-target")
			if err := os.WriteFile(aux, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "symlink":
				err = os.Symlink(aux, path)
			case "hardlink":
				err = os.Link(aux, path)
			case "corrupt":
				err = os.WriteFile(path, []byte("{}"), 0600)
			case "writable":
				err = os.WriteFile(path, raw, 0600)
				if err == nil {
					err = os.Chmod(path, 0666)
				}
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), controltransition.PinReceiptMaximumBytes+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.acknowledgeStorageTransitionPlan(t.Context(), v.Digest(), host, uid, nil); err == nil {
				t.Fatal("unsafe acknowledgement accepted")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(aux); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := s.Admit(CommandAuthorization{NodeID: s.node, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.acknowledgeStorageTransitionPlan(t.Context(), v.Digest(), host, uid, nil); err == nil {
		t.Fatal("ordinary destination reopened preliminary acknowledgement")
	}
	if _, err := controltransition.VerifyPinReceipt(v, raw); err != nil {
		t.Fatal("historical evidence disappeared", err)
	}
}
