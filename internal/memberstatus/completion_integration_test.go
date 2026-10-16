package memberstatus

import (
	"errors"
	"os"
	"testing"
)

func TestRetainedCompleteDrainAfterProcessStopIntegration(t *testing.T) {
	f := startMemberFixture(t)
	const operation = "0H248H248H248H248H248H248H"
	envelope, err := f.client.Drain(t.Context(), fixtureSurvivor(), operation, f.store)
	if err != nil || envelope.Receipt == nil {
		t.Fatalf("actual Unix drain: %+v %v", envelope, err)
	}
	unverified := envelope
	unverified.verified = false
	if err := f.store.RetainComplete(unverified); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unverified envelope retained: %v", err)
	}
	if err := f.store.RetainComplete(envelope); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RetainComplete(envelope); err != nil {
		t.Fatalf("idempotent retained receipt: %v", err)
	}
	if err := f.process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	f.process.Wait()
	reopened, err := NewFileStore(f.store.path)
	if err != nil {
		t.Fatal(err)
	}
	retained, found, err := reopened.ReadComplete()
	if err != nil || !found || !retained.verified || retained.ReceiptSHA256 == nil || *retained.ReceiptSHA256 != *envelope.ReceiptSHA256 {
		t.Fatalf("receipt after independent process stop: %+v %v %v", retained, found, err)
	}
	if err := os.Chmod(f.store.path+".complete", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.ReadComplete(); err == nil {
		t.Fatal("unsafe receipt permissions accepted")
	}
	if err := os.Chmod(f.store.path+".complete", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.store.path+".complete", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.ReadComplete(); err == nil {
		t.Fatal("changed receipt accepted")
	}
}
