package initialcontrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

func TestPublicationRefusesGuardBeforeReadingCredentials(t *testing.T) {
	refused := errors.New("global term lost")
	_, err := publishPreliminaryAdmitted(t.Context(), initialgrant.Config{}, preliminarytransfer.VerifiedUpload{}, profiles{}, func(context.Context) error { return refused })
	if !errors.Is(err, refused) {
		t.Fatalf("guard refusal: %v", err)
	}
}

func TestPublicationPinsSignerBeforeOpeningConnections(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "membership.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreignDER, err := x509.MarshalPKIXPublicKey(&foreign.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := initialgrant.Config{Membership: initialgrant.Membership{SigningKeyFile: path}}
	// Connection configuration is intentionally absent: signer rejection must
	// precede even accessing credentials for NATS or OCI.
	upload := preliminarytransfer.VerifiedUpload{Scope: preliminarytransfer.VerifiedScope{Scope: preliminarytransfer.Scope{SourcePublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: foreignDER}))}}}
	_, err = publishPreliminaryAdmitted(t.Context(), cfg, upload, profiles{}, func(context.Context) error { return nil })
	if err == nil || err.Error() != "initial control: publication signer differs from admitted capture source" {
		t.Fatalf("foreign signer: %v", err)
	}
}

func TestPublicationWorkerBoundsAttemptsAndRequiresRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	w := &preliminaryPublicationWorker{done: make(chan struct{}), status: PreliminaryPublicationStatus{State: "idle"}}
	var calls, reads atomic.Int32
	var ready, missing atomic.Bool
	var request atomic.Value
	request.Store("first authorization")
	go w.run(ctx, time.Millisecond, func() ([]byte, error) {
		reads.Add(1)
		if missing.Load() {
			return nil, os.ErrNotExist
		}
		return []byte(request.Load().(string)), nil
	}, func([]byte) error {
		if !ready.Load() {
			return errors.New("global term not ready")
		}
		return nil
	}, func([]byte) error { calls.Add(1); return errors.New("provider unavailable") })
	defer func() { cancel(); <-w.done }()
	wait := func(condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for !condition() {
			if time.Now().After(deadline) {
				t.Fatal("worker did not advance")
			}
			time.Sleep(time.Millisecond)
		}
	}
	wait(func() bool { return reads.Load() >= 5 })
	if calls.Load() != 0 {
		t.Fatal("attempt made before authority")
	}
	ready.Store(true)
	wait(func() bool { return calls.Load() == 3 })
	floor := reads.Load()
	wait(func() bool { return reads.Load() >= floor+5 })
	if calls.Load() != 3 {
		t.Fatal("unbounded provider retries")
	}
	missing.Store(true)
	floor = reads.Load()
	wait(func() bool { return reads.Load() >= floor+5 })
	missing.Store(false)
	floor = reads.Load()
	wait(func() bool { return reads.Load() >= floor+5 })
	if calls.Load() != 3 {
		t.Fatal("removing same request reset retry budget")
	}
	request.Store("renewed authorization")
	wait(func() bool { return calls.Load() == 6 })
	floor = reads.Load()
	wait(func() bool { return reads.Load() >= floor+5 })
	if calls.Load() != 6 {
		t.Fatal("renewal budget not bounded")
	}
}

func TestPublicationRequestRemovalAndReplacement(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TS_INITIALCONTROL_TEST_NAMESPACE") != "1" {
		t.Skip("requires isolated root namespace")
	}
	dir, err := os.MkdirTemp("/var/lib", "ts-publication-ingress-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "request.json")
	raw := []byte("original signed request")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publicationRequestUnchanged(t.Context(), path, raw); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, []byte("renewed signed request"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := publicationRequestUnchanged(t.Context(), path, raw); err == nil {
		t.Fatal("active attempt accepted replaced request")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := publicationRequestUnchanged(t.Context(), path, raw); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removal: %v", err)
	}
	if err := os.WriteFile(replacement, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := publicationRequestUnchanged(t.Context(), path, raw); err == nil {
		t.Fatal("linked replacement accepted")
	}
}
