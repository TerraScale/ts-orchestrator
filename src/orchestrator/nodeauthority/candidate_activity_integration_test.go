package nodeauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run only in an explicitly isolated root mount namespace. The public APIs
// retain their production fixed paths and ownership checks throughout.
func TestPublishedCandidateActivityExcludesOrdinaryAdmission(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TS_CANDIDATE_ACTIVITY_TEST_NAMESPACE") != "1" {
		t.Skip("requires root in a private mount namespace")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if self == host {
		t.Fatal("refusing to mount over the host namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", "/var/lib", "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount("/var/lib", 0); err != nil {
			t.Error(err)
		}
	})

	fixture := newCandidateTransferFixture(t)
	publication, err := readCandidateRecord(filepath.Join(fixture.directory, "preparation.json"), 0644, 0)
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "receiver")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewEpochStore(private, fixture.config.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.AdmitBootstrap(fixture.receipt.BootstrapGrantSHA256, fixture.receipt.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.AdmitCandidatePreparation(context.Background(), publication.PublicKey, publication.SignedGrant, fixture.config, fixture.receipt.BootstrapGrantSHA256, fixture.receipt.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	raw := fixture.request(t, nil, nil, nil)
	if _, observed, err := VerifyPublishedCandidateRequest(context.Background(), fixture.config, raw); err != nil || observed != receipt {
		t.Fatalf("fixed-path transfer admission: %v", err)
	}

	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- WithinPublishedCandidateMutation(operation, fixture.config, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release // Cancellation must not unlock while the worker is still joining.
			return ctx.Err()
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
	})
	select {
	case <-entered:
	case err := <-finished:
		t.Fatalf("candidate callback failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("candidate callback did not start")
	}
	command := CommandAuthorization{NodeID: fixture.config.NodeID, AuthorityID: "sfo-regional", Epoch: 1, CandidateID: "sfo-controller-one", LeaseID: "lease-one"}
	assertBlocked := func() {
		t.Helper()
		if err := store.Admit(command); err == nil {
			t.Fatal("ordinary authority overlapped live candidate effect")
		}
		floor, err := store.load()
		if err != nil || floor.Epoch != 0 {
			t.Fatalf("failed admission changed epoch: %+v %v", floor, err)
		}
		if observed, err := ValidatePublishedPreparation(context.Background(), fixture.config); err != nil || observed != receipt {
			t.Fatalf("failed admission changed publication: %v", err)
		}
	}
	assertBlocked()
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not observe cancellation")
	}
	assertBlocked()
	close(release)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("joined callback: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not join")
	}
	if err := store.Admit(command); err != nil {
		t.Fatalf("joined candidate effect prevented ordinary authority: %v", err)
	}
	floor, err := store.load()
	if err != nil || floor.Epoch != command.Epoch {
		t.Fatalf("ordinary floor missing: %+v %v", floor, err)
	}
	if _, err := ValidatePublishedPreparation(context.Background(), fixture.config); err == nil {
		t.Fatal("retired publication remained admitted")
	}
	if _, _, err := VerifyPublishedCandidateRequest(context.Background(), fixture.config, raw); err == nil {
		t.Fatal("retired publication authorized transfer")
	}
	called := false
	if err := WithinPublishedCandidateMutation(context.Background(), fixture.config, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("retired candidate callback ran")
	}
	if _, err := store.AdmitCandidatePreparation(context.Background(), publication.PublicKey, publication.SignedGrant, fixture.config, fixture.receipt.BootstrapGrantSHA256, fixture.receipt.ManifestSHA256); err == nil {
		t.Fatal("ordinary epoch reopened candidate preparation")
	}
}
