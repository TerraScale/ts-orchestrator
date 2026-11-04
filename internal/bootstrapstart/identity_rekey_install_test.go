package bootstrapstart

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func rootInstallerFixture(t *testing.T) (MarkerStore, bakedStore, IdentityRekeyJournal, TrustInputs, AcceptedIdentity) {
	t.Helper()
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	markers := testMarkerStore(t)
	if err := os.WriteFile(filepath.Join(markers.directory, markerName), []byte("obsolete identity bytes are opaque"), 0o644); err != nil {
		t.Fatal(err)
	}
	baked, rootDirectory, _ := bakedFixture(t)
	for _, key := range inputs.Genesis {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		rootPath := filepath.Join(rootDirectory, "001.pem")
		if err := os.Remove(rootPath); err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	// Retired inputs cannot authorize the proposed target, even when damaged.
	for _, name := range []string{identityFilename, anchorFilename} {
		if err := os.Remove(filepath.Join(baked.directory, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("absent-retired-authority", filepath.Join(baked.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	return markers, baked, journal, inputs, accepted
}

func TestRootInstallerInterruptedOperationResumesOnlyExactJournal(t *testing.T) {
	markers, baked, journal, _, accepted := rootInstallerFixture(t)
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unstaged proposal admitted external precommit: %v", err)
	}
	verified, inputs, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := markers.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); err != nil {
			t.Fatalf("interrupted exact operation did not resume: %v", err)
		}
	}
	changed := journal
	changed.AcceptedWire = bytes.Clone(journal.AcceptedWire)
	other := accepted.Clone()
	other.AcceptedAt = other.AcceptedAt.Add(time.Second)
	changed.AcceptedWire, err = EncodeAcceptedIdentity(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, changed, other.AcceptedAt, true); !errors.Is(err, ErrIdentityRekeyJournal) {
		t.Fatalf("another valid projection replaced the immutable operation: %v", err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt.Add(2*time.Hour), true); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired operation resumed effects: %v", err)
	}
	if err := markers.ReplaceIdentity(verified.Checkpoint(), accepted.Slot, accepted.AcceptedAt, acceptedObservation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); err != nil {
		t.Fatalf("retry after local commit failed: %v", err)
	}
	if err := os.Remove(filepath.Join(markers.directory, identityRekeyJournalName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false); !errors.Is(err, ErrAcceptancePredecessor) {
		t.Fatalf("accepted bytes without their journal fabricated a retry: %v", err)
	}
}
