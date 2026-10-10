package bootstrapstart

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

func TestCompletedRekeyStagesSuccessorWithoutLosingAcceptanceEvidence(t *testing.T) {
	first, inputs, accepted, key := identityRekeyJournalFixtureWithKey(t)
	first.Replicas = 1
	markers, baked, _, _, _ := rootInstallerFixture(t)
	// Both operations must be authorized by the same independently loaded roots.
	for _, public := range inputs.Genesis {
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(baked.directory, "trust-roots", "001.pem")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	store := completionMarkerFixture(t, first)
	markers.directory = store.directory
	js := completionJetStream(t)
	for i := range 10 {
		wire, subject := []byte("audit"), protocol.ControlRoot+".gru.host.audit"
		if i == 8 {
			wire, subject = []byte("obsolete identity bytes are opaque"), protocol.ControlRoot+".gru.lease"
		}
		if _, err := js.Publish(t.Context(), subject, wire); err != nil {
			t.Fatal(err)
		}
	}
	identity := accepted.Clone()
	identity.OperationID = entityid.Derive("test-rekey", "successor")
	checkpoint, _, _ := acceptedCheckpoint(t, identity, first.AcceptedWire)
	next, nextInputs, target := identityRekeyJournalForCheckpoint(t, identity, first.AcceptedWire, checkpoint, key, inputs.Genesis)
	next.Replicas = 1
	if err := markers.prepareIdentityRekeySuccessor(t.Context(), next, js, target.AcceptedAt, baked); !errors.Is(err, ErrIdentityRekeyPending) {
		t.Fatalf("uncompleted operation archived: %v", err)
	}
	verified, err := markers.verifiedIdentityRekey(accepted, inputs)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := verified.ResetEnvelope()
	if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE"} {
		if _, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authority.ReplaceIdentityRecords(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), verified.Values(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.CompleteIdentityReset(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := markers.prepareIdentityRekeySuccessor(t.Context(), next, js, target.AcceptedAt, baked); err != nil {
			t.Fatal(err)
		}
		// Crash before staging: restart still has the exact old accepted evidence.
		if err := markers.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); err != nil {
			t.Fatalf("archive interrupted accepted restart/completion: %v", err)
		}
	}
	if archive, err := os.ReadFile(filepath.Join(markers.directory, identityRekeyAcceptedJournalName(first.AcceptedWire))); err != nil || !bytes.Equal(archive, verified.Wire()) {
		t.Fatal("completed journal evidence was not retained exactly")
	}
	if err := markers.WriteIdentityRekeyJournal(next, nextInputs, acceptedObservation, target.AcceptedAt); err != nil {
		t.Fatalf("successor cannot stage: %v", err)
	}
	activePath := filepath.Join(markers.directory, identityRekeyJournalName)
	before, err := os.Stat(activePath)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := markers.prepareIdentityRekeySuccessor(t.Context(), next, js, target.AcceptedAt, baked); err != nil {
			t.Fatalf("exact staged-successor retry failed: %v", err)
		}
		if err := markers.WriteIdentityRekeyJournal(next, nextInputs, acceptedObservation, target.AcceptedAt); err != nil {
			t.Fatalf("exact journal retry failed: %v", err)
		}
	}
	if after, err := os.Stat(activePath); err != nil || !os.SameFile(before, after) {
		t.Fatal("retry replaced the active journal")
	}
	if archive, err := os.ReadFile(filepath.Join(markers.directory, identityRekeyAcceptedJournalName(first.AcceptedWire))); err != nil || !bytes.Equal(archive, verified.Wire()) {
		t.Fatal("retry changed archived predecessor evidence")
	}
	altered := next
	altered.Replicas = 3
	if err := markers.prepareIdentityRekeySuccessor(t.Context(), altered, js, target.AcceptedAt, baked); err == nil {
		t.Fatal("different successor journal was accepted as an exact retry")
	}
	if err := markers.prepareIdentityRekeySuccessor(t.Context(), next, js, target.AcceptedAt.AddDate(2, 0, 0), baked); err == nil {
		t.Fatal("expired successor was accepted as an exact retry")
	}
	if _, err := markers.verifiedIdentityRekey(accepted, inputs); !errors.Is(err, ErrIdentityRekeyLocalPending) {
		t.Fatalf("staged successor did not fence old local restart: %v", err)
	}
	current, _, err := verifyIdentityRekeyInstall(markers, baked, next, target.AcceptedAt, true)
	if err != nil {
		t.Fatalf("staged successor cannot install: %v", err)
	}
	if err := markers.ReplaceIdentity(current.Checkpoint(), target.Slot, target.AcceptedAt, acceptedObservation); err != nil {
		t.Fatal(err)
	}
	if _, err := markers.verifiedIdentityRekey(target, nextInputs); err != nil {
		t.Fatalf("successor acceptance lost its journal: %v", err)
	}
	if err := os.Remove(filepath.Join(markers.directory, identityRekeyJournalName)); err != nil {
		t.Fatal(err)
	}
	if _, err := markers.verifiedIdentityRekey(target, nextInputs); !errors.Is(err, ErrIdentityRekeyJournal) {
		t.Fatalf("old archive substituted for missing successor evidence: %v", err)
	}
}
