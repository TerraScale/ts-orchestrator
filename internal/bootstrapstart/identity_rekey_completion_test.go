package bootstrapstart

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func completionMarkerFixture(t *testing.T, journal IdentityRekeyJournal) MarkerStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := MarkerStore{directory: dir, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true}
	wire, err := protocol.EncodeJSON(journal)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{markerName: journal.AcceptedWire, identityRekeyJournalName: wire} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func completionJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE"} {
		if _, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = js.CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName, Subjects: []string{protocol.ControlStreamSubject()},
		Retention: jetstream.LimitsPolicy, MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		Storage: jetstream.FileStorage, Replicas: 1, DenyDelete: true, DenyPurge: true, Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func TestCompletionProbeRequiresImmutableOutcomeUnderRootedLocalIdentity(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	journal.Replicas = 1
	store := completionMarkerFixture(t, journal)
	js := completionJetStream(t)
	for i := range 10 {
		subject, wire := protocol.ControlRoot+".gru.host.audit", []byte("retained audit")
		if i == 8 {
			subject, wire = protocol.ControlRoot+".gru.lease", []byte("obsolete identity bytes are opaque")
		}
		if _, err := js.Publish(t.Context(), subject, wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); !errors.Is(err, ErrIdentityRekeyPending) {
		t.Fatalf("missing completion = %v", err)
	}
	verified, err := store.verifiedIdentityRekey(accepted, inputs)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); !errors.Is(err, ErrIdentityRekeyPending) {
		t.Fatalf("hold is not completion: %v", err)
	}
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE"} {
		if _, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1, History: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authority.ReplaceIdentityRecords(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), verified.Values(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); !errors.Is(err, ErrIdentityRekeyPending) {
		t.Fatalf("replacement is not completion: %v", err)
	}
	if _, err := authority.CompleteIdentityReset(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); err != nil {
		t.Fatalf("committed completion: %v", err)
	}
	// Completion remains evidence after current replay authorization expires.
	if _, err := verified.VerifyCurrent(inputs, accepted.AcceptedAt.Add(2*time.Hour)); err == nil {
		t.Fatal("expired journal authorized effects")
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, js); err != nil {
		t.Fatal(err)
	}
	changed := accepted.Clone()
	changed.ConfigSHA256["controller.json"] = digest([]byte("different root record"))
	if err := store.verifyIdentityRekeyCompletion(t.Context(), changed, inputs, js); !errors.Is(err, ErrIdentityRekeyLocalPending) {
		t.Fatalf("obsolete supplied record: %v", err)
	}
	if wire, err := os.ReadFile(filepath.Join(store.directory, markerName)); err != nil || !bytes.Equal(wire, journal.AcceptedWire) {
		t.Fatal("probe changed accepted identity")
	}
}

func TestCompletionProbeRejectsDamagedJournalBeforeNATS(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	store := completionMarkerFixture(t, journal)
	if err := os.WriteFile(filepath.Join(store.directory, identityRekeyJournalName), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, nil); err == nil {
		t.Fatal("damaged journal bypassed completion")
	}
}

func TestAcceptedRekeyRejectsMissingJournalBeforeAdmissionAndCompletion(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	store := completionMarkerFixture(t, journal)
	if err := os.Remove(filepath.Join(store.directory, identityRekeyJournalName)); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, inputs, nil); !errors.Is(err, ErrIdentityRekeyJournal) || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing required journal reported completion or ordinary installation: %v", err)
	}
	gate := Gate{Markers: store}
	if err := gate.checkRestartJournal(accepted, inputs); !errors.Is(err, ErrIdentityRekeyJournal) {
		t.Fatalf("accepted restart bypassed required evidence: %v", err)
	}
	if _, err := store.readAcceptedIdentityRekeyJournal(accepted); !errors.Is(err, ErrIdentityRekeyJournal) {
		t.Fatalf("prestart read bypassed required evidence: %v", err)
	}
	if wire, err := os.ReadFile(filepath.Join(store.directory, markerName)); err != nil || !bytes.Equal(wire, journal.AcceptedWire) {
		t.Fatal("missing-journal refusal changed the installed acceptance")
	}
}

func TestInitialAcceptanceNeedsNoRekeyJournalOrCompletion(t *testing.T) {
	accepted := acceptedIdentityFixture(t)
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		t.Fatal(err)
	}
	store := completionMarkerFixture(t, IdentityRekeyJournal{AcceptedWire: wire})
	if err := os.Remove(filepath.Join(store.directory, identityRekeyJournalName)); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyIdentityRekeyCompletion(t.Context(), accepted, TrustInputs{}, nil); err != nil {
		t.Fatalf("initial acceptance required rekey completion: %v", err)
	}
	if err := (Gate{Markers: store}).checkRestartJournal(accepted, TrustInputs{}); err != nil {
		t.Fatalf("initial acceptance required a rekey journal: %v", err)
	}
}
