package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type sequenceLineage struct{}

func (sequenceLineage) CheckLineage(string, string, string) error { return nil }

type sequenceFixture struct {
	now          time.Time
	root, leaf   ed25519.PrivateKey
	roots        trust.Keyring
	delegation   trust.Envelope
	migration    trust.Envelope
	migrationSHA string
	directory    string
}

func newSequenceFixture(t *testing.T) sequenceFixture {
	t.Helper()
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: "production", Architectures: []string{"amd64"},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: strings.Repeat("a", 40),
	}, now.Add(-time.Minute), now.Add(7*24*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "orchestrator", Environment: "production", SequenceFloor: 1000, SignerKeyID: keyID, SignerPublicKey: encoded}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 1000, IssuedAt: now, EvidenceSHA256: strings.Repeat("b", 64)})
	}
	signed, err := release.SignSequenceMigration(migration, now, root)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := trust.Fingerprint(signed)
	if err != nil {
		t.Fatal(err)
	}
	return sequenceFixture{now: now, root: root, leaf: leaf, roots: roots, delegation: delegation, migration: signed, migrationSHA: fingerprint, directory: t.TempDir()}
}

func (f sequenceFixture) update(t *testing.T, sequence uint64, run int64, digest string, qualified bool) Release {
	t.Helper()
	revision := strings.Repeat("c", 40)
	qual := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: revision, SourceTree: revision, GoVersion: release.DefaultGoVersion,
		GoModSHA256: digest, GoSumSHA256: digest,
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob, RunID: run + 4000, RunNumber: run, Conclusion: "success"},
		Artifacts:    []release.QualifiedArtifact{{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: 13, SHA256: digest}},
	}
	payload, err := trust.EncodePayload(qual)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	qualSHA := hex.EncodeToString(sum[:])
	binary := release.BinaryReceipt{Schema: release.BinarySchema, SourceRevision: revision, GoVersion: release.DefaultGoVersion, GOOS: "linux", GOARCH: "amd64", ELFMachine: "Advanced Micro Devices X86-64", Static: true, Bytes: 13, SHA256: digest, QualificationSHA256: qualSHA}
	envelope, err := release.SignBinaryUpdateReceiptSequenced(binary, qual, qualSHA, "GRU", "production", sequenceLineage{}, f.delegation, f.roots, f.leaf, f.now, 24*time.Hour, sequence, f.migrationSHA)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.EncodeEnvelope(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	if qualified {
		candidate := release.ProductionExpectation{SourceRevision: revision, ArtifactSHA256: digest, QualificationSHA256: qualSHA, Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: "amd64", Role: "orchestrator"}
		record := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
		for _, gate := range []string{"runtime-ha", "workload-safety"} {
			data := []byte(gate + digest)
			sum := sha256.Sum256(data)
			evidenceSHA := hex.EncodeToString(sum[:])
			path := filepath.Join(f.directory, evidenceSHA)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			retained, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(retained) != sum {
				t.Fatal("evidence changed on disk")
			}
			record.Evidence = append(record.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: evidenceSHA, Bytes: int64(len(retained)), CompletedAt: f.now.Add(-time.Minute)})
		}
		payload, err := trust.EncodePayload(record)
		if err != nil {
			t.Fatal(err)
		}
		qualification, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), f.now, f.now.Add(24*time.Hour), f.root)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := trust.EncodeEnvelope(qualification)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err = release.AttachProductionQualification(envelope, release.ProductionProof{Qualification: proof}, delegation, f.roots, f.leaf, release.UpdateExpectation{Cell: "GRU", Environment: "production", Architecture: "amd64"}, f.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := trust.EncodeEnvelope(f.migration)
	if err != nil {
		t.Fatal(err)
	}
	return Release{Digest: digest, SourceRevision: revision, RunNumber: run, Receipt: wire, Delegation: delegation, ReleaseSequence: sequence, SequenceMigration: migration, SequenceMigrationSHA256: f.migrationSHA, Actor: "ci", CreatedAt: f.now}
}

// Real file-backed JetStream is stopped and reopened on the same directory.
func sequenceRestartStore(t *testing.T) func() *Store {
	t.Helper()
	directory := t.TempDir()
	var srv *server.Server
	var conn *nats.Conn
	stop := func() {
		if conn != nil {
			conn.Close()
		}
		if srv != nil {
			srv.Shutdown()
			srv.WaitForShutdown()
		}
	}
	t.Cleanup(stop)
	return func() *Store {
		stop()
		var err error
		srv, err = server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: directory})
		if err != nil {
			t.Fatal(err)
		}
		go srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS did not start")
		}
		conn, err = nats.Connect(srv.ClientURL())
		if err != nil {
			t.Fatal(err)
		}
		js, err := jetstream.New(conn)
		if err != nil {
			t.Fatal(err)
		}
		fence := &epochFence{}
		fence.epoch.Store(7)
		store, err := OpenStore(t.Context(), js, "gru", 1, fence)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
}

func TestSequencePublicationDurableBoundary(t *testing.T) {
	fixture := newSequenceFixture(t)
	restart := sequenceRestartStore(t)
	store := restart()
	ctx := t.Context()
	legacy, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, RunNumber: 1000, Actor: "ci", CreatedAt: fixture.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: otherBad, RunNumber: 999, Actor: "ci", CreatedAt: fixture.now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy floor bypass: %v", err)
	}
	first := fixture.update(t, 1001, 1, toDigest, true)
	admitted, err := store.PublishSequencedRelease(ctx, 7, first, fixture.roots, "GRU", "production")
	if err != nil || admitted.RunNumber != 1 {
		t.Fatalf("new signer with preserved CI provenance: %+v %v", admitted, err)
	}
	// Identical bytes still consume their newer signer order atomically.
	second := fixture.update(t, 1002, 2, toDigest, true)
	if _, err := store.PublishSequencedRelease(ctx, 7, second, fixture.roots, "GRU", "production"); !errors.Is(err, ErrReleaseUnchanged) {
		t.Fatalf("same-byte higher sequence: %v", err)
	}
	desired, revision, err := store.Desired(ctx)
	if err != nil || desired.OrderingFloor.ReleaseSequence != 1002 || desired.LegacyFloor.RunNumber != 1000 || desired.Generation() != admitted.Generation {
		t.Fatalf("durable floors: %+v %v", desired, err)
	}
	for name, candidate := range map[string]Release{
		"stale":        first,
		"equivocation": fixture.update(t, 1002, 2, otherBad, true),
	} {
		if _, err := store.PublishSequencedRelease(ctx, 7, candidate, fixture.roots, "GRU", "production"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := store.PublishRelease(ctx, 7, first); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unverified direct API: %v", err)
	}
	if _, err := store.PublishRelease(ctx, 7, legacy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy after migration: %v", err)
	}
	// The complete CAS state must remain unchanged after refusals.
	if _, after, err := store.Desired(ctx); err != nil || after != revision {
		t.Fatalf("rejected publication changed desired: %d -> %d, %v", revision, after, err)
	}
	if _, err := store.RollbackRelease(ctx, 7, legacy.Generation, "ops", fixture.now); err != nil {
		t.Fatal(err)
	}
	store = restart()
	if _, err := store.PublishSequencedRelease(ctx, 7, second, fixture.roots, "GRU", "production"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay reactivated rollback after restart: %v", err)
	}
	// Cross the bounded rollback window; the first legacy receipt must disappear.
	for i := range ReleaseHistory + 1 {
		next := fixture.update(t, uint64(1003+i), int64(3+i), fmt.Sprintf("%064x", i+100), true)
		if _, err := store.PublishSequencedRelease(ctx, 7, next, fixture.roots, "GRU", "production"); err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}
	}
	if _, err := store.ReleaseGeneration(ctx, legacy.Generation); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("history did not purge: %v", err)
	}
	store = restart()
	desired, _, err = store.Desired(ctx)
	if err != nil || desired.OrderingFloor.ReleaseSequence != uint64(1003+ReleaseHistory) || desired.LegacyFloor.RunNumber != 1000 {
		t.Fatalf("floors lost after purge/restart: %+v %v", desired, err)
	}
	if _, err := store.PublishSequencedRelease(ctx, 7, first, fixture.roots, "GRU", "production"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("purge reset sequence: %v", err)
	}
}

func TestSequencePublicationRejectsInvalidProofBeforeWrites(t *testing.T) {
	fixture := newSequenceFixture(t)
	store, _ := testStore(t)
	ctx := t.Context()
	valid := fixture.update(t, 1001, 1, toDigest, true)
	tampered := valid
	tampered.ReleaseSequence++
	forgedRollback := valid
	forgedRollback.RollbackOf = 1
	wrongSigner := newSequenceFixture(t)
	wrongMigration := valid
	wrongMigration.SequenceMigration, _ = trust.EncodeEnvelope(wrongSigner.migration)
	wrongMigration.SequenceMigrationSHA256 = wrongSigner.migrationSHA
	for name, candidate := range map[string]Release{
		"tampered sequence":      tampered,
		"forged rollback":        forgedRollback,
		"wrong migration signer": wrongMigration,
		"no independent proof":   fixture.update(t, 1001, 1, toDigest, false),
	} {
		if _, err := store.PublishSequencedRelease(ctx, 7, candidate, fixture.roots, "GRU", "production"); err == nil {
			t.Fatalf("%s admitted", name)
		}
		if desired, revision, err := store.Desired(ctx); err != nil || revision != 0 || desired.Generation() != 0 {
			t.Fatalf("%s changed durable state: %+v %d %v", name, desired, revision, err)
		}
	}
	if _, err := store.PublishSequencedRelease(ctx, 7, valid, fixture.roots, "GRU", "production"); err != nil {
		t.Fatal(err)
	}
	// Another valid root authorization cannot replace the initial namespace.
	var migration release.SequenceMigration
	if err := protocol.DecodeStrict(fixture.migration.Payload, &migration, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	migration.Namespace = "replacement"
	replacement := fixture
	var err error
	replacement.migration, err = release.SignSequenceMigration(migration, fixture.now, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	replacement.migrationSHA, err = trust.Fingerprint(replacement.migration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishSequencedRelease(ctx, 7, replacement.update(t, 1002, 2, otherBad, true), fixture.roots, "GRU", "production"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unlinked migration replaced ordering namespace: %v", err)
	}
}
