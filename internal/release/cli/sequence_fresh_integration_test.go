package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFreshRoleMigrationOfflineSigningFilesystem(t *testing.T) {
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := trust.KeyID(signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceFreshRoleSchema, Purpose: release.SequenceFreshRolePurpose,
		Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "function-worker", Environment: "production", SequenceFloor: 100,
		SignerKeyID: id, SignerPublicKey: encoded, FreshCells: []string{"GRU", "SFO", "FRA"}}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "root.key")
	writePrivateKey(t, keyPath, root)
	candidate := filepath.Join(directory, "candidate.json")
	wire, err := trust.EncodePayload(migration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, wire, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "signed.json")
	args := []string{"--candidate", candidate, "--signing-key", keyPath, "--out", output}
	c := command{ctx: t.Context(), output: io.Discard}
	if err := c.signSequenceMigration(args); err != nil {
		t.Fatal(err)
	}
	envelope, err := readEnvelope(output)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFreshRoleBaselineCurrent(envelope, roots, migration.Role, migration.Environment, "GRU", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.ValidFor(migration.Role, migration.Environment, "GRU", fingerprint, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := c.signSequenceMigration(args); err == nil {
		t.Fatal("offline signing replaced the original baseline")
	}
	for _, test := range []struct {
		name   string
		change func(*release.SequenceMigration)
	}{
		{"legacy_schema", func(m *release.SequenceMigration) { m.Schema = release.SequenceMigrationSchema }},
		{"missing_purpose", func(m *release.SequenceMigration) { m.Purpose = "" }},
		{"legacy_history", func(m *release.SequenceMigration) { m.Regions = []release.SequenceFloor{{Cell: "GRU", RunNumber: 100}} }},
		{"duplicate_cells", func(m *release.SequenceMigration) { m.FreshCells = []string{"GRU", "GRU", "FRA"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := migration
			test.change(&changed)
			wire, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			candidate := filepath.Join(directory, "candidate.json")
			if err := os.WriteFile(candidate, wire, 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(directory, "signed.json")
			if err := c.signSequenceMigration([]string{"--candidate", candidate, "--signing-key", keyPath, "--out", output}); err == nil {
				t.Fatal("invalid fresh-role candidate was signed")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("invalid candidate created output: %v", err)
			}
		})
	}
}
