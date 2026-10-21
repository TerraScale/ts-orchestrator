package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSequenceMigrationOfflineSigningFilesystem(t *testing.T) {
	directory := t.TempDir()
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := trust.KeyID(signer)
	encoded, _ := trust.EncodeDelegatedPublicKey(signer)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "orchestrator", Environment: "production", SequenceFloor: 900, SignerKeyID: id, SignerPublicKey: encoded}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 900, EvidenceSHA256: strings.Repeat("a", 64)})
	}
	candidate := filepath.Join(directory, "migration.json")
	wire, err := trust.EncodePayload(migration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, wire, 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "root.key")
	writePrivateKey(t, keyPath, root)
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
	roots, _ := trust.ParseKeyring(public)
	signed, err := release.VerifySequenceMigrationCurrent(envelope, roots, "orchestrator", "production", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !signed.AdmitsLegacyFloor("GRU", 900, time.Time{}) || signed.AdmitsLegacyFloor("GRU", 901, time.Time{}) {
		t.Fatal("signed migration lost regional floor")
	}
	if err := c.signSequenceMigration(args); err == nil {
		t.Fatal("offline signing overwrote existing authorization")
	}
}
