package cli

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func serviceMigrationFixture(t *testing.T, base *applyHTTPFixture, role string, public ed25519.PublicKey, now time.Time) []byte {
	t.Helper()
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU",
		SignerKeyID: keyID, SignerPublicKey: encoded, Role: role, Environment: "production", SequenceFloor: 1}
	for _, cell := range []string{"FRA", "GRU", "SJC"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 1, IssuedAt: now.Add(-time.Minute), EvidenceSHA256: base.binary.SHA256})
	}
	envelope, err := release.SignSequenceMigration(migration, now.Add(-time.Minute), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
