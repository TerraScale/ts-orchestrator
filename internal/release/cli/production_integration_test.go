package cli

import (
	"crypto/ed25519"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"

	"os"
	"path/filepath"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func productionCandidate(binary binaryReceipt, cell string) release.ProductionExpectation {
	return release.ProductionExpectation{SourceRevision: binary.SourceRevision, ArtifactSHA256: binary.SHA256,
		QualificationSHA256: binary.QualificationSHA256, Cell: cell, Environment: "production",
		Runtime: release.ProductionRuntime, Architecture: binary.GOARCH, Role: "orchestrator"}
}

func writeProductionEvidence(t *testing.T, directory string, candidate release.ProductionExpectation) release.ProductionQualification {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(directory, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	record := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		data, err := json.Marshal(struct{ Gate, SourceRevision, ArtifactSHA256 string }{gate, candidate.SourceRevision, candidate.ArtifactSHA256})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		sum := hex.EncodeToString(digest[:])
		if err := os.WriteFile(filepath.Join(directory, "objects", sum), data, 0o600); err != nil {
			t.Fatal(err)
		}
		record.Evidence = append(record.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: sum,
			Bytes: int64(len(data)), CompletedAt: time.Now().UTC().Add(-3 * time.Hour)})
	}
	return record
}

func writeProductionRecord(t *testing.T, path string, record release.ProductionQualification, private ed25519.PrivateKey, issued, expires time.Time) {
	t.Helper()
	payload, err := trust.EncodePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), issued, expires, private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeQualificationDelegation(t *testing.T, path string, candidate release.ProductionExpectation, private, root ed25519.PrivateKey, domain string) {
	t.Helper()
	public := private.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	scope := release.ProductionQualificationScope(candidate)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}},
		time.Now().Add(-time.Hour), time.Now().Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := trust.EncodeEnvelope(delegation)
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
}
