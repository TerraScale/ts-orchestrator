package app

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func testProductionProof(t *testing.T, candidate release.ProductionExpectation, root ed25519.PrivateKey, issuedAt, expiresAt time.Time) *release.ProductionProof {
	t.Helper()
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " evidence")
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{
			Gate: gate, SHA256: digestOf(evidence), Bytes: int64(len(evidence)), CompletedAt: issuedAt.Add(-time.Second),
		})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), issuedAt, expiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return &release.ProductionProof{Qualification: wire}
}
