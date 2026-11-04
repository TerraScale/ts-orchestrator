package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func qualificationFixture(t *testing.T) (Qualification, []byte, string) {
	t.Helper()
	receipt := testBinaryReceipt()
	qualification := Qualification{
		Schema: QualificationSchema, Repository: QualificationRepository,
		SourceRevision: receipt.SourceRevision, SourceTree: receipt.SourceRevision,
		GoVersion: DefaultGoVersion, GoModSHA256: receipt.SHA256, GoSumSHA256: receipt.SHA256,
		Verification: QualificationCheck{Workflow: QualificationWorkflow, Job: QualificationJob,
			RunID: 4001, RunNumber: 620, Conclusion: "success"},
		Artifacts: []QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: receipt.Bytes, SHA256: receipt.SHA256},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: receipt.Bytes, SHA256: receipt.SHA256},
		},
	}
	wire, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	return qualification, wire, hex.EncodeToString(digest[:])
}

func TestQualificationBindsRequiredCheckAndBothRetainedArtifacts(t *testing.T) {
	qualification, wire, digest := qualificationFixture(t)
	decoded, observedDigest, err := DecodeQualification(wire)
	if err != nil || observedDigest != digest || decoded.Verification != qualification.Verification {
		t.Fatalf("DecodeQualification() = %+v, %q, %v", decoded, observedDigest, err)
	}
	receipt := testBinaryReceipt()
	receipt.QualificationSHA256 = digest
	if err := decoded.MatchBinary(receipt, digest); err != nil {
		t.Fatalf("MatchBinary() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Qualification)
	}{

		{"failed check", func(q *Qualification) { q.Verification.Conclusion = "failure" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := qualification
			changed.Artifacts = append([]QualifiedArtifact(nil), qualification.Artifacts...)
			test.mutate(&changed)
			encoded, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			decoded, changedDigest, err := DecodeQualification(encoded)
			if err == nil {
				err = decoded.MatchBinary(receipt, changedDigest)
			}
			if !errors.Is(err, ErrInvalidQualification) {
				t.Fatalf("changed qualification error = %v, want ErrInvalidQualification", err)
			}
		})
	}
}
