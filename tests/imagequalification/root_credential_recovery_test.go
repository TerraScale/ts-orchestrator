package imagequalification

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

func rootRecoveryFixture(t *testing.T) (qualificationFixture, principal.VerifiedPreparation, []byte, []byte) {
	t.Helper()
	f := fixture(t)
	a := f.prepared.Approval()
	a.Purpose, a.Candidate.Role = qualification.RootCredentialBoundaryPurpose, release.FoundationWriterRole
	a.ArtifactDisposition, a.ReaderIAMAuthority, a.ImagePublicationBucket = qualification.RetainTestedImage, qualification.ExactHostReaders, "gru-1-head"
	a.MaterialFixtures = nil
	a.ImageRetainUntil, a.ImageTransferUntil = f.now.Add(-15*time.Minute), f.now.Add(-20*time.Minute)
	a.CleanupUntil = f.now.Add(30 * time.Minute)
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var prep principal.Preparation
	if err := json.Unmarshal(payload, &prep); err != nil {
		t.Fatal(err)
	}
	prep.Schema, prep.ExpiresAt = principal.PreparationSchema, f.now.Add(-10*time.Minute)
	prep.IssuerPrincipal, prep.IssuerFingerprint = "ocid1.user.oc1..issuer", strings.Repeat("01:", 15)+"01"
	prep.PrincipalName, prep.GroupName, prep.PolicyName = "ts-qualification-"+a.RunID+"-user", "ts-qualification-"+a.RunID+"-group", "ts-qualification-"+a.RunID+"-policy"
	prep.Object = "qualification/" + a.RunID + "/" + a.Candidate.ArtifactSHA256 + ".qcow2"
	prep.PublicKeyPEM, prep.PublicKeyFingerprint, err = principal.GenerateKey(filepath.Join(t.TempDir(), "escrow"))
	if err != nil {
		t.Fatal(err)
	}
	prep.PolicyTemplate = principal.RequiredTemplate(prep)
	sign := func(body any, role string, expires time.Time) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(body)
		if err != nil {
			t.Fatal(err)
		}
		e, err := trust.Sign(payload, qualification.Scope(a.RunID, a.Candidate, role), f.now.Add(-60*time.Minute), expires, f.private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := sign(prep, "disposable-principal", prep.CleanupUntil)
	v, err := principal.VerifyPreparation(wire, nil, f.roots, prep.RunID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	statements := confinement.RequiredStatements(confinement.Scope{RunID: prep.RunID, Group: a.Group, Compartment: prep.Compartment, Bucket: prep.Bucket, Object: prep.Object, ExpiresAt: prep.ExpiresAt, CleanupUntil: prep.CleanupUntil})
	a = approvalFromPrincipal(prep, principal.Receipt{Principal: a.Principal, Group: a.Group, PolicyID: a.PolicyID, PolicyStatements: statements})
	return f, v, wire, sign(a, "disposable-host", prep.ExpiresAt)
}

func TestCleanupApprovalUsesOriginalExpiredCreateAuthority(t *testing.T) {
	f, v, preparation, approval := rootRecoveryFixture(t)
	p, err := cleanupApproval(v, preparation, nil, approval, f.roots, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.expires.Before(f.now) || p.approvalSHA256 != hashBytes(approval) || !p.approval.CleanupUntil.Equal(v.Preparation().CleanupUntil) {
		t.Fatal("cleanup changed original authority or renewed creation")
	}
	preparationEnvelope, err := trust.DecodeEnvelope(preparation)
	if err != nil {
		t.Fatal(err)
	}
	changedPreparation := v.Preparation()
	changedPreparation.MaxSpendMicros++
	preparationEnvelope.Payload, err = trust.EncodePayload(changedPreparation)
	if err != nil {
		t.Fatal(err)
	}
	preparationEnvelope, err = trust.Sign(preparationEnvelope.Payload, preparationEnvelope.Scope, preparationEnvelope.IssuedAt, preparationEnvelope.ExpiresAt, f.private)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := trust.EncodeEnvelope(preparationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanupApproval(v, changed, nil, approval, f.roots, f.now); err == nil {
		t.Fatal("altered original preparation accepted for cleanup")
	}
	e, err := trust.DecodeEnvelope(approval)
	if err != nil {
		t.Fatal(err)
	}
	a := p.approval
	a.MaxSpendMicros++
	e.Payload, err = trust.EncodePayload(a)
	if err != nil {
		t.Fatal(err)
	}
	e, err = trust.Sign(e.Payload, e.Scope, e.IssuedAt, e.ExpiresAt, f.private)
	if err != nil {
		t.Fatal(err)
	}
	changedApproval, err := trust.EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanupApproval(v, preparation, nil, changedApproval, f.roots, f.now); err == nil {
		t.Fatal("original signer changed the originally prepared spending bound")
	}
	if _, err := cleanupApproval(v, preparation, nil, approval, f.roots, p.approval.CleanupUntil); err == nil {
		t.Fatal("cleanup authority accepted at original exclusive deadline")
	}
}

func TestOuterRestartReachesCleanupWithoutSigningKeyOrLocalArtifacts(t *testing.T) {
	f, _, preparation, approval := rootRecoveryFixture(t)
	directory := t.TempDir()
	paths := rootCredentialPaths{Approval: filepath.Join(directory, "approval.json"), Journal: filepath.Join(directory, "resources.json"), PrincipalDirectory: filepath.Join(directory, "principal")}
	if err := os.WriteFile(paths.Approval, approval, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Journal, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runRootCredentialBoundary(t.Context(), preparation, nil, f.roots, nil, nil, paths)
	if err == nil || !strings.Contains(err.Error(), "issuer IAM region differs from signed preparation") {
		t.Fatalf("restart failed before reaching cleanup issuer verification: %v", err)
	}
}
