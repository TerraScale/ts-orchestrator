package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func TestCurrentBinaryVerificationRejectsTamperedArtifact(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(artifactPath, []byte("tampered artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyBinary([]string{
		"--receipt", fixture.receiptPath,
		"--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath,
		"--binary", artifactPath,
		"--qualification", fixture.qualificationPath,
		"--environment", "canary",
	})
	if err == nil {
		t.Fatal("verifyBinary() accepted tampered artifact bytes")
	}
}

type signedFixture struct {
	rootPath          string
	delegationPath    string
	receiptPath       string
	privatePath       string
	qualificationPath string
}

func newSignedBinaryFixture(t *testing.T, delegationLifetime time.Duration) signedFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegateID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	delegationIssued := now.Add(-time.Minute)
	delegationExpires := now.Add(delegationLifetime)
	if delegationLifetime < 0 {
		delegationIssued = now.Add(delegationLifetime - time.Minute)
		delegationExpires = now.Add(delegationLifetime)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: delegateID, SubjectPublicKey: encodedPublic,
		Capabilities: []trust.Capability{{
			Domain: binaryDomain, DeploymentID: entityid.Derive("build", testRevision), Cell: "BUILD", Environment: "canary",
			Role: "artifact", Slots: []string{"linux-amd64"}, Actions: []string{"sign"},
		}},
	}, delegationIssued, delegationExpires, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegationEncoded, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := x509.MarshalPKIXPublicKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER})
	privateDER, err := x509.MarshalPKCS8PrivateKey(delegatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.pub")
	delegationPath := filepath.Join(directory, "delegation.json")
	privatePath := filepath.Join(directory, "delegate.key")
	receiptPath := filepath.Join(directory, "receipt.json")
	qualificationPath := filepath.Join(directory, "qualification.json")
	writeFixtureFile(t, qualificationPath, testQualificationWire(t), 0o600)
	writeFixtureFile(t, rootPath, rootPEM, 0o600)
	writeFixtureFile(t, delegationPath, delegationEncoded, 0o600)
	writeFixtureFile(t, privatePath, privatePEM, 0o600)
	if err := validateDelegatedKey(privatePath); err != nil {
		t.Fatal(err)
	}
	receipt := testBinaryReceipt()
	payload, err := trust.EncodePayload(receipt)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(payload, binaryScope(receipt, "canary"), now, now.Add(5*time.Minute), delegatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	receiptEncoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, receiptPath, receiptEncoded, 0o600)
	return signedFixture{rootPath: rootPath, delegationPath: delegationPath, receiptPath: receiptPath, privatePath: privatePath, qualificationPath: qualificationPath}
}

func validateDelegatedKey(path string) error {
	_, err := readDelegatedPrivateKey(path)
	return err
}

func writeFixtureFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testBinaryReceipt() binaryReceipt {
	digest := sha256.Sum256([]byte("static binary"))
	qualificationDigest := sha256.Sum256(testQualificationBytes())
	return binaryReceipt{
		Schema: binarySchema, SourceRevision: testRevision, GoVersion: defaultGoVersion,
		GOOS: "linux", GOARCH: "amd64", ELFMachine: linuxAMD64Machine, Static: true,
		Bytes: 13, SHA256: hex.EncodeToString(digest[:]), QualificationSHA256: hex.EncodeToString(qualificationDigest[:]),
	}
}

func testQualificationBytes() []byte {
	digest := sha256.Sum256([]byte("static binary"))
	qualification := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: testRevision, SourceTree: testRevision,
		GoVersion: defaultGoVersion, GoModSHA256: hex.EncodeToString(digest[:]), GoSumSHA256: hex.EncodeToString(digest[:]),
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow,
			Job: release.QualificationJob, RunID: 4001, RunNumber: 620, Conclusion: "success"},
		Artifacts: []release.QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: 13, SHA256: hex.EncodeToString(digest[:])},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: 13, SHA256: hex.EncodeToString(digest[:])},
		},
	}
	wire, _ := trust.EncodePayload(qualification)
	return wire
}

func testQualificationWire(t *testing.T) []byte {
	t.Helper()
	wire := testQualificationBytes()
	if _, _, err := release.DecodeQualification(wire); err != nil {
		t.Fatal(err)
	}
	return wire
}
