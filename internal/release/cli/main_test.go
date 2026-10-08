package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func TestDecodeCanonicalPayloadRejectsAlternateEncoding(t *testing.T) {
	receipt := testBinaryReceipt()
	encoded, err := trust.EncodePayload(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded binaryReceipt
	if err := decodeCanonicalPayload(encoded, &decoded); err != nil {
		t.Fatalf("canonical payload rejected: %v", err)
	}
	if err := decodeCanonicalPayload(append(bytes.Clone(encoded), '\n'), &decoded); err == nil {
		t.Fatal("accepted alternate JSON encoding with trailing whitespace")
	}
	if err := decodeCanonicalPayload([]byte(`{"schema":"terrascale.release.binary.v1","unknown":true}`), &decoded); err == nil {
		t.Fatal("accepted an unknown payload member")
	}
}

func TestCurrentBinaryVerificationRequiresDelegationAndExactScope(t *testing.T) {
	for _, test := range []struct {
		name        string
		delegation  time.Duration
		environment string
		wantError   bool
	}{
		{name: "current exact scope", delegation: time.Hour, environment: "canary"},
		{name: "expired delegation", delegation: -time.Hour, environment: "canary", wantError: true},
		{name: "wrong environment", delegation: time.Hour, environment: "production", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSignedBinaryFixture(t, test.delegation)
			verified, err := verifyBinaryReceiptFiles(fixture.receiptPath, fixture.delegationPath, fixture.rootPath, test.environment)
			if test.wantError {
				if err == nil {
					t.Fatal("verifyBinaryReceiptFiles() succeeded; want rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyBinaryReceiptFiles() error = %v", err)
			}
			if !verified.IsVerified() || verified.Receipt() != testBinaryReceipt() {
				t.Fatalf("verified receipt = %+v, want %+v", verified, testBinaryReceipt())
			}
		})
	}
}

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

func TestSignBinaryChecksDelegateSlotAndEmitsCurrentEnvelope(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	candidatePath := filepath.Join(filepath.Dir(fixture.rootPath), "candidate.json")
	candidate, err := trust.EncodePayload(testBinaryReceipt())
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, candidatePath, candidate, 0o600)
	binaryPath := filepath.Join(filepath.Dir(fixture.rootPath), "retained-binary")
	writeFixtureFile(t, binaryPath, []byte("static binary"), 0o600)
	signedPath := filepath.Join(filepath.Dir(fixture.rootPath), "signed.json")
	args := []string{
		"--candidate", candidatePath,
		"--binary", binaryPath,
		"--qualification", fixture.qualificationPath,
		"--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--environment", "canary",
		"--out", signedPath,
	}
	observed := testBinaryReceipt()
	inspect := func(string, string, string) (binaryReceipt, error) { return observed, nil }
	check := func(release.Qualification, string) error { return nil }
	if err := signBinaryWithCheck(args, check, inspect); err != nil {
		t.Fatalf("signBinary() error = %v", err)
	}
	verified, err := verifyBinaryReceiptFiles(signedPath, fixture.delegationPath, fixture.rootPath, "canary")
	if err != nil {
		t.Fatalf("signed binary receipt failed current verification: %v", err)
	}
	if !verified.IsVerified() || verified.Receipt() != testBinaryReceipt() {
		t.Fatalf("verified binary receipt = %+v", verified)
	}
	wrongSlot := testBinaryReceipt()
	wrongSlot.GOARCH, wrongSlot.ELFMachine = "arm64", linuxARM64Machine
	observed = wrongSlot
	wrongCandidate, err := trust.EncodePayload(wrongSlot)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, candidatePath, wrongCandidate, 0o600)
	wrongArgs := []string{
		"--candidate", candidatePath,
		"--binary", binaryPath,
		"--qualification", fixture.qualificationPath,
		"--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--environment", "canary",
		"--out", filepath.Join(filepath.Dir(fixture.rootPath), "wrong-scope.json"),
	}
	if err := signBinaryWithCheck(wrongArgs, check, inspect); err == nil {
		t.Fatal("signBinary() accepted a candidate outside the delegated architecture slot")
	}
}

func TestPutImmutableStreamsAndChecksExactReadback(t *testing.T) {
	asset := []byte("immutable release bytes")
	digest := sha256.Sum256(asset)
	client := &fakeObjectClient{}
	if err := putImmutable(t.Context(), client, "namespace", "bucket", "releases/sha/asset", bytes.NewReader(asset), int64(len(asset)), digest[:]); err != nil {
		t.Fatalf("first immutable upload: %v", err)
	}
	if !bytes.Equal(client.stored, asset) || client.lastPut.IfNoneMatch == nil || *client.lastPut.IfNoneMatch != "*" ||
		client.lastPut.ContentLength == nil || *client.lastPut.ContentLength != int64(len(asset)) ||
		client.lastPut.OpcContentSha256 == nil || *client.lastPut.OpcContentSha256 != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("upload did not stream the bytes with conditional create")
	}
	if err := putImmutable(t.Context(), client, "namespace", "bucket", "releases/sha/asset", bytes.NewReader(asset), int64(len(asset)), digest[:]); err != nil {
		t.Fatalf("identical retry should verify existing immutable object: %v", err)
	}
	client.stored = []byte("different bytes")
	if err := putImmutable(t.Context(), client, "namespace", "bucket", "releases/sha/asset", bytes.NewReader(asset), int64(len(asset)), digest[:]); err == nil {
		t.Fatal("accepted a conflicting immutable object")
	}
}

func TestBoundedReadSeekerSupportsRetriesWithoutReadingPastSize(t *testing.T) {
	reader := &boundedReadSeeker{source: bytes.NewReader([]byte("release-tail")), size: int64(len("release"))}
	contents, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "release" {
		t.Fatalf("bounded body = %q, want %q", contents, "release")
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	contents, err = io.ReadAll(reader)
	if err != nil || string(contents) != "release" {
		t.Fatalf("rewound bounded body = %q, error = %v", contents, err)
	}
	if _, err := reader.Seek(1, io.SeekEnd); err == nil {
		t.Fatal("bounded reader accepted a seek after its declared end")
	}
}

func TestImageIdentityAndGuestPathValidation(t *testing.T) {
	validOCID := "ocid1.image.oc1.sa-saopaulo-1.BBBBBBBBBBBBBBBBBBBBBBBBBB"
	if !validOCIImageIDForRegion(validOCID, "GRU") {
		t.Fatal("rejected a GRU image OCID")
	}
	if validOCIImageIDForRegion(validOCID, "FRA") {
		t.Fatal("accepted an image OCID in the wrong region")
	}
	for _, path := range []string{"", "relative", "/bin/../tmp/x", "/bin/", "/bin/x\x00y"} {
		if validGuestBinaryPath(path) {
			t.Errorf("accepted unsafe guest path %q", path)
		}
	}
	for _, path := range []string{"/usr/local/bin/terrascale-orchestrator", "/opt/ts-orch/bin/worker"} {
		if !validGuestBinaryPath(path) {
			t.Errorf("rejected valid guest path %q", path)
		}
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

type fakeObjectClient struct {
	stored  []byte
	lastPut objectstorage.PutObjectRequest
}

func (client *fakeObjectClient) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	client.lastPut = request
	if client.stored != nil {
		return objectstorage.PutObjectResponse{}, errors.New("conditional create conflict")
	}
	contents, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	client.stored = contents
	return objectstorage.PutObjectResponse{}, nil
}

func (client *fakeObjectClient) GetObject(_ context.Context, _ objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	contents := bytes.Clone(client.stored)
	length := int64(len(contents))
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(contents)), ContentLength: common.Int64(length)}, nil
}

func TestReadDelegatedPrivateKeyRejectsGroupAccess(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	keyPath := filepath.Join(filepath.Dir(fixture.rootPath), "delegate.key")
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readDelegatedPrivateKey(keyPath); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("readDelegatedPrivateKey() error = %v, want owner-only permission rejection", err)
	}
}
