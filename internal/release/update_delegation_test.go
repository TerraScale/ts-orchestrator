package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	testLineageBase       = "89abcdef0123456789abcdef0123456789abcdef"
	testServiceRepository = "https://github.com/TerraScale/terrabase"
)

type fakeLineage struct {
	err   error
	calls []string
}

func (lineage *fakeLineage) CheckLineage(base, revision, ref string) error {
	lineage.calls = append(lineage.calls, base+" "+revision+" "+ref)
	return lineage.err
}

type updateFixture struct {
	now           time.Time
	roots         trust.Keyring
	rootPrivate   ed25519.PrivateKey
	leafPrivate   ed25519.PrivateKey
	delegation    BinaryUpdateDelegation
	envelope      trust.Envelope
	binary        BinaryReceipt
	qualification Qualification
	qualDigest    string
}

func newUpdateFixture(t *testing.T) updateFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	qualification, _, qualDigest := qualificationFixture(t)
	binary := testBinaryReceipt()
	binary.QualificationSHA256 = qualDigest
	fixture := updateFixture{
		now: now, roots: roots, rootPrivate: rootPrivate, leafPrivate: leafPrivate,
		binary: binary, qualification: qualification, qualDigest: qualDigest,
		delegation: BinaryUpdateDelegation{
			Schema: UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
			Environment: "canary", Architectures: []string{"amd64", "arm64"},
			Services:   []ServiceGrant{{Role: "terrabase", Repository: testServiceRepository}, {Role: "ts-auth", Repository: testServiceRepository}},
			Repository: QualificationRepository, Workflow: QualificationWorkflow, Ref: LineageRef, LineageBase: testLineageBase,
		},
	}
	fixture.envelope = fixture.signDelegation(t, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	return fixture
}

func (fixture updateFixture) signDelegation(t *testing.T, issuedAt, expiresAt time.Time) trust.Envelope {
	t.Helper()
	envelope, err := SignUpdateDelegation(fixture.delegation, issuedAt, expiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (fixture updateFixture) sign(cell string, checker LineageChecker) (trust.Envelope, error) {
	return SignBinaryUpdateReceipt(fixture.binary, fixture.qualification, fixture.qualDigest, cell, "canary",
		checker, fixture.envelope, fixture.roots, fixture.leafPrivate, fixture.now, 24*time.Hour)
}

func (fixture updateFixture) verify(t *testing.T, receipt trust.Envelope, expected UpdateExpectation, now time.Time) (VerifiedBinary, error) {
	t.Helper()
	return VerifyBinaryUpdateCurrent(encodeEnvelope(t, receipt), encodeEnvelope(t, fixture.envelope), fixture.roots, expected, now)
}

func TestBinaryUpdateReceiptSignsAnyQualifiedDescendantInScope(t *testing.T) {
	fixture := newUpdateFixture(t)
	lineage := &fakeLineage{}
	receipt, err := fixture.sign("GRU", lineage)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(lineage.calls) != 1 || lineage.calls[0] != testLineageBase+" "+testSourceRevision+" "+LineageRef {
		t.Fatalf("lineage checks = %q", lineage.calls)
	}
	verified, err := fixture.verify(t, receipt, UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"}, fixture.now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verified.IsVerified() || verified.Receipt() != fixture.binary {
		t.Fatalf("verified = %+v", verified)
	}
	// The same delegation covers a different qualified source without a new
	// root signature.
	other := fixture
	other.binary.SourceRevision = strings.Repeat("e", 40)
	other.qualification.SourceRevision = other.binary.SourceRevision
	otherReceipt, err := other.sign("GRU", &fakeLineage{})
	if err != nil {
		t.Fatalf("second qualified source: %v", err)
	}
	if verified, err := other.verify(t, otherReceipt, UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"},
		fixture.now); err != nil || verified.Receipt().SourceRevision != other.binary.SourceRevision {
		t.Fatalf("second source verify: %v", err)
	}
	mismatched := other
	mismatched.qualification.SourceRevision = testSourceRevision
	if _, err := mismatched.sign("GRU", &fakeLineage{}); !errors.Is(err, ErrInvalidQualification) {
		t.Fatalf("binary signed against a qualification for another source: %v", err)
	}
}
