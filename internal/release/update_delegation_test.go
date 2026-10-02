package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testLineageBase = "89abcdef0123456789abcdef0123456789abcdef"

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
			Environment: "canary", Cells: []string{"FRA", "GRU"}, Architectures: []string{"amd64", "arm64"},
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

func TestBinaryUpdateReceiptRejectsOutOfScopeConsumers(t *testing.T) {
	fixture := newUpdateFixture(t)
	receipt, err := fixture.sign("GRU", &fakeLineage{})
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]UpdateExpectation{
		"other cell":        {Environment: "canary", Cell: "FRA", Architecture: "amd64"},
		"other arch":        {Environment: "canary", Cell: "GRU", Architecture: "arm64"},
		"other environment": {Environment: "production", Cell: "GRU", Architecture: "amd64"},
		"unknown cell":      {Environment: "canary", Cell: "XYZ", Architecture: "amd64"},
	} {
		if _, err := fixture.verify(t, receipt, expected, fixture.now); err == nil {
			t.Errorf("%s accepted the receipt", name)
		}
	}
	if _, err := fixture.verify(t, receipt, UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"},
		fixture.now.Add(8*24*time.Hour)); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired delegation accepted: %v", err)
	}
}

func TestBinaryUpdateSigningEnforcesScopeLineageAndKey(t *testing.T) {
	fixture := newUpdateFixture(t)
	if _, err := fixture.sign("SFO", &fakeLineage{}); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("cell outside delegation signed: %v", err)
	}
	if _, err := fixture.sign("GRU", &fakeLineage{err: errors.New("not an ancestor")}); !errors.Is(err, ErrLineage) {
		t.Fatalf("non-descendant source signed: %v", err)
	}
	if _, err := fixture.sign("GRU", nil); !errors.Is(err, ErrLineage) {
		t.Fatalf("unchecked lineage signed: %v", err)
	}
	failed := fixture
	failed.qualification.Verification.Conclusion = "failure"
	if _, err := failed.sign("GRU", &fakeLineage{}); !errors.Is(err, ErrInvalidQualification) {
		t.Fatalf("unqualified source signed: %v", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := fixture
	wrongKey.leafPrivate = otherKey
	if _, err := wrongKey.sign("GRU", &fakeLineage{}); !errors.Is(err, trust.ErrKeyMismatch) {
		t.Fatalf("undelegated key signed: %v", err)
	}
	if _, err := SignUpdateDelegation(fixture.delegation, fixture.now, fixture.now.Add(MaxUpdateDelegationLifetime+time.Second),
		fixture.rootPrivate); err == nil {
		t.Fatal("long-lived update delegation signed")
	}
	unsorted := fixture.delegation
	unsorted.Cells = []string{"GRU", "FRA"}
	if err := unsorted.Validate(); err == nil {
		t.Fatal("non-canonical cell list accepted")
	}
	otherRef := fixture.delegation
	otherRef.Ref = "refs/heads/feature"
	if err := otherRef.Validate(); err == nil {
		t.Fatal("non-main lineage accepted")
	}
}

func TestBinaryUpdateReceiptIsBoundToExactDelegation(t *testing.T) {
	fixture := newUpdateFixture(t)
	receipt, err := fixture.sign("GRU", &fakeLineage{})
	if err != nil {
		t.Fatal(err)
	}
	// A re-issued delegation with another lineage base no longer covers the
	// receipt, and a forged delegation from a non-root key never verifies.
	reissued := fixture
	reissued.delegation.LineageBase = strings.Repeat("f", 40)
	reissued.envelope = reissued.signDelegation(t, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	expected := UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"}
	if _, err := reissued.verify(t, receipt, expected, fixture.now); !errors.Is(err, ErrLineage) {
		t.Fatalf("receipt verified under a different delegation: %v", err)
	}
	forged := fixture
	forged.rootPrivate = fixture.leafPrivate
	forged.envelope = forged.signDelegation(t, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	if _, err := forged.verify(t, receipt, expected, fixture.now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("leaf-signed delegation accepted: %v", err)
	}
	// The per-source verifier never accepts an update receipt.
	if _, err := VerifyBinaryCurrent(encodeEnvelope(t, receipt), encodeEnvelope(t, fixture.envelope), fixture.roots,
		BinaryExpectation{Environment: "canary"}, fixture.now); err == nil {
		t.Fatal("update receipt accepted as a per-source receipt")
	}
}
