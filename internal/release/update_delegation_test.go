package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	testLineageBase       = "89abcdef0123456789abcdef0123456789abcdef"
	testServiceRepository = "https://git.terrascale.tech/TerraScale/terrabase"
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

func TestBinaryUpdateReceiptHistoricalOutlivesExpiryNotScope(t *testing.T) {
	fixture := newUpdateFixture(t)
	receipt, err := fixture.sign("GRU", &fakeLineage{})
	if err != nil {
		t.Fatal(err)
	}
	historical := func(roots trust.Keyring, expected UpdateExpectation) (HistoricalBinary, error) {
		return VerifyBinaryUpdateHistorical(encodeEnvelope(t, receipt), encodeEnvelope(t, fixture.envelope), roots, expected)
	}
	gru := UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"}
	if _, err := fixture.verify(t, receipt, gru, fixture.now.Add(8*24*time.Hour)); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired delegation accepted as current: %v", err)
	}
	verified, err := historical(fixture.roots, gru)
	if err != nil || !verified.IsVerified() || verified.Receipt() != fixture.binary {
		t.Fatalf("historical = %+v, %v", verified, err)
	}
	for name, expected := range map[string]UpdateExpectation{
		"other cell":        {Environment: "canary", Cell: "FRA", Architecture: "amd64"},
		"other arch":        {Environment: "canary", Cell: "GRU", Architecture: "arm64"},
		"other environment": {Environment: "production", Cell: "GRU", Architecture: "amd64"},
	} {
		if _, err := historical(fixture.roots, expected); err == nil {
			t.Errorf("%s accepted the receipt historically", name)
		}
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoots, err := trust.ParseKeyring(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := historical(otherRoots, gru); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("receipt under another root = %v, want untrusted key", err)
	}
}

func TestBinaryUpdateSigningEnforcesScopeLineageAndKey(t *testing.T) {
	fixture := newUpdateFixture(t)
	armOnly := fixture
	armOnly.delegation.Architectures = []string{"arm64"}
	armOnly.envelope = armOnly.signDelegation(t, fixture.now.Add(-time.Minute), fixture.now.Add(7*24*time.Hour))
	if _, err := armOnly.sign("GRU", &fakeLineage{}); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("architecture outside delegation signed: %v", err)
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
	otherRef := fixture.delegation
	otherRef.Ref = "refs/heads/feature"
	if err := otherRef.Validate(); err == nil {
		t.Fatal("non-main lineage accepted")
	}
}

func TestBinaryUpdateDelegationServices(t *testing.T) {
	fixture := newUpdateFixture(t)
	if err := fixture.delegation.Validate(); err != nil {
		t.Fatalf("delegation with services: %v", err)
	}
	if !fixture.delegation.MayRelease("terrabase", testServiceRepository) || fixture.delegation.MayRelease("terrabase", "https://git.terrascale.tech/TerraScale/other") ||
		fixture.delegation.MayRelease("ts-orchestrator", testServiceRepository) {
		t.Fatal("MayRelease does not name exactly the granted role and repository")
	}
	for name, services := range map[string][]ServiceGrant{
		"unsorted":       {{Role: "ts-auth", Repository: testServiceRepository}, {Role: "terrabase", Repository: testServiceRepository}},
		"duplicate role": {{Role: "terrabase", Repository: testServiceRepository}, {Role: "terrabase", Repository: testServiceRepository}},
		"bad role":       {{Role: "TerraBase", Repository: testServiceRepository}},
		"plain http":     {{Role: "terrabase", Repository: "http://git.terrascale.tech/TerraScale/terrabase"}},
	} {
		invalid := fixture.delegation
		invalid.Services = services
		if err := invalid.Validate(); err == nil {
			t.Errorf("%s services accepted", name)
		}
	}
	tooMany := make([]ServiceGrant, maxUpdateDelegationServices+1)
	for index := range tooMany {
		tooMany[index] = ServiceGrant{Role: fmt.Sprintf("role-%02d", index), Repository: testServiceRepository}
	}
	fixture.delegation.Services = tooMany
	if err := fixture.delegation.Validate(); err == nil {
		t.Error("17 services accepted")
	}
}

func TestVerifyReleaseDelegationCurrent(t *testing.T) {
	fixture := newUpdateFixture(t)
	wire := encodeEnvelope(t, fixture.envelope)
	delegation, key, expires, err := VerifyReleaseDelegationCurrent(wire, fixture.roots, "canary", fixture.now)
	if err != nil {
		t.Fatalf("verify release delegation: %v", err)
	}
	if !slices.Equal(delegation.Services, fixture.delegation.Services) || !key.Equal(fixture.leafPrivate.Public()) ||
		!expires.Equal(fixture.envelope.ExpiresAt) {
		t.Fatalf("delegation = %+v, key %x", delegation, key)
	}
	if _, _, _, err := VerifyReleaseDelegationCurrent(wire, fixture.roots, "production", fixture.now); err == nil {
		t.Fatal("delegation for another environment accepted")
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

func TestBinaryUpdateReceiptRefusesANearlyExpiredDelegation(t *testing.T) {
	fixture := newUpdateFixture(t)
	fixture.envelope = fixture.signDelegation(t, fixture.now.Add(-time.Minute), fixture.now.Add(10*time.Minute))
	if _, err := fixture.sign("GRU", &fakeLineage{}); err == nil {
		t.Fatal("a receipt capped to ten minutes by its delegation was signed")
	}
	fixture.envelope = fixture.signDelegation(t, fixture.now.Add(-time.Minute), fixture.now.Add(2*time.Hour))
	receipt, err := fixture.sign("GRU", &fakeLineage{})
	if err != nil || !receipt.ExpiresAt.Equal(fixture.envelope.ExpiresAt) {
		t.Fatalf("receipt capped to a usable delegation remainder = %v, %v", receipt.ExpiresAt, err)
	}
}
