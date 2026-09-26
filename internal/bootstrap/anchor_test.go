package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type bootstrapAnchorFixture struct {
	now           time.Time
	rootPublic    ed25519.PublicKey
	rootPrivate   ed25519.PrivateKey
	ledgerPublic  ed25519.PublicKey
	ledgerPrivate ed25519.PrivateKey
	ledgerGrant   trust.Envelope
	ledgerWire    []byte
	roots         trust.Keyring
	intentWire    []byte
	anchor        BootstrapAnchor
}

func newBootstrapAnchorFixture(t *testing.T) bootstrapAnchorFixture {
	t.Helper()
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, ledgerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{
		SchemaVersion: 1, Generation: 4, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{
			{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"},
			{Cell: oci.RegionFRA, OCIRegion: "eu-frankfurt-1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ledgerGrant := signBootstrapLedgerGrant(t, rootPrivate, ledgerPublic, "deployment-a", oci.RegionFRA,
		"production", []string{"seed-a"}, now.Add(-4*time.Hour), now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
	ledgerWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	anchor := BootstrapAnchor{
		SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: oci.RegionFRA, OCIRegion: "eu-frankfurt-1",
		ControllerSlots: []string{"seed-a"}, LedgerDelegationWire: bytes.Clone(ledgerWire),
		StorageDomain: StorageDomain{
			Namespace: "namespace-a", LedgerBucket: "bootstrap-ledger",
			LedgerKMSKeyOCID: "ocid1.key.oc1.eu-frankfurt-1.ledger", HeadBucket: "bootstrap-head",
			HeadKMSKeyOCID: "ocid1.key.oc1.eu-frankfurt-1.head", Prefix: "private/bootstrap",
		},
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: digestBytes(intentWire),
		InitialRegionIntentWire: bytes.Clone(intentWire),
	}
	return bootstrapAnchorFixture{now: now, rootPublic: rootPublic, rootPrivate: rootPrivate,
		ledgerPublic: ledgerPublic, ledgerPrivate: ledgerPrivate, ledgerGrant: ledgerGrant, ledgerWire: ledgerWire, roots: roots,
		intentWire: intentWire, anchor: anchor}
}

func signBootstrapLedgerGrant(t *testing.T, root ed25519.PrivateKey, ledger ed25519.PublicKey,
	deployment string, cell oci.Region, environment string, slots []string, issuedAt, expiresAt time.Time,
) trust.Envelope {
	t.Helper()
	capabilities := make([]trust.Capability, 0, 5)
	for _, domain := range []string{domainBootstrapHead, domainBootstrapIntent, domainBootstrapResult,
		domainBootstrapCandidate, domainBootstrapProgress} {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: deployment, Cell: string(cell), Environment: environment,
			Role: roleController, Slots: append([]string(nil), slots...), Actions: []string{"sign"},
		})
	}
	return signBootstrapLedgerDelegation(t, root, ledger, capabilities, issuedAt, expiresAt)
}

func signBootstrapLedgerDelegation(t *testing.T, root ed25519.PrivateKey, ledger ed25519.PublicKey,
	capabilities []trust.Capability, issuedAt, expiresAt time.Time,
) trust.Envelope {
	t.Helper()
	encodedPublic, err := trust.EncodeDelegatedPublicKey(ledger)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, ledger), SubjectPublicKey: encodedPublic,
		Capabilities: capabilities,
	}, issuedAt, expiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (fixture bootstrapAnchorFixture) sign(t *testing.T, issuedAt, expiresAt time.Time) trust.Envelope {
	t.Helper()
	envelope, err := SignBootstrapAnchor(fixture.anchor, issuedAt, expiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestBootstrapAnchorCurrentVerificationPinsIdentityAndReturnsDefensiveCopies(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	input := cloneBootstrapAnchor(fixture.anchor)
	envelope := fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(24*time.Hour))
	input.InitialRegionIntentWire[0] ^= 1
	verified, err := VerifyBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{
		DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}, fixture.now, BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatalf("VerifyBootstrapAnchor() error = %v", err)
	}
	if !verified.IsVerified() || verified.Digest() == "" || !bytes.Equal(verified.Wire(), mustAnchorWire(t, envelope)) {
		t.Fatalf("verified anchor does not preserve proof identity: digest=%q", verified.Digest())
	}
	anchorCopy := verified.Anchor()
	anchorCopy.InitialRegionIntentWire[0] ^= 1
	intentCopy := verified.InitialRegionIntent()
	intentCopy.Regions[0].OCIRegion = "mutated-region"
	if !bytes.Equal(verified.Anchor().InitialRegionIntentWire, fixture.intentWire) ||
		verified.InitialRegionIntent().Regions[0].OCIRegion != "sa-saopaulo-1" {
		t.Fatal("verified anchor exposed aliased region-intent data")
	}
	if verified.StorageDomain() != fixture.anchor.StorageDomain {
		t.Fatalf("verified storage domain = %+v; want %+v", verified.StorageDomain(), fixture.anchor.StorageDomain)
	}
	verifiedGrant, err := verified.LedgerDelegation()
	if err != nil || verifiedGrant.SubjectKeyID() != keyID(t, fixture.ledgerPublic) {
		t.Fatalf("LedgerDelegation() = %q, %v", verifiedGrant.SubjectKeyID(), err)
	}
	expected, err := verified.ManifestExpectation("seed-a", "ocid1.image.oc1.eu-frankfurt-1.image-a")
	if err != nil {
		t.Fatalf("ManifestExpectation() error = %v", err)
	}
	if expected.DeploymentID != fixture.anchor.DeploymentID || expected.Environment != fixture.anchor.Environment ||
		expected.ClusterID != fixture.anchor.ClusterID || expected.Cell != fixture.anchor.Cell || expected.Slot != "seed-a" ||
		expected.StorageDomain != fixture.anchor.StorageDomain || !slices.Equal(expected.ControllerSlots, fixture.anchor.ControllerSlots) || expected.IntentGeneration != 4 ||
		expected.IntentSHA256 != digestBytes(fixture.intentWire) {
		t.Fatalf("anchor-derived manifest expectation = %+v", expected)
	}
	if _, err := verified.ManifestExpectation("seed-a", "not-an-image"); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("ManifestExpectation() error for invalid image = %v", err)
	}
	if _, err := verified.ManifestExpectation("outside-slot", "ocid1.image.oc1.eu-frankfurt-1.image-a"); !errors.Is(err, ErrBootstrapAnchorInvalid) {
		t.Fatalf("ManifestExpectation() error for unanchored slot = %v", err)
	}
}

func TestBootstrapAnchorRejectsWrongLocalIdentityAndRoot(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	envelope := fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(24*time.Hour))
	for _, expected := range []BootstrapAnchorExpectation{
		{DeploymentID: "deployment-b", Environment: "production", Cell: oci.RegionFRA},
		{DeploymentID: "deployment-a", Environment: "canary", Cell: oci.RegionFRA},
		{DeploymentID: "deployment-a", Environment: "production", Cell: oci.RegionGRU},
	} {
		if _, err := VerifyBootstrapAnchor(envelope, fixture.roots, expected, fixture.now, BootstrapAnchorTrustPolicy()); err == nil {
			t.Fatalf("VerifyBootstrapAnchor() accepted wrong local identity %+v", expected)
		}
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBootstrapAnchor(envelope, wrongRoots, BootstrapAnchorExpectation{
		DeploymentID: "deployment-a", Environment: "production", Cell: oci.RegionFRA,
	}, fixture.now, BootstrapAnchorTrustPolicy()); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("VerifyBootstrapAnchor() error for wrong root = %v", err)
	}
}

func TestBootstrapAnchorRequiresCanonicalBoundedIntentAndExactPins(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	tests := []struct {
		name   string
		mutate func(*BootstrapAnchor)
	}{
		{name: "legacy anchor version", mutate: func(anchor *BootstrapAnchor) { anchor.SchemaVersion = 1 }},
		{name: "removed intent bytes", mutate: func(anchor *BootstrapAnchor) { anchor.InitialRegionIntentWire = nil }},
		{name: "oversized intent bytes", mutate: func(anchor *BootstrapAnchor) {
			anchor.InitialRegionIntentWire = bytes.Repeat([]byte{'x'}, MaxInitialRegionIntentBytes+1)
		}},
		{name: "noncanonical intent bytes", mutate: func(anchor *BootstrapAnchor) {
			anchor.InitialRegionIntentWire = append(bytes.Clone(anchor.InitialRegionIntentWire), '\n')
			anchor.InitialRegionIntentSHA256 = digestBytes(anchor.InitialRegionIntentWire)
		}},
		{name: "intent generation mismatch", mutate: func(anchor *BootstrapAnchor) { anchor.InitialRegionIntentGeneration++ }},
		{name: "intent digest mismatch", mutate: func(anchor *BootstrapAnchor) {
			anchor.InitialRegionIntentSHA256 = digestBytes([]byte("different intent"))
		}},
		{name: "intent excludes anchor cell", mutate: func(anchor *BootstrapAnchor) {
			intentWire, err := trust.EncodePayload(oci.RegionIntent{
				SchemaVersion: 1, Generation: anchor.InitialRegionIntentGeneration, BootstrapRegion: oci.RegionGRU,
				Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			anchor.InitialRegionIntentWire = intentWire
			anchor.InitialRegionIntentSHA256 = digestBytes(intentWire)
		}},
		{name: "invalid storage domain", mutate: func(anchor *BootstrapAnchor) {
			anchor.StorageDomain.HeadBucket = anchor.StorageDomain.LedgerBucket
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := cloneBootstrapAnchor(fixture.anchor)
			test.mutate(&anchor)
			if err := anchor.Validate(); !errors.Is(err, ErrBootstrapAnchorInvalid) {
				t.Fatalf("BootstrapAnchor.Validate() error = %v; want ErrBootstrapAnchorInvalid", err)
			}
		})
	}
}

func TestHistoricalBootstrapAnchorOnlyProvesAcceptedInterval(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	issuedAt := fixture.now.Add(-2 * time.Hour)
	expiresAt := fixture.now.Add(-time.Hour)
	envelope := fixture.sign(t, issuedAt, expiresAt)
	if _, err := VerifyBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{
		DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}, fixture.now, BootstrapAnchorTrustPolicy()); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("VerifyBootstrapAnchor() error for expired anchor = %v", err)
	}
	historical, err := VerifyHistoricalBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{
		DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}, issuedAt.Add(time.Minute), BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatalf("VerifyHistoricalBootstrapAnchor() error = %v", err)
	}
	if historical.Digest() == "" || !historical.AcceptedAt().Equal(issuedAt.Add(time.Minute)) {
		t.Fatalf("historical anchor proof does not preserve accepted time: digest=%q acceptedAt=%s", historical.Digest(), historical.AcceptedAt())
	}
	historicalGrant, err := historical.HistoricalLedgerDelegation()
	if err != nil || historicalGrant.SubjectKeyID() != keyID(t, fixture.ledgerPublic) {
		t.Fatalf("HistoricalLedgerDelegation() = %q, %v", historicalGrant.SubjectKeyID(), err)
	}
	if _, err := VerifyHistoricalBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{
		DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell,
	}, expiresAt, BootstrapAnchorTrustPolicy()); !errors.Is(err, ErrBootstrapAnchorInvalid) {
		t.Fatalf("historical verification accepted an install at expiry: %v", err)
	}
}

func TestBootstrapAnchorRequiresExactSingleSignerLedgerCapabilitySet(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	var baseGrant trust.Delegation
	if err := protocol.DecodeStrict(fixture.ledgerGrant.Payload, &baseGrant, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*BootstrapAnchor)
	}{
		{name: "missing controller slots", mutate: func(anchor *BootstrapAnchor) { anchor.ControllerSlots = nil }},
		{name: "duplicate controller slot", mutate: func(anchor *BootstrapAnchor) {
			anchor.ControllerSlots = []string{"seed-a", "seed-a"}
		}},
		{name: "unsorted controller slots", mutate: func(anchor *BootstrapAnchor) {
			anchor.ControllerSlots = []string{"seed-a", "peer-b"}
		}},
		{name: "slot does not match instance descriptor grammar", mutate: func(anchor *BootstrapAnchor) {
			anchor.ControllerSlots = []string{"seed/a"}
		}},
		{name: "grant contains another slot", mutate: func(anchor *BootstrapAnchor) {
			grant := signBootstrapLedgerGrant(t, fixture.rootPrivate, fixture.ledgerPublic, anchor.DeploymentID,
				anchor.Cell, anchor.Environment, []string{"seed-a", "peer-b"}, fixture.now.Add(-4*time.Hour),
				fixture.now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
			anchor.LedgerDelegationWire = mustAnchorWire(t, grant)
		}},
		{name: "grant misses one ledger capability", mutate: func(anchor *BootstrapAnchor) {
			capabilities := slices.Clone(baseGrant.Capabilities[:2])
			grant := signBootstrapLedgerDelegation(t, fixture.rootPrivate, fixture.ledgerPublic, capabilities,
				fixture.now.Add(-4*time.Hour), fixture.now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
			anchor.LedgerDelegationWire = mustAnchorWire(t, grant)
		}},
		{name: "grant has an extra capability", mutate: func(anchor *BootstrapAnchor) {
			capabilities := slices.Clone(baseGrant.Capabilities)
			capabilities = append(capabilities, trust.Capability{
				Domain: "bootstrap-extra", DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell),
				Environment: anchor.Environment, Role: roleController, Slots: []string{"seed-a"}, Actions: []string{"sign"},
			})
			grant := signBootstrapLedgerDelegation(t, fixture.rootPrivate, fixture.ledgerPublic, capabilities,
				fixture.now.Add(-4*time.Hour), fixture.now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
			anchor.LedgerDelegationWire = mustAnchorWire(t, grant)
		}},
		{name: "missing ledger grant", mutate: func(anchor *BootstrapAnchor) { anchor.LedgerDelegationWire = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := cloneBootstrapAnchor(fixture.anchor)
			test.mutate(&anchor)
			if err := anchor.Validate(); !errors.Is(err, ErrBootstrapAnchorInvalid) {
				t.Fatalf("BootstrapAnchor.Validate() error = %v; want ErrBootstrapAnchorInvalid", err)
			}
		})
	}

	grant := fixture.ledgerGrant
	_, otherRootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badGrant := signBootstrapLedgerGrant(t, otherRootPrivate, fixture.ledgerPublic, fixture.anchor.DeploymentID,
		fixture.anchor.Cell, fixture.anchor.Environment, fixture.anchor.ControllerSlots,
		fixture.now.Add(-4*time.Hour), fixture.now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
	badWire, err := trust.EncodeEnvelope(badGrant)
	if err != nil {
		t.Fatal(err)
	}
	anchor := cloneBootstrapAnchor(fixture.anchor)
	anchor.LedgerDelegationWire = badWire
	envelope, err := SignBootstrapAnchor(anchor, fixture.now, fixture.now.Add(time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell,
	}, fixture.now, BootstrapAnchorTrustPolicy()); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("VerifyBootstrapAnchor() error for wrong grant root = %v", err)
	}
	if err := validateBootstrapAnchorGrantInterval(fixture.now, fixture.now.Add(time.Hour), grant); err != nil {
		t.Fatalf("valid grant interval rejected: %v", err)
	}
	if err := validateBootstrapAnchorGrantInterval(grant.IssuedAt.Add(-time.Second), fixture.now.Add(time.Hour), grant); !errors.Is(err, trust.ErrDelegationTime) {
		t.Fatalf("anchor interval before grant returned %v", err)
	}
}

func mustAnchorWire(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
