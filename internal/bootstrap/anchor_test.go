package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
	ledgerGrant := signBootstrapLedgerGrant(t, rootPrivate, ledgerPublic, "0000000000F9PR1WNVDTEXS31Z", oci.RegionFRA,
		"production", []string{"seed-a"}, now.Add(-4*time.Hour), now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
	ledgerWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	anchor := BootstrapAnchor{
		SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production",
		ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionFRA, OCIRegion: "eu-frankfurt-1",
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

func TestBootstrapAnchorSignsRegionalKMSKeyOCIDsWithFutureUse(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	fixture.anchor.Cell = oci.RegionGRU
	fixture.anchor.OCIRegion = "sa-saopaulo-1"
	fixture.anchor.StorageDomain.LedgerKMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.vaultpart.ledgerkey"
	fixture.anchor.StorageDomain.HeadKMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.vaultpart.headkey"
	grant := signBootstrapLedgerGrant(t, fixture.rootPrivate, fixture.ledgerPublic,
		fixture.anchor.DeploymentID, fixture.anchor.Cell, fixture.anchor.Environment,
		fixture.anchor.ControllerSlots, fixture.now.Add(-4*time.Hour), fixture.now.Add(MaxBootstrapAnchorLifetime-4*time.Hour))
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchor.LedgerDelegationWire = grantWire
	if err := fixture.anchor.StorageDomain.Validate(); err != nil {
		t.Fatalf("StorageDomain.Validate() rejected regional OCI KMS IDs: %v", err)
	}
	if err := fixture.anchor.Validate(); err != nil {
		t.Fatalf("BootstrapAnchor.Validate() rejected regional OCI KMS IDs: %v", err)
	}
	fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(24*time.Hour))
}

func mustAnchorWire(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
