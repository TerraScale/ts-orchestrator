package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func verifiedAnchorFixture(t *testing.T) (bootstrap.VerifiedBootstrapAnchor, bootstrap.HistoricalBootstrapAnchor,
	trust.Keyring, ed25519.PrivateKey, []byte,
) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-b"}
	capabilities := make([]trust.Capability, 0, 5)
	for _, domain := range []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"} {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: "deployment-a",
			Cell: "GRU", Environment: "production", Role: "controller", Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: ledgerID, SubjectPublicKey: ledgerWire, Capabilities: capabilities},
		now.Add(-time.Hour), now.Add(24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", ControllerSlots: slots, LedgerDelegationWire: grantWire,
		StorageDomain: bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "head-bucket",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"},
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]),
		InitialRegionIntentWire: intentWire}
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := bootstrap.BootstrapAnchorExpectation{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell}
	current, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	historical, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return current, historical, roots, rootPrivate, anchorWire
}

func TestHistoricalLedgerOpenerAcceptsCurrentFiveDomainGrantReadOnly(t *testing.T) {
	_, historical, roots, _, _ := verifiedAnchorFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test",
		"sa-saopaulo-1", "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", string(private), nil)
	opener := InstancePrincipalLedgerOpener{provider: provider}
	reader, err := opener.OpenHistoricalLedger(context.Background(), historical, roots)
	if err != nil {
		t.Fatalf("production restart cannot open historical v3 anchor ledger: %v", err)
	}
	if _, ok := reader.(admissionLedger); !ok {
		t.Fatalf("historical ledger opener returned a write-capable ledger: %T", reader)
	}
}

func TestLedgerOpenerUsesExactVerifiedGrantAndBakedRoots(t *testing.T) {
	current, historical, roots, _, _ := verifiedAnchorFixture(t)
	currentConfig, err := currentLedgerConfig(current, roots)
	if err != nil {
		t.Fatal(err)
	}
	historicalConfig, err := historicalLedgerConfig(historical, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !currentConfig.AnchorExpiresAt.Equal(current.ExpiresAt()) || !historicalConfig.AnchorExpiresAt.IsZero() {
		t.Fatalf("current/historical ledger expiry contract differs: current=%s historical=%s",
			currentConfig.AnchorExpiresAt, historicalConfig.AnchorExpiresAt)
	}
	for _, config := range []bootstrap.LedgerConfig{currentConfig, historicalConfig} {
		if config.DeploymentID != "deployment-a" || config.Cell != oci.RegionGRU ||
			config.Namespace != "namespace-a" || config.Bucket != "ledger-bucket" ||
			config.HeadBucket != "head-bucket" || !slices.Equal(config.ControllerSlots, []string{"controller-b"}) ||
			len(config.TrustRoots) != 1 || len(config.Delegations) != 1 {
			t.Fatalf("ledger opener lost exact root/grant/storage/slot contract: %+v", config)
		}
	}
	if _, err := currentLedgerConfig(bootstrap.VerifiedBootstrapAnchor{}, roots); !errors.Is(err, ErrLedgerGrant) {
		t.Fatalf("zero current proof = %v", err)
	}
	if _, err := historicalLedgerConfig(bootstrap.HistoricalBootstrapAnchor{}, roots); !errors.Is(err, ErrLedgerGrant) {
		t.Fatalf("zero historical proof = %v", err)
	}
}
