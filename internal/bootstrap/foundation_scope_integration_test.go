package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestRootSignedRegionalAnchorPersistsIndependentHomeFoundationReference(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	home := FoundationScope{InstallationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(), TenancyID: "ocid1.tenancy.oc1..test", OCIRegion: "sa-saopaulo-1", GrantGeneration: 3, GrantSHA256: strings.Repeat("a", 64), StorageDomain: StorageDomain{Namespace: "home", LedgerBucket: "home-ledger", HeadBucket: "home-heads", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "bootstrap"}}
	fixture.anchor.FoundationScope = &home
	envelope := fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	wire := mustAnchorWire(t, envelope)
	path := filepath.Join(t.TempDir(), "anchor.json")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := trust.DecodeEnvelope(persisted)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyBootstrapAnchor(decoded, fixture.roots, BootstrapAnchorExpectation{DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}, fixture.now, BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	got, err := verified.FoundationScope()
	if err != nil || got != home {
		t.Fatalf("home=%+v err=%v", got, err)
	}
	if verified.Anchor().ClusterID == home.ClusterID || verified.Anchor().OCIRegion == home.OCIRegion {
		t.Fatal("home discovery overwrote independent regional identity")
	}
	copy := verified.Anchor()
	copy.FoundationScope.ClusterID = entityid.New()
	again, _ := verified.FoundationScope()
	if again != home {
		t.Fatal("accessor leaked mutable home scope")
	}
	for _, scenario := range []string{"foreign home region", "missing digest", "unbound generation", "foreign KMS region"} {
		t.Run(scenario, func(t *testing.T) {
			changed := home
			switch scenario {
			case "foreign home region":
				changed.OCIRegion = "eu-frankfurt-1"
			case "missing digest":
				changed.GrantSHA256 = ""
			case "unbound generation":
				changed.GrantGeneration = 0
			case "foreign KMS region":
				changed.StorageDomain.HeadKMSKeyOCID = "ocid1.key.oc1.eu-frankfurt-1.head"
			}
			fixture.anchor.FoundationScope = &changed
			if _, err := SignBootstrapAnchor(fixture.anchor, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate); err == nil {
				t.Fatal("invalid home reference signed")
			}
		})
	}
	fixture.anchor.FoundationScope = nil
	historical := fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	old, err := VerifyBootstrapAnchor(historical, fixture.roots, BootstrapAnchorExpectation{DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}, fixture.now, BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.FoundationScope(); err == nil {
		t.Fatal("historical nil home scope authorized cold discovery")
	}
}

func TestRootSignedInitialRegistrationCannotReplacePinnedLedger(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	domain := fixture.anchor.StorageDomain
	home := FoundationScope{InstallationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(), TenancyID: "ocid1.tenancy.oc1..test", OCIRegion: "sa-saopaulo-1", GrantGeneration: 1, GrantSHA256: strings.Repeat("a", 64), StorageDomain: StorageDomain{Namespace: "home", LedgerBucket: "home-ledger", HeadBucket: "home-heads", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "bootstrap"}}
	fixture.anchor.FoundationScope = &home
	registration := InitialSourceRegistration{InstallationID: fixture.anchor.FoundationScope.InstallationID, DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, ClusterID: fixture.anchor.ClusterID, Cell: fixture.anchor.Cell, Generation: 1, PlanSHA256: strings.Repeat("b", 64), SeedSlot: fixture.anchor.ControllerSlots[0], ControllerSlots: fixture.anchor.ControllerSlots, StorageDomain: domain, LedgerRecordDomains: BootstrapLedgerCapabilityDomains()}
	fixture.anchor.InitialSourceRegistration = &registration
	if _, err := SignBootstrapAnchor(fixture.anchor, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate); err == nil {
		t.Fatal("registration replaced preexisting fixed signer")
	}
	fixture.anchor.LedgerDelegationWire = nil
	envelope := fixture.sign(t, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	wire := mustAnchorWire(t, envelope)
	path := filepath.Join(t.TempDir(), "initial-anchor.json")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = trust.DecodeEnvelope(persisted)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := VerifyBootstrapAnchor(envelope, fixture.roots, BootstrapAnchorExpectation{DeploymentID: fixture.anchor.DeploymentID, Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}, fixture.now, BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.LedgerDelegation(); err == nil {
		t.Fatal("initial registration manufactured a fixed ledger delegation")
	}
	cloned := anchor.Anchor()
	cloned.InitialSourceRegistration.ControllerSlots[0] = "changed"
	if anchor.Anchor().InitialSourceRegistration.ControllerSlots[0] == "changed" {
		t.Fatal("registration leaked mutable authority")
	}
	fixture.anchor.InitialSourceRegistration = nil
	if _, err := SignBootstrapAnchor(fixture.anchor, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate); err == nil {
		t.Fatal("missing every ledger authority was accepted")
	}
}
