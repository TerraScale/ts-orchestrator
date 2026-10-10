package app

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// A chain pin bound to another acceptance must not admit the retained config,
// even when the manifest and chain are validly signed.
func TestNativeRetainedChainPinMustMatchAcceptedIdentity(t *testing.T) {
	f, p := newRetainedChainFixture(t, false)
	err := f.history.verifyProfile(terrabase.Role, nativeRegressionProfile(), p)
	if err == nil || err.Error() != "retained material/config acceptance mismatch" {
		t.Fatalf("chain pin bound to another acceptance: err = %v", err)
	}
}

// A chain pin bound to the retained acceptance passes both identity checks.
// The fixture config is not a full controller config, so verification stops at
// config validation; reaching that step proves the pin and identity admitted it.
func TestNativeRetainedChainPinAdmitsMatchingAcceptance(t *testing.T) {
	f, p := newRetainedChainFixture(t, true)
	err := f.history.verifyProfile(terrabase.Role, nativeRegressionProfile(), p)
	if err == nil || err.Error() != "signed controller config does not match role, slot, or fixed paths" {
		t.Fatalf("chain pin bound to the retained acceptance: err = %v", err)
	}
}

// newRetainedChainFixture returns provenance whose manifest and material chain
// are validly signed for controller-a. matchingPin binds the chain's controller-a
// pin to the retained accepted identity instead of an unrelated digest.
func newRetainedChainFixture(t *testing.T, matchingPin bool) (*retainedConsumerFixture, nativeProfileProvenance) {
	t.Helper()
	f := newRetainedConsumerFixture(t)
	now := time.Now().UTC()
	const slot = "controller-a"
	// Manifests validate only the production and canary environments.
	f.history.services.identity.Environment = "canary"
	identity := f.history.services.identity
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment,
		ClusterID: "0000000000DMC7WFP9VHV640EP", Cell: oci.RegionGRU, ControllerSlots: []string{slot}}
	proof, err := trust.Sign([]byte(`{}`), trust.Scope{Domain: "terrascale.release.image", DeploymentID: identity.DeploymentID,
		Cell: "gru", Environment: identity.Environment, Role: "oci-image", Slot: slot}, now, now.Add(time.Hour), f.keys.root)
	if err != nil {
		t.Fatal(err)
	}
	proofWire, err := trust.EncodeEnvelope(proof)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"version":1,"nats":{},"controller":{}}`)
	manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: identity.DeploymentID,
		ClusterID: expected.ClusterID, Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", Environment: identity.Environment,
		ControllerRole: "controller", Slot: slot, SeedSlot: slot, ControllerSlots: []string{slot},
		IntentGeneration: 1, IntentSHA256: strings.Repeat("a", 64), ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.fixture",
		ImageArchitecture: "linux-amd64", ReleaseReceiptSHA256: controllerSHA256(proofWire),
		ReleaseImageReceiptWire: proofWire, ReleaseDelegationWire: proofWire,
		StorageDomain: bootstrap.StorageDomain{Namespace: "fixture", LedgerBucket: "ledger", HeadBucket: "heads",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.heads"},
		Profiles: []bootstrap.LaunchProfile{{Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..fixture",
			AvailabilityDomain: "fixture:SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.fixture", Shape: "VM.Standard.E4.Flex"}},
		ControllerConfig: config, ControllerConfigSHA256: controllerSHA256(config)}
	for _, name := range bootstrap.ControllerConfigFileNames {
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: []byte(`{}`), SHA256: controllerSHA256([]byte(`{}`))})
	}
	envelope, err := bootstrap.SignManifest(manifest, now, now.Add(time.Hour), f.keys.root)
	if err != nil {
		t.Fatal(err)
	}
	manifestWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	accepted, _, _ := identityRekeyConfigFixture(t)
	accepted.DeploymentID, accepted.Environment, accepted.Cell = identity.DeploymentID, identity.Environment, string(oci.RegionGRU)
	identityWire, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		t.Fatal(err)
	}
	material := generationtest.New(t, now).WithoutIssuers(t).InterRegion(t, now, expected.ControllerSlots).
		With(map[string][]byte{"controller-" + slot + ".json": config})
	generation := material.Generation(expected, 1, "")
	if matchingPin {
		generation.ControllerConfigs[0].AcceptanceSHA256 = acceptance
	}
	signed, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.AddDate(0, 6, 0), f.keys.root)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{signed})
	if err != nil {
		t.Fatal(err)
	}
	return f, nativeProfileProvenance{Manifest: manifestWire, Config: config, MaterialChain: chain, Identity: identityWire}
}
