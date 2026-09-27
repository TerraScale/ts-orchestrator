package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type initialFounderCLIFixture struct {
	*manifestFixture
	identityPath  string
	planPath      string
	selectorPath  string
	manifestPaths []string
	plan          bootstrap.FounderPlan
	selection     bootstrapstart.FounderSelection
	manifestWires map[string][]byte
}

func newInitialFounderCLIFixture(t *testing.T) initialFounderCLIFixture {
	t.Helper()
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	fixture.manifest.ControllerConfig = []byte(`{"nats":{},"controller":{}}`)
	fixture.manifest.ControllerConfigSHA256 = digest(fixture.manifest.ControllerConfig)
	for _, name := range bootstrap.ControllerConfigFileNames {
		body := []byte(`{}`)
		fixture.manifest.ControllerFiles = append(fixture.manifest.ControllerFiles,
			bootstrap.ControllerConfigFile{Name: name, SHA256: digest(body), Bytes: body})
	}
	slots := []string{"controller-a", "controller-b", "seed-a"}
	fixture.writeAnchorFor(t, fixture.anchorForSlots(t, slots), 48*time.Hour)
	anchorWire, err := os.ReadFile(fixture.anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	anchorHash := sha256.Sum256(anchorWire)
	identity := bootstrapstart.BakedIdentity{SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}
	identityWire, err := protocol.EncodeJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(fixture.directory, "identity.json")
	writeFixture(t, identityPath, identityWire, 0o600)
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerKeyID, err := trust.KeyID(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerDelegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: peerKeyID, SubjectPublicKey: peerPublicWire,
		Capabilities: []trust.Capability{{Domain: "terrascale.bootstrap.peer-receipt",
			DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
			Role: "controller", Slots: slots[:2], Actions: []string{"sign"}}},
	}, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []bootstrap.LaunchProfile{
		{Slot: slots[0], CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
			SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1.controller-a",
			NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller-a"}, Shape: "VM.Standard.E5.Flex"},
		{Slot: slots[1], CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-2",
			SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1.controller-b",
			NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller-b"}, Shape: "VM.Standard.E5.Flex"},
		{Slot: slots[2], CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-3",
			SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1.seed-a",
			NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.seed-a"}, Shape: "VM.Standard.E5.Flex"},
	}
	manifestWires := make(map[string][]byte, 3)
	manifestPaths := make([]string, 0, 3)
	pins := make([]bootstrapstart.FounderManifestPin, 0, 3)
	for _, slot := range slots {
		manifest := fixture.manifest
		manifest.Slot, manifest.SeedSlot = slot, "seed-a"
		manifest.ControllerSlots = slices.Clone(slots)
		manifest.Profiles = slices.Clone(profiles)
		manifest.PeerReceiptDelegation = &peerDelegation
		manifest.ReleaseImageReceiptWire = slices.Clone(fixture.imageWire)
		manifest.ReleaseDelegationWire = slices.Clone(fixture.delegationWire)
		manifest.Secrets = nil
		if slot != "seed-a" {
			for _, name := range []string{"client-ca", "client-certificate", "client-key", "route-ca", "route-certificate", "route-key"} {
				manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{
					Purpose: bootstrap.SecretController, Slot: slot,
					SecretOCID:    "ocid1.secret.oc1.sa-saopaulo-1." + slot + "-" + name,
					VersionNumber: 1, SHA256: digest([]byte(slot + name)), MaxBytes: 1024,
					TargetFile: slot + "-" + name + ".pem",
				})
			}
		}
		envelope, err := bootstrap.SignManifest(manifest, fixture.now, fixture.now.Add(22*time.Hour), fixture.rootPrivate)
		if err != nil {
			t.Fatalf("sign %s manifest: %v", slot, err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		manifestWires[slot] = wire
		path := filepath.Join(fixture.directory, slot+".manifest.json")
		writeFixture(t, path, wire, 0o600)
		manifestPaths = append(manifestPaths, path)
		pins = append(pins, bootstrapstart.FounderManifestPin{Slot: slot, SHA256: digest(wire)})
	}
	ipBySlot := map[string]string{"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "seed-a": "10.44.0.10"}
	peers := make([]bootstrap.FounderPeerRow, 0, 2)
	for index, slot := range slots[:2] {
		routes := make([]bootstrap.FounderEndpoint, 0, 2)
		for _, target := range slots {
			if target != slot {
				routes = append(routes, bootstrap.FounderEndpoint{Slot: target, PrivateIP: ipBySlot[target], Port: 6222})
			}
		}
		materials := bootstrap.FounderTLSMaterialDigests{
			ClientCA: digest([]byte(slot + "client-ca")), ClientCertificate: digest([]byte(slot + "client-certificate")),
			ClientPrivateKey: digest([]byte(slot + "client-key")), RouteCA: digest([]byte(slot + "route-ca")),
			RouteCertificate: digest([]byte(slot + "route-certificate")), RoutePrivateKey: digest([]byte(slot + "route-key")),
		}
		profile := profiles[index]
		peers = append(peers, bootstrap.FounderPeerRow{Slot: slot, ManifestSHA256: digest(manifestWires[slot]),
			ImageOCID: fixture.manifest.ImageOCID, ImageCompartmentOCID: "ocid1.compartment.oc1..imagecompartment",
			CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
			FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
			NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), Shape: profile.Shape,
			WholeOCPUs: 2, MemoryInGB: 12, BootVolumeGB: 50,
			BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced, PrivateIP: ipBySlot[slot],
			RouteEndpoints: routes, ClientEndpoints: []bootstrap.FounderEndpoint{{Slot: slot, PrivateIP: ipBySlot[slot], Port: 4222}},
			TLSMaterial: materials})
	}
	plan := bootstrap.FounderPlan{SchemaVersion: bootstrap.FounderPlanSchemaVersion,
		DeploymentID: identity.DeploymentID, Cell: identity.Cell, Environment: identity.Environment,
		SeedSlot: "seed-a", AnchorSHA256: hex.EncodeToString(anchorHash[:]), ControllerSlots: slices.Clone(slots),
		SeedManifestSHA256: digest(manifestWires["seed-a"]), SeedPrivateIP: ipBySlot["seed-a"],
		Peers: peers, Budget: bootstrap.FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100},
		LaunchDeadline: fixture.now.Add(20 * time.Hour)}
	planWire, err := protocol.EncodeJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(fixture.directory, "founder-plan.candidate.json")
	writeFixture(t, planPath, planWire, 0o600)
	return initialFounderCLIFixture{manifestFixture: fixture, identityPath: identityPath,
		planPath: planPath, selectorPath: filepath.Join(fixture.directory, "founder-selection.candidate.json"),
		manifestPaths: manifestPaths, manifestWires: manifestWires, plan: plan,
		selection: bootstrapstart.FounderSelection{SchemaVersion: 1, DeploymentID: identity.DeploymentID,
			Cell: string(identity.Cell), Environment: identity.Environment, Generation: 1,
			AnchorSHA256: hex.EncodeToString(anchorHash[:]), Manifests: pins}}
}

func (fixture initialFounderCLIFixture) manifestArgs() []string {
	args := make([]string, 0, 2*len(fixture.manifestPaths))
	for _, path := range fixture.manifestPaths {
		args = append(args, "--manifest", path)
	}
	return args
}

func TestSignInitialFounderPlanAndSelection(t *testing.T) {
	fixture := newInitialFounderCLIFixture(t)
	planOutput := filepath.Join(fixture.directory, "founder-plan.signed.json")
	planArgs := []string{"sign-founder-plan", "--candidate", fixture.planPath,
		"--identity", fixture.identityPath, "--anchor", fixture.anchorPath,
		"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath,
		"--out", planOutput, "--valid-for", "21h"}
	planArgs = append(planArgs, fixture.manifestArgs()...)
	if err := runAt(planArgs, fixture.now); err != nil {
		t.Fatalf("sign founder plan: %v", err)
	}
	planWire, err := os.ReadFile(planOutput)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := os.ReadFile(fixture.anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPlan, err := bootstrap.VerifyFounderPlan(planWire, fixture.roots, anchorWire,
		fixture.manifestWires, fixture.now, founderPlanPolicy)
	if err != nil || !verifiedPlan.IsVerified() {
		t.Fatalf("CLI founder plan is not launch-capable: %v", err)
	}
	fixture.selection.PlanSHA256 = digest(planWire)
	selectionPayload, err := protocol.EncodeJSON(fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.selectorPath, selectionPayload, 0o600)
	selectionOutput := filepath.Join(fixture.directory, "founder-selection.signed.json")
	selectionArgs := []string{"sign-initial-founder-selection", "--candidate", fixture.selectorPath,
		"--identity", fixture.identityPath, "--anchor", fixture.anchorPath, "--plan", planOutput,
		"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath,
		"--out", selectionOutput, "--valid-for", "1h"}
	selectionArgs = append(selectionArgs, fixture.manifestArgs()...)
	if err := runAt(selectionArgs, fixture.now); err != nil {
		t.Fatalf("sign generation-one selector: %v", err)
	}
	signedSelection, err := os.ReadFile(selectionOutput)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(signedSelection)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := trust.VerifyCurrent(envelope, trust.Scope{Domain: bootstrapstart.FounderSelectionDomain,
		DeploymentID: fixture.selection.DeploymentID, Cell: fixture.selection.Cell,
		Environment: fixture.selection.Environment, Role: "deployment-anchor", Slot: "region"},
		fixture.roots, fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || !slices.Equal(payload, selectionPayload) {
		t.Fatalf("CLI selector is not the exact reviewed generation-one payload: %v", err)
	}
	fixture.selection.Manifests[0].SHA256 = digest([]byte("changed manifest"))
	badPayload, err := protocol.EncodeJSON(fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.selectorPath, badPayload, 0o600)
	selectionArgs[14] = filepath.Join(fixture.directory, "bad-founder-selection.signed.json")
	if err := runAt(selectionArgs, fixture.now); err == nil {
		t.Fatal("CLI signed a selector with a changed manifest pin")
	}
}
