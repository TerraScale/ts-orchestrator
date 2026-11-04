package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type founderPlanFixture struct {
	now           time.Time
	policy        trust.Policy
	authority     testBootstrapAuthority
	anchor        VerifiedBootstrapAnchor
	anchorWire    []byte
	plan          FounderPlan
	planWire      []byte
	manifestWires map[string][]byte
}

func newFounderPlanFixture(t *testing.T) founderPlanFixture {
	t.Helper()
	authority := newTestBootstrapAuthority(t)
	now := authority.now
	policy := trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: time.Minute}
	controllerSlots := []string{"controller-a", "controller-b", "seed-a"}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{
		SchemaVersion: 1, Generation: 4, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerGrant := signBootstrapLedgerGrant(t, authority.rootPrivate, ledgerPublic, "0000000000F9PR1WNVDTEXS31Z", oci.RegionGRU,
		"production", controllerSlots, now.Add(-time.Hour), now.Add(24*time.Hour))
	ledgerGrantWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	storage := authority.manifest.StorageDomain
	anchorValue := BootstrapAnchor{
		SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production",
		ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: storage,
		ControllerSlots: slices.Clone(controllerSlots), LedgerDelegationWire: ledgerGrantWire,
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: digestBytes(intentWire),
		InitialRegionIntentWire: bytes.Clone(intentWire),
	}
	anchorEnvelope, err := SignBootstrapAnchor(anchorValue, now.Add(-time.Minute), now.Add(24*time.Hour), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := VerifyBootstrapAnchor(anchorEnvelope, authority.roots, BootstrapAnchorExpectation{
		DeploymentID: anchorValue.DeploymentID, Environment: anchorValue.Environment, Cell: anchorValue.Cell,
	}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}

	peerSlots := []string{"controller-a", "controller-b"}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerDelegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, authority.peerPublic), SubjectPublicKey: peerPublicWire,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: anchorValue.DeploymentID, Cell: string(anchorValue.Cell),
			Environment: anchorValue.Environment, Role: roleController, Slots: peerSlots, Actions: []string{"sign"},
		}},
	}, now.Add(-time.Hour), now.Add(23*time.Hour), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}

	regionIPs := map[string]string{"seed-a": "10.44.0.10", "controller-a": "10.44.0.11", "controller-b": "10.44.0.12"}
	profiles := []LaunchProfile{
		founderProfile("controller-a", "FAULT-DOMAIN-1"),
		founderProfile("controller-b", "FAULT-DOMAIN-2"),
		founderProfile("seed-a", "FAULT-DOMAIN-3"),
	}
	manifestWires := make(map[string][]byte, len(controllerSlots))
	manifestDigests := make(map[string]string, len(controllerSlots))
	for _, slot := range controllerSlots {
		manifest := cloneManifest(authority.manifest)
		manifest.DeploymentID = anchorValue.DeploymentID
		manifest.Environment = anchorValue.Environment
		manifest.ClusterID = anchorValue.ClusterID
		manifest.Cell = anchorValue.Cell
		manifest.OCIRegion = anchorValue.OCIRegion
		manifest.IntentGeneration = anchorValue.InitialRegionIntentGeneration
		manifest.IntentSHA256 = anchorValue.InitialRegionIntentSHA256
		manifest.ControllerRole = roleController
		manifest.Slot = slot
		manifest.SeedSlot = "seed-a"
		manifest.ControllerSlots = slices.Clone(controllerSlots)
		manifest.Profiles = slices.Clone(profiles)
		manifest.ImageOCID = authority.manifest.ImageOCID
		manifest.StorageDomain = storage
		manifest.PeerReceiptDelegation = &peerDelegation
		manifest.Secrets = nil
		if slot != "seed-a" {
			material := founderTLSMaterial(slot)
			for index, digest := range material.digests() {
				name := founderTLSMaterialName(index)
				manifest.Secrets = append(manifest.Secrets, SecretReference{
					Purpose: SecretController, Slot: slot,
					SecretOCID:    "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot + "-" + name,
					VersionNumber: 1, SHA256: digest, MaxBytes: 1024, TargetFile: slot + "-" + name + ".pem",
				})
			}
		}
		envelope, err := SignManifest(manifest, now.Add(-time.Minute), now.Add(23*time.Hour), authority.rootPrivate)
		if err != nil {
			t.Fatalf("sign %s manifest: %v", slot, err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		manifestWires[slot] = wire
		manifestDigests[slot], err = trust.Fingerprint(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}

	peers := make([]FounderPeerRow, 0, founderPlanPeerCount)
	for _, slot := range peerSlots {
		profile := profileForSlot(t, profiles, slot)
		routes := make([]FounderEndpoint, 0, founderPlanPeerCount)
		for _, target := range controllerSlots {
			if target != slot {
				routes = append(routes, FounderEndpoint{Slot: target, PrivateIP: regionIPs[target], Port: 6222})
			}
		}
		peers = append(peers, FounderPeerRow{
			Slot: slot, ManifestSHA256: manifestDigests[slot], ImageOCID: authority.manifest.ImageOCID,
			ImageCompartmentOCID: "ocid1.compartment.oc1..imagecompartment", CompartmentOCID: profile.CompartmentOCID,
			AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
			SubnetOCID: profile.SubnetOCID, NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs),
			Shape: profile.Shape, WholeOCPUs: 2, MemoryInGB: 12, BootVolumeGB: 50,
			BootVolumeTier: FounderBootVolumeTierBalanced,
			PrivateIP:      regionIPs[slot], RouteEndpoints: routes,
			ClientEndpoints: []FounderEndpoint{{Slot: slot, PrivateIP: regionIPs[slot], Port: 4222}},
			TLSMaterial:     founderTLSMaterial(slot),
		})
	}
	plan := FounderPlan{
		SchemaVersion: FounderPlanSchemaVersion, DeploymentID: anchorValue.DeploymentID, Cell: anchorValue.Cell,
		Environment: anchorValue.Environment, SeedSlot: "seed-a", AnchorSHA256: anchor.Digest(),
		ControllerSlots: slices.Clone(controllerSlots), SeedManifestSHA256: manifestDigests["seed-a"],
		SeedPrivateIP: regionIPs["seed-a"], Peers: peers,
		Budget:         FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100},
		LaunchDeadline: now.Add(22 * time.Hour),
	}
	planWire := signFounderPlanWire(t, plan, "seed-a", authority.rootPrivate, now.Add(-time.Minute), now.Add(23*time.Hour))
	return founderPlanFixture{
		now: now, policy: policy, authority: authority, anchor: anchor, anchorWire: anchorWire,
		plan: plan, planWire: planWire, manifestWires: manifestWires,
	}
}

func founderProfile(slot, faultDomain string) LaunchProfile {
	return LaunchProfile{
		Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..compartment",
		AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: faultDomain,
		SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1." + slot,
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1." + slot},
		Shape:                     "VM.Standard.E5.Flex",
	}
}

func profileForSlot(t *testing.T, profiles []LaunchProfile, slot string) LaunchProfile {
	t.Helper()
	for _, profile := range profiles {
		if profile.Slot == slot {
			return cloneProfile(profile)
		}
	}
	t.Fatalf("profile for %q is missing", slot)
	return LaunchProfile{}
}

func founderTLSMaterial(slot string) FounderTLSMaterialDigests {
	return FounderTLSMaterialDigests{
		ClientCA:          digestBytes([]byte(slot + " client ca")),
		ClientCertificate: digestBytes([]byte(slot + " client certificate")),
		ClientPrivateKey:  digestBytes([]byte(slot + " client private key")),
		RouteCA:           digestBytes([]byte(slot + " route ca")),
		RouteCertificate:  digestBytes([]byte(slot + " route certificate")),
		RoutePrivateKey:   digestBytes([]byte(slot + " route private key")),
	}
}

func founderTLSMaterialName(index int) string {
	return [...]string{"client-ca", "client-certificate", "client-key", "route-ca", "route-certificate", "route-key"}[index]
}

func signFounderPlanWire(
	t *testing.T,
	plan FounderPlan,
	scopeSlot string,
	root ed25519.PrivateKey,
	issuedAt time.Time,
	expiresAt time.Time,
) []byte {
	t.Helper()
	payload, err := trust.EncodePayload(plan)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{
		Domain: FounderPlanDomain, DeploymentID: plan.DeploymentID, Cell: string(plan.Cell),
		Environment: plan.Environment, Role: roleController, Slot: scopeSlot,
	}, issuedAt, expiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture founderPlanFixture) verify(t *testing.T) VerifiedFounderPlan {
	t.Helper()
	verified, err := VerifyFounderPlan(fixture.planWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy)
	if err != nil {
		t.Fatalf("VerifyFounderPlan(): %v", err)
	}
	return verified
}

func TestVerifyFounderPlanAndAuthorizePeerFromExactLaunchToken(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	verified := fixture.verify(t)
	if verified.Digest() == "" || !verified.IsVerified() || !slices.Equal(verified.Plan().ControllerSlots, fixture.plan.ControllerSlots) {
		t.Fatal("verified plan did not preserve its exact root-authorized topology")
	}
	row := fixture.plan.Peers[0]
	launch := fixture.launchAuthorization(t, verified, row, "", "")
	peer, err := verified.AuthorizePeer(row.Slot, launch, fixture.authority.roots, fixture.now, fixture.policy)
	if err != nil {
		t.Fatalf("AuthorizePeer(): %v", err)
	}
	request, err := peer.LaunchRequest(fixture.now)
	if err != nil {
		t.Fatalf("LaunchRequest(): %v", err)
	}
	if !peer.IsVerified() || request.Slot != row.Slot ||
		request.FounderPlanSHA256 != verified.Digest() || request.ManifestSHA256 != row.ManifestSHA256 ||
		request.Row.ImageCompartmentOCID != row.ImageCompartmentOCID ||
		request.Row.PrivateIP != row.PrivateIP || request.RetryToken != launch.intent.RetryToken ||
		request.Row.TLSMaterial.ClientCA != row.TLSMaterial.ClientCA {
		t.Fatalf("typed founder launch request lost a signed pin: %+v", request)
	}
	if !peer.EffectDeadline().Equal(fixture.plan.LaunchDeadline) {
		t.Fatalf("effect deadline = %s, want earlier signed plan deadline %s", peer.EffectDeadline(), fixture.plan.LaunchDeadline)
	}
	if _, err := peer.LaunchRequest(fixture.plan.LaunchDeadline); !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("launch request at its deadline = %v, want ErrFounderPlanExpired", err)
	}
	request.Row.NetworkSecurityGroupOCIDs[0] = "mutated"
	second, err := peer.LaunchRequest(fixture.now)
	if err != nil || second.Row.NetworkSecurityGroupOCIDs[0] == "mutated" {
		t.Fatal("founder peer launch request did not return defensive row copies")
	}
}

func (fixture founderPlanFixture) launchAuthorization(
	t *testing.T,
	plan VerifiedFounderPlan,
	row FounderPeerRow,
	planDigestPin string,
	rowDigestPin string,
) LaunchAuthorization {
	t.Helper()
	client := newFakeObjectStorageClient()
	client.setNow(fixture.now)
	controllerSlots := slices.Clone(fixture.plan.ControllerSlots)
	capabilities := make([]trust.Capability, 0, 3)
	for _, domain := range []string{domainBootstrapHead, domainBootstrapIntent, domainBootstrapResult,
		domainBootstrapCandidate, domainBootstrapProgress} {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: fixture.plan.DeploymentID, Cell: string(fixture.plan.Cell),
			Environment: fixture.plan.Environment, Role: roleController, Slots: slices.Clone(controllerSlots), Actions: []string{"sign"},
		})
	}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(fixture.authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, fixture.authority.peerPublic),
		SubjectPublicKey: peerPublicWire, Capabilities: capabilities,
	}, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.VerifyDelegationCurrent(ledgerGrant, fixture.authority.roots, fixture.now, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	anchor := fixture.anchor.Anchor()
	config := LedgerConfig{
		DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     anchor.StorageDomain.Namespace, Bucket: anchor.StorageDomain.LedgerBucket,
		KMSKeyID: anchor.StorageDomain.LedgerKMSKeyOCID, Prefix: anchor.StorageDomain.Prefix,
		HeadBucket: anchor.StorageDomain.HeadBucket, HeadKMSKeyID: anchor.StorageDomain.HeadKMSKeyOCID,
		Environment: anchor.Environment, ControllerSlots: controllerSlots, AnchorExpiresAt: fixture.anchor.ExpiresAt(),
		TrustRoots: fixture.authority.roots, Delegations: []trust.VerifiedDelegation{delegation},
		TrustPolicy: fixture.policy, VerificationNow: client.currentTime,
	}
	ledger, err := NewLedger(client, config)
	if err != nil {
		t.Fatalf("NewLedger(): %v", err)
	}
	profile := LaunchProfile{
		Slot: row.Slot, CompartmentOCID: row.CompartmentOCID, AvailabilityDomain: row.AvailabilityDomain,
		FaultDomain: row.FaultDomain, SubnetOCID: row.SubnetOCID,
		NetworkSecurityGroupOCIDs: slices.Clone(row.NetworkSecurityGroupOCIDs), Shape: row.Shape,
	}
	launchDigest, err := launchProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	rowDigest, err := FounderPeerRowDigest(row)
	if err != nil {
		t.Fatal(err)
	}
	if planDigestPin == "" {
		planDigestPin = plan.Digest()
	}
	if rowDigestPin == "" {
		rowDigestPin = rowDigest
	}
	intent := Intent{
		SchemaVersion: 1, Mode: IntentModeManaged, DeploymentID: anchor.DeploymentID,
		Cell: string(anchor.Cell), Environment: anchor.Environment, Role: roleController, Slot: row.Slot,
		Attempt: 1, Generation: 1, ManifestDigest: row.ManifestSHA256,
		ReleaseReceiptDigest: digestBytes([]byte("release")), RegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		ImageOCID: row.ImageOCID, RegionIntentDigest: anchor.InitialRegionIntentSHA256,
		LaunchRequestDigest: launchDigest, FounderPlanSHA256: planDigestPin, PeerRowDigest: rowDigestPin,
		CreateKey: "create-" + row.Slot, RetryToken: "retry-" + row.Slot, CreatedAt: fixture.now,
		OCIRegion: "sa-saopaulo-1", CompartmentOCID: row.CompartmentOCID,
		AvailabilityDomain: row.AvailabilityDomain, FaultDomain: row.FaultDomain, SubnetOCID: row.SubnetOCID,
		NetworkSecurityGroupIDs: slices.Clone(row.NetworkSecurityGroupOCIDs), Shape: row.Shape, Node: row.Slot,
	}
	scope := BootstrapScope{DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: row.Slot}
	intentPayload, err := trust.EncodePayload(intent)
	if err != nil {
		t.Fatal(err)
	}
	intentEnvelope, err := trust.Sign(intentPayload, trust.Scope{
		Domain: domainBootstrapIntent, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: anchor.Environment, Role: roleController, Slot: row.Slot,
	}, fixture.now, fixture.now.Add(23*time.Hour), fixture.authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodeEnvelope(intentEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	head := SlotHead{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: anchor.Environment,
		Role: roleController, Slot: row.Slot, Attempt: 1, Generation: 1, IntentDigest: digestBytes(intentWire),
	}
	headPayload, err := trust.EncodePayload(head)
	if err != nil {
		t.Fatal(err)
	}
	headEnvelope, err := trust.Sign(headPayload, trust.Scope{
		Domain: domainBootstrapHead, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: anchor.Environment, Role: roleController, Slot: row.Slot,
	}, fixture.now, fixture.now.Add(23*time.Hour), fixture.authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	headWire, err := trust.EncodeEnvelope(headEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.ReserveSlot(t.Context(), scope, intentWire, headWire); err != nil {
		t.Fatalf("ReserveSlot(): %v", err)
	}
	launch, err := ledger.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("ReadForLaunch(): %v", err)
	}
	return launch
}
