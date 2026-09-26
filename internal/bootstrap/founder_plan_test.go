package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
	ledgerGrant := signBootstrapLedgerGrant(t, authority.rootPrivate, ledgerPublic, "deployment-a", oci.RegionGRU,
		"production", controllerSlots, now.Add(-time.Hour), now.Add(24*time.Hour))
	ledgerGrantWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	storage := authority.manifest.StorageDomain
	anchorValue := BootstrapAnchor{
		SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: storage,
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
					SecretOCID:    "ocid1.secret.oc1.sa-saopaulo-1." + slot + "-" + name,
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

func TestCompletedFounderPlanVerificationSurvivesLaunchDeadlineOnly(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	fixture.plan.LaunchDeadline = fixture.now.Add(3 * time.Minute)
	fixture.planWire = signFounderPlanWire(t, fixture.plan, fixture.plan.SeedSlot,
		fixture.authority.rootPrivate, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour))
	restartedAt := fixture.now.Add(4 * time.Minute)
	if _, err := VerifyFounderPlan(fixture.planWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, restartedAt, fixture.policy); !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("launch-capable verifier accepted expired launch window: %v", err)
	}
	completed, err := VerifyFounderPlanForCompletedPeerContinuation(fixture.planWire,
		fixture.authority.roots, fixture.anchorWire, fixture.manifestWires, restartedAt, fixture.policy)
	if err != nil || !completed.IsVerified() || completed.Digest() != digestBytes(fixture.planWire) ||
		completed.SeedSlot() != fixture.plan.SeedSlot {
		t.Fatalf("read-only completed plan verification: %+v err=%v", completed, err)
	}
	if !completed.StoredCompletionBeforeLaunchDeadline(fixture.plan.LaunchDeadline.Add(-time.Second),
		fixture.plan.LaunchDeadline.Add(-time.Second)) ||
		completed.StoredCompletionBeforeLaunchDeadline(fixture.plan.LaunchDeadline, fixture.plan.LaunchDeadline) {
		t.Fatal("completed plan did not conservatively enforce durable proof timing")
	}
	deadline := fixture.plan.LaunchDeadline
	for _, test := range []struct {
		name         string
		resultStored time.Time
		headStored   time.Time
		want         bool
	}{
		{name: "both durably before deadline", resultStored: deadline.Add(-2 * time.Second),
			headStored: deadline.Add(-time.Second), want: true},
		{name: "result timely but head late", resultStored: deadline.Add(-2 * time.Second),
			headStored: deadline, want: false},
		{name: "result late but head timely", resultStored: deadline,
			headStored: deadline.Add(-time.Second), want: false},
		{name: "result in deadline second", resultStored: deadline.Add(-time.Second / 2),
			headStored: deadline.Add(-2 * time.Second), want: false},
		{name: "head in deadline second", resultStored: deadline.Add(-2 * time.Second),
			headStored: deadline.Add(-time.Second / 2), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := completed.StoredCompletionBeforeLaunchDeadline(test.resultStored, test.headStored); got != test.want {
				t.Fatalf("stored completion before deadline = %t, want %t", got, test.want)
			}
		})
	}
	row, ok := completed.PeerRow("controller-a")
	if !ok || row.ManifestSHA256 != fixture.plan.Peers[0].ManifestSHA256 {
		t.Fatalf("completed plan lost exact peer row: %+v ok=%v", row, ok)
	}
	row.NetworkSecurityGroupOCIDs[0] = "changed"
	rowAgain, _ := completed.PeerRow("controller-a")
	if rowAgain.NetworkSecurityGroupOCIDs[0] == "changed" {
		t.Fatal("read-only peer row exposed mutable plan storage")
	}
	if _, err := VerifyFounderPlanForCompletedPeerContinuation(fixture.planWire,
		fixture.authority.roots, fixture.anchorWire, fixture.manifestWires,
		fixture.now.Add(24*time.Hour), fixture.policy); err == nil {
		t.Fatal("expired signed plan authorized completed-peer continuation")
	}
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

func TestFounderPlanRejectsCanonicalSignatureScopeAndCurrentAuthorityFailures(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	if _, err := VerifyFounderPlan(append(bytes.Clone(fixture.planWire), '\n'), fixture.authority.roots,
		fixture.anchorWire, fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanInvalid) {
		t.Fatalf("noncanonical envelope error = %v, want ErrFounderPlanInvalid", err)
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFounderPlan(fixture.planWire, wrongRoots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("wrong-root verification error = %v, want ErrFounderPlanAuthorization", err)
	}
	shortLivedWire := signFounderPlanWire(t, fixture.plan, fixture.plan.SeedSlot, fixture.authority.rootPrivate,
		fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour))
	if _, err := VerifyFounderPlan(shortLivedWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("expired root signature error = %v, want ErrFounderPlanAuthorization", err)
	}
	wrongScopeWire := signFounderPlanWire(t, fixture.plan, "controller-a", fixture.authority.rootPrivate,
		fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour))
	if _, err := VerifyFounderPlan(wrongScopeWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("wrong-scope verification error = %v, want ErrFounderPlanAuthorization", err)
	}
	if _, err := VerifyFounderPlan(fixture.planWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.plan.LaunchDeadline, fixture.policy); !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("expired launch deadline error = %v, want ErrFounderPlanExpired", err)
	}
	lateDeadlinePlan := cloneFounderPlan(fixture.plan)
	lateDeadlinePlan.LaunchDeadline = fixture.now.Add(24 * time.Hour)
	lateDeadlineWire := signFounderPlanWire(t, lateDeadlinePlan, fixture.plan.SeedSlot, fixture.authority.rootPrivate,
		fixture.now, fixture.now.Add(24*time.Hour))
	if _, err := VerifyFounderPlan(lateDeadlineWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("deadline beyond original retry bound error = %v, want ErrFounderPlanExpired", err)
	}
	changedAnchor := fixture.anchor.Anchor()
	changedAnchor.ClusterID = "cluster-other"
	changedAnchorEnvelope, err := SignBootstrapAnchor(changedAnchor, fixture.now.Add(-time.Minute),
		fixture.now.Add(24*time.Hour), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	changedAnchorWire, err := trust.EncodeEnvelope(changedAnchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFounderPlan(fixture.planWire, fixture.authority.roots, changedAnchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("changed current anchor error = %v, want ErrFounderPlanAuthorization", err)
	}
}

func TestFounderPlanValidatesExactPeersBudgetAndBoundedTopology(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	tests := []struct {
		name   string
		mutate func(*FounderPlan)
	}{
		{name: "missing peer", mutate: func(plan *FounderPlan) { plan.Peers = plan.Peers[:1] }},
		{name: "invalid image compartment", mutate: func(plan *FounderPlan) { plan.Peers[0].ImageCompartmentOCID = "ocid1.tenancy.oc1..imageowner" }},
		{name: "unsupported boot tier", mutate: func(plan *FounderPlan) { plan.Peers[0].BootVolumeTier = FounderBootVolumeTier("custom") }},
		{name: "boot volume below OCI minimum", mutate: func(plan *FounderPlan) { plan.Peers[0].BootVolumeGB = 49 }},
		{name: "boot volume above OCI maximum", mutate: func(plan *FounderPlan) { plan.Peers[0].BootVolumeGB = 32769 }},
		{name: "duplicate slot", mutate: func(plan *FounderPlan) { plan.Peers[1].Slot = plan.Peers[0].Slot }},
		{name: "duplicate IP", mutate: func(plan *FounderPlan) { plan.Peers[1].PrivateIP = plan.Peers[0].PrivateIP }},
		{name: "duplicate seed IP", mutate: func(plan *FounderPlan) { plan.Peers[0].PrivateIP = plan.SeedPrivateIP }},
		{name: "unbounded endpoint", mutate: func(plan *FounderPlan) { plan.Peers[0].RouteEndpoints[0].PrivateIP = "0.0.0.0" }},
		{name: "cross-region hostname", mutate: func(plan *FounderPlan) { plan.Peers[0].RouteEndpoints[0].PrivateIP = "route.eu.example" }},
		{name: "mismatched budget", mutate: func(plan *FounderPlan) { plan.Budget.MemoryInGB++ }},
		{name: "resource overflow", mutate: func(plan *FounderPlan) {
			plan.Peers[0].WholeOCPUs = ^uint32(0)
			plan.Budget.WholeOCPUs = ^uint32(0)
		}},
		{name: "unbounded TLS digest", mutate: func(plan *FounderPlan) { plan.Peers[0].TLSMaterial.RouteCA = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := cloneFounderPlan(fixture.plan)
			test.mutate(&plan)
			if err := plan.Validate(); !errors.Is(err, ErrFounderPlanInvalid) {
				t.Fatalf("FounderPlan.Validate() error = %v, want ErrFounderPlanInvalid", err)
			}
		})
	}
	if err := fixture.plan.Validate(); err != nil {
		t.Fatalf("valid exact-two-peer budget/topology: %v", err)
	}
	maxVolumePlan := cloneFounderPlan(fixture.plan)
	maxVolumePlan.Peers[0].BootVolumeGB = 32768
	maxVolumePlan.Peers[1].BootVolumeGB = 32768
	maxVolumePlan.Budget.BootVolumeGB = 65536
	if err := maxVolumePlan.Validate(); err != nil {
		t.Fatalf("maximum OCI boot-volume size should be accepted: %v", err)
	}
	if vpusPerGB, supported := FounderBootVolumeTierBalanced.VPUsPerGB(); !supported || vpusPerGB != 10 {
		t.Fatalf("balanced boot-volume VPUs/GB = %d, supported %v; want 10, true", vpusPerGB, supported)
	}
	if _, supported := FounderBootVolumeTier("custom").VPUsPerGB(); supported {
		t.Fatal("unknown boot-volume tier unexpectedly has an OCI VPU mapping")
	}
}

func TestFounderPeerRowUsesCompartmentAndTierWirePins(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	wire, err := json.Marshal(fixture.plan.Peers[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["image_compartment_ocid"]; !ok {
		t.Fatalf("founder peer wire omits image_compartment_ocid: %s", wire)
	}
	if _, ok := fields["imageOwnerOcid"]; ok {
		t.Fatalf("founder peer wire still carries an unverifiable image owner: %s", wire)
	}
	var tier string
	if err := json.Unmarshal(fields["bootVolumeTier"], &tier); err != nil || tier != "balanced" {
		t.Fatalf("boot volume tier wire = %q, error %v; want balanced", tier, err)
	}
}

func TestFounderPlanRejectsManifestReplayAndUnpinnedMaterial(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	missing := cloneFounderManifestWires(fixture.manifestWires)
	delete(missing, "controller-b")
	if _, err := VerifyFounderPlan(fixture.planWire, fixture.authority.roots, fixture.anchorWire,
		missing, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("missing slot manifest error = %v, want ErrFounderPlanAuthorization", err)
	}

	plan := cloneFounderPlan(fixture.plan)
	plan.Peers[0].TLSMaterial.ClientCA = digestBytes([]byte("not in peer manifest"))
	planWire := signFounderPlanWire(t, plan, plan.SeedSlot, fixture.authority.rootPrivate,
		fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour))
	if _, err := VerifyFounderPlan(planWire, fixture.authority.roots, fixture.anchorWire,
		fixture.manifestWires, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("unpinned TLS digest error = %v, want ErrFounderPlanAuthorization", err)
	}

	changed := cloneFounderManifestWires(fixture.manifestWires)
	peerManifest := manifestFromWire(t, changed["controller-a"], fixture.authority.roots, fixture.now, fixture.policy)
	peerManifest.Profiles[0].Shape = "VM.Standard.E4.Flex"
	changedEnvelope, err := SignManifest(peerManifest, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	changed["controller-a"], err = trust.EncodeEnvelope(changedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	plan = cloneFounderPlan(fixture.plan)
	plan.Peers[0].ManifestSHA256, err = trust.Fingerprint(changedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	planWire = signFounderPlanWire(t, plan, plan.SeedSlot, fixture.authority.rootPrivate,
		fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour))
	if _, err := VerifyFounderPlan(planWire, fixture.authority.roots, fixture.anchorWire,
		changed, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPlanAuthorization) {
		t.Fatalf("overlapping profile mismatch error = %v, want ErrFounderPlanAuthorization", err)
	}
}

func TestFounderPeerRejectsPlanAndRowDigestReplay(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	verified := fixture.verify(t)
	row := fixture.plan.Peers[0]
	for _, test := range []struct {
		name          string
		planDigestPin string
		rowDigestPin  string
	}{
		{name: "plan digest", planDigestPin: digestBytes([]byte("other plan"))},
		{name: "peer row digest", rowDigestPin: digestBytes([]byte("other row"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			launch := fixture.launchAuthorization(t, verified, row, test.planDigestPin, test.rowDigestPin)
			if _, err := verified.AuthorizePeer(row.Slot, launch, fixture.authority.roots, fixture.now, fixture.policy); !errors.Is(err, ErrFounderPeerAuthorization) {
				t.Fatalf("replayed authorization error = %v, want ErrFounderPeerAuthorization", err)
			}
		})
	}
}

func TestFounderPeerDeadlineUsesOriginalIntentRetryTimestamp(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	verified := fixture.verify(t)
	row := fixture.plan.Peers[0]
	launch := fixture.launchAuthorization(t, verified, row, "", "")
	launch.intentRecord.LastModified = fixture.now.Add(-2 * time.Hour)
	launch.intentRecord.ServerDate = fixture.now
	if _, err := verified.AuthorizePeer(row.Slot, launch, fixture.authority.roots,
		fixture.now.Add(21*time.Hour), fixture.policy); !errors.Is(err, ErrFounderPlanExpired) {
		t.Fatalf("original retry deadline error = %v, want ErrFounderPlanExpired", err)
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
		SchemaVersion: 2, Mode: IntentModeManaged, DeploymentID: anchor.DeploymentID,
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
		SchemaVersion: 2, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: anchor.Environment,
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

func cloneFounderManifestWires(wires map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(wires))
	for slot, wire := range wires {
		cloned[slot] = bytes.Clone(wire)
	}
	return cloned
}

func manifestFromWire(t *testing.T, wire []byte, roots trust.Keyring, now time.Time, policy trust.Policy) Manifest {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := trust.VerifyCurrent(envelope, envelope.Scope, roots, now, policy)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ManifestPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
