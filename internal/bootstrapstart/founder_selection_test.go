package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type founderSelectionObjects struct {
	items map[string][]byte
	reads map[string]int
	onGet func(string, int)
}

func (objects *founderSelectionObjects) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if request.NamespaceName == nil || *request.NamespaceName != "namespace-a" {
		return objectstorage.GetObjectResponse{}, errors.New("reader escaped baked namespace")
	}
	key := *request.BucketName + "/" + *request.ObjectName
	objects.reads[key]++
	if objects.onGet != nil {
		objects.onGet(key, objects.reads[key])
	}
	body, ok := objects.items[key]
	if !ok {
		return objectstorage.GetObjectResponse{}, errors.New("missing exact object")
	}
	etag := digestWire(body)
	length := int64(len(body))
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(body)),
		ContentLength: &length, ETag: &etag}, nil
}

type founderSelectionFixture struct {
	now        time.Time
	root       ed25519.PrivateKey
	baked      BakedInputs
	accepted   AcceptedInstall
	domain     bootstrap.StorageDomain
	plan       bootstrap.FounderPlan
	planWire   []byte
	anchorWire []byte
	manifests  map[string][]byte
	objects    *founderSelectionObjects
	floor      *FounderSelectionFloorStore
	selection  FounderSelection
}

func newFounderSelectionFixture(t *testing.T) *founderSelectionFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
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
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-a", "controller-b", "seed-a"}
	domain := bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "head-bucket",
		HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"}
	ledgerWire := signTestDelegation(t, root, ledgerPublic, []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result"}, slots, now.Add(-time.Hour), now.Add(24*time.Hour))
	regionWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	anchorValue := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", StorageDomain: domain, ControllerSlots: slots, LedgerDelegationWire: ledgerWire,
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: digestWire(regionWire), InitialRegionIntentWire: regionWire}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(anchorValue, now.Add(-time.Minute), now.Add(23*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	peerDelegationWire := signTestDelegation(t, root, peerPublic, []string{"terrascale.bootstrap.peer-receipt"}, slots[:2], now.Add(-time.Hour), now.Add(23*time.Hour))
	peerDelegation, err := trust.DecodeEnvelope(peerDelegationWire)
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, err := trust.Sign([]byte(`{}`), trust.Scope{Domain: "terrascale.release.image", DeploymentID: "release-a",
		Cell: "GRU", Environment: "production", Role: "oci-image", Slot: "ocid1.image.oc1.sa-saopaulo-1.image"},
		now.Add(-time.Minute), now.Add(23*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	releaseWire, err := trust.EncodeEnvelope(releaseEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	profiles := make([]bootstrap.LaunchProfile, 0, 3)
	ipBySlot := map[string]string{"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "seed-a": "10.44.0.10"}
	for i, slot := range slots {
		profiles = append(profiles, bootstrap.LaunchProfile{Slot: slot,
			CompartmentOCID: "ocid1.compartment.oc1..compartment", AvailabilityDomain: "SA-SAOPAULO-1-AD-1",
			FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", i+1), SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1." + slot,
			NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1." + slot}, Shape: "VM.Standard.E5.Flex"})
	}
	manifests := make(map[string][]byte, 3)
	pins := make([]FounderManifestPin, 0, 3)
	for _, slot := range slots {
		manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion,
			DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a", Cell: oci.RegionGRU,
			OCIRegion: "sa-saopaulo-1", IntentGeneration: 4, IntentSHA256: digestWire(regionWire),
			ControllerRole: "controller", Slot: slot, SeedSlot: "seed-a", ControllerSlots: slices.Clone(slots),
			Profiles: slices.Clone(profiles), ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image", ImageArchitecture: "linux-amd64",
			ReleaseReceiptSHA256: digestWire(releaseWire), ReleaseImageReceiptWire: releaseWire,
			ReleaseDelegationWire: peerDelegationWire, PeerReceiptDelegation: &peerDelegation, StorageDomain: domain}
		if slot != "seed-a" {
			for i, name := range []string{"client-ca", "client-certificate", "client-key", "route-ca", "route-certificate", "route-key"} {
				manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: bootstrap.SecretController, Slot: slot,
					SecretOCID: fmt.Sprintf("ocid1.secret.oc1.sa-saopaulo-1.%s-%d", slot, i), VersionNumber: 1,
					SHA256: digestWire([]byte(slot + name)), MaxBytes: 1024, TargetFile: slot + "-" + name + ".pem"})
			}
		}
		envelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(22*time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		manifests[slot] = wire
		pins = append(pins, FounderManifestPin{Slot: slot, SHA256: digestWire(wire)})
	}
	peers := make([]bootstrap.FounderPeerRow, 0, 2)
	for i, slot := range slots[:2] {
		material := bootstrap.FounderTLSMaterialDigests{
			ClientCA: digestWire([]byte(slot + "client-ca")), ClientCertificate: digestWire([]byte(slot + "client-certificate")),
			ClientPrivateKey: digestWire([]byte(slot + "client-key")), RouteCA: digestWire([]byte(slot + "route-ca")),
			RouteCertificate: digestWire([]byte(slot + "route-certificate")), RoutePrivateKey: digestWire([]byte(slot + "route-key"))}
		routes := make([]bootstrap.FounderEndpoint, 0, 2)
		for _, target := range slots {
			if target != slot {
				routes = append(routes, bootstrap.FounderEndpoint{Slot: target, PrivateIP: ipBySlot[target], Port: 6222})
			}
		}
		peers = append(peers, bootstrap.FounderPeerRow{Slot: slot, ManifestSHA256: digestWire(manifests[slot]),
			ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image", ImageCompartmentOCID: "ocid1.compartment.oc1..imagecompartment",
			CompartmentOCID: profiles[i].CompartmentOCID, AvailabilityDomain: profiles[i].AvailabilityDomain,
			FaultDomain: profiles[i].FaultDomain, SubnetOCID: profiles[i].SubnetOCID,
			NetworkSecurityGroupOCIDs: slices.Clone(profiles[i].NetworkSecurityGroupOCIDs), Shape: profiles[i].Shape,
			WholeOCPUs: 2, MemoryInGB: 12, BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced,
			PrivateIP: ipBySlot[slot], RouteEndpoints: routes,
			ClientEndpoints: []bootstrap.FounderEndpoint{{Slot: slot, PrivateIP: ipBySlot[slot], Port: 4222}}, TLSMaterial: material})
	}
	plan := bootstrap.FounderPlan{SchemaVersion: bootstrap.FounderPlanSchemaVersion, DeploymentID: "deployment-a",
		Cell: oci.RegionGRU, Environment: "production", SeedSlot: "seed-a", AnchorSHA256: digestWire(anchorWire),
		ControllerSlots: slots, SeedManifestSHA256: digestWire(manifests["seed-a"]), SeedPrivateIP: ipBySlot["seed-a"],
		Peers: peers, Budget: bootstrap.FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100},
		LaunchDeadline: now.Add(21 * time.Hour)}
	planPayload, err := trust.EncodePayload(plan)
	if err != nil {
		t.Fatal(err)
	}
	planEnvelope, err := trust.Sign(planPayload, trust.Scope{Domain: bootstrap.FounderPlanDomain, DeploymentID: "deployment-a",
		Cell: "GRU", Environment: "production", Role: "controller", Slot: "seed-a"}, now.Add(-time.Minute), now.Add(22*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	planWire, err := trust.EncodeEnvelope(planEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifests, now,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: time.Minute}); err != nil {
		t.Fatalf("founder fixture: %v", err)
	}
	accepted := testMarker()
	accepted.Slot, accepted.AnchorSHA256, accepted.AcceptedAt = "seed-a", digestWire(anchorWire), now
	accepted.ManifestSHA256 = digestWire(manifests["seed-a"])
	selection := FounderSelection{SchemaVersion: 1, DeploymentID: "deployment-a", Cell: "GRU", Environment: "production",
		Generation: 1, PlanSHA256: digestWire(planWire), AnchorSHA256: digestWire(anchorWire), Manifests: pins}
	return &founderSelectionFixture{now: now, root: root,
		baked:    BakedInputs{Identity: BakedIdentity{SchemaVersion: 1, DeploymentID: "deployment-a", Cell: oci.RegionGRU, Environment: "production"}, Roots: roots, AnchorWire: anchorWire},
		accepted: accepted, domain: domain, plan: plan, planWire: planWire, anchorWire: anchorWire, manifests: manifests,
		objects: &founderSelectionObjects{items: make(map[string][]byte), reads: make(map[string]int)},
		floor:   testFounderFloor(t), selection: selection}
}

func signTestDelegation(t *testing.T, root ed25519.PrivateKey, subject ed25519.PublicKey,
	domains, slots []string, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	keyID, err := trust.KeyID(subject)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(subject)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, len(domains))
	for _, domain := range domains {
		capabilities = append(capabilities, trust.Capability{Domain: domain,
			DeploymentID: "deployment-a", Cell: "GRU", Environment: "production", Role: "controller",
			Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: publicWire, Capabilities: capabilities}, issuedAt, expiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture *founderSelectionFixture) signSelection(t *testing.T, selection FounderSelection, expiresAt time.Time) []byte {
	t.Helper()
	payload, err := protocol.EncodeJSON(selection)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: FounderSelectionDomain,
		DeploymentID: "deployment-a", Cell: "GRU", Environment: "production",
		Role: "deployment-anchor", Slot: "region"}, fixture.now.Add(-time.Minute), expiresAt, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture *founderSelectionFixture) publish(t *testing.T, selection FounderSelection) []byte {
	t.Helper()
	selectionWire := fixture.signSelection(t, selection, fixture.now.Add(time.Hour))
	selector := FounderSelectionObjectName(fixture.domain, "deployment-a", "GRU", "production")
	fixture.objects.items[fixture.domain.HeadBucket+"/"+selector] = selectionWire
	for digest, wire := range map[string][]byte{digestWire(fixture.planWire): fixture.planWire,
		digestWire(fixture.anchorWire): fixture.anchorWire} {
		fixture.objects.items[fixture.domain.LedgerBucket+"/"+FounderImmutableObjectName(fixture.domain,
			"deployment-a", "GRU", "production", digest)] = wire
	}
	for _, wire := range fixture.manifests {
		digest := digestWire(wire)
		fixture.objects.items[fixture.domain.LedgerBucket+"/"+FounderImmutableObjectName(fixture.domain,
			"deployment-a", "GRU", "production", digest)] = wire
	}
	return selectionWire
}

func (fixture *founderSelectionFixture) reader(t *testing.T) *CurrentFounderAuthorityReader {
	t.Helper()
	reader, err := NewCurrentFounderAuthorityReader(fixture.baked, fixture.accepted, fixture.objects, fixture.floor)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func TestCurrentFounderSelectionReadsRealSignedSnapshotAndSupersedes(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	a := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(a)); err != nil {
		t.Fatal(err)
	}
	reader := fixture.reader(t)
	current, err := reader.ReadCurrent(t.Context(), fixture.now)
	if err != nil || !current.Plan.IsVerified() || current.Plan.Digest() != digestWire(fixture.planWire) {
		t.Fatalf("selected A: %+v, %v", current, err)
	}
	oldPlanDigest, oldAnchorDigest := digestWire(fixture.planWire), digestWire(fixture.anchorWire)
	fixture.resignSelectedAnchorAndPlan(t)
	bSelection := fixture.selection
	bSelection.Generation = 2
	bSelection.PlanSHA256 = digestWire(fixture.planWire)
	bSelection.AnchorSHA256 = digestWire(fixture.anchorWire)
	b := fixture.publish(t, bSelection)
	current, err = reader.ReadCurrent(t.Context(), fixture.now)
	if err != nil || current.SelectionGeneration != 2 || current.SelectionSHA256 != digestWire(b) ||
		current.Plan.Digest() == oldPlanDigest || current.Anchor.Digest() == oldAnchorDigest {
		t.Fatalf("selected B: generation=%d err=%v", current.SelectionGeneration, err)
	}
	fixture.objects.items[fixture.domain.HeadBucket+"/"+FounderSelectionObjectName(fixture.domain,
		"deployment-a", "GRU", "production")] = a
	restarted := fixture.reader(t)
	if _, err := restarted.ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("unexpired selected B rolled back to A: %v", err)
	}
}

func (fixture *founderSelectionFixture) resignSelectedAnchorAndPlan(t *testing.T) {
	t.Helper()
	oldEnvelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(oldEnvelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		t.Fatal(err)
	}
	newAnchor, err := bootstrap.SignBootstrapAnchor(anchor, fixture.now.Add(-30*time.Second), fixture.now.Add(23*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchorWire, err = trust.EncodeEnvelope(newAnchor)
	if err != nil {
		t.Fatal(err)
	}
	fixture.plan.AnchorSHA256 = digestWire(fixture.anchorWire)
	payload, err := trust.EncodePayload(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	newPlan, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain, DeploymentID: "deployment-a",
		Cell: "GRU", Environment: "production", Role: "controller", Slot: "seed-a"},
		fixture.now.Add(-30*time.Second), fixture.now.Add(22*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.planWire, err = trust.EncodeEnvelope(newPlan)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCurrentFounderSelectionRejectsTornAndWrongPins(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*founderSelectionFixture)
	}{
		{name: "plan digest", mutate: func(f *founderSelectionFixture) { f.selection.PlanSHA256 = strings.Repeat("a", 64) }},
		{name: "manifest digest", mutate: func(f *founderSelectionFixture) { f.selection.Manifests[0].SHA256 = strings.Repeat("b", 64) }},
		{name: "wrong scope", mutate: func(f *founderSelectionFixture) { f.selection.Cell = "SFO" }},
		{name: "missing manifest", mutate: func(f *founderSelectionFixture) { f.selection.Manifests = f.selection.Manifests[:2] }},
		{name: "torn selector", mutate: func(f *founderSelectionFixture) {
			key := f.domain.HeadBucket + "/" + FounderSelectionObjectName(f.domain, "deployment-a", "GRU", "production")
			f.objects.onGet = func(got string, count int) {
				if got == key && count == 2 {
					f.objects.items[key] = []byte(`{"changed":true}`)
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFounderSelectionFixture(t)
			test.mutate(fixture)
			wire := fixture.publish(t, fixture.selection)
			if err := fixture.floor.Initialize(1, digestWire(wire)); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
				t.Fatalf("invalid selection: %v", err)
			}
		})
	}
}

func TestCurrentFounderSelectionRejectsExpiredAndMissingFloor(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	fixture.publish(t, fixture.selection)
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("missing provisioned floor: %v", err)
	}
	expired := fixture.signSelection(t, fixture.selection, fixture.now)
	key := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain, "deployment-a", "GRU", "production")
	fixture.objects.items[key] = expired
	if err := fixture.floor.Initialize(1, digestWire(expired)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("expired selector: %v", err)
	}
}

func TestCurrentFounderSelectionRejectsSameGenerationEquivocationAndWrongDomain(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	a := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(a)); err != nil {
		t.Fatal(err)
	}
	fixture.resignSelectedAnchorAndPlan(t)
	equivocation := fixture.selection
	equivocation.PlanSHA256 = digestWire(fixture.planWire)
	equivocation.AnchorSHA256 = digestWire(fixture.anchorWire)
	fixture.publish(t, equivocation)
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("same-generation different signed selection: %v", err)
	}
	payload, err := protocol.EncodeJSON(fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.bootstrap.other-selection",
		DeploymentID: "deployment-a", Cell: "GRU", Environment: "production", Role: "deployment-anchor", Slot: "region"},
		fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(wrong)
	if err != nil {
		t.Fatal(err)
	}
	key := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain, "deployment-a", "GRU", "production")
	fixture.objects.items[key] = wire
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("wrong signed domain: %v", err)
	}
}

func TestCurrentFounderSelectionRejectsSelectedAnchorChangingDiscoveryDomain(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	originalBaked := bytes.Clone(fixture.baked.AnchorWire)
	fixture.resignSelectedAnchorAndPlan(t)
	envelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(envelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		t.Fatal(err)
	}
	anchor.StorageDomain.LedgerBucket = "other-ledger-bucket"
	changed, err := bootstrap.SignBootstrapAnchor(anchor, fixture.now.Add(-30*time.Second), fixture.now.Add(23*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchorWire, err = trust.EncodeEnvelope(changed)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selection.AnchorSHA256 = digestWire(fixture.anchorWire)
	fixture.baked.AnchorWire = originalBaked
	wire := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(wire)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("selected anchor redirected discovery domain: %v", err)
	}
}

func TestCurrentFounderSelectionRequiresAcceptedSeedContinuity(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	wire := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(wire)); err != nil {
		t.Fatal(err)
	}
	fixture.accepted.ManifestSHA256 = strings.Repeat("a", 64)
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("selected seed manifest differs from installed seed: %v", err)
	}
	fixture = newFounderSelectionFixture(t)
	envelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(envelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		t.Fatal(err)
	}
	anchor.ClusterID = "cluster-other"
	changed, err := bootstrap.SignBootstrapAnchor(anchor, fixture.now.Add(-30*time.Second), fixture.now.Add(23*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchorWire, err = trust.EncodeEnvelope(changed)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selection.AnchorSHA256 = digestWire(fixture.anchorWire)
	wire = fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(wire)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("selected cluster differs from installed seed: %v", err)
	}
}

func TestCurrentFounderSelectionExpiresDuringRead(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	fresh := time.Now().UTC()
	wire := fixture.signSelection(t, fixture.selection, fresh.Add(50*time.Millisecond))
	fixture.publish(t, fixture.selection)
	selector := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain, "deployment-a", "GRU", "production")
	fixture.objects.items[selector] = wire
	if err := fixture.floor.Initialize(1, digestWire(wire)); err != nil {
		t.Fatal(err)
	}
	fixture.objects.onGet = func(key string, count int) {
		if key == selector && count == 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fresh); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("selector expired before return: %v", err)
	}
}

var _ FounderSelectionObjectReader = (*founderSelectionObjects)(nil)
