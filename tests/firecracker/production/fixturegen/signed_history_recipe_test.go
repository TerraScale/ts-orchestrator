package fixturegen

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignedHistoryRecipeCompletesThreeSlotsThroughPublicLedger(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recipe := syntheticSignedHistoryRecipe(t, now, []byte("synthetic orchestrator executable"))
	capture, err := NewCapturingObjectStorage(now)
	if err != nil {
		t.Fatal(err)
	}
	anchor := recipe.Anchor.Anchor()
	grant, err := recipe.Anchor.LedgerDelegation()
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := bootstrap.NewLedger(capture, bootstrap.LedgerConfig{
		DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     anchor.StorageDomain.Namespace, Bucket: anchor.StorageDomain.LedgerBucket,
		KMSKeyID: anchor.StorageDomain.LedgerKMSKeyOCID, Prefix: anchor.StorageDomain.Prefix,
		HeadBucket: anchor.StorageDomain.HeadBucket, HeadKMSKeyID: anchor.StorageDomain.HeadKMSKeyOCID,
		Environment: anchor.Environment, ControllerSlots: slices.Clone(anchor.ControllerSlots),
		AnchorExpiresAt: recipe.Anchor.ExpiresAt(), TrustRoots: recipe.Roots,
		Delegations: []trust.VerifiedDelegation{grant}, TrustPolicy: bootstrap.BootstrapAnchorTrustPolicy(),
		VerificationNow: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	seed, peers, err := recipe.Prepare(ledger)
	if err != nil {
		t.Fatalf("prepare public signed history: %v", err)
	}
	completed, err := BuildCompletedHistories(t.Context(), ledger, seed, peers)
	if err != nil {
		t.Fatalf("complete three public ledger histories: %v", err)
	}
	if completed.Seed.Result == nil || completed.Seed.Result.InstanceOCID != recipe.Observed["seed-a"].InstanceOCID ||
		len(completed.Peers) != 2 || capture.PutCount() == 0 {
		t.Fatalf("signed history did not complete three slots: seed=%+v peers=%d puts=%d",
			completed.Seed.Result, len(completed.Peers), capture.PutCount())
	}
	for _, slot := range []string{"controller-a", "controller-b"} {
		state := completed.Peers[slot]
		if state.Result == nil || state.Result.InstanceOCID != recipe.Observed[slot].InstanceOCID ||
			state.CandidateRecord == nil || state.ProgressRecord == nil || state.PeerReceiptRecord == nil ||
			state.Head.CandidateDigest == "" || state.Head.ResultDigest == "" {
			t.Fatalf("managed %s lacks completed candidate/progress/result proof: %+v", slot, state)
		}
	}
}

func syntheticSignedHistoryRecipe(t *testing.T, now time.Time, binary []byte) SignedHistoryRecipe {
	return syntheticSignedHistoryRecipeWithMaterials(t, now, binary, nil)
}

func syntheticSignedHistoryRecipeWithMaterials(t *testing.T, now time.Time, binary []byte,
	credentials map[string]map[string][]byte,
) SignedHistoryRecipe {
	return signedHistoryRecipeWithMaterialsAndReceipt(t, now, binary, credentials, nil)
}

func signedHistoryRecipeWithMaterialsAndReceipt(t *testing.T, now time.Time, binary []byte,
	credentials map[string]map[string][]byte, suppliedReceipt *release.ImageReceipt,
) SignedHistoryRecipe {
	t.Helper()
	rootPublic, rootPrivate := historyTestKey(t)
	ledgerPublic, ledgerPrivate := historyTestKey(t)
	releasePublic, releasePrivate := historyTestKey(t)
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-a", "controller-b", "seed-a"}
	deploymentID := entityid.Derive("test-deployment", "production-restart-fixture")
	imageOCID := "ocid1.image.oc1.sa-saopaulo-1.restartfixture"
	if suppliedReceipt != nil {
		imageOCID = suppliedReceipt.OCIImageOCID
	}
	ledgerCapabilities := make([]trust.Capability, 0, 5)
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		ledgerCapabilities = append(ledgerCapabilities, trust.Capability{Domain: domain,
			DeploymentID: deploymentID, Cell: "GRU", Environment: "production", Role: "controller",
			Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	ledgerGrant := historyTestDelegation(t, rootPrivate, ledgerPublic, ledgerCapabilities, now)
	ledgerGrantWire := historyTestEnvelope(t, ledgerGrant)
	regionWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	storage := bootstrap.StorageDomain{Namespace: "0000000000DZBJSM2QGKHTM26H", LedgerBucket: "ledger-fixture",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledgerfixture", HeadBucket: "head-fixture",
		HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.headfixture", Prefix: "private/bootstrap"}
	anchorValue := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: deploymentID, Environment: "production", ClusterID: "0000000000DZBJSM2QGKHTM26H",
		Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: storage,
		ControllerSlots: slices.Clone(slots), LedgerDelegationWire: ledgerGrantWire,
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: historyDigest(regionWire),
		InitialRegionIntentWire: regionWire}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(anchorValue, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{
		DeploymentID: deploymentID, Environment: "production", Cell: oci.RegionGRU,
	}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	releaseRevision := strings.Repeat("a", 40)
	if suppliedReceipt != nil {
		releaseRevision = suppliedReceipt.SourceRevision
	}
	releaseGrant := historyTestDelegation(t, rootPrivate, releasePublic, []trust.Capability{{
		Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", releaseRevision), Cell: "GRU", Environment: "production",
		Role: "oci-image", Slots: []string{imageOCID}, Actions: []string{"sign"},
	}}, now)
	releaseGrantWire := historyTestEnvelope(t, releaseGrant)
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: releaseRevision,
		GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: int64(len(binary)),
		BinarySHA256: historyDigest(binary), BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.basefixture",
		QualificationSHA256: strings.Repeat("e", 64),
		BaseImageRegion:     "GRU", BaseImageSHA256: strings.Repeat("b", 64),
		KernelRelease: "6.1.0-fixture", KernelSHA256: strings.Repeat("c", 64),
		ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: strings.Repeat("d", 64),
		OCIImageOCID: imageOCID, OCIRegion: "GRU"}
	if suppliedReceipt != nil {
		receipt = *suppliedReceipt
	}
	receiptValidity := time.Hour
	if suppliedReceipt != nil {
		// The local VM run has a 60-minute worst-case staging/boot/reboot
		// bound; two hours leaves a further hour inside the delegation cap.
		receiptValidity = 2 * time.Hour
	}
	imageEnvelope, err := release.SignImageReceipt(receipt, "production", releaseGrant, roots,
		releasePrivate, now, receiptValidity)
	if err != nil {
		t.Fatal(err)
	}
	imageWire := historyTestEnvelope(t, imageEnvelope)
	peerGrant := historyTestDelegation(t, rootPrivate, ledgerPublic, []trust.Capability{{
		Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: deploymentID, Cell: "GRU",
		Environment: "production", Role: "controller", Slots: []string{"controller-a", "controller-b"},
		Actions: []string{"sign"},
	}}, now)
	profiles := []bootstrap.LaunchProfile{
		historyTestProfile("controller-a", "FAULT-DOMAIN-1"),
		historyTestProfile("controller-b", "FAULT-DOMAIN-2"),
		historyTestProfile("seed-a", "FAULT-DOMAIN-3"),
	}
	manifestWires := make(map[string][]byte, 3)
	manifestDigests := make(map[string]string, 3)
	for _, slot := range slots {
		manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion,
			DeploymentID: deploymentID, Environment: "production", ClusterID: anchorValue.ClusterID,
			Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 1,
			IntentSHA256: anchorValue.InitialRegionIntentSHA256, ControllerRole: "controller", Slot: slot,
			SeedSlot: "seed-a", ControllerSlots: slices.Clone(slots), Profiles: slices.Clone(profiles),
			ImageOCID: imageOCID, ImageArchitecture: "linux-amd64",
			ReleaseReceiptSHA256: historyDigest(imageWire), ReleaseImageReceiptWire: imageWire,
			ReleaseDelegationWire: releaseGrantWire, PeerReceiptDelegation: &peerGrant,
			StorageDomain: storage}
		manifest.ControllerConfig = []byte(`{"nats":{},"controller":{}}`)
		manifest.ControllerConfigSHA256 = historyDigest(manifest.ControllerConfig)
		for _, name := range bootstrap.ControllerConfigFileNames {
			body := []byte(`{}`)
			manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
				Name: name, SHA256: historyDigest(body), Bytes: body,
			})
		}
		if credentials == nil {
			manifest.Secrets = []bootstrap.SecretReference{{Purpose: bootstrap.SecretRegionalShared,
				SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.regionalfixture", VersionNumber: 1,
				SHA256: historyDigest([]byte("regional fixture credential")), MaxBytes: 1024,
				TargetFile: "regional.key"}}
			if slot != "seed-a" {
				manifest.Secrets = append(manifest.Secrets, historyTestTLSSecrets(slot)...)
			}
		} else {
			material := credentials[slot]
			names := slices.Sorted(maps.Keys(material))
			for index, name := range names {
				manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{
					Purpose: bootstrap.SecretController, Slot: slot,
					SecretOCID:    fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.%s-credential-%02d", slot, index),
					VersionNumber: 1, SHA256: historyDigest(material[name]),
					MaxBytes: bootstrap.MaxSecretBytes, TargetFile: name,
				})
			}
		}
		envelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
		if err != nil {
			t.Fatalf("sign %s manifest: %v", slot, err)
		}
		manifestWires[slot] = historyTestEnvelope(t, envelope)
		manifestDigests[slot], err = trust.Fingerprint(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	privateIPs := map[string]string{"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "seed-a": "10.44.0.10"}
	rows := make([]bootstrap.FounderPeerRow, 0, 2)
	for _, slot := range slots[:2] {
		profile := profiles[slices.IndexFunc(profiles, func(p bootstrap.LaunchProfile) bool { return p.Slot == slot })]
		routes := make([]bootstrap.FounderEndpoint, 0, 2)
		for _, target := range slots {
			if target != slot {
				routes = append(routes, bootstrap.FounderEndpoint{Slot: target, PrivateIP: privateIPs[target], Port: 6222})
			}
		}
		rows = append(rows, bootstrap.FounderPeerRow{Slot: slot, ManifestSHA256: manifestDigests[slot],
			ImageOCID: imageOCID, ImageCompartmentOCID: "ocid1.compartment.oc1..imagesfixture",
			CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
			FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
			NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs),
			Shape:                     profile.Shape, WholeOCPUs: 2, MemoryInGB: 12, BootVolumeGB: 50,
			BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced, PrivateIP: privateIPs[slot],
			RouteEndpoints:  routes,
			ClientEndpoints: []bootstrap.FounderEndpoint{{Slot: slot, PrivateIP: privateIPs[slot], Port: 4222}},
			TLSMaterial:     historyFixtureTLSMaterial(slot, credentials)})
	}
	planValue := bootstrap.FounderPlan{SchemaVersion: bootstrap.FounderPlanSchemaVersion,
		DeploymentID: deploymentID, Cell: oci.RegionGRU, Environment: "production", SeedSlot: "seed-a",
		AnchorSHA256: anchor.Digest(), ControllerSlots: slices.Clone(slots),
		SeedManifestSHA256: manifestDigests["seed-a"], SeedPrivateIP: privateIPs["seed-a"],
		Peers: rows, Budget: bootstrap.FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100},
		LaunchDeadline: now.Add(90 * time.Minute)}
	planPayload, err := trust.EncodePayload(planValue)
	if err != nil {
		t.Fatal(err)
	}
	planEnvelope, err := trust.Sign(planPayload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: deploymentID, Cell: "GRU", Environment: "production", Role: "controller", Slot: "seed-a"},
		now, now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	planWire := historyTestEnvelope(t, planEnvelope)
	selection := bootstrapstart.FounderSelection{SchemaVersion: 1, DeploymentID: deploymentID,
		Cell: "GRU", Environment: "production", Generation: 1,
		PlanSHA256: historyDigest(planWire), AnchorSHA256: anchor.Digest()}
	for _, slot := range slots {
		selection.Manifests = append(selection.Manifests,
			bootstrapstart.FounderManifestPin{Slot: slot, SHA256: historyDigest(manifestWires[slot])})
	}
	selectionPayload, err := trust.EncodePayload(selection)
	if err != nil {
		t.Fatal(err)
	}
	selectionEnvelope, err := trust.Sign(selectionPayload, trust.Scope{
		Domain: bootstrapstart.FounderSelectionDomain, DeploymentID: deploymentID, Cell: "GRU",
		Environment: "production", Role: "deployment-anchor", Slot: "region",
	}, now, now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(map[string]ObservedController, 3)
	for _, slot := range slots {
		observed[slot] = ObservedController{InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + slot,
			CreateKey: "create-" + slot, ProviderRequestID: "request-" + slot,
			ETag: "etag-" + slot}
		if slot != "seed-a" {
			value := observed[slot]
			value.RetryToken = "retry-" + slot
			observed[slot] = value
		}
	}
	return SignedHistoryRecipe{Anchor: anchor, FounderPlanWire: planWire,
		ManifestWires: manifestWires, FounderSelectionWire: historyTestEnvelope(t, selectionEnvelope),
		RootPrivateKey: rootPrivate, LedgerPrivateKey: ledgerPrivate, FounderPrivateKey: ledgerPrivate,
		Roots: roots, Now: now, ReviewedSeedPlanSHA256: historyDigest([]byte("reviewed seed plan")),
		Observed: observed}
}

func historyFixtureTLSMaterial(slot string, credentials map[string]map[string][]byte) bootstrap.FounderTLSMaterialDigests {
	if credentials == nil {
		return historyTestTLSMaterial(slot)
	}
	material := credentials[slot]
	return bootstrap.FounderTLSMaterialDigests{
		ClientCA:          historyDigest(material["nats-ca.pem"]),
		ClientCertificate: historyDigest(material["nats-"+slot+".pem"]),
		ClientPrivateKey:  historyDigest(material["nats-"+slot+".key"]),
		RouteCA:           historyDigest(material["nats-ca.pem"]),
		RouteCertificate:  historyDigest(material["nats-"+slot+".pem"]),
		RoutePrivateKey:   historyDigest(material["nats-"+slot+".key"]),
	}
}

func historyTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func historyTestDelegation(t *testing.T, root ed25519.PrivateKey, public ed25519.PublicKey,
	capabilities []trust.Capability, now time.Time,
) trust.Envelope {
	t.Helper()
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: id, SubjectPublicKey: publicWire, Capabilities: capabilities},
		now.Add(-time.Minute), now.Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func historyTestEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func historyTestProfile(slot, faultDomain string) bootstrap.LaunchProfile {
	return bootstrap.LaunchProfile{Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..restartfixture",
		AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: faultDomain,
		SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1." + slot,
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1." + slot},
		Shape:                     "VM.Standard.E5.Flex"}
}

func historyTestTLSMaterial(slot string) bootstrap.FounderTLSMaterialDigests {
	return bootstrap.FounderTLSMaterialDigests{
		ClientCA:          historyDigest([]byte(slot + " client-ca")),
		ClientCertificate: historyDigest([]byte(slot + " client-certificate")),
		ClientPrivateKey:  historyDigest([]byte(slot + " client-key")),
		RouteCA:           historyDigest([]byte(slot + " route-ca")),
		RouteCertificate:  historyDigest([]byte(slot + " route-certificate")),
		RoutePrivateKey:   historyDigest([]byte(slot + " route-key")),
	}
}

func historyTestTLSSecrets(slot string) []bootstrap.SecretReference {
	material := historyTestTLSMaterial(slot)
	digests := []string{material.ClientCA, material.ClientCertificate, material.ClientPrivateKey,
		material.RouteCA, material.RouteCertificate, material.RoutePrivateKey}
	names := []string{"client-ca", "client-certificate", "client-key", "route-ca", "route-certificate", "route-key"}
	secrets := make([]bootstrap.SecretReference, 0, 6)
	for index, name := range names {
		secrets = append(secrets, bootstrap.SecretReference{Purpose: bootstrap.SecretController, Slot: slot,
			SecretOCID:    fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.%s-%s", slot, name),
			VersionNumber: 1, SHA256: digests[index], MaxBytes: 1024,
			TargetFile: slot + "-" + name + ".pem"})
	}
	return secrets
}
