//go:build fixturetest

// Package runtimefixture constructs signed authority over the actual OCI SDK
// transport for integration tests. It exposes no raw authority constructor.
package runtimefixture

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type Fixture struct {
	Reader      *bootstrapstart.CurrentFounderAuthorityReader
	Accepted    bootstrapstart.AcceptedIdentity
	Foundations region.FoundationResolver
	Roots       trust.Keyring
	revoke      func()
}

// RevokeCurrent corrupts the actual selector response, so subsequent reads must
// fail signature verification rather than reuse a cached authority snapshot.
func (f *Fixture) RevokeCurrent() { f.revoke() }

func New(t testing.TB, privateIP string, hostEnrollment []byte, material generationtest.Material) *Fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	bundle, err := hostenroll.ParsePublicBundle(hostEnrollment)
	require(t, err)
	if bundle.Cell != "gru" || bundle.Region != "GRU" {
		t.Fatal("runtime fixture requires the actual GRU public enrollment bundle")
	}
	environment := bundle.Environment
	deployment, cluster, installation := entityid.New(), entityid.New(), entityid.New()
	slots := []string{"controller-a", "controller-b", "controller-c"}
	const seed = "controller-c"
	const image = "ocid1.image.oc1.sa-saopaulo-1.fixture"
	const tenancy = "ocid1.tenancy.oc1..fixture"
	const parent = "ocid1.compartment.oc1..parent"
	const shared = "ocid1.compartment.oc1..shared"
	public, root, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	roots, err := trust.ParseKeyring(public)
	require(t, err)
	scope := func(domain, role, slot string) trust.Scope {
		return trust.Scope{Domain: domain, DeploymentID: deployment, Cell: "GRU", Environment: environment, Role: role, Slot: slot}
	}
	domain := bootstrap.StorageDomain{Namespace: "fixture", LedgerBucket: "ledger", HeadBucket: "heads",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"}
	resourceIDs := map[string]any{"control_compartment": "ocid1.compartment.oc1..control", "vault": "ocid1.vault.oc1.sa-saopaulo-1.control", "key": domain.HeadKMSKeyOCID}
	plan := map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy,
		"parent_compartment_id": parent, "shared_compartment_id": shared, "resource_ids": resourceIDs}
	grant := region.FoundationGrant{SchemaVersion: 1, InstallationID: installation, Generation: 1, TenancyID: tenancy,
		ParentCompartmentID: parent, SharedCompartmentID: shared, Currency: "USD", MonthlyLimitMinor: 10000,
		CleanupOwner: "fixture", Regions: []region.FoundationIntent{{Generation: 1, Plan: plan}}}
	grantWire := signed(t, root, grant, scope("terrascale.foundation.scope", "foundation", cluster), now, 45*time.Minute)
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	ledger := delegation(t, root, ledgerPublic, scope("", "controller", ""),
		[]string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"}, slots, now)
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	require(t, err)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: deployment,
		Environment: environment, ClusterID: cluster, Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: domain,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster,
			TenancyID: tenancy, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, GrantGeneration: 1, GrantSHA256: digest(grantWire)},
		ControllerSlots: slots, LedgerDelegationWire: ledger, InitialRegionIntentGeneration: 1,
		InitialRegionIntentSHA256: digest(intentWire), InitialRegionIntentWire: intentWire}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), root)
	require(t, err)
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	require(t, err)
	verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots,
		bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: environment, Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	require(t, err)
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	peerWire := delegation(t, root, peerPublic, scope("", "controller", ""), []string{"terrascale.bootstrap.peer-receipt"}, slots[:2], now)
	peerEnvelope, err := trust.DecodeEnvelope(peerWire)
	require(t, err)
	imageWire, imageGrant := imageProof(t, root, roots, environment, image, now)
	profiles := make([]bootstrap.LaunchProfile, len(slots))
	ips := map[string]string{"controller-a": "10.250.0.11", "controller-b": "10.250.0.12", seed: privateIP}
	for i, slot := range slots {
		profiles[i] = bootstrap.LaunchProfile{Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..control",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", i+1),
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.fixture", NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.fixture"}, Shape: "VM.Standard.E5.Flex"}
	}
	manifests := make(map[string][]byte, len(slots))
	pins := make([]bootstrapstart.FounderManifestPin, len(slots))
	for i, slot := range slots {
		manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: deployment,
			Environment: environment, ClusterID: cluster, Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 1,
			IntentSHA256: digest(intentWire), ControllerRole: "controller", Slot: slot, SeedSlot: seed, ControllerSlots: slots,
			Profiles: profiles, ImageOCID: image, ImageArchitecture: "linux-amd64", ReleaseReceiptSHA256: digest(imageWire),
			ReleaseImageReceiptWire: imageWire, ReleaseDelegationWire: imageGrant, PeerReceiptDelegation: &peerEnvelope,
			StorageDomain: domain, Secrets: references(slot), ControllerConfig: []byte(`{"nats":{},"controller":{}}`)}
		manifest.ControllerConfigSHA256 = digest(manifest.ControllerConfig)
		for _, name := range bootstrap.ControllerConfigFileNames {
			wire := []byte(`{}`)
			if name == "oci-region.json" {
				wire, err = trust.EncodePayload(oci.RegionConfig{Region: oci.RegionGRU, ImageID: image, Shape: "VM.Standard.E5.Flex"})
				require(t, err)
			}
			manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, SHA256: digest(wire), Bytes: wire})
		}
		envelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(50*time.Minute), root)
		require(t, err)
		manifests[slot], err = trust.EncodeEnvelope(envelope)
		require(t, err)
		pins[i] = bootstrapstart.FounderManifestPin{Slot: slot, SHA256: digest(manifests[slot])}
	}
	founder := bootstrap.FounderPlan{SchemaVersion: bootstrap.FounderPlanSchemaVersion, DeploymentID: deployment,
		Cell: oci.RegionGRU, Environment: environment, SeedSlot: seed, AnchorSHA256: digest(anchorWire), ControllerSlots: slots,
		SeedManifestSHA256: digest(manifests[seed]), SeedPrivateIP: privateIP,
		Budget: bootstrap.FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100}, LaunchDeadline: now.Add(35 * time.Minute)}
	for i, slot := range slots[:2] {
		profile := profiles[i]
		row := bootstrap.FounderPeerRow{Slot: slot, ManifestSHA256: digest(manifests[slot]), ImageOCID: image,
			ImageCompartmentOCID: "ocid1.compartment.oc1..images", CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
			FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID, NetworkSecurityGroupOCIDs: profile.NetworkSecurityGroupOCIDs,
			Shape: profile.Shape, WholeOCPUs: 2, MemoryInGB: 12, BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced,
			PrivateIP: ips[slot], ClientEndpoints: []bootstrap.FounderEndpoint{{Slot: slot, PrivateIP: ips[slot], Port: 4222}},
			TLSMaterial: bootstrap.FounderTLSMaterialDigests{ClientCA: digest([]byte("ca.pem")), RouteCA: digest([]byte("ca.pem")),
				ClientCertificate: digest([]byte(slot + "-tls-cert.pem")), RouteCertificate: digest([]byte(slot + "-tls-cert.pem")),
				ClientPrivateKey: digest([]byte(slot + "-tls-key.pem")), RoutePrivateKey: digest([]byte(slot + "-tls-key.pem"))}}
		for _, target := range slots {
			if target != slot {
				row.RouteEndpoints = append(row.RouteEndpoints, bootstrap.FounderEndpoint{Slot: target, PrivateIP: ips[target], Port: 6222})
			}
		}
		founder.Peers = append(founder.Peers, row)
	}
	founderWire := signed(t, root, founder, scope(bootstrap.FounderPlanDomain, "controller", seed), now, 40*time.Minute)
	_, err = bootstrap.VerifyFounderPlan(founderWire, roots, anchorWire, manifests, now, trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: time.Minute})
	require(t, err)
	selection := bootstrapstart.FounderSelection{SchemaVersion: 1, DeploymentID: deployment, Cell: "GRU", Environment: environment,
		Generation: 1, PlanSHA256: digest(founderWire), AnchorSHA256: digest(anchorWire), Manifests: pins}
	selectionWire := signed(t, root, selection, scope(bootstrapstart.FounderSelectionDomain, "deployment-anchor", "region"), now, 30*time.Minute)
	selector := domain.HeadBucket + "/" + bootstrapstart.FounderSelectionObjectName(domain, deployment, "GRU", environment)
	objects := map[string][]byte{selector: selectionWire, domain.HeadBucket + "/" + domain.Prefix + "/foundation-scope-v1.json": grantWire}
	for _, wire := range append([][]byte{anchorWire, founderWire}, slices.Collect(maps.Values(manifests))...) {
		objects[domain.LedgerBucket+"/"+bootstrapstart.FounderImmutableObjectName(domain, deployment, "GRU", environment, digest(wire))] = wire
	}
	planWire, err := json.Marshal(plan, json.Deterministic(true))
	require(t, err)
	record := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: tenancy,
		ParentCompartmentID: parent, SharedCompartmentID: shared, Generation: 1, IntentDigest: digest(planWire), OperationID: entityid.New(), Epoch: 1,
		Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now,
		ResourceIDs: map[string]string{"control_compartment": resourceIDs["control_compartment"].(string), "vault": resourceIDs["vault"].(string), "key": domain.HeadKMSKeyOCID}}
	objects[domain.HeadBucket+"/orchestrator/regions/v1/GRU.json"], err = json.Marshal(record)
	require(t, err)
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
			http.Error(w, "signed SDK GET required", http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/n/"+domain.Namespace+"/b/")
		bucket, key, ok := strings.Cut(path, "/o/")
		mu.Lock()
		wire, exists := objects[bucket+"/"+key]
		mu.Unlock()
		if !ok || !exists {
			http.Error(w, `{"code":"NotFound","message":"absent"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", digest(wire))
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require(t, err)
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture", string(private), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	require(t, err)
	client.Host, client.HTTPClient = server.URL, server.Client()
	floor, err := bootstrapstart.NewFounderSelectionFloorStoreFixture(t.TempDir())
	require(t, err)
	require(t, floor.Initialize(1, digest(selectionWire)))
	accepted := acceptedIdentity(t, privateIP, material, hostEnrollment, now)
	accepted.DeploymentID, accepted.ClusterID, accepted.Environment = deployment, cluster, environment
	marker := bootstrapstart.AcceptedInstall{SchemaVersion: 1, AnchorSHA256: digest(anchorWire), ManifestSHA256: digest(manifests[seed]),
		ReceiptSHA256: digest([]byte("receipt")), ImageReceiptSHA256: digest(imageWire), DeploymentID: deployment, Cell: "GRU", Slot: seed, SeedSlot: seed,
		ImageOCID: accepted.ImageOCID, InstanceOCID: accepted.InstanceOCID, PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: privateIP,
		HeadAttempt: 1, HeadGeneration: 1, ResultSHA256: digest([]byte("result")), BinarySHA256: accepted.Binary.SHA256,
		MaterialSHA256: map[string]string{"ca.pem": digest(material.Files["ca.pem"])}, AcceptedAt: now}
	baked := bootstrapstart.BakedInputs{Identity: bootstrapstart.BakedIdentity{SchemaVersion: 1, DeploymentID: deployment, Cell: oci.RegionGRU, Environment: environment}, Roots: roots, AnchorWire: anchorWire}
	reader, err := bootstrapstart.NewCurrentFounderAuthorityReader(baked, marker, &client, floor)
	require(t, err)
	_, err = reader.ReadRuntimeAuthority(t.Context(), accepted, now)
	require(t, err)
	footprint, err := region.NewSignedFootprint(&client, verifiedAnchor, roots, tenancy)
	require(t, err)
	store, err := region.NewObjectFoundationStore(&client, domain.Namespace, domain.HeadBucket)
	require(t, err)
	foundations := region.FoundationResolver{Footprint: footprint, Store: store}
	_, err = foundations.Resolve(t.Context(), "GRU")
	require(t, err)
	return &Fixture{Reader: reader, Accepted: accepted, Foundations: foundations, Roots: roots, revoke: func() {
		mu.Lock()
		objects[selector] = append(bytes.Clone(selectionWire), '!')
		mu.Unlock()
	}}
}

func require(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func digest(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }

func signed(t testing.TB, root ed25519.PrivateKey, payload any, scope trust.Scope, now time.Time, lifetime time.Duration) []byte {
	t.Helper()
	wire, err := trust.EncodePayload(payload)
	require(t, err)
	envelope, err := trust.Sign(wire, scope, now.Add(-time.Minute), now.Add(lifetime), root)
	require(t, err)
	wire, err = trust.EncodeEnvelope(envelope)
	require(t, err)
	return wire
}

func delegation(t testing.TB, root ed25519.PrivateKey, public ed25519.PublicKey, scope trust.Scope, domains, slots []string, now time.Time) []byte {
	t.Helper()
	keyID, err := trust.KeyID(public)
	require(t, err)
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	require(t, err)
	grant := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: publicWire}
	for _, domain := range domains {
		grant.Capabilities = append(grant.Capabilities, trust.Capability{Domain: domain, DeploymentID: scope.DeploymentID,
			Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: slots, Actions: []string{"sign"}})
	}
	envelope, err := trust.SignDelegation(grant, now.Add(-time.Minute), now.Add(time.Hour), root)
	require(t, err)
	wire, err := trust.EncodeEnvelope(envelope)
	require(t, err)
	return wire
}

func imageProof(t testing.TB, root ed25519.PrivateKey, roots trust.Keyring, environment, image string, now time.Time) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	const revision = "0123456789abcdef0123456789abcdef01234567"
	wire := delegation(t, root, public, trust.Scope{DeploymentID: entityid.Derive("build", revision), Cell: "GRU", Environment: environment, Role: "oci-image"},
		[]string{release.ImageDomain}, []string{image}, now)
	grant, err := trust.DecodeEnvelope(wire)
	require(t, err)
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision, GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest([]byte("binary")), QualificationSHA256: digest([]byte("qualification")),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: digest([]byte("base")),
		KernelRelease: "6.1.0-fixture", KernelSHA256: digest([]byte("kernel")), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: digest([]byte("image")), OCIImageOCID: image, OCIRegion: "GRU"}
	envelope, err := release.SignImageReceipt(receipt, environment, grant, roots, private, now.Add(-time.Minute), 45*time.Minute)
	require(t, err)
	imageWire, err := trust.EncodeEnvelope(envelope)
	require(t, err)
	return imageWire, wire
}

func references(slot string) []bootstrap.SecretReference {
	roles := map[string]bootstrap.SecretPurpose{"operator.jwt": bootstrap.SecretRegionalShared, "system.jwt": bootstrap.SecretRegionalShared,
		"cell.jwt": bootstrap.SecretRegionalShared, "system.creds": bootstrap.SecretRegionalShared, "ca.pem": bootstrap.SecretRegionalShared,
		"route-password": bootstrap.SecretRegionalShared, "ticket.pub": bootstrap.SecretRegionalShared, "ticket.key": bootstrap.SecretRegionalShared,
		"host-nats-issuer.seed": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer, "host-tls-issuer-key.pem": bootstrap.SecretHostIssuer,
		slot + ".creds": bootstrap.SecretController, slot + "-tls-cert.pem": bootstrap.SecretController,
		slot + "-tls-key.pem": bootstrap.SecretController, slot + "-response.key": bootstrap.SecretController}
	refs := make([]bootstrap.SecretReference, 0, len(roles))
	for _, name := range slices.Sorted(maps.Keys(roles)) {
		ref := bootstrap.SecretReference{Purpose: roles[name], SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot,
			VersionNumber: 1, SHA256: digest([]byte(name)), MaxBytes: 65536, TargetFile: name}
		if ref.Purpose == bootstrap.SecretController {
			ref.Slot = slot
		}
		refs = append(refs, ref)
	}
	return refs
}

func acceptedIdentity(t testing.TB, privateIP string, material generationtest.Material, enrollment []byte, now time.Time) bootstrapstart.AcceptedIdentity {
	t.Helper()
	pins := map[string]string{"controller.json": digest([]byte("controller")), "oci-region.json": digest([]byte("region")),
		"oci-region-intent.json": digest([]byte("intent")), "placement.json": digest([]byte("placement"))}
	launchPins := map[string]string{bootstrapstart.HostEnrollmentFilename: digest(enrollment), bootstrapstart.OperatorSSHKeyFilename: digest([]byte("ssh")),
		bootstrapstart.ManagedHostImageReceiptFilename: digest([]byte("image-receipt")), bootstrapstart.ManagedHostImageDelegationFilename: digest([]byte("image-grant"))}
	store := identityrekey.StoreIdentity{Directory: t.TempDir(), ServerName: "fixture-controller-c", RaftNodeID: "NODE0000",
		ServerNameSHA256: digest([]byte("server")), NodeIdentitySHA256: digest([]byte("node"))}
	binary := identityrekey.BinaryPin{SHA256: digest([]byte("binary")), Size: 13, Architecture: "amd64"}
	accepted := bootstrapstart.AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginInitial, OperationID: entityid.New(),
		Environment: "canary", Cell: "GRU", Slot: "controller-c", SeedSlot: "controller-c", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.manager", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.fixture",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.manager", PrimaryPrivateIP: privateIP, Binary: binary,
		Broker: identityrekey.BrokerIdentity{Operator: material.OperatorID, SystemAccount: material.SystemID, CellAccount: material.CellID,
			HostSigner: material.HostSignerID, RoleSigner: material.RoleSignerID}, Store: store,
		ConfigSHA256: pins, LaunchMaterialSHA256: launchPins, MaterialReferences: references("controller-c"), AcceptedAt: now}
	accepted.ControllerBindings = []bootstrapstart.ControllerBinding{{Slot: accepted.Slot, InstanceOCID: accepted.InstanceOCID, ImageOCID: accepted.ImageOCID,
		PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: privateIP, Binary: binary, Store: store}}
	return accepted
}
