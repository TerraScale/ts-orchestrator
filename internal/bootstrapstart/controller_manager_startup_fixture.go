//go:build fixturetest

package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/crypto/ssh"
)

// ControllerManagerStartupFixture contains authority created by the signed
// external-seed producers and Gate. It does not attest native image execution,
// live credential installation, HomeIAM or either managed peer's completion.
type ControllerManagerStartupFixture struct {
	Reader   *CurrentFounderAuthorityReader
	Accepted AcceptedIdentity
	Observer *OCIInstanceObserver
	Roots    trust.Keyring
	Root     ed25519.PrivateKey
	Launch   LaunchMaterial
	Instance InstanceObservation
	Anchor   bootstrap.VerifiedBootstrapAnchor
	Storage  *objectstorage.ObjectStorageClient
}

const ControllerManagerStartupDeployment = "0000000000F9PR1WNVDTEXS31Z"
const ControllerManagerStartupCluster = "0000000000RMSAJ9B0JFV7ESHN"

// NewControllerManagerStartupFixture reuses the recipient fixture's signed
// SDK/CAS boundary, completing only controller-c before the downstream manager.
func NewControllerManagerStartupFixture(t *testing.T, enrollment []byte, broker identityrekey.BrokerIdentity,
	root ed25519.PrivateKey, foundation bootstrap.FoundationScope,
) *ControllerManagerStartupFixture {
	t.Helper()
	bundle, err := hostenroll.ParsePublicBundle(enrollment)
	if err != nil || bundle.MatchesImageLayout() != nil || bundle.Cell != "gru" || bundle.Environment != "production" || bundle.CellAccountNKey != broker.CellAccount {
		t.Fatalf("manager fixture requires its actual production-scope public enrollment bundle: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if len(root) != ed25519.PrivateKeySize || foundation.Validate() != nil ||
		foundation.DeploymentID != ControllerManagerStartupDeployment || foundation.ClusterID != ControllerManagerStartupCluster {
		t.Fatal("manager fixture requires its genuine root key and matching signed home foundation reference")
	}
	root = bytes.Clone(root)
	public := root.Public().(ed25519.PublicKey)
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, ledgerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(root); clear(ledgerKey) })
	const deployment = ControllerManagerStartupDeployment
	const cluster = ControllerManagerStartupCluster
	const seed = "controller-c"
	slots := []string{"controller-a", "controller-b", seed}
	grant := func(subject ed25519.PublicKey, domains, grantedSlots []string) trust.Envelope {
		t.Helper()
		id, err := trust.KeyID(subject)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeDelegatedPublicKey(subject)
		if err != nil {
			t.Fatal(err)
		}
		var capabilities []trust.Capability
		for _, domain := range domains {
			capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: deployment,
				Cell: "GRU", Environment: "production", Role: "controller", Slots: slices.Clone(grantedSlots), Actions: []string{"sign"}})
		}
		envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
			SubjectKeyID: id, SubjectPublicKey: wire, Capabilities: capabilities}, now.Add(-time.Minute), now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	envelopeWire := func(envelope trust.Envelope) []byte {
		t.Helper()
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	imageWire, imageGrantWire := managerStartupImage(t, roots, root, now)
	domain := bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "head-bucket",
		HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"}
	if foundation.StorageDomain != domain {
		t.Fatal("manager fixture home reference differs from its exact SDK storage scope")
	}
	regionWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	anchorValue := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: deployment, ClusterID: cluster, Environment: "production", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1",
		StorageDomain: domain, FoundationScope: &foundation, ControllerSlots: slots, LedgerDelegationWire: envelopeWire(grant(ledgerPublic, bootstrap.BootstrapLedgerCapabilityDomains(), slots)),
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: digestWire(regionWire), InitialRegionIntentWire: regionWire}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(anchorValue, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire := envelopeWire(anchorEnvelope)
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, BakedIdentity{DeploymentID: deployment,
		Environment: "production", Cell: oci.RegionGRU}.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	peerGrant := grant(ledgerPublic, []string{"terrascale.bootstrap.peer-receipt"}, slots[:2])
	privateIPs := map[string]string{"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", seed: "10.44.0.10"}
	profiles := make([]bootstrap.LaunchProfile, 0, 3)
	for index, slot := range slots {
		profiles = append(profiles, bootstrap.LaunchProfile{Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", index+1),
			SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1." + slot,
			NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1." + slot}, Shape: "VM.Standard.E5.Flex"})
	}
	manifests := make(map[string][]byte, 3)
	var seedManifest bootstrap.Manifest
	for _, slot := range slots {
		manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: deployment,
			ClusterID: cluster, Environment: "production", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1",
			IntentGeneration: 4, IntentSHA256: digestWire(regionWire), ControllerRole: "controller", Slot: slot, SeedSlot: seed,
			ControllerSlots: slots, Profiles: profiles, ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.managerstartup",
			ImageArchitecture: "linux-" + runtime.GOARCH, ReleaseReceiptSHA256: digestWire(imageWire), ReleaseImageReceiptWire: imageWire,
			ReleaseDelegationWire: imageGrantWire, PeerReceiptDelegation: &peerGrant, StorageDomain: domain}
		manifest.ControllerConfig = []byte(`{"nats":{},"controller":{}}`)
		manifest.ControllerConfigSHA256 = digestWire(manifest.ControllerConfig)
		for _, name := range bootstrap.ControllerConfigFileNames {
			wire := []byte(`{}`)
			if name == "oci-region.json" {
				wire, err = protocol.EncodeJSON(oci.RegionConfig{Region: oci.RegionGRU, ImageID: manifest.ImageOCID, Shape: "VM.Standard.E5.Flex"})
				if err != nil {
					t.Fatal(err)
				}
			}
			manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, SHA256: digestWire(wire), Bytes: wire})
		}
		for _, name := range []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ca.pem", "route-password", "ticket.pub", "ticket.key",
			"host-nats-issuer.seed", "host-tls-issuer-cert.pem", "host-tls-issuer-key.pem", slot + ".creds", slot + "-tls-cert.pem", slot + "-tls-key.pem", slot + "-response.key"} {
			purpose := bootstrap.SecretRegionalShared
			refSlot := ""
			if strings.HasPrefix(name, "host-") {
				purpose = bootstrap.SecretHostIssuer
			} else if strings.HasPrefix(name, slot) {
				purpose, refSlot = bootstrap.SecretController, slot
			}
			manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: purpose, Slot: refSlot,
				SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot + "-material", VersionNumber: 1,
				SHA256: digestWire([]byte(name)), MaxBytes: 65536, TargetFile: name})
		}
		envelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		manifests[slot] = envelopeWire(envelope)
		if slot == seed {
			seedManifest = manifest
		}
	}
	var peers []bootstrap.FounderPeerRow
	for index, slot := range slots[:2] {
		profile := profiles[index]
		var routes []bootstrap.FounderEndpoint
		for _, other := range slots {
			if other != slot {
				routes = append(routes, bootstrap.FounderEndpoint{Slot: other, PrivateIP: privateIPs[other], Port: 6222})
			}
		}
		peers = append(peers, bootstrap.FounderPeerRow{Slot: slot, ManifestSHA256: digestWire(manifests[slot]), ImageOCID: seedManifest.ImageOCID,
			ImageCompartmentOCID: "ocid1.compartment.oc1..images", CompartmentOCID: profile.CompartmentOCID,
			AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
			NetworkSecurityGroupOCIDs: profile.NetworkSecurityGroupOCIDs, Shape: profile.Shape, WholeOCPUs: 2, MemoryInGB: 12,
			BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced, PrivateIP: privateIPs[slot], RouteEndpoints: routes,
			ClientEndpoints: []bootstrap.FounderEndpoint{{Slot: slot, PrivateIP: privateIPs[slot], Port: 4222}},
			TLSMaterial: bootstrap.FounderTLSMaterialDigests{ClientCA: digestWire([]byte("ca.pem")), RouteCA: digestWire([]byte("ca.pem")),
				ClientCertificate: digestWire([]byte(slot + "-tls-cert.pem")), RouteCertificate: digestWire([]byte(slot + "-tls-cert.pem")),
				ClientPrivateKey: digestWire([]byte(slot + "-tls-key.pem")), RoutePrivateKey: digestWire([]byte(slot + "-tls-key.pem"))}})
	}
	plan := bootstrap.FounderPlan{SchemaVersion: bootstrap.FounderPlanSchemaVersion, DeploymentID: deployment, Cell: oci.RegionGRU,
		Environment: "production", SeedSlot: seed, AnchorSHA256: anchor.Digest(), ControllerSlots: slots,
		SeedManifestSHA256: digestWire(manifests[seed]), SeedPrivateIP: privateIPs[seed], Peers: peers,
		Budget: bootstrap.FounderResourceBudget{WholeOCPUs: 4, MemoryInGB: 24, BootVolumeGB: 100}, LaunchDeadline: now.Add(30 * time.Minute)}
	planPayload, err := trust.EncodePayload(plan)
	if err != nil {
		t.Fatal(err)
	}
	planEnvelope, err := trust.Sign(planPayload, trust.Scope{Domain: bootstrap.FounderPlanDomain, DeploymentID: deployment,
		Cell: "GRU", Environment: "production", Role: "controller", Slot: seed}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	planWire := envelopeWire(planEnvelope)
	if _, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifests, now, trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: time.Minute}); err != nil {
		t.Fatal(err)
	}
	selection := FounderSelection{SchemaVersion: 1, DeploymentID: deployment, Cell: "GRU", Environment: "production",
		Generation: 1, PlanSHA256: digestWire(planWire), AnchorSHA256: anchor.Digest()}
	for _, slot := range slots {
		selection.Manifests = append(selection.Manifests, FounderManifestPin{Slot: slot, SHA256: digestWire(manifests[slot])})
	}
	selectionPayload, err := trust.EncodePayload(selection)
	if err != nil {
		t.Fatal(err)
	}
	selectionEnvelope, err := trust.Sign(selectionPayload, trust.Scope{Domain: FounderSelectionDomain, DeploymentID: deployment,
		Cell: "GRU", Environment: "production", Role: "deployment-anchor", Slot: "region"}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	selectionWire := envelopeWire(selectionEnvelope)
	profile := profiles[2]
	observed := InstanceObservation{InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + seed, BootstrapCreateKey: "manager-startup-create",
		CompartmentOCID: profile.CompartmentOCID, ImageOCID: seedManifest.ImageOCID, AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, Shape: profile.Shape, SubnetOCID: profile.SubnetOCID, NSGOCIDs: profile.NetworkSecurityGroupOCIDs,
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1." + seed, PrimaryPrivateIP: privateIPs[seed], PrimaryVNIC: true,
		LifecycleState: "RUNNING", ETag: "manager-startup-instance"}
	storage, observer := managerStartupSDK(t, observed)
	config, err := currentLedgerConfig(anchor, roots)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := bootstrap.NewLedger(storage, config)
	if err != nil {
		t.Fatal(err)
	}
	put := func(bucket, key string, wire []byte, kms string) {
		t.Helper()
		digest := sha256.Sum256(wire)
		_, err := storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(bucket),
			ObjectName: new(key), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)),
			IfNoneMatch: new("*"), OpcSseKmsKeyId: new(kms), OpcContentSha256: new(base64.StdEncoding.EncodeToString(digest[:]))})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, wire := range [][]byte{anchorWire, planWire, manifests[slots[0]], manifests[slots[1]], manifests[seed]} {
		put(domain.LedgerBucket, FounderImmutableObjectName(domain, deployment, "GRU", "production", digestWire(wire)), wire, domain.LedgerKMSKeyOCID)
	}
	put(domain.HeadBucket, FounderSelectionObjectName(domain, deployment, "GRU", "production"), selectionWire, domain.HeadKMSKeyOCID)
	manifestEnvelope, err := trust.DecodeEnvelope(manifests[seed])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := anchor.ManifestExpectation(seed, seedManifest.ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, roots, expected, now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := BuildExternalSeedReservation(ExternalSeedReservationRequest{Identity: BakedIdentity{SchemaVersion: 1,
		DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, Anchor: anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire(planWire), CreateIdentity: observed.BootstrapCreateKey, LedgerPrivate: ledgerKey,
		Now: now, ExpiresAt: now.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	scope := bootstrap.BootstrapScope{DeploymentID: deployment, Cell: "GRU", Slot: seed}
	if _, err := ledger.ReserveSlot(t.Context(), scope, reservation.IntentWire, reservation.InitialHeadWire); err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := VerifyExternalSeedObservation(anchor, manifest, state, observed, observed.PrimaryPrivateIP)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{Identity: BakedIdentity{SchemaVersion: 1,
		DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, Anchor: anchor, Manifest: manifest, Roots: roots,
		State: state, Observation: observed, ObservedAt: now, ExpectedPrivateIP: observed.PrimaryPrivateIP,
		RootPrivate: root, LedgerPrivate: ledgerKey, Now: now, ExpiresAt: now.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RecordExternalSeed(t.Context(), scope, manifests[seed], completion.ReceiptWire, facts, completion.ResultWire, completion.CompletedHeadWire); err != nil {
		t.Fatal(err)
	}
	fixture := &ControllerManagerStartupFixture{Roots: roots, Root: root, Observer: observer, Instance: observed, Anchor: anchor, Storage: storage}
	directory := t.TempDir()
	write := func(name string, wire []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, wire, mode); err != nil {
			t.Fatal(err)
		}
	}
	trustDirectory := filepath.Join(directory, "bootstrap")
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(trustDirectory, "trust-roots", "001.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o444)
	identityWire, err := protocol.EncodeJSON(BakedIdentity{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU})
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Launch = LaunchMaterial{Identity: identityWire, Anchor: anchorWire, HostEnrollment: bytes.Clone(enrollment),
		OperatorSSHKey: ssh.MarshalAuthorizedKey(sshPublic), ManagedHostImageReceipt: imageWire, ManagedHostImageDelegation: imageGrantWire}
	for index, name := range launchMaterialNames {
		write(filepath.Join(trustDirectory, name), fixture.Launch.wires()[index], 0o444)
	}
	storeDirectory := filepath.Join(directory, "nats")
	serverWire := []byte("gru-1-ctl-3\n")
	nodeWire := []byte(`{"version":1,"cell":"gru","instance":"controller-c","node_id":"NODE0001"}`)
	write(filepath.Join(storeDirectory, "server-name"), serverWire, 0o600)
	write(filepath.Join(storeDirectory, "node-identity.json"), nodeWire, 0o600)
	if err := os.Chmod(storeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := identityrekey.StoreIdentity{Directory: storeDirectory, ServerName: "gru-1-ctl-3", RaftNodeID: "NODE0001",
		ServerNameSHA256: digestWire(serverWire), NodeIdentitySHA256: digestWire(nodeWire)}
	markerDirectory, floorDirectory := filepath.Join(directory, "marker"), filepath.Join(directory, "floor")
	for _, path := range []string{markerDirectory, floorDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	markers := MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Geteuid()), allowUnsafeAncestors: true}
	floor := &FounderSelectionFloorStore{directory: floorDirectory, ownerUID: uint32(os.Geteuid()), allowUnsafeAncestors: true}
	baked := BakedInputs{Identity: BakedIdentity{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU},
		Genesis: roots, Roots: roots, AnchorWire: anchorWire}
	trustStore := bakedStore{directory: trustDirectory, ownerUID: uint32(os.Geteuid()), ownerGID: uint32(os.Getegid()), allowUnsafeAncestors: true}
	gate := Gate{Roots: roots, AnchorWire: anchorWire, Expected: baked.Identity.AnchorExpectation(),
		LoadedControllerConfigSHA256: seedManifest.ControllerConfigSHA256,
		Descriptor:                   managerStartupDescriptor{instance: observed.InstanceOCID}, Instances: observer,
		Ledgers: managerStartupLedger{ledger}, Binary: managerStartupChecks{}, Material: managerStartupChecks{}, Credentials: managerStartupChecks{},
		InitialIdentity: func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return broker, store, nil
		},
		ObserveIdentity: func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return broker, store, nil
		},
		Markers: markers, ClockCheck: func() error { return nil }, Now: time.Now, trustStore: &trustStore,
		InitialFounderFloor: func(context.Context, AcceptedInstall, time.Time) error {
			return floor.Initialize(1, digestWire(selectionWire))
		}}
	marker, err := gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fixture.Accepted, err = markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fixture.Reader, err = NewCurrentFounderAuthorityReader(baked, marker, storage, floor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Reader.ReadRuntimeAuthority(t.Context(), fixture.Accepted, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type managerStartupDescriptor struct{ instance string }

func (managerStartupDescriptor) FetchDescriptor(context.Context) (Descriptor, error) {
	return Descriptor{SchemaVersion: 1, Slot: "controller-c"}, nil
}
func (source managerStartupDescriptor) FetchInstanceID(context.Context) (string, error) {
	return source.instance, nil
}

type managerStartupLedger struct{ *bootstrap.Ledger }

func (ledger managerStartupLedger) OpenCurrentLedger(_ context.Context, anchor bootstrap.VerifiedBootstrapAnchor, _ trust.Keyring) (AdmissionLedger, error) {
	if !anchor.IsVerified() {
		return nil, ErrAdmission
	}
	return ledger.Ledger, nil
}

// These retain NODE's explicit non-native image/material boundary; no accepted
// identity, current signed authority, ledger result or SDK observation is faked.
type managerStartupChecks struct{}

func (managerStartupChecks) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	value := image.Receipt()
	return RunningBinary{SHA256: value.BinarySHA256, Bytes: value.BinaryBytes, Architecture: value.Architecture}, nil
}
func (managerStartupChecks) VerifyAccepted(identityrekey.BinaryPin) (RunningBinary, error) {
	return RunningBinary{}, ErrRunningBinaryMismatch
}
func (managerStartupChecks) VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation) (RunningBinary, error) {
	return RunningBinary{}, ErrRunningBinaryMismatch
}
func (managerStartupChecks) PrepareInitial(_ context.Context, _ bootstrap.StartupAuthority, _ bootstrap.VerifiedReceipt, _ map[string]string, verify CurrentProofVerifier) error {
	return verify(time.Now())
}
func (managerStartupChecks) RestartPins(AcceptedIdentity, trust.Keyring) (MaterialPins, error) {
	return MaterialPins{}, ErrMaterial
}
func (managerStartupChecks) VerifyRestart(context.Context, AcceptedIdentity, MaterialPins) error {
	return ErrMaterial
}
func (managerStartupChecks) VerifyInitialLiveCredentials(_ context.Context, pins MaterialPins, _ bootstrap.StartupAuthority) error {
	if len(pins.Digests) == 0 {
		return ErrLiveCredentials
	}
	return nil
}
func (managerStartupChecks) VerifyLiveCredentials(context.Context, MaterialPins, AcceptedIdentity) error {
	return ErrLiveCredentials
}

func managerStartupImage(t *testing.T, roots trust.Keyring, root ed25519.PrivateKey, now time.Time) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	const revision = "0123456789abcdef0123456789abcdef01234567"
	const image = "ocid1.image.oc1.sa-saopaulo-1.managerstartup"
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", revision), Cell: "GRU",
			Environment: "production", Role: "oci-image", Slots: []string{image}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision, GoVersion: release.DefaultGoVersion,
		Architecture: runtime.GOARCH, BinaryBytes: 13, BinarySHA256: strings.Repeat("a", 64), QualificationSHA256: strings.Repeat("e", 64),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: strings.Repeat("b", 64),
		KernelRelease: "6.1.0-test+1", KernelSHA256: strings.Repeat("c", 64), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: strings.Repeat("d", 64), OCIImageOCID: image, OCIRegion: "GRU"}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{
		SourceRevision: revision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256,
		Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: runtime.GOARCH, Role: "orchestrator"}}
	directory := t.TempDir()
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		wire := []byte("test-only manager startup image evidence: " + gate)
		path := filepath.Join(directory, digestWire(wire))
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		retained, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(retained, wire) {
			t.Fatal("retained image evidence changed", err)
		}
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digestWire(retained), Bytes: int64(len(retained)), CompletedAt: now.Add(-2 * time.Minute)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Production = &release.ProductionProof{Qualification: proof}
	signed, err := release.SignImageReceipt(receipt, "production", grant, roots, private, now.Add(-time.Minute), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	return wire, delegationWire
}

func managerStartupSDK(t *testing.T, observed InstanceObservation) (*objectstorage.ObjectStorageClient, *OCIInstanceObserver) {
	t.Helper()
	type storedObject struct {
		wire     []byte
		etag     string
		modified time.Time
	}
	var mu sync.Mutex
	objects := make(map[string]storedObject)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned SDK request", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/n/namespace-a/b/") {
			mu.Lock()
			defer mu.Unlock()
			bucket, key, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/n/namespace-a/b/"), "/o/")
			if !ok {
				http.Error(w, "invalid object path", 400)
				return
			}
			name := bucket + "/" + key
			stored, exists := objects[name]
			if r.Method == http.MethodPut {
				if r.Header.Get("if-none-match") != "*" && r.Header.Get("if-match") == "" {
					http.Error(w, "conditional write required", 400)
					return
				}
				if r.Header.Get("if-none-match") == "*" && exists || r.Header.Get("if-match") != "" && (!exists || r.Header.Get("if-match") != stored.etag) {
					http.Error(w, `{"code":"PreconditionFailed","message":"CAS rejected"}`, 412)
					return
				}
				wire, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
				if err != nil || int64(len(wire)) != r.ContentLength {
					http.Error(w, "invalid object body", 400)
					return
				}
				digest := sha256.Sum256(wire)
				// The production foundation journal uses bucket encryption and ETag CAS.
				journal := bucket == "head-bucket" && key == "orchestrator/regions/v1/GRU.json"
				kms := "ocid1.key.oc1.sa-saopaulo-1.head"
				if bucket == "ledger-bucket" {
					kms = "ocid1.key.oc1.sa-saopaulo-1.ledger"
				}
				if bucket != "head-bucket" && bucket != "ledger-bucket" || !journal &&
					(r.Header.Get("opc-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) || r.Header.Get("opc-sse-kms-key-id") != kms) {
					http.Error(w, "missing checksum or KMS scope", 400)
					return
				}
				stored = storedObject{wire: bytes.Clone(wire), etag: hex.EncodeToString(digest[:]), modified: time.Now().UTC().Truncate(time.Second)}
				objects[name] = stored
				w.Header().Set("ETag", stored.etag)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "unsupported object operation", 405)
				return
			}
			if !exists {
				http.Error(w, `{"code":"ObjectNotFound","message":"absent"}`, 404)
				return
			}
			w.Header().Set("ETag", stored.etag)
			w.Header().Set("Last-Modified", stored.modified.Format(http.TimeFormat))
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Content-Length", fmt.Sprint(len(stored.wire)))
			_, _ = w.Write(stored.wire)
			return
		}
		var body any
		switch r.URL.Path {
		case "/20160918/instances/" + observed.InstanceOCID:
			body = core.Instance{Id: new(observed.InstanceOCID), CompartmentId: new(observed.CompartmentOCID), ImageId: new(observed.ImageOCID),
				AvailabilityDomain: new(observed.AvailabilityDomain), FaultDomain: new(observed.FaultDomain), Shape: new(observed.Shape), LifecycleState: core.InstanceLifecycleStateRunning}
		case "/20160918/vnicAttachments":
			if r.URL.Query().Get("instanceId") != observed.InstanceOCID {
				http.Error(w, "foreign instance", 404)
				return
			}
			body = []core.VnicAttachment{{InstanceId: new(observed.InstanceOCID), CompartmentId: new(observed.CompartmentOCID),
				VnicId: new(observed.PrimaryVNICOCID), SubnetId: new(observed.SubnetOCID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}}
		case "/20160918/vnics/" + observed.PrimaryVNICOCID:
			body = core.Vnic{Id: new(observed.PrimaryVNICOCID), CompartmentId: new("ocid1.compartment.oc1..network"), AvailabilityDomain: new(observed.AvailabilityDomain),
				SubnetId: new(observed.SubnetOCID), PrivateIp: new(observed.PrimaryPrivateIP), IsPrimary: new(true), NsgIds: observed.NSGOCIDs, LifecycleState: core.VnicLifecycleStateAvailable}
		case "/20160918/subnets/" + observed.SubnetOCID:
			body = core.Subnet{Id: new(observed.SubnetOCID), CompartmentId: new("ocid1.compartment.oc1..network"),
				VcnId: new("ocid1.vcn.oc1.sa-saopaulo-1.managerstartup"), LifecycleState: core.SubnetLifecycleStateAvailable}
		default:
			http.Error(w, "unexpected OCI SDK operation", 404)
			return
		}
		if err := json.MarshalWrite(w, body); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test-fingerprint", string(private), nil)
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	storage.Host, storage.HTTPClient = server.URL, server.Client()
	compute.Host, compute.HTTPClient = server.URL, server.Client()
	network.Host, network.HTTPClient = server.URL, server.Client()
	return &storage, &OCIInstanceObserver{compute: &compute, network: &network}
}
