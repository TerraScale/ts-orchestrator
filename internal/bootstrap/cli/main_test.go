package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

type manifestFixture struct {
	now                  time.Time
	roots                trust.Keyring
	rootPublic           ed25519.PublicKey
	rootPrivate          ed25519.PrivateKey
	delegatePrivate      ed25519.PrivateKey
	ledgerPublic         ed25519.PublicKey
	ledgerDelegationWire []byte
	ledgerExpiresAt      time.Time
	manifest             bootstrap.Manifest
	anchor               bootstrap.BootstrapAnchor
	image                release.ImageReceipt
	imageWire            []byte
	delegationWire       []byte
	initialIntentWire    []byte
	directory            string
	candidatePath        string
	anchorCandidatePath  string
	anchorPath           string
	intentPath           string
	ledgerDelegationPath string
	imagePath            string
	delegationPath       string
	rootPath             string
	privatePath          string
	controllerConfigPath string
	regionConfigPath     string
	placementConfigPath  string
}

func newManifestFixture(t *testing.T, delegationFor, imageFor time.Duration) *manifestFixture {
	t.Helper()
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegateKeyID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedDelegatePublic, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	image := qualifyImageFixture(t, testImageReceipt(), "production", rootPrivate, now, release.MaxUpdateReceiptLifetime)
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: delegateKeyID, SubjectPublicKey: encodedDelegatePublic,
		Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", image.SourceRevision), Cell: "GRU", Environment: "production",
			Role: "oci-image", Slots: []string{image.OCIImageOCID}, Actions: []string{"sign"},
		}},
	}, now.Add(-24*time.Hour), now.Add(delegationFor), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	imageEnvelope, err := release.SignImageReceipt(image, "production", delegation, roots,
		delegatePrivate, now, imageFor)
	if err != nil {
		t.Fatal(err)
	}
	imageWire := encodeEnvelope(t, imageEnvelope)
	delegationWire := encodeEnvelope(t, delegation)
	imageDigest := sha256.Sum256(imageWire)
	initialIntentWire, err := trust.EncodePayload(oci.RegionIntent{
		SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.Manifest{
		SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production",
		ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 1,
		IntentSHA256: digest(initialIntentWire), ControllerRole: "controller", Slot: "seed-a", SeedSlot: "seed-a",
		ControllerSlots: []string{"seed-a"},
		Profiles: []bootstrap.LaunchProfile{{
			Slot: "seed-a", CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet", Shape: "VM.Standard.E5.Flex",
		}},
		ImageOCID: image.OCIImageOCID, ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256: hex.EncodeToString(imageDigest[:]),
		StorageDomain: bootstrap.StorageDomain{
			Namespace: "namespace", LedgerBucket: "bootstrap-ledger",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "bootstrap-head",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap",
		},
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublicWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerKeyID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerExpiresAt := now.Add(bootstrap.MaxBootstrapAnchorLifetime - 24*time.Hour)
	ledgerCapabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		ledgerCapabilities = append(ledgerCapabilities, trust.Capability{
			Domain: domain, DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell),
			Environment: manifest.Environment, Role: manifest.ControllerRole,
			Slots: append([]string(nil), manifest.ControllerSlots...), Actions: []string{"sign"},
		})
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: ledgerKeyID, SubjectPublicKey: ledgerPublicWire,
		Capabilities: ledgerCapabilities,
	}, now.Add(-24*time.Hour), ledgerExpiresAt, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ledgerDelegationWire := encodeEnvelope(t, ledgerGrant)
	directory := t.TempDir()
	rootDER, err := x509.MarshalPKIXPublicKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &manifestFixture{
		now: now, roots: roots, rootPublic: rootPublic, rootPrivate: rootPrivate,
		delegatePrivate: delegatePrivate, ledgerPublic: ledgerPublic,
		ledgerDelegationWire: ledgerDelegationWire, ledgerExpiresAt: ledgerExpiresAt,
		manifest: manifest, image: image,
		imageWire: imageWire, delegationWire: delegationWire, initialIntentWire: initialIntentWire, directory: directory,
		candidatePath:       filepath.Join(directory, "candidate.json"),
		anchorCandidatePath: filepath.Join(directory, "anchor-candidate.json"),
		anchorPath:          filepath.Join(directory, "bootstrap-anchor.json"), intentPath: filepath.Join(directory, "region-intent.json"),
		ledgerDelegationPath: filepath.Join(directory, "ledger-delegation.json"),
		imagePath:            filepath.Join(directory, "image.json"),
		delegationPath:       filepath.Join(directory, "release-delegation.json"), rootPath: filepath.Join(directory, "root.pub"),
		privatePath:          filepath.Join(directory, "root.key"),
		controllerConfigPath: filepath.Join(directory, "controller-config.json"),
		regionConfigPath:     filepath.Join(directory, "oci-region.json"),
		placementConfigPath:  filepath.Join(directory, "placement.json"),
	}
	writeFixture(t, fixture.imagePath, imageWire, 0o600)
	writeFixture(t, fixture.delegationPath, delegationWire, 0o600)
	writeFixture(t, fixture.rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}), 0o644)
	writeFixture(t, fixture.privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writeFixture(t, fixture.intentPath, initialIntentWire, 0o600)
	writeFixture(t, fixture.ledgerDelegationPath, ledgerDelegationWire, 0o600)
	fixture.writeAnchor(t, bootstrap.BootstrapAnchor{
		SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: manifest.DeploymentID,
		Environment: manifest.Environment, ClusterID: manifest.ClusterID, Cell: manifest.Cell,
		OCIRegion: manifest.OCIRegion, StorageDomain: manifest.StorageDomain,
		ControllerSlots: append([]string(nil), manifest.ControllerSlots...), LedgerDelegationWire: bytes.Clone(ledgerDelegationWire),
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: digest(initialIntentWire),
		InitialRegionIntentWire: bytes.Clone(initialIntentWire),
	})
	return fixture
}

func (fixture *manifestFixture) args(output string, validFor string) []string {
	args := []string{
		"--candidate", fixture.candidatePath,
		"--controller-config", fixture.controllerConfigPath,
		"--controller-config-sha256", fixtureFileDigest(fixture.controllerConfigPath),
		"--oci-region-intent", fixture.intentPath,
		"--oci-region-intent-sha256", digest(fixture.initialIntentWire),
		"--oci-region-config", fixture.regionConfigPath,
		"--oci-region-config-sha256", fixtureFileDigest(fixture.regionConfigPath),
		"--placement-config", fixture.placementConfigPath,
		"--placement-config-sha256", fixtureFileDigest(fixture.placementConfigPath),
		"--anchor", fixture.anchorPath,
		"--image-receipt", fixture.imagePath,
		"--release-delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--out", output,
	}
	if validFor != "" {
		args = append(args, "--valid-for", validFor)
	}
	return args
}

func (fixture *manifestFixture) anchorArgs(output string, validFor string) []string {
	args := []string{
		"--candidate", fixture.anchorCandidatePath,
		"--region-intent", fixture.intentPath,
		"--ledger-delegation", fixture.ledgerDelegationPath,
		"--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath,
		"--out", output,
	}
	if validFor != "" {
		args = append(args, "--valid-for", validFor)
	}
	return args
}

func (fixture *manifestFixture) writeCandidate(t *testing.T, manifest bootstrap.Manifest) {
	t.Helper()
	guestPath := func(name string) string { return filepath.Join(bootstrapstart.MaterialDirectory, name) }
	privateIP := map[string]string{"seed-a": "10.0.0.11", "peer-b": "10.0.0.12"}
	host := privateIP[manifest.Slot]
	if host == "" {
		host = "10.0.0.13"
	}
	tls := natscell.TLSFiles{CAFile: guestPath("ca.pem"), CertFile: guestPath(manifest.Slot + "-tls-cert.pem"),
		KeyFile: guestPath(manifest.Slot + "-tls-key.pem")}
	routes := make([]string, 0, len(manifest.ControllerSlots))
	for _, slot := range manifest.ControllerSlots {
		if slot != manifest.Slot {
			routes = append(routes, "nats-route://"+privateIP[slot]+":6222")
		}
	}
	cfg := app.Config{Version: app.ConfigVersion, NATS: natscell.Config{Cell: strings.ToLower(string(manifest.Cell)), Instance: manifest.Slot,
		Replicas: len(manifest.ControllerSlots), ClientRole: "controller", URL: "tls://" + host + ":4222",
		CredentialsFile: guestPath(manifest.Slot + ".creds"), TLS: tls,
		Embedded: &natscell.Embedded{Host: host, Port: 4222, RouteHost: host, RoutePort: 6222,
			Routes: routes, StoreDir: "/var/lib/terrascale-orchestrator-controller/nats", StoreMaxBytes: 4 << 30,
			TLS: tls, RouteTLS: tls, RouteUser: "ts-route", RoutePasswordFile: guestPath("route-password"),
			OperatorJWTFile: guestPath("operator.jwt"), SystemJWTFile: guestPath("system.jwt"),
			CellJWTFile: guestPath("cell.jwt"), SystemCredentialsFile: guestPath("system.creds"),
			TicketPublicKeyFile: guestPath("ticket.pub"), BrokerIDs: slices.Clone(manifest.ControllerSlots)}},
		Controller: app.ControllerConfig{CandidateID: entityid.Derive("controller", manifest.DeploymentID, string(manifest.Cell), manifest.Slot),
			ArtifactStoreMaxBytes: 512 << 20,
			ResponseKeyFile:       guestPath(manifest.Slot + "-response.key"), BrokerTicketKeyFile: guestPath("ticket.key"),
			HostNATSIssuerSeedFile:      guestPath("host-nats-issuer.seed"),
			HostTLSIssuerKeyFile:        guestPath("host-tls-issuer-key.pem"),
			HostTLSIssuerCertFile:       guestPath("host-tls-issuer-cert.pem"),
			HostEnrollmentListenAddress: host + ":8443",
			OciRegionIntentFile:         "/etc/terrascale-orchestrator/oci-region-intent.json",
			OciRegionConfig:             "/etc/terrascale-orchestrator/oci-region.json",
			PlacementConfig:             "/etc/terrascale-orchestrator/placement.json",
			TrustedSigners: []app.TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(fixture.rootPublic),
				Roles: []string{"terrabase"}, Environments: []string{manifest.Environment}, CanRegisterHosts: true,
				CanPlaceTerraBase: true, CanPrepareManagedMaterial: true}}}}
	configWire, err := protocol.EncodeJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.controllerConfigPath, configWire, 0o600)
	regionWire, err := protocol.EncodeJSON(oci.RegionConfig{Region: manifest.Cell, Generation: manifest.IntentGeneration,
		Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com", CompartmentID: "ocid1.compartment.oc1..owned",
		ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1",
		FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: "ocid1.subnet.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		ImageID:                 "ocid1.image.oc1..managed", Shape: "VM.Standard.A1.Flex", BootVolumeGB: 50,
		BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50, Owner: "test-owner"})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.regionConfigPath, regionWire, 0o600)
	placementWire, err := protocol.EncodeJSON(struct {
		Environment string              `json:"environment"`
		MemberRole  string              `json:"member_role"`
		Resources   placement.Resources `json:"resources"`
	}{Environment: manifest.Environment, MemberRole: "terrabase", Resources: placement.Resources{
		CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 50 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.placementConfigPath, placementWire, 0o600)
	secretNames := []string{manifest.Slot + ".creds", "ca.pem", manifest.Slot + "-tls-cert.pem",
		manifest.Slot + "-tls-key.pem", "route-password", "operator.jwt", "system.jwt", "cell.jwt",
		"system.creds", "ticket.pub", manifest.Slot + "-response.key", "ticket.key",
		"host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem"}
	for _, name := range secretNames {
		if slices.ContainsFunc(manifest.Secrets, func(reference bootstrap.SecretReference) bool {
			return reference.TargetFile == name
		}) {
			continue
		}
		purpose, slot := bootstrap.SecretRegionalShared, ""
		if strings.HasPrefix(name, manifest.Slot+"-") || name == manifest.Slot+".creds" {
			purpose, slot = bootstrap.SecretController, manifest.Slot
		}
		if strings.HasPrefix(name, "host-") {
			purpose, slot = bootstrap.SecretHostIssuer, ""
		}
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: purpose, Slot: slot,
			SecretOCID:    "ocid1.vaultsecret.oc1.sa-saopaulo-1." + strings.ReplaceAll(name, ".", "-"),
			VersionNumber: 1, SHA256: digest([]byte(name)), MaxBytes: int64(len(name)), TargetFile: name})
	}
	encoded, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.candidatePath, encoded, 0o600)
}

func fixtureFileDigest(path string) string {
	wire, _ := os.ReadFile(path)
	return digest(wire)
}

func (fixture *manifestFixture) writeAnchorCandidate(t *testing.T, anchor bootstrap.BootstrapAnchor) {
	t.Helper()
	encoded, err := trust.EncodePayload(anchor)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.anchorCandidatePath, encoded, 0o600)
}

func (fixture *manifestFixture) writeAnchor(t *testing.T, anchor bootstrap.BootstrapAnchor) {
	fixture.writeAnchorAt(t, anchor, fixture.now, fixture.ledgerExpiresAt)
}

func (fixture *manifestFixture) writeAnchorFor(t *testing.T, anchor bootstrap.BootstrapAnchor, validFor time.Duration) {
	t.Helper()
	expiresAt := fixture.now.Add(validFor)
	if fixture.ledgerExpiresAt.Before(expiresAt) {
		expiresAt = fixture.ledgerExpiresAt
	}
	fixture.writeAnchorAt(t, anchor, fixture.now, expiresAt)
}

func (fixture *manifestFixture) writeAnchorAt(t *testing.T, anchor bootstrap.BootstrapAnchor, issuedAt, expiresAt time.Time) {
	t.Helper()
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, issuedAt, expiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchor = anchor
	writeFixture(t, fixture.anchorPath, encoded, 0o600)
}

func (fixture *manifestFixture) setLedgerGrant(t *testing.T, slots []string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: fixture.manifest.DeploymentID, Cell: string(fixture.manifest.Cell),
			Environment: fixture.manifest.Environment, Role: fixture.manifest.ControllerRole,
			Slots: append([]string(nil), slots...), Actions: []string{"sign"},
		})
	}
	grant, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: publicWire,
		Capabilities: capabilities,
	}, fixture.now.Add(-24*time.Hour), fixture.ledgerExpiresAt, fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ledgerDelegationWire = encodeEnvelope(t, grant)
	fixture.ledgerPublic = public
	writeFixture(t, fixture.ledgerDelegationPath, fixture.ledgerDelegationWire, 0o600)
}

func (fixture *manifestFixture) anchorForSlots(t *testing.T, slots []string) bootstrap.BootstrapAnchor {
	t.Helper()
	fixture.setLedgerGrant(t, slots)
	anchor := fixture.anchor
	anchor.ControllerSlots = append([]string(nil), slots...)
	anchor.LedgerDelegationWire = bytes.Clone(fixture.ledgerDelegationWire)
	return anchor
}

func (fixture *manifestFixture) writeProofs(t *testing.T, imageWire, delegationWire []byte) {
	t.Helper()
	writeFixture(t, fixture.imagePath, imageWire, 0o600)
	writeFixture(t, fixture.delegationPath, delegationWire, 0o600)
	fixture.manifest.ReleaseReceiptSHA256 = digest(imageWire)
}

func (fixture *manifestFixture) verifyOutput(t *testing.T, output string, expected bootstrap.Manifest) trust.Envelope {
	t.Helper()
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("decode signed output: %v", err)
	}
	verified, err := bootstrap.VerifyManifest(envelope, fixture.roots, bootstrap.ManifestExpectation{
		DeploymentID: expected.DeploymentID, Environment: expected.Environment, ClusterID: expected.ClusterID,
		Cell: expected.Cell, Slot: expected.Slot, ImageOCID: expected.ImageOCID, StorageDomain: expected.StorageDomain,
		ControllerSlots:  append([]string(nil), expected.ControllerSlots...),
		IntentGeneration: expected.IntentGeneration, IntentSHA256: expected.IntentSHA256,
	}, fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatalf("verify signed output: %v", err)
	}
	manifest := verified.Manifest()
	if !bytes.Equal(manifest.ReleaseImageReceiptWire, fixture.imageWire) ||
		!bytes.Equal(manifest.ReleaseDelegationWire, fixture.delegationWire) || manifest.ReleaseReceiptSHA256 != digest(fixture.imageWire) {
		t.Fatal("signed manifest did not preserve the exact supplied release proof wires")
	}
	return envelope
}

func testImageReceipt() release.ImageReceipt {
	imageDigest := digest([]byte("image bytes"))
	return release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: testRevision, GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest([]byte("binary bytes")),
		QualificationSHA256: digest([]byte("qualification fixture")),
		BaseImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU",
		BaseImageSHA256: imageDigest, KernelRelease: "6.1.0-test+1", KernelSHA256: imageDigest,
		ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: imageDigest,
		OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.bootstrap", OCIRegion: "GRU",
	}
}

func writeFixture(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func encodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodePayload(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// qualifyImageFixture signs test-only disk qualification independently of the image publisher.
func qualifyImageFixture(t *testing.T, image release.ImageReceipt, environment string, root ed25519.PrivateKey, at time.Time, lifetime time.Duration) release.ImageReceipt {
	t.Helper()
	record := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256,
			QualificationSHA256: image.QualificationSHA256, Cell: image.OCIRegion, Environment: environment,
			Runtime: release.ProductionRuntime, Architecture: image.Architecture, Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " image evidence")
		record.Evidence = append(record.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digest(evidence), Bytes: int64(len(evidence)), CompletedAt: at.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), at, at.Add(lifetime), root)
	if err != nil {
		t.Fatal(err)
	}
	image.Production = &release.ProductionProof{Qualification: encodeEnvelope(t, proof)}
	return image
}
