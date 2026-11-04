package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type testBootstrapAuthority struct {
	now          time.Time
	policy       trust.Policy
	rootPublic   ed25519.PublicKey
	rootPrivate  ed25519.PrivateKey
	peerPublic   ed25519.PublicKey
	peerPrivate  ed25519.PrivateKey
	roots        trust.Keyring
	manifest     Manifest
	delegation   trust.Envelope
	regionalData []byte
}

func TestSeedAndPeerReceiptsBindExactInstanceAndManifest(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	seedManifest := authority.verifyManifest(t, "seed-a", authority.manifest)
	seedFacts := authority.facts(seedManifest, "seed-a")
	seedEnvelope, err := SignSeedReceipt(seedManifest, seedFacts, authority.now.Add(-30*time.Second), authority.now.Add(5*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSeed, err := VerifySeedReceipt(seedEnvelope, seedManifest, authority.roots, seedFacts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedSeed.InstanceOCID() != seedFacts.InstanceOCID || verifiedSeed.Slot() != "seed-a" {
		t.Fatalf("verified seed receipt = %#v", verifiedSeed.Receipt())
	}

	wrongRootPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongRootPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySeedReceipt(seedEnvelope, seedManifest, wrongRoots, seedFacts, authority.now, authority.policy); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("wrong receipt root error = %v", err)
	}
	corruptedSignature := seedEnvelope
	corruptedSignature.Signature = "not-a-valid-signature"
	if _, err := VerifySeedReceipt(corruptedSignature, seedManifest, authority.roots, seedFacts, authority.now, authority.policy); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("corrupted receipt signature error = %v", err)
	}

	mutations := map[string]func(*InstanceFacts){
		"foreign instance": func(facts *InstanceFacts) { facts.InstanceOCID = "ocid1.instance.oc1.iad.foreign" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			facts := seedFacts
			mutate(&facts)
			if _, err := VerifySeedReceipt(seedEnvelope, seedManifest, authority.roots, facts, authority.now, authority.policy); !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("mutated facts error = %v", err)
			}
		})
	}

	peerManifest := authority.verifyManifest(t, "peer-b", authority.manifest)
	peerFacts := authority.facts(peerManifest, "peer-b")
	peerEnvelope, err := SignPeerReceipt(peerManifest, peerFacts, authority.now.Add(-30*time.Second), authority.now.Add(5*time.Minute), authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPeer, err := VerifyPeerReceipt(peerEnvelope, peerManifest, peerFacts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedPeer.Slot() != "peer-b" || verifiedPeer.InstanceOCID() != peerFacts.InstanceOCID {
		t.Fatalf("verified peer receipt = %#v", verifiedPeer.Receipt())
	}
	if _, err := VerifySeedReceipt(peerEnvelope, peerManifest, authority.roots, peerFacts, authority.now, authority.policy); err == nil {
		t.Fatal("peer receipt verified through the seed receipt path")
	}
	if _, err := SignPeerReceipt(peerManifest, peerFacts, authority.now.Add(-30*time.Second), authority.now.Add(5*time.Minute), authority.rootPrivate); err == nil {
		t.Fatal("peer receipt accepted a private key outside the delegation")
	}

	otherManifest := authority.manifest
	otherManifest.ReleaseImageReceiptWire = makeDifferentEnvelopeWire(t, authority)
	otherManifest.ReleaseReceiptSHA256 = digestBytes(otherManifest.ReleaseImageReceiptWire)
	otherVerified := authority.verifyManifest(t, "seed-a", otherManifest)
	if _, err := VerifySeedReceipt(seedEnvelope, otherVerified, authority.roots, seedFacts, authority.now, authority.policy); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("receipt replayed with a different manifest error = %v", err)
	}

	oldManifest := authority.manifest
	oldManifest.Slot = "seed-a"
	manifestEnvelope, err := SignManifest(oldManifest, authority.now.Add(-20*time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	oldVerified, err := VerifyManifest(manifestEnvelope, authority.roots, ManifestExpectation{
		DeploymentID: oldManifest.DeploymentID, Environment: oldManifest.Environment, ClusterID: oldManifest.ClusterID,
		Cell: oldManifest.Cell, Slot: oldManifest.Slot, ImageOCID: oldManifest.ImageOCID, StorageDomain: oldManifest.StorageDomain,
		ControllerSlots: slices.Clone(oldManifest.ControllerSlots),
	}, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	oldFacts := authority.facts(oldVerified, "seed-a")
	expired, err := SignSeedReceipt(oldVerified, oldFacts, authority.now.Add(-10*time.Minute), authority.now.Add(-time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySeedReceipt(expired, oldVerified, authority.roots, oldFacts, authority.now, authority.policy); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired receipt error = %v", err)
	}
}

func TestVaultRequiresVerifiedReceiptAndPinsExactSecretVersion(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := authority.verifyManifest(t, "seed-a", authority.manifest)
	facts := authority.facts(manifest, "seed-a")
	receiptEnvelope, err := SignSeedReceipt(manifest, facts, authority.now.Add(-30*time.Second), authority.now.Add(5*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := VerifySeedReceipt(receiptEnvelope, manifest, authority.roots, facts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	secretRef := authority.manifest.Secrets[0]
	reader := &memorySecretReader{bundle: SecretBundle{
		SecretOCID: secretRef.SecretOCID, VersionNumber: secretRef.VersionNumber,
		ContentType: "BASE64", ContentBase64: base64.StdEncoding.EncodeToString(authority.regionalData),
	}}
	vault := &Vault{reader: reader, now: func() time.Time { return authority.now }}
	directory := t.TempDir()
	if err := vault.Materialize(t.Context(), manifest, receipt, secretRef, directory); err != nil {
		t.Fatal(err)
	}
	if reader.secretID != secretRef.SecretOCID || reader.version != secretRef.VersionNumber || reader.calls != 1 {
		t.Fatalf("Vault request was not pinned to the exact secret version: %#v", reader)
	}
	content, err := os.ReadFile(filepath.Join(directory, secretRef.TargetFile))
	if err != nil || string(content) != string(authority.regionalData) {
		t.Fatalf("materialized content = %q, err = %v", content, err)
	}
	info, err := os.Stat(filepath.Join(directory, secretRef.TargetFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("materialized file mode = %v, err = %v", info.Mode().Perm(), err)
	}

	reader = &memorySecretReader{bundle: SecretBundle{
		SecretOCID: secretRef.SecretOCID, VersionNumber: secretRef.VersionNumber + 1,
		ContentType: "BASE64", ContentBase64: base64.StdEncoding.EncodeToString(authority.regionalData),
	}}
	vault.reader = reader
	secondDirectory := t.TempDir()
	if err := vault.Materialize(t.Context(), manifest, receipt, secretRef, secondDirectory); !errors.Is(err, ErrVaultSecretMismatch) {
		t.Fatalf("wrong secret version error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(secondDirectory, secretRef.TargetFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong secret version created a file: %v", err)
	}

	peerManifest := authority.verifyManifest(t, "peer-b", authority.manifest)
	peerFacts := authority.facts(peerManifest, "peer-b")
	peerEnvelope, err := SignPeerReceipt(peerManifest, peerFacts, authority.now.Add(-30*time.Second), authority.now.Add(5*time.Minute), authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	peerReceipt, err := VerifyPeerReceipt(peerEnvelope, peerManifest, peerFacts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	reader.calls = 0
	if err := vault.Materialize(t.Context(), peerManifest, peerReceipt, authority.manifest.Secrets[1], t.TempDir()); !errors.Is(err, ErrReceiptInvalid) {
		t.Fatalf("peer receipt fetched founder-only secret: %v", err)
	}
	if reader.calls != 0 {
		t.Fatal("Vault was called before secret scope authorization")
	}
}

type memorySecretReader struct {
	bundle   SecretBundle
	err      error
	calls    int
	secretID string
	version  int64
}

func (reader *memorySecretReader) GetSecretBundle(_ context.Context, secretID string, version int64) (SecretBundle, error) {
	reader.calls++
	reader.secretID = secretID
	reader.version = version
	return reader.bundle, reader.err
}

func newTestBootstrapAuthority(t *testing.T) testBootstrapAuthority {
	t.Helper()
	now := time.Date(2026, time.September, 24, 14, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, peerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerKeyID := keyID(t, peerPublic)
	peerPublicString, err := trust.EncodeDelegatedPublicKey(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: peerKeyID, SubjectPublicKey: peerPublicString,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: string(oci.RegionGRU),
			Environment: "production", Role: "controller", Slots: []string{"peer-b"}, Actions: []string{"sign"},
		}},
	}, now.Add(-time.Minute), now.Add(20*time.Minute), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, err := trust.Sign([]byte(`{}`), trust.Scope{
		Domain: release.ImageDomain, DeploymentID: "0000000000NBCYX286D4RHE6ZP", Cell: "GRU", Environment: "production",
		Role: "oci-image", Slot: "ocid1.image.oc1.sa-saopaulo-1.image",
	}, now.Add(-time.Minute), now.Add(20*time.Minute), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	releaseWire, err := trust.EncodeEnvelope(releaseEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	releaseDelegationWire, err := trust.EncodeEnvelope(delegationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	regional := []byte("regional shared private key")
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production",
		ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 4,
		IntentSHA256: digestBytes([]byte("regional intent")), ControllerRole: "controller", Slot: "seed-a",
		SeedSlot: "seed-a", ControllerSlots: []string{"peer-b", "seed-a"},
		Profiles: []LaunchProfile{
			{Slot: "seed-a", CompartmentOCID: "ocid1.compartment.oc1..compartment", AvailabilityDomain: "SA-SAOPAULO-1-AD-1",
				FaultDomain: "FAULT-DOMAIN-1", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.seed", Shape: "VM.Standard.E5.Flex",
				NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsgseed"}},
			{Slot: "peer-b", CompartmentOCID: "ocid1.compartment.oc1..compartment", AvailabilityDomain: "SA-SAOPAULO-1-AD-1",
				FaultDomain: "FAULT-DOMAIN-2", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.peer", Shape: "VM.Standard.E5.Flex",
				NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.iad.nsgpeer"}},
		},
		ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image", ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256:    digestBytes(releaseWire),
		ReleaseImageReceiptWire: releaseWire, ReleaseDelegationWire: releaseDelegationWire,
		PeerReceiptDelegation: &delegationEnvelope,
		StorageDomain: StorageDomain{
			Namespace: "namespace", LedgerBucket: "bootstrap-ledger", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger",
			HeadBucket: "bootstrap-head", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap",
		},
		Secrets: []SecretReference{
			{Purpose: SecretRegionalShared, SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.regional", VersionNumber: 2,
				SHA256: digestBytes(regional), MaxBytes: 128, TargetFile: "regional.key"},
			{Purpose: SecretSeedFounder, Slot: "seed-a", SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.founder", VersionNumber: 3,
				SHA256: digestBytes([]byte("founder")), MaxBytes: 128, TargetFile: "founder.key"},
			{Purpose: SecretController, Slot: "seed-a", SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.seed", VersionNumber: 1,
				SHA256: digestBytes([]byte("seed")), MaxBytes: 128, TargetFile: "seed.key"},
			{Purpose: SecretController, Slot: "peer-b", SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.peer", VersionNumber: 1,
				SHA256: digestBytes([]byte("peer")), MaxBytes: 128, TargetFile: "peer.key"},
		},
	}
	controllerConfig := []byte(`{"nats":{},"controller":{}}`)
	manifest.ControllerConfig = controllerConfig
	manifest.ControllerConfigSHA256 = digestBytes(controllerConfig)
	for _, name := range ControllerConfigFileNames {
		body := []byte(`{}`)
		manifest.ControllerFiles = append(manifest.ControllerFiles, ControllerConfigFile{
			Name: name, SHA256: digestBytes(body), Bytes: body,
		})
	}
	return testBootstrapAuthority{
		now: now, policy: trust.Policy{MaxLifetime: time.Hour, ClockSkew: time.Minute},
		rootPublic: rootPublic, rootPrivate: rootPrivate, peerPublic: peerPublic, peerPrivate: peerPrivate,
		roots: roots, manifest: manifest, delegation: delegationEnvelope, regionalData: regional,
	}
}

func (authority testBootstrapAuthority) verifyManifest(t *testing.T, slot string, manifest Manifest) VerifiedManifest {
	t.Helper()
	manifest.Slot = slot
	envelope, err := SignManifest(manifest, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyManifest(envelope, authority.roots, ManifestExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, Slot: slot, ImageOCID: manifest.ImageOCID, StorageDomain: manifest.StorageDomain,
		ControllerSlots: slices.Clone(manifest.ControllerSlots),
	}, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func (authority testBootstrapAuthority) facts(manifest VerifiedManifest, slot string) InstanceFacts {
	profile, _ := manifest.Profile(slot)
	return InstanceFacts{
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", Role: "controller", Slot: slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + slot, CompartmentOCID: profile.CompartmentOCID,
		ImageOCID: authority.manifest.ImageOCID, CreateKey: "launch-" + slot,
		IntentSHA256: digestBytes([]byte("intent-" + slot)), Profile: profile,
	}
}

func keyID(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	value, err := trust.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func makeDifferentEnvelopeWire(t *testing.T, authority testBootstrapAuthority) []byte {
	t.Helper()
	envelope, err := trust.Sign([]byte(`{"changed":true}`), trust.Scope{
		Domain: release.ImageDomain, DeploymentID: "0000000000A16YGSP64YK28MAE", Cell: "GRU", Environment: "production",
		Role: "oci-image", Slot: authority.manifest.ImageOCID,
	}, authority.now.Add(-time.Minute), authority.now.Add(20*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

var _ SecretBundleReader = (*memorySecretReader)(nil)
