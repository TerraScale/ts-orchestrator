package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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

func TestManifestVerifiesExactSlotAndReturnsDefensiveCopies(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	verified := authority.verifyManifest(t, "peer-b", authority.manifest)
	if verified.Digest() == "" {
		t.Fatal("verified manifest has no digest")
	}
	copy := verified.Manifest()
	copy.ControllerSlots[0] = "mutated"
	copy.Profiles[0].NetworkSecurityGroupOCIDs[0] = "mutated"
	copy.Secrets[0].TargetFile = "mutated"
	copy.ReleaseImageReceiptWire[0] ^= 1
	copy.ReleaseDelegationWire[0] ^= 1
	copy.PeerReceiptDelegation.Signature = "mutated"
	profile, ok := verified.Profile("peer-b")
	if !ok || profile.Slot != "peer-b" || profile.NetworkSecurityGroupOCIDs[0] != "ocid1.networksecuritygroup.oc1.iad.nsgpeer" {
		t.Fatalf("verified manifest was changed through a returned copy: %#v", profile)
	}
	if got := verified.Manifest().ControllerSlots; !slices.Equal(got, authority.manifest.ControllerSlots) {
		t.Fatalf("controller slots changed through a returned copy: %q", got)
	}
	verifiedCopy := verified.Manifest()
	if !bytes.Equal(verifiedCopy.ReleaseImageReceiptWire, authority.manifest.ReleaseImageReceiptWire) ||
		!bytes.Equal(verifiedCopy.ReleaseDelegationWire, authority.manifest.ReleaseDelegationWire) {
		t.Fatal("release proof wires changed through a returned manifest copy")
	}

	envelope, err := SignManifest(authority.manifest, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(envelope, authority.roots, ManifestExpectation{
		DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a",
		Cell: oci.RegionGRU, Slot: "peer-b", ImageOCID: authority.manifest.ImageOCID, StorageDomain: authority.manifest.StorageDomain,
		ControllerSlots: slices.Clone(authority.manifest.ControllerSlots),
	}, authority.now, authority.policy); err == nil {
		t.Fatal("manifest scoped to seed-a verified as peer-b")
	}
	wrongImage := ManifestExpectation{
		DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a",
		Cell: oci.RegionGRU, Slot: "peer-b", ImageOCID: "ocid1.image.oc1.iad.otherimage", StorageDomain: authority.manifest.StorageDomain,
		ControllerSlots: slices.Clone(authority.manifest.ControllerSlots),
	}
	if _, err := VerifyManifest(envelope, authority.roots, wrongImage, authority.now, authority.policy); err == nil {
		t.Fatal("manifest verified with a different expected image")
	}
}

func TestSignManifestDoesNotRetainCallerReleaseWireAliases(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := authority.manifest
	originalReceipt := bytes.Clone(manifest.ReleaseImageReceiptWire)
	originalDelegation := bytes.Clone(manifest.ReleaseDelegationWire)
	envelope, err := SignManifest(manifest, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ReleaseImageReceiptWire[0] ^= 1
	manifest.ReleaseDelegationWire[0] ^= 1
	verified, err := VerifyManifest(envelope, authority.roots, ManifestExpectation{
		DeploymentID: authority.manifest.DeploymentID, Environment: authority.manifest.Environment,
		ClusterID: authority.manifest.ClusterID, Cell: authority.manifest.Cell, Slot: authority.manifest.Slot,
		ImageOCID: authority.manifest.ImageOCID, StorageDomain: authority.manifest.StorageDomain,
		ControllerSlots: slices.Clone(authority.manifest.ControllerSlots),
	}, authority.now, authority.policy)
	if err != nil {
		t.Fatalf("signed manifest changed through caller wire aliases: %v", err)
	}
	signedManifest := verified.Manifest()
	if !bytes.Equal(signedManifest.ReleaseImageReceiptWire, originalReceipt) ||
		!bytes.Equal(signedManifest.ReleaseDelegationWire, originalDelegation) {
		t.Fatal("signed manifest payload did not preserve the original release proof bytes")
	}
}

func TestManifestV2RequiresCanonicalReleaseWiresAndPinnedStorageDomain(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	if err := authority.manifest.Validate(); err != nil {
		t.Fatalf("valid v2 manifest rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "v1 schema version", mutate: func(manifest *Manifest) { manifest.SchemaVersion = 1 }},
		{name: "missing image receipt wire", mutate: func(manifest *Manifest) { manifest.ReleaseImageReceiptWire = nil }},
		{name: "missing release delegation wire", mutate: func(manifest *Manifest) { manifest.ReleaseDelegationWire = nil }},
		{name: "unsorted controller slots", mutate: func(manifest *Manifest) {
			manifest.ControllerSlots = []string{"seed-a", "peer-b"}
		}},
		{name: "slot outside instance descriptor grammar", mutate: func(manifest *Manifest) {
			manifest.Slot, manifest.SeedSlot = "seed/a", "seed/a"
			manifest.ControllerSlots = []string{"seed/a"}
		}},
		{name: "noncanonical image receipt wire", mutate: func(manifest *Manifest) {
			manifest.ReleaseImageReceiptWire = append(bytes.Clone(manifest.ReleaseImageReceiptWire), '\n')
			manifest.ReleaseReceiptSHA256 = digestBytes(manifest.ReleaseImageReceiptWire)
		}},
		{name: "noncanonical release delegation wire", mutate: func(manifest *Manifest) {
			manifest.ReleaseDelegationWire = append(bytes.Clone(manifest.ReleaseDelegationWire), '\n')
		}},
		{name: "wrong image receipt digest", mutate: func(manifest *Manifest) {
			manifest.ReleaseReceiptSHA256 = digestBytes([]byte("different wire"))
		}},
		{name: "oversize image receipt wire", mutate: func(manifest *Manifest) {
			manifest.ReleaseImageReceiptWire = bytes.Repeat([]byte{'x'}, MaxManifestBytes+1)
		}},
		{name: "empty namespace", mutate: func(manifest *Manifest) { manifest.StorageDomain.Namespace = "" }},
		{name: "same ledger and head bucket", mutate: func(manifest *Manifest) {
			manifest.StorageDomain.HeadBucket = manifest.StorageDomain.LedgerBucket
		}},
		{name: "invalid ledger KMS OCID", mutate: func(manifest *Manifest) {
			manifest.StorageDomain.LedgerKMSKeyOCID = "not-an-ocid"
		}},
		{name: "unsafe storage prefix", mutate: func(manifest *Manifest) { manifest.StorageDomain.Prefix = "private/../bootstrap" }},
		{name: "overlong storage prefix", mutate: func(manifest *Manifest) {
			manifest.StorageDomain.Prefix = string(bytes.Repeat([]byte{'a'}, 129))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := cloneManifest(authority.manifest)
			test.mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("Manifest.Validate() error = %v", err)
			}
		})
	}

	v1 := authority.manifest
	v1.SchemaVersion = 1
	payload, err := trust.EncodePayload(v1)
	if err != nil {
		t.Fatal(err)
	}
	v1Envelope, err := trust.Sign(payload, trust.Scope{
		Domain: "terrascale.bootstrap.manifest", DeploymentID: v1.DeploymentID, Cell: string(v1.Cell),
		Environment: v1.Environment, Role: v1.ControllerRole, Slot: v1.Slot,
	}, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(v1Envelope, authority.roots, ManifestExpectation{
		DeploymentID: v1.DeploymentID, Environment: v1.Environment, ClusterID: v1.ClusterID,
		Cell: v1.Cell, Slot: v1.Slot, ImageOCID: v1.ImageOCID, StorageDomain: v1.StorageDomain,
		ControllerSlots: slices.Clone(v1.ControllerSlots),
	}, authority.now, authority.policy); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("VerifyManifest() error for signed v1 schema = %v; want ErrManifestInvalid", err)
	}

	if emptyPrefix := authority.manifest.StorageDomain; emptyPrefix.Prefix != "" {
		emptyPrefix.Prefix = ""
		if err := emptyPrefix.Validate(); err != nil {
			t.Fatalf("canonical empty ledger prefix rejected: %v", err)
		}
	}
}

func TestCurrentAndHistoricalManifestRequireExactExpectedStorageDomain(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifestEnvelope, err := SignManifest(authority.manifest, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := ManifestExpectation{
		DeploymentID: authority.manifest.DeploymentID, Environment: authority.manifest.Environment,
		ClusterID: authority.manifest.ClusterID, Cell: authority.manifest.Cell,
		Slot: authority.manifest.Slot, ImageOCID: authority.manifest.ImageOCID,
		StorageDomain: authority.manifest.StorageDomain, ControllerSlots: slices.Clone(authority.manifest.ControllerSlots),
	}
	verified, err := VerifyManifest(manifestEnvelope, authority.roots, expected, authority.now, ManifestTrustPolicy())
	if err != nil {
		t.Fatalf("VerifyManifest() error = %v", err)
	}
	if got := verified.StorageDomain(); got != expected.StorageDomain {
		t.Fatalf("verified storage domain = %+v, want %+v", got, expected.StorageDomain)
	}
	withoutSlots := expected
	withoutSlots.ControllerSlots = nil
	if _, err := VerifyManifest(manifestEnvelope, authority.roots, withoutSlots, authority.now, ManifestTrustPolicy()); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("current verifier accepted an expectation without anchor slots: %v", err)
	}
	if _, err := VerifyHistoricalManifest(manifestEnvelope, authority.roots, withoutSlots, ManifestTrustPolicy()); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("historical verifier accepted an expectation without anchor slots: %v", err)
	}
	wrongSlots := expected
	wrongSlots.ControllerSlots = []string{"peer-b"}
	if _, err := VerifyManifest(manifestEnvelope, authority.roots, wrongSlots, authority.now, ManifestTrustPolicy()); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("current verifier accepted a different anchor slot set: %v", err)
	}

	wrong := expected
	wrong.StorageDomain.Namespace = "stale-namespace"
	if _, err := VerifyManifest(manifestEnvelope, authority.roots, wrong, authority.now, ManifestTrustPolicy()); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("current verifier accepted a descriptor for another storage domain: %v", err)
	}
	if _, err := VerifyHistoricalManifest(manifestEnvelope, authority.roots, wrong, ManifestTrustPolicy()); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("historical verifier accepted a descriptor for another storage domain: %v", err)
	}
}

func TestManifestRejectsExpiredWrongRootAndOverbroadPeerDelegation(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	peer := authority.manifest
	peer.Slot = "peer-b"
	envelope, err := SignManifest(peer, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := ManifestExpectation{
		DeploymentID: peer.DeploymentID, Environment: peer.Environment, ClusterID: peer.ClusterID,
		Cell: peer.Cell, Slot: peer.Slot, ImageOCID: peer.ImageOCID, StorageDomain: peer.StorageDomain,
		ControllerSlots: slices.Clone(peer.ControllerSlots),
	}
	if _, err := VerifyManifest(envelope, authority.roots, expected, authority.now.Add(time.Hour), authority.policy); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired manifest error = %v", err)
	}
	wrongRootPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(wrongRootPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(envelope, wrongRoots, expected, authority.now, authority.policy); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("wrong root error = %v", err)
	}

	peerPublicString, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	tooBroad := trust.Delegation{
		SchemaVersion:    trust.SchemaVersion,
		SubjectKeyID:     keyID(t, authority.peerPublic),
		SubjectPublicKey: peerPublicString,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: peer.DeploymentID, Cell: string(peer.Cell),
			Environment: peer.Environment, Role: peer.ControllerRole, Slots: []string{"seed-a", "peer-b"}, Actions: []string{"sign"},
		}},
	}
	overbroadEnvelope, err := trust.SignDelegation(tooBroad, authority.now.Add(-time.Minute), authority.now.Add(20*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	peer.PeerReceiptDelegation = &overbroadEnvelope
	overbroadManifest, err := SignManifest(peer, authority.now.Add(-time.Minute), authority.now.Add(30*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(overbroadManifest, authority.roots, expected, authority.now, authority.policy); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("overbroad peer delegation error = %v", err)
	}
}

func TestManifestValidationRejectsUnboundProfilesAndSecretOutputs(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := cloneManifest(authority.manifest)
	manifest.Profiles = manifest.Profiles[:1]
	if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest without every exact slot profile error = %v", err)
	}

	manifest = cloneManifest(authority.manifest)
	manifest.Secrets[1].TargetFile = manifest.Secrets[0].TargetFile
	if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest with duplicate output path error = %v", err)
	}

	manifest = cloneManifest(authority.manifest)
	manifest.Profiles[0].SubnetOCID = "ocid1.image.oc1.iad.notasubnet"
	if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest with wrong profile OCID kind error = %v", err)
	}

	manifest = cloneManifest(authority.manifest)
	manifest.ControllerFiles[1].Bytes = []byte(`{"changed":true}`)
	if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("manifest with changed signed sidecar bytes error = %v", err)
	}
}

func TestManifestKeepsIssuerAndOperatorLocalFilesInTheirRoles(t *testing.T) {
	manifest := newTestBootstrapAuthority(t).manifest
	reference := manifest.Secrets[0]
	for _, name := range []string{"host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem"} {
		reference.TargetFile = name
		reference.Purpose = SecretRegionalShared
		if err := reference.validate(manifest); !errors.Is(err, ErrManifestInvalid) {
			t.Fatalf("%s accepted as regional shared: %v", name, err)
		}
		reference.Purpose = SecretHostIssuer
		if err := reference.validate(manifest); err != nil {
			t.Fatalf("%s rejected as host issuer: %v", name, err)
		}
	}
	for _, name := range []string{"issuer-operator.seed", "issuer-system.seed", "issuer-cell.seed", "issuer-ca.key",
		"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem"} {
		reference.TargetFile = name
		reference.Purpose = SecretRegionalShared
		if err := reference.validate(manifest); !errors.Is(err, ErrManifestInvalid) {
			t.Fatalf("owner-only %s accepted for publication: %v", name, err)
		}
	}
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
		"wrong role":       func(facts *InstanceFacts) { facts.Role = "operator" },
		"wrong image":      func(facts *InstanceFacts) { facts.ImageOCID = "ocid1.image.oc1.iad.foreign" },
		"wrong compartment": func(facts *InstanceFacts) {
			facts.CompartmentOCID = "ocid1.compartment.oc1..foreign"
		},
		"wrong create key": func(facts *InstanceFacts) { facts.CreateKey = "different-launch-key" },
		"wrong intent":     func(facts *InstanceFacts) { facts.IntentSHA256 = digestBytes([]byte("different-intent")) },
		"wrong subnet":     func(facts *InstanceFacts) { facts.Profile.SubnetOCID = "ocid1.subnet.oc1.iad.foreign" },
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

func TestVaultRejectsDigestTraversalSymlinkOverwriteAndInterruptedWrites(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	reference := authority.manifest.Secrets[0]
	bundle := SecretBundle{
		SecretOCID: reference.SecretOCID, VersionNumber: reference.VersionNumber,
		ContentType: "BASE64", ContentBase64: base64.StdEncoding.EncodeToString(authority.regionalData),
	}
	if _, err := decodeSecretBundle(bundle, reference); err != nil {
		t.Fatalf("valid secret bundle rejected: %v", err)
	}
	wrongDigest := reference
	wrongDigest.SHA256 = digestBytes([]byte("other-content"))
	if _, err := decodeSecretBundle(bundle, wrongDigest); !errors.Is(err, ErrVaultSecretMismatch) {
		t.Fatalf("wrong content digest error = %v", err)
	}
	bundle.ContentType = "TEXT"
	if _, err := decodeSecretBundle(bundle, reference); !errors.Is(err, ErrVaultSecretMismatch) {
		t.Fatalf("non-base64 secret content type error = %v", err)
	}
	bundle.ContentType = "BASE64"
	bundle.ContentBase64 = "not-base64!"
	if _, err := decodeSecretBundle(bundle, reference); !errors.Is(err, ErrVaultSecretMismatch) {
		t.Fatalf("invalid base64 error = %v", err)
	}

	directory := t.TempDir()
	if err := materializeSecretWith(directory, "partial.key", []byte("complete secret"), func(writer io.Writer, value []byte) error {
		_, _ = writer.Write(value[:4])
		return errors.New("simulated interrupted write")
	}); !errors.Is(err, ErrMaterialization) {
		t.Fatalf("interrupted materialization error = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("interrupted materialization left visible files: %v, err = %v", entries, err)
	}

	outside := filepath.Join(t.TempDir(), "outside.key")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "linked.key")); err != nil {
		t.Fatal(err)
	}
	if err := materializeSecret(directory, "linked.key", []byte("replacement")); !errors.Is(err, ErrMaterialization) {
		t.Fatalf("existing symlink target error = %v", err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "untouched" {
		t.Fatalf("symlink target changed: %q, err = %v", content, err)
	}
	if err := materializeSecret(directory, "../outside.key", []byte("replacement")); !errors.Is(err, ErrMaterialization) {
		t.Fatalf("path traversal error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "existing.key"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := materializeSecret(directory, "existing.key", []byte("replacement")); !errors.Is(err, ErrMaterialization) {
		t.Fatalf("existing file overwrite error = %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(directory, "existing.key")); err != nil || string(content) != "existing" {
		t.Fatalf("existing file changed: %q, err = %v", content, err)
	}

	if err := materializeSecretWith(directory, "private.key", []byte("private"), nil); !errors.Is(err, ErrMaterialization) {
		t.Fatalf("nil materializer error = %v", err)
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
			Domain: peerReceiptDomain, DeploymentID: "deployment-a", Cell: string(oci.RegionGRU),
			Environment: "production", Role: "controller", Slots: []string{"peer-b"}, Actions: []string{"sign"},
		}},
	}, now.Add(-time.Minute), now.Add(20*time.Minute), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, err := trust.Sign([]byte(`{}`), trust.Scope{
		Domain: release.ImageDomain, DeploymentID: "release-a", Cell: "GRU", Environment: "production",
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
		SchemaVersion: ManifestSchemaVersion, DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 4,
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
			{Purpose: SecretRegionalShared, SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.regional", VersionNumber: 2,
				SHA256: digestBytes(regional), MaxBytes: 128, TargetFile: "regional.key"},
			{Purpose: SecretSeedFounder, Slot: "seed-a", SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.founder", VersionNumber: 3,
				SHA256: digestBytes([]byte("founder")), MaxBytes: 128, TargetFile: "founder.key"},
			{Purpose: SecretController, Slot: "seed-a", SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.seed", VersionNumber: 1,
				SHA256: digestBytes([]byte("seed")), MaxBytes: 128, TargetFile: "seed.key"},
			{Purpose: SecretController, Slot: "peer-b", SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.peer", VersionNumber: 1,
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
		DeploymentID: "deployment-a", Environment: "production", ClusterID: "cluster-a", Cell: oci.RegionGRU,
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
		Domain: release.ImageDomain, DeploymentID: "release-b", Cell: "GRU", Environment: "production",
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

func TestManifestCurrentRootKeyTypeMatchesOCICompartmentOCID(t *testing.T) {
	if !isOCID("ocid1.compartment.oc1..compartment", "compartment") {
		t.Fatal("global OCI compartment OCID with an empty region was rejected")
	}
}

func TestMaterializeSecretCreatesOwnerOnlyFile(t *testing.T) {
	directory := t.TempDir()
	if err := materializeSecret(directory, "secret.key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "secret.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode = %v, err = %v", info.Mode().Perm(), err)
	}
}
