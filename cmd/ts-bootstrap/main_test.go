package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

type manifestFixture struct {
	now             time.Time
	roots           trust.Keyring
	rootPublic      ed25519.PublicKey
	rootPrivate     ed25519.PrivateKey
	delegatePrivate ed25519.PrivateKey
	manifest        bootstrap.Manifest
	image           release.ImageReceipt
	imageWire       []byte
	delegationWire  []byte
	directory       string
	candidatePath   string
	imagePath       string
	delegationPath  string
	rootPath        string
	privatePath     string
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
	image := testImageReceipt()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: delegateKeyID, SubjectPublicKey: encodedDelegatePublic,
		Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: image.SourceRevision, Cell: "GRU", Environment: "production",
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
	manifest := bootstrap.Manifest{
		SchemaVersion: bootstrap.ManifestSchemaVersion, DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", IntentGeneration: 1,
		IntentSHA256: digest([]byte("intent")), ControllerRole: "controller", Slot: "seed-a", SeedSlot: "seed-a",
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
		delegatePrivate: delegatePrivate, manifest: manifest, image: image,
		imageWire: imageWire, delegationWire: delegationWire, directory: directory,
		candidatePath: filepath.Join(directory, "candidate.json"), imagePath: filepath.Join(directory, "image.json"),
		delegationPath: filepath.Join(directory, "release-delegation.json"), rootPath: filepath.Join(directory, "root.pub"),
		privatePath: filepath.Join(directory, "root.key"),
	}
	writeFixture(t, fixture.imagePath, imageWire, 0o600)
	writeFixture(t, fixture.delegationPath, delegationWire, 0o600)
	writeFixture(t, fixture.rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}), 0o644)
	writeFixture(t, fixture.privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	return fixture
}

func (fixture *manifestFixture) args(output string, validFor string) []string {
	args := []string{
		"--candidate", fixture.candidatePath,
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

func (fixture *manifestFixture) writeCandidate(t *testing.T, manifest bootstrap.Manifest) {
	t.Helper()
	encoded, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.candidatePath, encoded, 0o600)
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

func TestSignManifestSignsEachSlotWithExactCurrentReleaseProofs(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	var envelopeDigests []string
	for _, slot := range []string{"seed-a", "peer-b"} {
		t.Run(slot, func(t *testing.T) {
			manifest := fixture.manifest
			manifest.Slot, manifest.SeedSlot, manifest.ControllerSlots = slot, slot, []string{slot}
			manifest.Profiles = []bootstrap.LaunchProfile{{
				Slot: slot, CompartmentOCID: "ocid1.compartment.oc1..compartment",
				AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
				SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet", Shape: "VM.Standard.E5.Flex",
			}}
			fixture.writeCandidate(t, manifest)
			output := filepath.Join(fixture.directory, slot+".manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "2160h")...), fixture.now); err != nil {
				t.Fatalf("sign-manifest: %v", err)
			}
			envelope := fixture.verifyOutput(t, output, manifest)
			if !envelope.ExpiresAt.Equal(fixture.now.Add(45 * 24 * time.Hour)) {
				t.Fatalf("manifest expiry = %s, want image receipt expiry %s", envelope.ExpiresAt, fixture.now.Add(45*24*time.Hour))
			}
			envelopeDigests = append(envelopeDigests, digest(mustEncodeEnvelope(t, envelope)))
		})
	}
	if envelopeDigests[0] == envelopeDigests[1] {
		t.Fatal("per-slot manifests unexpectedly have the same signed envelope digest")
	}
}

func TestSignManifestRejectsInvalidCandidatesAndIdentityMismatches(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(*testing.T, *manifestFixture) []byte
	}{
		{name: "missing schema version", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.SchemaVersion = 0
			return mustEncodePayload(t, manifest)
		}},
		{name: "missing cluster id", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			encoded := mustEncodePayload(t, fixture.manifest)
			withoutCluster := bytes.Replace(encoded, []byte(`"clusterId":"cluster-a",`), nil, 1)
			if bytes.Equal(encoded, withoutCluster) {
				t.Fatal("test failed to remove the clusterId field")
			}
			return withoutCluster
		}},
		{name: "unknown field", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			encoded := mustEncodePayload(t, fixture.manifest)
			return append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
		}},
		{name: "conflicting image wire", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ReleaseImageReceiptWire = []byte("different proof")
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong image", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.different"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong region", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.Cell, manifest.OCIRegion = oci.RegionFRA, "eu-frankfurt-1"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong architecture", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ImageArchitecture = "linux-arm64"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong environment", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.Environment = "canary"
			return mustEncodePayload(t, manifest)
		}},
		{name: "wrong digest", candidate: func(t *testing.T, fixture *manifestFixture) []byte {
			manifest := fixture.manifest
			manifest.ReleaseReceiptSHA256 = strings.Repeat("0", 64)
			return mustEncodePayload(t, manifest)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
			candidate := test.candidate(t, fixture)
			writeFixture(t, fixture.candidatePath, candidate, 0o600)
			output := filepath.Join(fixture.directory, "bad.manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
				t.Fatal("sign-manifest accepted invalid candidate")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid candidate created output: stat error = %v", err)
			}
		})
	}
}

func TestSignManifestRejectsWrongRootKeyAndBadProofWires(t *testing.T) {
	t.Run("mismatched private key", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(wrongPrivate)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, fixture.privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "wrong-key.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
			t.Fatal("sign-manifest accepted a private key that does not match root public key")
		}
	})

	for _, test := range []struct {
		name string
		wire func(*testing.T, *manifestFixture) []byte
	}{
		{name: "tampered image signature", wire: func(t *testing.T, fixture *manifestFixture) []byte {
			envelope, err := trust.DecodeEnvelope(fixture.imageWire)
			if err != nil {
				t.Fatal(err)
			}
			signature := []byte(envelope.Signature)
			if signature[0] == 'A' {
				signature[0] = 'B'
			} else {
				signature[0] = 'A'
			}
			envelope.Signature = string(signature)
			return mustEncodeEnvelope(t, envelope)
		}},
		{name: "noncanonical release delegation", wire: func(_ *testing.T, fixture *manifestFixture) []byte {
			return append(bytes.Clone(fixture.delegationWire), '\n')
		}},
		{name: "expired image receipt", wire: func(t *testing.T, fixture *manifestFixture) []byte {
			payload, err := trust.EncodePayload(fixture.image)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, release.ImageScope(fixture.image, "production"),
				fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), fixture.delegatePrivate)
			if err != nil {
				t.Fatal(err)
			}
			return mustEncodeEnvelope(t, envelope)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
			imageWire := test.wire(t, fixture)
			fixture.writeProofs(t, imageWire, fixture.delegationWire)
			fixture.writeCandidate(t, fixture.manifest)
			output := filepath.Join(fixture.directory, "bad-proof.manifest.json")
			if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "")...), fixture.now); err == nil {
				t.Fatal("sign-manifest accepted invalid release proof")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid proof created output: stat error = %v", err)
			}
		})
	}
}

func TestSignManifestRejectsShortProofWindowAndNeverOverwrites(t *testing.T) {
	t.Run("less than minimum validity", func(t *testing.T) {
		fixture := newManifestFixture(t, 12*time.Hour, 30*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "short-window.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "48h")...), fixture.now); err == nil {
			t.Fatal("sign-manifest accepted fewer than the minimum 24 hours of remaining proof validity")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short proof window created output: stat error = %v", err)
		}
	})

	t.Run("existing output is preserved", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "signed.manifest.json")
		args := append([]string{"sign-manifest"}, fixture.args(output, "720h")...)
		if err := runAt(args, fixture.now); err != nil {
			t.Fatalf("first sign-manifest: %v", err)
		}
		before, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := runAt(args, fixture.now); err == nil {
			t.Fatal("sign-manifest overwrote an existing output")
		}
		after, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("existing output changed after refused overwrite")
		}
	})
}

func TestSignManifestClampsToReleaseAndPeerDelegationExpiries(t *testing.T) {
	t.Run("release delegation", func(t *testing.T) {
		fixture := newManifestFixture(t, 40*24*time.Hour, 90*24*time.Hour)
		fixture.writeCandidate(t, fixture.manifest)
		output := filepath.Join(fixture.directory, "release-clamped.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "2160h")...), fixture.now); err != nil {
			t.Fatalf("sign-manifest: %v", err)
		}
		envelope := fixture.verifyOutput(t, output, fixture.manifest)
		if !envelope.ExpiresAt.Equal(fixture.now.Add(40 * 24 * time.Hour)) {
			t.Fatalf("manifest expiry = %s, want release delegation expiry %s", envelope.ExpiresAt, fixture.now.Add(40*24*time.Hour))
		}
	})

	t.Run("peer delegation", func(t *testing.T) {
		fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
		peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peerKeyID, err := trust.KeyID(peerPublic)
		if err != nil {
			t.Fatal(err)
		}
		encodedPeerPublic, err := trust.EncodeDelegatedPublicKey(peerPublic)
		if err != nil {
			t.Fatal(err)
		}
		peerDelegation, err := trust.SignDelegation(trust.Delegation{
			SchemaVersion: trust.SchemaVersion, SubjectKeyID: peerKeyID, SubjectPublicKey: encodedPeerPublic,
			Capabilities: []trust.Capability{{
				Domain: "terrascale.bootstrap.peer-receipt", DeploymentID: fixture.manifest.DeploymentID,
				Cell: string(fixture.manifest.Cell), Environment: fixture.manifest.Environment,
				Role: fixture.manifest.ControllerRole, Slots: []string{"peer-b"}, Actions: []string{"sign"},
			}},
		}, fixture.now.Add(-time.Minute), fixture.now.Add(48*time.Hour), fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		manifest := fixture.manifest
		manifest.ControllerSlots = []string{"seed-a", "peer-b"}
		manifest.Profiles = append(manifest.Profiles, bootstrap.LaunchProfile{
			Slot: "peer-b", CompartmentOCID: "ocid1.compartment.oc1..compartment",
			AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-2",
			SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.peer", Shape: "VM.Standard.E5.Flex",
		})
		manifest.PeerReceiptDelegation = &peerDelegation
		fixture.writeCandidate(t, manifest)
		output := filepath.Join(fixture.directory, "peer-clamped.manifest.json")
		if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err != nil {
			t.Fatalf("sign-manifest: %v", err)
		}
		envelope := fixture.verifyOutput(t, output, manifest)
		if !envelope.ExpiresAt.Equal(fixture.now.Add(48 * time.Hour)) {
			t.Fatalf("manifest expiry = %s, want peer delegation expiry %s", envelope.ExpiresAt, fixture.now.Add(48*time.Hour))
		}
	})
}

func TestSignManifestRejectsFinalEnvelopeOverSizeLimit(t *testing.T) {
	fixture := newManifestFixture(t, 60*24*time.Hour, 45*24*time.Hour)
	manifest := fixture.manifest
	manifest.ReleaseImageReceiptWire = bytes.Clone(fixture.imageWire)
	manifest.ReleaseDelegationWire = bytes.Clone(fixture.delegationWire)
	manifest.Slot = strings.Repeat("s", 256)
	manifest.SeedSlot = manifest.Slot
	manifest.ControllerSlots = []string{manifest.Slot}
	manifest.Profiles[0].Slot = manifest.Slot
	for index := range 128 {
		target := "file-" + strings.Repeat("x", 120) + fmt.Sprintf("%03d", index)
		ocidPrefix := "ocid1.secret.oc1.sa-saopaulo-1."
		suffix := fmt.Sprintf("%03d", index)
		secretOCID := ocidPrefix + strings.Repeat("a", 255-len(ocidPrefix)-len(suffix)) + suffix
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{
			Purpose: bootstrap.SecretController, Slot: manifest.Slot, SecretOCID: secretOCID,
			VersionNumber: int64(index + 1), SHA256: digest([]byte(fmt.Sprintf("secret-%d", index))),
			MaxBytes: bootstrap.MaxSecretBytes, TargetFile: target,
		})
		payload, err := trust.EncodePayload(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > bootstrap.MaxManifestBytes {
			manifest.Secrets = manifest.Secrets[:len(manifest.Secrets)-1]
			break
		}
	}
	manifest.StorageDomain.Namespace = strings.Repeat("n", 128)
	manifest.StorageDomain.Prefix = strings.Repeat("p", 128)
	if err := manifest.Validate(); err != nil {
		t.Fatalf("large size-boundary fixture is invalid: %v", err)
	}
	payload, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < bootstrap.MaxManifestBytes-1024 {
		t.Fatalf("size-boundary payload is too small to exceed the envelope bound: %d bytes", len(payload))
	}
	manifest.ReleaseImageReceiptWire = nil
	manifest.ReleaseDelegationWire = nil
	fixture.writeCandidate(t, manifest)
	output := filepath.Join(fixture.directory, "oversize.manifest.json")
	if err := runAt(append([]string{"sign-manifest"}, fixture.args(output, "720h")...), fixture.now); err == nil {
		encoded, readErr := os.ReadFile(output)
		t.Fatalf("sign-manifest accepted a %d-byte signed envelope exceeding the manifest limit (read error %v)", len(encoded), readErr)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize manifest created output: stat error = %v", err)
	}
}

func testImageReceipt() release.ImageReceipt {
	imageDigest := digest([]byte("image bytes"))
	return release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: testRevision, GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest([]byte("binary bytes")),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU",
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

func mustEncodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	return encodeEnvelope(t, envelope)
}

func mustEncodePayload(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
