package fixturegen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestPacketImageReceiptBindsExecutableAndImage(t *testing.T) {
	root, manifest, rootKey, roots := packetFixture(t)
	packet, err := ValidatePacket(root, roots, manifest.FixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegateID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("a", 40)
	imageOCID := "ocid1.image.oc1.sa-saopaulo-1.CUSTOM"
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: delegateID, SubjectPublicKey: publicWire,
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", revision), Cell: "GRU",
			Environment: "production", Role: "oci-image", Slots: []string{imageOCID}, Actions: []string{"sign"}}},
	}, manifest.FixtureNow.Add(-time.Minute), manifest.FixtureNow.Add(2*time.Hour), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	imageDigest := sha256.Sum256([]byte("image input"))
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision,
		GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: manifest.Binary.Size,
		BinarySHA256: manifest.Binary.SHA256, BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE",
		QualificationSHA256: strings.Repeat("e", 64),
		BaseImageRegion:     "GRU", BaseImageSHA256: hex.EncodeToString(imageDigest[:]),
		KernelRelease: "6.1.0-test+1", KernelSHA256: hex.EncodeToString(imageDigest[:]),
		ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: hex.EncodeToString(imageDigest[:]),
		OCIImageOCID: imageOCID, OCIRegion: "GRU"}
	sign := func(receipt release.ImageReceipt) []byte {
		t.Helper()
		receipt = qualifyHistoryImageFixture(t, receipt, "production", rootKey, manifest.FixtureNow, time.Hour)
		envelope, err := release.SignImageReceipt(receipt, "production", delegation, roots,
			delegatePrivate, manifest.FixtureNow, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	imageWire := sign(receipt)
	if _, err := VerifyPacketImageReceipt(packet, imageWire, delegationWire, roots, imageOCID, manifest.FixtureNow); err != nil {
		t.Fatalf("exact signed binary/image binding: %v", err)
	}
	if _, err := VerifyPacketImageReceipt(packet, imageWire, delegationWire, roots,
		"ocid1.image.oc1.sa-saopaulo-1.OTHER", manifest.FixtureNow); err == nil {
		t.Fatal("image OCID substitution accepted")
	}
	changed := receipt
	changed.BinarySHA256 = strings.Repeat("0", 64)
	if _, err := VerifyPacketImageReceipt(packet, sign(changed), delegationWire, roots,
		imageOCID, manifest.FixtureNow); err == nil {
		t.Fatal("signed image receipt for another executable accepted")
	}
	for name, body := range map[string][]byte{
		"simulator/release-image-receipt.json": imageWire,
		"simulator/release-delegation.json":    delegationWire,
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.WriteFile(full, body, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		manifest.Files = append(manifest.Files, FileEntry{Path: name, SHA256: hex.EncodeToString(digest[:]),
			Size: int64(len(body)), Mode: 0o600, OwnerRole: "simulator-host"})
	}
	slices.SortFunc(manifest.Files, func(a, b FileEntry) int { return strings.Compare(a.Path, b.Path) })
	writeManifest(t, root, manifest, rootKey)
	packet, err = ValidatePacket(root, roots, manifest.FixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPacketEmbeddedImage(packet, roots, imageOCID, manifest.FixtureNow); err != nil {
		t.Fatalf("embedded release proof failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "simulator", "release-image-receipt.json"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPacketEmbeddedImage(packet, roots, imageOCID, manifest.FixtureNow); err == nil {
		t.Fatal("changed embedded image receipt accepted")
	}
}
