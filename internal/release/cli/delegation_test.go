package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"path/filepath"

	"testing"
	"time"
)

const testDelegationImageOCID = "ocid1.image.oc1.sa-saopaulo-1.ABC123"

type delegationFixture struct {
	now         time.Time
	rootPublic  ed25519.PublicKey
	leafPrivate ed25519.PrivateKey
	rootPath    string
	privatePath string
	leafPath    string
	directory   string
}

func newDelegationFixture(t *testing.T) delegationFixture {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	fixture := delegationFixture{now: time.Now().UTC().Truncate(time.Second), rootPublic: rootPublic,
		leafPrivate: leafPrivate, rootPath: filepath.Join(directory, "root.pub"),
		privatePath: filepath.Join(directory, "root.key"), leafPath: filepath.Join(directory, "leaf.pub"),
		directory: directory}
	writePublicKey(t, fixture.rootPath, rootPublic)
	writePublicKey(t, fixture.leafPath, leafPublic)
	writePrivateKey(t, fixture.privatePath, rootPrivate)
	return fixture
}

func writePublicKey(t *testing.T, path string, public ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
}

func writePrivateKey(t *testing.T, path string, private ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func (fixture delegationFixture) args(output string) []string {
	return []string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--source-revision", testRevision,
		"--arch", "amd64", "--arch", "arm64",
		"--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", fixture.now.Add(time.Hour).Format(time.RFC3339), "--out", output}
}

func testDelegationImageReceipt(binary binaryReceipt) imageReceipt {
	digest := sha256.Sum256([]byte("image"))
	return imageReceipt{Schema: imageSchema, SourceRevision: testRevision, GoVersion: defaultGoVersion,
		Architecture: "amd64", BinaryBytes: binary.Bytes, BinarySHA256: binary.SHA256,
		QualificationSHA256: binary.QualificationSHA256,
		BaseImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.BASE123", BaseImageRegion: "GRU",
		BaseImageSHA256: hex.EncodeToString(digest[:]), KernelRelease: "6.12.0",
		KernelSHA256: hex.EncodeToString(digest[:]), ImageFormat: "qcow2", ImageBytes: 4096,
		ImageSHA256: hex.EncodeToString(digest[:]), OCIImageOCID: testDelegationImageOCID, OCIRegion: "GRU"}
}
