package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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

// A second region's image is delegated for its own cell: the OCID must be
// one of that cell's region.
func TestSignDelegationImageOfAnotherCatalogCell(t *testing.T) {
	fixture := newDelegationFixture(t)
	first := filepath.Join(fixture.directory, "binary-delegation.json")
	if err := signDelegationAt(fixture.args(first), fixture.now); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(fixture.directory, "image-delegation.json")
	for _, args := range [][]string{{"--image-cell", "LHR", "--image-ocid", testDelegationImageOCID},
		{"--image-cell", "SFO", "--image-ocid", testDelegationImageOCID}} {
		if err := signDelegationAt(append(fixture.args(image), append(args, "--previous-delegation", first)...), fixture.now); err == nil {
			t.Fatal("signed an image delegation outside its cell's region", args)
		}
	}
	sfo := "ocid1.image.oc1.us-sanjose-1.ABC123"
	if err := signDelegationAt(append(fixture.args(image), "--image-cell", "SFO", "--image-ocid", sfo, "--previous-delegation", first), fixture.now); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.VerifyDelegationCurrent(envelope, roots, fixture.now,
		trust.Policy{MaxLifetime: release.MaxDelegationLifetime, ClockSkew: time.Minute})
	want := capabilityForScope(release.ImageScope(release.ImageReceipt{SourceRevision: testRevision, OCIRegion: "SFO", OCIImageOCID: sfo}, "canary"))
	if err != nil || !slices.ContainsFunc(delegation.Capabilities(), func(c trust.Capability) bool { return reflect.DeepEqual(c, want) }) {
		t.Fatal(err, delegation.Capabilities())
	}
}

func TestSignDelegationBinaryThenImageRetainsBinaryAuthority(t *testing.T) {
	fixture := newDelegationFixture(t)
	firstPath := filepath.Join(fixture.directory, "binary-delegation.json")
	if err := signDelegationAt(fixture.args(firstPath), fixture.now); err != nil {
		t.Fatalf("sign binary delegation: %v", err)
	}
	firstWire, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	firstEnvelope, err := trust.DecodeEnvelope(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	first, err := trust.VerifyDelegationCurrent(firstEnvelope, roots, fixture.now,
		trust.Policy{MaxLifetime: release.MaxDelegationLifetime, ClockSkew: time.Minute})
	if err != nil || len(first.Capabilities()) != 2 {
		t.Fatalf("binary-only delegation invalid: capabilities=%v error=%v", first.Capabilities(), err)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		if !slices.ContainsFunc(first.Capabilities(), func(cap trust.Capability) bool {
			return cap.Domain == release.BinaryDomain && cap.DeploymentID == entityid.Derive("build", testRevision) &&
				cap.Cell == "BUILD" && cap.Environment == "canary" && cap.Role == "artifact" &&
				slices.Equal(cap.Slots, []string{"linux-" + architecture}) && slices.Equal(cap.Actions, []string{"sign"})
		}) {
			t.Fatalf("missing exact %s binary capability", architecture)
		}
	}
	binary := testBinaryReceipt()
	signedBinary, err := release.SignBinaryReceipt(binary, "canary", firstEnvelope, roots,
		fixture.leafPrivate, fixture.now, 30*time.Minute)
	if err != nil {
		t.Fatalf("sign binary receipt: %v", err)
	}
	binaryWire, err := trust.EncodeEnvelope(signedBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyBinaryCurrent(binaryWire, firstWire, roots,
		release.BinaryExpectation{Environment: "canary"}, fixture.now); err != nil {
		t.Fatalf("verify binary under first delegation: %v", err)
	}

	secondPath := filepath.Join(fixture.directory, "image-delegation.json")
	secondArgs := append(fixture.args(secondPath), "--image-cell", "GRU", "--image-ocid", testDelegationImageOCID,
		"--previous-delegation", firstPath)
	if err := signDelegationAt(append(fixture.args(secondPath), "--image-cell", "GRU",
		"--image-ocid", testDelegationImageOCID), fixture.now); err == nil {
		t.Fatal("image delegation without a prior binary delegation was signed")
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"changed source", []string{"--source-revision", strings.Repeat("a", 40)}},
		{"changed expiry", []string{"--expires-at", fixture.now.Add(2 * time.Hour).Format(time.RFC3339)}},
		{"changed architecture set", []string{"--arch", "amd64"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append(slices.Clone(secondArgs), test.args...)
			if test.name == "changed architecture set" {
				args = []string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
					"--signing-key", fixture.privatePath, "--source-revision", testRevision,
					"--arch", "amd64", "--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
					"--expires-at", fixture.now.Add(time.Hour).Format(time.RFC3339), "--out", secondPath,
					"--image-cell", "GRU", "--image-ocid", testDelegationImageOCID,
					"--previous-delegation", firstPath}
			}
			if err := signDelegationAt(args, fixture.now); err == nil {
				t.Fatal("image phase changed a previously authorized binary boundary")
			}
		})
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherLeaf := filepath.Join(fixture.directory, "other-leaf.pub")
	writePublicKey(t, otherLeaf, otherPublic)
	if err := signDelegationAt(append(slices.Clone(secondArgs), "--subject-public-key", otherLeaf), fixture.now); err == nil {
		t.Fatal("image phase changed the delegated leaf")
	}
	malformedPrior := filepath.Join(fixture.directory, "malformed-prior.json")
	writeFixtureFile(t, malformedPrior, []byte("not an envelope"), 0o600)
	if err := signDelegationAt(append(slices.Clone(secondArgs), "--previous-delegation", malformedPrior), fixture.now); err == nil {
		t.Fatal("image phase accepted a malformed previous delegation")
	}
	rootPrivate, err := readOfflineRootPrivateKey(fixture.privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rootPrivate)
	leafPublic := fixture.leafPrivate.Public().(ed25519.PublicKey)
	leafID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	leafEncoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	priorPayload := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: leafID,
		SubjectPublicKey: leafEncoded, Capabilities: first.Capabilities()}
	for _, test := range []struct {
		name      string
		private   ed25519.PrivateKey
		issuedAt  time.Time
		expiresAt time.Time
	}{
		{"wrong root", otherPrivate, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour)},
		{"expired", rootPrivate, fixture.now.Add(-2 * time.Hour), fixture.now.Add(-time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			prior, err := trust.SignDelegation(priorPayload, test.issuedAt, test.expiresAt, test.private)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := trust.EncodeEnvelope(prior)
			if err != nil {
				t.Fatal(err)
			}
			priorPath := filepath.Join(fixture.directory, strings.ReplaceAll(test.name, " ", "-")+"-prior.json")
			writeFixtureFile(t, priorPath, wire, 0o600)
			if err := signDelegationAt(append(slices.Clone(secondArgs), "--previous-delegation", priorPath), fixture.now); err == nil {
				t.Fatal("image phase accepted an untrusted or expired previous delegation")
			}
		})
	}
	if err := signDelegationAt(secondArgs, fixture.now); err != nil {
		t.Fatalf("sign expanded delegation: %v", err)
	}
	secondWire, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	secondEnvelope, err := trust.DecodeEnvelope(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	second, err := trust.VerifyDelegationCurrent(secondEnvelope, roots, fixture.now,
		trust.Policy{MaxLifetime: release.MaxDelegationLifetime, ClockSkew: time.Minute})
	if err != nil || len(second.Capabilities()) != 3 || first.SubjectKeyID() != second.SubjectKeyID() ||
		!slices.EqualFunc(first.Capabilities(), second.Capabilities()[:2], func(a, b trust.Capability) bool {
			return a.Domain == b.Domain && a.DeploymentID == b.DeploymentID && a.Cell == b.Cell &&
				a.Environment == b.Environment && a.Role == b.Role && slices.Equal(a.Slots, b.Slots) &&
				slices.Equal(a.Actions, b.Actions)
		}) {
		t.Fatalf("expanded delegation lost binary scope: error=%v", err)
	}
	if _, err := release.VerifyBinaryCurrent(binaryWire, secondWire, roots,
		release.BinaryExpectation{Environment: "canary"}, fixture.now); err != nil {
		t.Fatalf("verify prior binary under expanded delegation: %v", err)
	}
	image := testDelegationImageReceipt(binary)
	evidenceDir := t.TempDir()
	candidate := release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256,
		QualificationSHA256: image.QualificationSHA256, Cell: image.OCIRegion, Environment: "canary",
		Runtime: release.ProductionRuntime, Architecture: image.Architecture, Role: "orchestrator"}
	record := writeProductionEvidence(t, evidenceDir, candidate)
	writeProductionRecord(t, filepath.Join(evidenceDir, image.OCIRegion, image.Architecture, "production.json"), record,
		rootPrivate, fixture.now, fixture.now.Add(time.Hour))
	proof, err := readProductionProof(evidenceDir, image.OCIRegion, image.Architecture)
	if err != nil {
		t.Fatal(err)
	}
	image.Production = &proof
	signedImage, err := release.SignImageReceipt(image, "canary", secondEnvelope, roots,
		fixture.leafPrivate, fixture.now, 30*time.Minute)
	if err != nil {
		t.Fatalf("sign image receipt: %v", err)
	}
	imageWire, err := trust.EncodeEnvelope(signedImage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyImageCurrent(imageWire, secondWire, roots,
		release.ImageExpectation{Environment: "canary", LogicalRegion: "GRU",
			OCIImageOCID: testDelegationImageOCID, Architecture: "amd64"}, fixture.now); err != nil {
		t.Fatalf("verify exact GRU image: %v", err)
	}
	if _, err := release.VerifyImageCurrent(imageWire, firstWire, roots,
		release.ImageExpectation{Environment: "canary", LogicalRegion: "GRU",
			OCIImageOCID: testDelegationImageOCID, Architecture: "amd64"}, fixture.now); err == nil {
		t.Fatal("binary-only delegation authorized an image")
	}
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

func TestSignDelegationRejectsInvalidScopeTimeKeysAndOverwrite(t *testing.T) {
	fixture := newDelegationFixture(t)
	output := filepath.Join(fixture.directory, "delegation.json")
	base := fixture.args(output)
	rootPrivatePath := fixture.privatePath
	badPrivatePath := filepath.Join(fixture.directory, "bad-root.key")
	writeFixtureFile(t, badPrivatePath, []byte("not PEM"), 0o600)
	badLeafPath := filepath.Join(fixture.directory, "bad-leaf.pub")
	writeFixtureFile(t, badLeafPath, []byte("not PEM"), 0o600)
	for _, test := range []struct {
		name string
		args []string
	}{
		{"production", []string{"--environment", "production"}},
		{"source", []string{"--source-revision", "short"}},
		{"architecture", []string{"--arch", "riscv64"}},
		{"duplicate architecture", []string{"--arch", "amd64"}},
		{"wildcard architecture", []string{"--arch", "*"}},
		{"foreign image", []string{"--image-cell", "SFO", "--image-ocid", testDelegationImageOCID}},
		{"missing image pair", []string{"--image-cell", "GRU"}},
		{"malformed image", []string{"--image-cell", "GRU", "--image-ocid", "ocid1.image.invalid"}},
		{"non UTC", []string{"--issued-at", fixture.now.Add(-time.Minute).Format("2006-01-02T15:04:05-03:00")}},
		{"expired", []string{"--expires-at", fixture.now.Add(-time.Second).Format(time.RFC3339)}},
		{"future issue", []string{"--issued-at", fixture.now.Add(time.Minute).Format(time.RFC3339)}},
		{"overlong", []string{"--expires-at", fixture.now.Add(release.MaxDelegationLifetime + time.Hour).Format(time.RFC3339)}},
		{"malformed private", []string{"--signing-key", badPrivatePath}},
		{"malformed subject", []string{"--subject-public-key", badLeafPath}},
		{"arbitrary scope flag", []string{"--capability", "*"}},
		{"extra action flag", []string{"--action", "manage"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append(slices.Clone(base), test.args...)
			if err := signDelegationAt(args, fixture.now); err == nil {
				t.Fatal("invalid delegation was signed")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("invalid delegation wrote output: %v", err)
			}
		})
	}
	withoutArchitectures := []string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--source-revision", testRevision,
		"--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", fixture.now.Add(time.Hour).Format(time.RFC3339), "--out", output}
	if err := signDelegationAt(withoutArchitectures, fixture.now); err == nil {
		t.Fatal("delegation without binary capabilities was signed")
	}
	symlinkPath := filepath.Join(fixture.directory, "root-symlink.key")
	if err := os.Symlink(rootPrivatePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := signDelegationAt(append(slices.Clone(base), "--signing-key", symlinkPath), fixture.now); err == nil {
		t.Fatal("symlinked root signing key was accepted")
	}
	if err := os.Chmod(rootPrivatePath, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := signDelegationAt(base, fixture.now); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("insecure root key error = %v", err)
	}
	if err := os.Chmod(rootPrivatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	writePublicKey(t, fixture.leafPath, fixture.rootPublic)
	if err := signDelegationAt(base, fixture.now); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Fatalf("root-as-leaf error = %v", err)
	}
	if err := os.Remove(fixture.leafPath); err != nil {
		t.Fatal(err)
	}
	writePublicKey(t, fixture.leafPath, fixture.leafPrivate.Public().(ed25519.PublicKey))
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writePublicKey(t, fixture.rootPath, otherPublic)
	if err := signDelegationAt(base, fixture.now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("root mismatch error = %v", err)
	}
	writePublicKey(t, fixture.rootPath, fixture.rootPublic)
	if err := signDelegationAt(base, fixture.now); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := signDelegationAt(base, fixture.now); err == nil || !strings.Contains(err.Error(), "without overwrite") {
		t.Fatalf("overwrite error = %v", err)
	}
	second, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("overwrite changed signed output: %v", err)
	}
}
