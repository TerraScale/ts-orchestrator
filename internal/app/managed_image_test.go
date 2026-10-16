package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const managedImageTestOCID = "ocid1.image.oc1.sa-saopaulo-1.QUALIFIED"

func managedImageVerifierFixture(t *testing.T, architecture string) (*managedImageVerifier, time.Time) {
	t.Helper()
	return managedImageVerifierFixtureForBytes(t, architecture, bytes.Repeat([]byte("b"), 100), bytes.Repeat([]byte("i"), 1024))
}

func managedImageVerifierFixtureForBytes(t *testing.T, architecture string, binary, image []byte) (*managedImageVerifier, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", "0123456789abcdef0123456789abcdef01234567"),
			Cell: "GRU", Environment: "production", Role: "oci-image", Slots: []string{managedImageTestOCID}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	binaryHash, imageHash := sha256.Sum256(binary), sha256.Sum256(image)
	binaryDigest, imageDigest := hex.EncodeToString(binaryHash[:]), hex.EncodeToString(imageHash[:])
	receipt := release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		GoVersion: release.DefaultGoVersion, Architecture: architecture, BinaryBytes: int64(len(binary)),
		BinarySHA256: binaryDigest, QualificationSHA256: binaryDigest,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU", BaseImageSHA256: imageDigest,
		KernelRelease: "6.1.0-test+1", KernelSHA256: binaryDigest, ImageFormat: "qcow2",
		ImageBytes: int64(len(image)), ImageSHA256: imageDigest, OCIImageOCID: managedImageTestOCID, OCIRegion: "GRU",
	}
	receipt.Production = imageProductionProofFixture(t, receipt, "production", roots, rootPrivate, now, time.Hour)
	signed, err := release.SignImageReceipt(receipt, "production", delegation, roots,
		delegatePrivate, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return &managedImageVerifier{
		region: oci.RegionConfig{Region: oci.RegionGRU, ImageID: managedImageTestOCID,
			CompartmentID: "ocid1.compartment.oc1..workload", ImageCompartmentID: "ocid1.compartment.oc1..owned",
			Shape: "VM.Standard.Future.Flex", AvailabilityDomain: "test:SA-SAOPAULO-1-AD-1"},
		environment: "production", roots: roots,
		receiptWire: receiptWire, delegationWire: delegationWire,
		now: func() time.Time { return now },
	}, now
}

func imageProductionProofFixture(t *testing.T, receipt release.ImageReceipt, environment string, roots trust.Keyring,
	qualifier ed25519.PrivateKey, issuedAt time.Time, lifetime time.Duration,
) *release.ProductionProof {
	t.Helper()
	candidate := release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: environment,
		Runtime: release.ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}
	record := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	directory := t.TempDir()
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		data, err := json.Marshal(struct {
			Gate      string
			Candidate release.ProductionExpectation
		}{gate, candidate})
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		path := filepath.Join(directory, digest)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		retained, err := os.ReadFile(path)
		if err != nil || len(retained) != len(data) || sha256.Sum256(retained) != sum {
			t.Fatalf("retained %s image evidence differs from signed candidate: %v", gate, err)
		}
		record.Evidence = append(record.Evidence, release.ProductionGateEvidence{
			Gate: gate, SHA256: digest, Bytes: int64(len(retained)), CompletedAt: issuedAt.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), issuedAt, issuedAt.Add(lifetime), qualifier)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "qualification.json")
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, wire) {
		t.Fatalf("retained image proof differs from signed bytes: %v", err)
	}
	if _, err := release.VerifyProductionCurrent(retained, nil, roots, candidate, issuedAt); err != nil {
		t.Fatal(err)
	}
	return &release.ProductionProof{Qualification: retained}
}
