package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	hash := sha256.Sum256([]byte("qualified fixture"))
	digest := hex.EncodeToString(hash[:])
	receipt := release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		GoVersion: release.DefaultGoVersion, Architecture: architecture, BinaryBytes: 100,
		BinarySHA256: digest, QualificationSHA256: digest,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU", BaseImageSHA256: digest,
		KernelRelease: "6.1.0-test+1", KernelSHA256: digest, ImageFormat: "qcow2",
		ImageBytes: 1024, ImageSHA256: digest, OCIImageOCID: managedImageTestOCID, OCIRegion: "GRU",
	}
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
