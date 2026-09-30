package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const managedImageTestOCID = "ocid1.image.oc1.sa-saopaulo-1.QUALIFIED"

func TestManagedControllerFleetPassesQualifiedImageVerifier(t *testing.T) {
	region := oci.RegionConfig{Region: oci.RegionGRU, ImageID: managedImageTestOCID}
	intent := oci.RegionIntent{Generation: 7}
	verifier := &managedImageVerifier{}
	var called bool
	hostMetadata := map[string]string{"terrascale-host-enrollment-v1": "{}"}
	fleet, err := openManagedControllerFleet(t.Context(), region, intent, nil, nil, hostMetadata,
		func(_ context.Context, got oci.RegionConfig) (oci.ImageQualificationVerifier, error) {
			if !reflect.DeepEqual(got, region) {
				t.Fatal("verifier received a different regional image pin")
			}
			return verifier, nil
		},
		func(gotRegion oci.RegionConfig, gotIntent oci.RegionIntent, _ oci.Journal,
			_ authority.Fencer, drain oci.DrainRequester, stopped oci.WriterStopVerifier,
			gotVerifier oci.ImageQualificationVerifier, gotMetadata map[string]string,
		) (oci.Fleet, error) {
			called = true
			if !reflect.DeepEqual(gotRegion, region) || gotIntent.Generation != intent.Generation ||
				gotVerifier != verifier || drain != nil || stopped != nil || !reflect.DeepEqual(gotMetadata, hostMetadata) {
				t.Fatal("managed fleet constructor lost its exact image verifier or regional scope")
			}
			return regionOnlyFleet{region: region.Region}, nil
		})
	if err != nil || !called || fleet == nil {
		t.Fatalf("managed fleet was not built with qualification: fleet=%v called=%t err=%v", fleet, called, err)
	}
	_, err = openManagedControllerFleet(t.Context(), region, intent, nil, nil, hostMetadata,
		func(context.Context, oci.RegionConfig) (oci.ImageQualificationVerifier, error) { return nil, nil },
		func(oci.RegionConfig, oci.RegionIntent, oci.Journal, authority.Fencer,
			oci.DrainRequester, oci.WriterStopVerifier, oci.ImageQualificationVerifier, map[string]string,
		) (oci.Fleet, error) {
			t.Fatal("fleet constructor called without image qualification")
			return nil, nil
		})
	if err == nil {
		t.Fatal("managed fleet admitted a nil image verifier")
	}
}

type fixedManagedImageReadback struct {
	image      core.Image
	compatible core.ImageShapeCompatibilityEntry
	imageCalls int
	shapeCalls int
}

func (reader *fixedManagedImageReadback) GetImage(_ context.Context, request core.GetImageRequest) (core.GetImageResponse, error) {
	reader.imageCalls++
	if request.ImageId == nil || *request.ImageId != managedImageTestOCID {
		return core.GetImageResponse{}, errors.New("wrong image requested")
	}
	return core.GetImageResponse{Image: reader.image}, nil
}

func (reader *fixedManagedImageReadback) GetImageShapeCompatibilityEntry(_ context.Context,
	request core.GetImageShapeCompatibilityEntryRequest,
) (core.GetImageShapeCompatibilityEntryResponse, error) {
	reader.shapeCalls++
	if request.ImageId == nil || *request.ImageId != managedImageTestOCID ||
		request.ShapeName == nil || *request.ShapeName != "VM.Standard.A1.Flex" {
		return core.GetImageShapeCompatibilityEntryResponse{}, errors.New("wrong shape requested")
	}
	return core.GetImageShapeCompatibilityEntryResponse{ImageShapeCompatibilityEntry: reader.compatible}, nil
}

func TestManagedImageVerifierRequiresCurrentSignedReceiptAndOCIReadback(t *testing.T) {
	verifier, reader, now := managedImageVerifierFixture(t)
	if err := verifier.VerifyImageQualified(t.Context(), oci.RegionGRU, managedImageTestOCID); err != nil {
		t.Fatalf("qualified OCI image held: %v", err)
	}
	if reader.imageCalls != 1 || reader.shapeCalls != 1 {
		t.Fatalf("OCI image and shape readback calls = %d, %d; want 1, 1", reader.imageCalls, reader.shapeCalls)
	}
	for _, test := range []struct {
		name   string
		mutate func(*managedImageVerifier, *fixedManagedImageReadback)
	}{
		{"wrong fleet image", func(v *managedImageVerifier, _ *fixedManagedImageReadback) { v.region.ImageID += "OTHER" }},
		{"expired release receipt", func(v *managedImageVerifier, _ *fixedManagedImageReadback) {
			v.now = func() time.Time { return now.Add(2 * time.Hour) }
		}},
		{"different OCI image", func(_ *managedImageVerifier, r *fixedManagedImageReadback) {
			r.image.Id = new("ocid1.image.oc1.sa-saopaulo-1.OTHER")
		}},
		{"different OCI compartment", func(_ *managedImageVerifier, r *fixedManagedImageReadback) {
			r.image.CompartmentId = new("ocid1.compartment.oc1..other")
		}},
		{"unavailable OCI image", func(_ *managedImageVerifier, r *fixedManagedImageReadback) {
			r.image.LifecycleState = core.ImageLifecycleStateDisabled
		}},
		{"incompatible OCI shape", func(_ *managedImageVerifier, r *fixedManagedImageReadback) {
			r.compatible.Shape = new("VM.Standard.E5.Flex")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := *verifier
			copyReader := *reader
			candidate.images = &copyReader
			test.mutate(&candidate, &copyReader)
			if err := candidate.VerifyImageQualified(t.Context(), oci.RegionGRU, managedImageTestOCID); err == nil {
				t.Fatal("unqualified image passed managed fleet gate")
			}
		})
	}
}

func managedImageVerifierFixture(t *testing.T) (*managedImageVerifier, *fixedManagedImageReadback, time.Time) {
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
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: "0123456789abcdef0123456789abcdef01234567",
			Cell: "GRU", Environment: "production", Role: "oci-image", Slots: []string{managedImageTestOCID}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("qualified fixture"))
	digest := hex.EncodeToString(hash[:])
	receipt := release.ImageReceipt{
		Schema: release.ImageSchema, SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		GoVersion: release.DefaultGoVersion, Architecture: "arm64", BinaryBytes: 100,
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
	reader := &fixedManagedImageReadback{
		image: core.Image{Id: new(managedImageTestOCID), CompartmentId: new("ocid1.compartment.oc1..owned"),
			LifecycleState: core.ImageLifecycleStateAvailable},
		compatible: core.ImageShapeCompatibilityEntry{ImageId: new(managedImageTestOCID), Shape: new("VM.Standard.A1.Flex")},
	}
	return &managedImageVerifier{
		region: oci.RegionConfig{Region: oci.RegionGRU, ImageID: managedImageTestOCID,
			CompartmentID: "ocid1.compartment.oc1..workload", ImageCompartmentID: "ocid1.compartment.oc1..owned",
			Shape: "VM.Standard.A1.Flex"},
		environment: "production", architecture: "arm64", roots: roots,
		receiptWire: receiptWire, delegationWire: delegationWire, images: reader,
		now: func() time.Time { return now },
	}, reader, now
}
