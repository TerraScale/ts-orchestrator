package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testSourceRevision = "0123456789abcdef0123456789abcdef01234567"

func TestBinaryReceiptSignVerifyLifetimeBoundary(t *testing.T) {
	t.Run("maximum accepted delegation signs and verifies", func(t *testing.T) {
		fixture := newReleaseFixture(t, MaxDelegationLifetime)
		encoded := signBinary(t, fixture, time.Hour)
		delegationWire := encodeEnvelope(t, fixture.delegation)
		verified, err := VerifyBinaryCurrent(encoded, delegationWire, fixture.roots,
			BinaryExpectation{Environment: "canary"}, fixture.now)
		if err != nil {
			t.Fatalf("VerifyBinaryCurrent() error = %v", err)
		}
		if !verified.IsVerified() || verified.Receipt() != fixture.binary {
			t.Fatalf("verified value = %+v", verified)
		}
		digest := sha256.Sum256(encoded)
		if verified.EnvelopeSHA256() != hex.EncodeToString(digest[:]) || verified.KeyID() == "" ||
			!verified.IssuedAt().Equal(fixture.now) || !verified.ExpiresAt().Before(fixture.delegation.ExpiresAt) {
			t.Fatalf("proof metadata does not bind the signed wire and delegation: %+v", verified)
		}
	})

	t.Run("signer rejects delegation longer than verifier policy", func(t *testing.T) {
		fixture := newReleaseFixture(t, MaxDelegationLifetime+time.Second)
		_, err := SignBinaryReceipt(fixture.binary, "canary", fixture.delegation,
			fixture.roots, fixture.delegatePrivate, fixture.now, time.Hour)
		if !errors.Is(err, trust.ErrInvalid) {
			t.Fatalf("SignBinaryReceipt() error = %v; want trust.ErrInvalid", err)
		}
		manualReceipt := signDirect(t, fixture.binary, BinaryScope(fixture.binary, "canary"),
			fixture.delegatePrivate, fixture.now, fixture.now.Add(time.Hour))
		_, err = VerifyBinaryCurrent(encodeEnvelope(t, manualReceipt), encodeEnvelope(t, fixture.delegation), fixture.roots,
			BinaryExpectation{Environment: "canary"}, fixture.now)
		if !errors.Is(err, trust.ErrInvalid) {
			t.Fatalf("VerifyBinaryCurrent() error = %v; want trust.ErrInvalid", err)
		}
	})
}

func TestImageReceiptClampsToDelegationAndPinsExactEnvelope(t *testing.T) {
	fixture := newReleaseFixture(t, time.Hour)
	signedImage := signImage(t, fixture, 24*time.Hour)
	delegationWire := encodeEnvelope(t, fixture.delegation)
	imageWire := encodeEnvelope(t, signedImage)
	verified, err := VerifyImageCurrent(imageWire, delegationWire, fixture.roots, ImageExpectation{
		Environment: "canary", LogicalRegion: "GRU", OCIImageOCID: fixture.image.OCIImageOCID,
		Architecture: "amd64",
	}, fixture.now)
	if err != nil {
		t.Fatalf("VerifyImageCurrent() error = %v", err)
	}
	if !verified.IsVerified() || verified.Receipt() != fixture.image || verified.EnvelopeSHA256() != fingerprintWire(t, imageWire) {
		t.Fatalf("verified image does not preserve exact pinned receipt: %+v", verified)
	}
	if !verified.ExpiresAt().Equal(fixture.delegation.ExpiresAt) {
		t.Fatalf("signed receipt expires at %s; want delegation expiry %s", verified.ExpiresAt(), fixture.delegation.ExpiresAt)
	}
}

func TestImageReceiptRequiresManifestImageIdentity(t *testing.T) {
	fixture := newReleaseFixture(t, time.Hour)
	imageWire := encodeEnvelope(t, signImage(t, fixture, 30*time.Minute))
	delegationWire := encodeEnvelope(t, fixture.delegation)
	for _, expected := range []ImageExpectation{
		{Environment: "canary", LogicalRegion: "FRA", OCIImageOCID: fixture.image.OCIImageOCID, Architecture: "amd64"},
		{Environment: "canary", LogicalRegion: "GRU", OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.WRONG", Architecture: "amd64"},
		{Environment: "canary", LogicalRegion: "GRU", OCIImageOCID: fixture.image.OCIImageOCID, Architecture: "arm64"},
	} {
		if _, err := VerifyImageCurrent(imageWire, delegationWire, fixture.roots, expected, fixture.now); !errors.Is(err, ErrExpectationMismatch) {
			t.Errorf("VerifyImageCurrent(%+v) error = %v; want ErrExpectationMismatch", expected, err)
		}
	}
}

func TestImageReceiptAllowsDiskImagesLargerThanBinaryLimit(t *testing.T) {
	receipt := testImageReceipt()
	receipt.ImageBytes = MaxArtifactBytes + 1
	if err := receipt.Validate(); err != nil {
		t.Fatalf("ImageReceipt.Validate() rejected a QCOW2 disk larger than the embedded binary limit: %v", err)
	}
}

func TestReceiptLifetimeHasItsOwnLimit(t *testing.T) {
	fixture := newReleaseFixture(t, MaxDelegationLifetime)
	_, err := SignBinaryReceipt(fixture.binary, "canary", fixture.delegation, fixture.roots,
		fixture.delegatePrivate, fixture.now, MaxReceiptLifetime+time.Second)
	if err == nil {
		t.Fatalf("SignBinaryReceipt() accepted receipt validity %s", MaxReceiptLifetime+time.Second)
	}
}

func TestHistoricalReceiptsDoNotAuthorizeCurrentUse(t *testing.T) {
	fixture := newReleaseFixture(t, time.Hour)
	issued, expires := fixture.now, fixture.now.Add(30*time.Minute)
	binaryEnvelope := signDirect(t, fixture.binary, BinaryScope(fixture.binary, "canary"), fixture.delegatePrivate, issued, expires)
	imageEnvelope := signDirect(t, fixture.image, ImageScope(fixture.image, "canary"), fixture.delegatePrivate, issued, expires)
	binaryWire, imageWire := encodeEnvelope(t, binaryEnvelope), encodeEnvelope(t, imageEnvelope)
	delegationWire := encodeEnvelope(t, fixture.delegation)
	tooLate := fixture.now.Add(2 * time.Hour)

	if _, err := VerifyBinaryCurrent(binaryWire, delegationWire, fixture.roots,
		BinaryExpectation{Environment: "canary"}, tooLate); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("VerifyBinaryCurrent() error = %v; want expired current authorization", err)
	}
	historicalBinary, err := VerifyBinaryHistorical(binaryWire, delegationWire, fixture.roots,
		BinaryExpectation{Environment: "canary"})
	if err != nil || !historicalBinary.IsVerified() || historicalBinary.Receipt() != fixture.binary {
		t.Fatalf("VerifyBinaryHistorical() = %+v, %v", historicalBinary, err)
	}

	imageExpected := ImageExpectation{Environment: "canary", LogicalRegion: "GRU", OCIImageOCID: fixture.image.OCIImageOCID}
	if _, err := VerifyImageCurrent(imageWire, delegationWire, fixture.roots, imageExpected, tooLate); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("VerifyImageCurrent() error = %v; want expired current authorization", err)
	}
	historicalImage, err := VerifyImageHistorical(imageWire, delegationWire, fixture.roots, imageExpected)
	if err != nil || !historicalImage.IsVerified() || historicalImage.Receipt() != fixture.image {
		t.Fatalf("VerifyImageHistorical() = %+v, %v", historicalImage, err)
	}
}

type releaseFixture struct {
	delegatePrivate ed25519.PrivateKey
	roots           trust.Keyring
	delegation      trust.Envelope
	now             time.Time
	binary          BinaryReceipt
	image           ImageReceipt
}

func newReleaseFixture(t *testing.T, delegationLifetime time.Duration) releaseFixture {
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
	image := testImageReceipt()
	delegationIssuedAt := now.Add(-time.Minute)
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
		Capabilities: []trust.Capability{
			{Domain: BinaryDomain, DeploymentID: testSourceRevision, Cell: "BUILD", Environment: "canary",
				Role: "artifact", Slots: []string{"linux-amd64"}, Actions: []string{"sign"}},
			{Domain: ImageDomain, DeploymentID: testSourceRevision, Cell: "GRU", Environment: "canary",
				Role: "oci-image", Slots: []string{image.OCIImageOCID}, Actions: []string{"sign"}},
		},
	}, delegationIssuedAt, delegationIssuedAt.Add(delegationLifetime), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	return releaseFixture{
		delegatePrivate: delegatePrivate, roots: roots, delegation: delegation,
		now: now, binary: testBinaryReceipt(), image: image,
	}
}

func testBinaryReceipt() BinaryReceipt {
	digest := sha256.Sum256([]byte("static binary"))
	return BinaryReceipt{
		Schema: BinarySchema, SourceRevision: testSourceRevision, GoVersion: DefaultGoVersion,
		GOOS: "linux", GOARCH: "amd64", ELFMachine: "Advanced Micro Devices X86-64", Static: true,
		Bytes: 13, SHA256: hex.EncodeToString(digest[:]),
	}
}

func testImageReceipt() ImageReceipt {
	digest := sha256.Sum256([]byte("image input"))
	return ImageReceipt{
		Schema: ImageSchema, SourceRevision: testSourceRevision, GoVersion: DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: testBinaryReceipt().SHA256,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU",
		BaseImageSHA256: hex.EncodeToString(digest[:]), KernelRelease: "6.1.0-test+1",
		KernelSHA256: hex.EncodeToString(digest[:]), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: hex.EncodeToString(digest[:]), OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.CUSTOM", OCIRegion: "GRU",
	}
}

func signBinary(t *testing.T, fixture releaseFixture, validFor time.Duration) []byte {
	t.Helper()
	envelope, err := SignBinaryReceipt(fixture.binary, "canary", fixture.delegation, fixture.roots,
		fixture.delegatePrivate, fixture.now, validFor)
	if err != nil {
		t.Fatal(err)
	}
	return encodeEnvelope(t, envelope)
}

func signImage(t *testing.T, fixture releaseFixture, validFor time.Duration) trust.Envelope {
	t.Helper()
	envelope, err := SignImageReceipt(fixture.image, "canary", fixture.delegation, fixture.roots,
		fixture.delegatePrivate, fixture.now, validFor)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func signDirect(t *testing.T, payload any, scope trust.Scope, privateKey ed25519.PrivateKey, issuedAt, expiresAt time.Time) trust.Envelope {
	t.Helper()
	encoded, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(encoded, scope, issuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func encodeEnvelope(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fingerprintWire(t *testing.T, encoded []byte) string {
	t.Helper()
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
