// Package release defines the signed release receipt wire contract shared by
// release tooling and runtime consumers.
package release

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	BinaryDomain = "terrascale.release.binary"
	ImageDomain  = "terrascale.release.image"
	BinarySchema = "terrascale.release.binary.v2"
	ImageSchema  = "terrascale.release.image.v2"

	DefaultGoVersion       = "go1.27.3"
	MaxArtifactBytes int64 = 512 << 20

	// MaxDelegationLifetime is the release-specific ceiling for a root-signed
	// release signer delegation. Signers and verifiers apply the same limit.
	MaxDelegationLifetime = 365 * 24 * time.Hour
	// MaxReceiptLifetime independently bounds a signed binary or image receipt.
	MaxReceiptLifetime     = 365 * 24 * time.Hour
	DefaultReceiptValidity = 30 * 24 * time.Hour

	clockSkew = time.Minute
)

var (
	ErrInvalidReceipt      = errors.New("release receipt is invalid")
	ErrExpectationMismatch = errors.New("release receipt does not match expected image or scope")
	revisionPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imageIDPart            = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// BinaryReceipt is the v2 signed description of one CI-qualified static Linux binary.
// Field names and JSON tags are part of the immutable receipt wire contract.
type BinaryReceipt struct {
	Schema              string `json:"schema"`
	SourceRevision      string `json:"source_revision"`
	GoVersion           string `json:"go_version"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	ELFMachine          string `json:"elf_machine"`
	Static              bool   `json:"static"`
	Bytes               int64  `json:"bytes"`
	SHA256              string `json:"sha256"`
	QualificationSHA256 string `json:"qualification_sha256"`
}

// ImageReceipt is the v2 signed description of a QCOW2 image and its embedded
// orchestrator binary. OCIRegion and BaseImageRegion use logical region names
// (GRU, SJC, or FRA), not Oracle region slugs.
type ImageReceipt struct {
	Schema              string           `json:"schema"`
	SourceRevision      string           `json:"source_revision"`
	GoVersion           string           `json:"go_version"`
	Architecture        string           `json:"architecture"`
	BinaryBytes         int64            `json:"binary_bytes"`
	BinarySHA256        string           `json:"binary_sha256"`
	QualificationSHA256 string           `json:"qualification_sha256"`
	BaseImageOCID       string           `json:"base_image_ocid"`
	BaseImageRegion     string           `json:"base_image_region"`
	BaseImageSHA256     string           `json:"base_image_sha256"`
	KernelRelease       string           `json:"kernel_release"`
	KernelSHA256        string           `json:"kernel_sha256"`
	ImageFormat         string           `json:"image_format"`
	ImageBytes          int64            `json:"image_bytes"`
	ImageSHA256         string           `json:"image_sha256"`
	OCIImageOCID        string           `json:"oci_image_ocid"`
	OCIRegion           string           `json:"oci_region"`
	Production          *ProductionProof `json:"production,omitempty"`
	// HostProduction carries independent isolation proofs; each selected host role verifies its own proof.
	HostProduction map[string]ProductionProof `json:"host_production,omitempty"`
}

// BinaryExpectation limits verification to a release environment. The binary
// receipt itself supplies its signed source revision and architecture scope.
type BinaryExpectation struct {
	Environment string
}

// ImageExpectation binds verification to facts established by a caller. The
// architecture, when supplied, uses receipt values "amd64" or "arm64"; a
// bootstrap caller maps its "linux-amd64" or "linux-arm64" value explicitly.
// OCIImageOCID is optional for tooling that has no separately pinned image ID.
type ImageExpectation struct {
	Environment   string
	LogicalRegion string
	OCIImageOCID  string
	Architecture  string
}

// VerifiedBinary is returned only by current signature and delegation checks.
// Its private proof prevents callers from manufacturing an authorized value.
type VerifiedBinary struct {
	receipt BinaryReceipt
	proof   receiptProof
}

// HistoricalBinary proves that an immutable binary receipt was validly signed
// at issuance. It does not authorize a current mutation or secret retrieval.
type HistoricalBinary struct {
	receipt BinaryReceipt
	proof   receiptProof
}

// VerifiedImage is returned only by current signature and delegation checks.
// Its private proof prevents callers from manufacturing an authorized value.
type VerifiedImage struct {
	receipt ImageReceipt
	proof   receiptProof
}

// HistoricalImage proves that an immutable image receipt was validly signed
// at issuance. It does not authorize a current mutation or secret retrieval.
type HistoricalImage struct {
	receipt ImageReceipt
	proof   receiptProof
}

type receiptProof struct {
	envelopeSHA256 string
	keyID          string
	issuedAt       time.Time
	expiresAt      time.Time
	verified       bool
}

// Validate checks all signed binary identity, platform, size, and digest fields.
func (receipt BinaryReceipt) Validate() error {
	if receipt.Schema != BinarySchema || !revisionPattern.MatchString(receipt.SourceRevision) ||
		receipt.GoVersion != DefaultGoVersion || receipt.GOOS != "linux" || !receipt.Static ||
		receipt.Bytes <= 0 || receipt.Bytes > MaxArtifactBytes || !digestPattern.MatchString(receipt.SHA256) ||
		!digestPattern.MatchString(receipt.QualificationSHA256) {
		return fmt.Errorf("%w: binary schema, source, toolchain, platform, size, or digest", ErrInvalidReceipt)
	}
	expectedMachine := ""
	switch receipt.GOARCH {
	case "amd64":
		expectedMachine = "Advanced Micro Devices X86-64"
	case "arm64":
		expectedMachine = "AArch64"
	default:
		return fmt.Errorf("%w: unsupported binary architecture", ErrInvalidReceipt)
	}
	if receipt.ELFMachine != expectedMachine {
		return fmt.Errorf("%w: ELF machine does not match architecture", ErrInvalidReceipt)
	}
	return nil
}

// Validate checks all signed image, embedded binary, base image, and kernel
// identity fields.
func (receipt ImageReceipt) Validate() error {
	if receipt.Schema != ImageSchema || !revisionPattern.MatchString(receipt.SourceRevision) ||
		receipt.GoVersion != DefaultGoVersion || receipt.BinaryBytes <= 0 || receipt.BinaryBytes > MaxArtifactBytes ||
		!digestPattern.MatchString(receipt.BinarySHA256) || !digestPattern.MatchString(receipt.QualificationSHA256) ||
		!ValidRegion(receipt.BaseImageRegion) ||
		!ValidOCIImageIDForRegion(receipt.BaseImageOCID, receipt.BaseImageRegion) || !digestPattern.MatchString(receipt.BaseImageSHA256) ||
		!validKernelRelease(receipt.KernelRelease) || !digestPattern.MatchString(receipt.KernelSHA256) || receipt.ImageFormat != "qcow2" ||
		receipt.ImageBytes <= 0 || !digestPattern.MatchString(receipt.ImageSHA256) ||
		!ValidRegion(receipt.OCIRegion) || !ValidOCIImageIDForRegion(receipt.OCIImageOCID, receipt.OCIRegion) ||
		receipt.BaseImageRegion != receipt.OCIRegion {
		return fmt.Errorf("%w: image source, OCI scope, base image, kernel, format, size, or digest", ErrInvalidReceipt)
	}
	if receipt.Architecture != "amd64" && receipt.Architecture != "arm64" {
		return fmt.Errorf("%w: unsupported image architecture", ErrInvalidReceipt)
	}
	return nil
}

// BinaryScope returns the exact signed scope for a binary receipt.
func BinaryScope(receipt BinaryReceipt, environment string) trust.Scope {
	return trust.Scope{
		Domain: BinaryDomain, DeploymentID: entityid.Derive("build", receipt.SourceRevision), Cell: "BUILD",
		Environment: environment, Role: "artifact", Slot: "linux-" + receipt.GOARCH,
	}
}

// ImageScope returns the exact signed scope for an image receipt. Its cell is
// the logical region code carried by ImageReceipt.OCIRegion.
func ImageScope(receipt ImageReceipt, environment string) trust.Scope {
	return trust.Scope{
		Domain: ImageDomain, DeploymentID: entityid.Derive("build", receipt.SourceRevision), Cell: receipt.OCIRegion,
		Environment: environment, Role: "oci-image", Slot: receipt.OCIImageOCID,
	}
}

// SignBinaryReceipt verifies a current root delegation, applies the release
// signing lifetime limits, signs the canonical payload, and re-verifies the
// result through the consumer policy before returning it.
func SignBinaryReceipt(receipt BinaryReceipt, environment string, delegation trust.Envelope, roots trust.Keyring,
	privateKey ed25519.PrivateKey, now time.Time, validFor time.Duration,
) (trust.Envelope, error) {
	if err := receipt.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if err := validateEnvironment(environment); err != nil {
		return trust.Envelope{}, err
	}
	return signReceipt(receipt, BinaryScope(receipt, environment), delegation, roots, privateKey, now, validFor)
}

// SignImageReceipt verifies a current root delegation, applies the release
// signing lifetime limits, signs the canonical payload, and re-verifies the
// result through the consumer policy before returning it.
func SignImageReceipt(receipt ImageReceipt, environment string, delegation trust.Envelope, roots trust.Keyring,
	privateKey ed25519.PrivateKey, now time.Time, validFor time.Duration,
) (trust.Envelope, error) {
	if err := receipt.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if err := validateEnvironment(environment); err != nil {
		return trust.Envelope{}, err
	}
	if validFor <= 0 || validFor > MaxReceiptLifetime {
		return trust.Envelope{}, fmt.Errorf("receipt validity must be positive and at most %s", MaxReceiptLifetime)
	}
	productionExpiry, err := verifyImageProduction(receipt, environment, roots, now)
	if err != nil {
		return trust.Envelope{}, err
	}
	if validFor > 0 && productionExpiry.Before(now.Add(validFor)) {
		validFor = productionExpiry.Sub(now)
	}
	return signReceipt(receipt, ImageScope(receipt, environment), delegation, roots, privateKey, now, validFor)
}

// VerifyBinaryCurrent verifies a canonical receipt wire, a currently valid
// root-signed delegation, the exact signer capability, and the environment.
func VerifyBinaryCurrent(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected BinaryExpectation, now time.Time,
) (VerifiedBinary, error) {
	if err := validateEnvironment(expected.Environment); err != nil {
		return VerifiedBinary{}, err
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return VerifiedBinary{}, err
	}
	receipt, err := decodeCanonicalPayload[BinaryReceipt](envelope.Payload)
	if err != nil {
		return VerifiedBinary{}, err
	}
	if err := receipt.Validate(); err != nil {
		return VerifiedBinary{}, err
	}
	scope := BinaryScope(receipt, expected.Environment)
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return VerifiedBinary{}, fmt.Errorf("verify current release delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, scope, delegation, now, receiptPolicy()); err != nil {
		return VerifiedBinary{}, fmt.Errorf("verify current signed binary receipt: %w", err)
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedBinary{}, err
	}
	return VerifiedBinary{receipt: receipt, proof: proof}, nil
}

// VerifyBinaryHistorical verifies that a binary receipt was authorized at
// issuance. The distinct result type cannot be passed as current authority.
func VerifyBinaryHistorical(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected BinaryExpectation,
) (HistoricalBinary, error) {
	if err := validateEnvironment(expected.Environment); err != nil {
		return HistoricalBinary{}, err
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return HistoricalBinary{}, err
	}
	receipt, err := decodeCanonicalPayload[BinaryReceipt](envelope.Payload)
	if err != nil {
		return HistoricalBinary{}, err
	}
	if err := receipt.Validate(); err != nil {
		return HistoricalBinary{}, err
	}
	scope := BinaryScope(receipt, expected.Environment)
	delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, delegationPolicy())
	if err != nil {
		return HistoricalBinary{}, fmt.Errorf("verify historical release delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedHistorical(envelope, scope, delegation, receiptPolicy()); err != nil {
		return HistoricalBinary{}, fmt.Errorf("verify historical signed binary receipt: %w", err)
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return HistoricalBinary{}, err
	}
	return HistoricalBinary{receipt: receipt, proof: proof}, nil
}

// VerifyImageCurrent verifies a canonical image receipt, current delegation,
// exact capability, and all caller-supplied image identity facts.
func VerifyImageCurrent(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected ImageExpectation, now time.Time,
) (VerifiedImage, error) {
	if err := validateImageExpectation(expected); err != nil {
		return VerifiedImage{}, err
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return VerifiedImage{}, err
	}
	receipt, err := decodeCanonicalPayload[ImageReceipt](envelope.Payload)
	if err != nil {
		return VerifiedImage{}, err
	}
	if err := receipt.Validate(); err != nil {
		return VerifiedImage{}, err
	}
	if err := matchImageExpectation(receipt, expected); err != nil {
		return VerifiedImage{}, err
	}
	scope := ImageScope(receipt, expected.Environment)
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return VerifiedImage{}, fmt.Errorf("verify current release delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, scope, delegation, now, receiptPolicy()); err != nil {
		return VerifiedImage{}, fmt.Errorf("verify current signed image receipt: %w", err)
	}
	productionExpiry, err := verifyImageProduction(receipt, expected.Environment, roots, now)
	if err != nil {
		return VerifiedImage{}, err
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedImage{}, err
	}
	if productionExpiry.Before(proof.expiresAt) {
		proof.expiresAt = productionExpiry
	}
	return VerifiedImage{receipt: receipt, proof: proof}, nil
}

// VerifyImageHistorical verifies an image receipt's signature, issuance-time
// delegation, scope, and identity. Its distinct result is audit evidence only.
func VerifyImageHistorical(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected ImageExpectation,
) (HistoricalImage, error) {
	if err := validateImageExpectation(expected); err != nil {
		return HistoricalImage{}, err
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return HistoricalImage{}, err
	}
	receipt, err := decodeCanonicalPayload[ImageReceipt](envelope.Payload)
	if err != nil {
		return HistoricalImage{}, err
	}
	if err := receipt.Validate(); err != nil {
		return HistoricalImage{}, err
	}
	if err := matchImageExpectation(receipt, expected); err != nil {
		return HistoricalImage{}, err
	}
	scope := ImageScope(receipt, expected.Environment)
	delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, delegationPolicy())
	if err != nil {
		return HistoricalImage{}, fmt.Errorf("verify historical release delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedHistorical(envelope, scope, delegation, receiptPolicy()); err != nil {
		return HistoricalImage{}, fmt.Errorf("verify historical signed image receipt: %w", err)
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return HistoricalImage{}, err
	}
	return HistoricalImage{receipt: receipt, proof: proof}, nil
}

func (verified VerifiedBinary) IsVerified() bool       { return verified.proof.verified }
func (verified VerifiedBinary) Receipt() BinaryReceipt { return verified.receipt }
func (verified VerifiedBinary) EnvelopeSHA256() string { return verified.proof.envelopeSHA256 }
func (verified VerifiedBinary) KeyID() string          { return verified.proof.keyID }
func (verified VerifiedBinary) IssuedAt() time.Time    { return verified.proof.issuedAt }
func (verified VerifiedBinary) ExpiresAt() time.Time   { return verified.proof.expiresAt }

func (historical HistoricalBinary) IsVerified() bool       { return historical.proof.verified }
func (historical HistoricalBinary) Receipt() BinaryReceipt { return historical.receipt }
func (historical HistoricalBinary) EnvelopeSHA256() string { return historical.proof.envelopeSHA256 }
func (historical HistoricalBinary) KeyID() string          { return historical.proof.keyID }
func (historical HistoricalBinary) IssuedAt() time.Time    { return historical.proof.issuedAt }
func (historical HistoricalBinary) ExpiresAt() time.Time   { return historical.proof.expiresAt }

func (verified VerifiedImage) IsVerified() bool       { return verified.proof.verified }
func (verified VerifiedImage) Receipt() ImageReceipt  { return cloneImageReceipt(verified.receipt) }
func (verified VerifiedImage) EnvelopeSHA256() string { return verified.proof.envelopeSHA256 }
func (verified VerifiedImage) KeyID() string          { return verified.proof.keyID }
func (verified VerifiedImage) IssuedAt() time.Time    { return verified.proof.issuedAt }
func (verified VerifiedImage) ExpiresAt() time.Time   { return verified.proof.expiresAt }

func (historical HistoricalImage) IsVerified() bool { return historical.proof.verified }
func (historical HistoricalImage) Receipt() ImageReceipt {
	return cloneImageReceipt(historical.receipt)
}
func (historical HistoricalImage) EnvelopeSHA256() string { return historical.proof.envelopeSHA256 }
func (historical HistoricalImage) KeyID() string          { return historical.proof.keyID }
func (historical HistoricalImage) IssuedAt() time.Time    { return historical.proof.issuedAt }
func (historical HistoricalImage) ExpiresAt() time.Time   { return historical.proof.expiresAt }

// ValidEnvironment reports whether value names a supported release environment.
func ValidEnvironment(value string) bool { return value == "production" || value == "canary" }

// ValidRegion reports whether value is a supported logical region code.
func ValidRegion(value string) bool { return catalog.IsCell(value) }

// ValidOCIImageIDForRegion checks both the image OCID form and logical-region
// mapping used by signed release receipts.
func ValidOCIImageIDForRegion(value, region string) bool {
	if !ValidRegion(region) || !strings.HasPrefix(value, "ocid1.image.") || len(value) > 255 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) == 5 && parts[0] == "ocid1" && parts[1] == "image" && parts[2] == "oc1" &&
		parts[3] == oracleRegion(region) && imageIDPart.MatchString(parts[4])
}

// ValidKernelRelease reports whether value is a bounded, simple kernel release
// token suitable for a signed image receipt.
func ValidKernelRelease(value string) bool { return validKernelRelease(value) }

// ValidSourceRevision reports whether value is a full lowercase Git SHA-1
// revision accepted by binary and image release receipts.
func ValidSourceRevision(value string) bool { return revisionPattern.MatchString(value) }

func signReceipt(payload any, scope trust.Scope, delegationEnvelope trust.Envelope, roots trust.Keyring,
	privateKey ed25519.PrivateKey, now time.Time, validFor time.Duration,
) (trust.Envelope, error) {
	if validFor <= 0 || validFor > MaxReceiptLifetime {
		return trust.Envelope{}, fmt.Errorf("receipt validity must be positive and no longer than %s", MaxReceiptLifetime)
	}
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return trust.Envelope{}, fmt.Errorf("verify current release delegation: %w", err)
	}
	expiresAt := now.Add(validFor)
	if delegationEnvelope.ExpiresAt.Before(expiresAt) {
		expiresAt = delegationEnvelope.ExpiresAt
	}
	if !expiresAt.After(now) {
		return trust.Envelope{}, trust.ErrExpired
	}
	encodedPayload, err := trust.EncodePayload(payload)
	if err != nil {
		return trust.Envelope{}, err
	}
	envelope, err := trust.Sign(encodedPayload, scope, now, expiresAt, privateKey)
	if err != nil {
		return trust.Envelope{}, err
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, scope, delegation, now, receiptPolicy()); err != nil {
		return trust.Envelope{}, fmt.Errorf("release signer is not delegated for this exact scope: %w", err)
	}
	return envelope, nil
}

func decodeEnvelopePair(envelopeWire, delegationWire []byte) (trust.Envelope, trust.Envelope, error) {
	envelope, err := trust.DecodeEnvelope(envelopeWire)
	if err != nil {
		return trust.Envelope{}, trust.Envelope{}, err
	}
	delegation, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return trust.Envelope{}, trust.Envelope{}, fmt.Errorf("decode release delegation: %w", err)
	}
	return envelope, delegation, nil
}

func decodeCanonicalPayload[T any](encoded []byte) (T, error) {
	var value T
	if len(encoded) == 0 || len(encoded) > trust.MaxPayloadBytes {
		return value, fmt.Errorf("%w: receipt payload size", ErrInvalidReceipt)
	}
	if err := protocol.DecodeStrict(encoded, &value, trust.MaxPayloadBytes); err != nil {
		return value, fmt.Errorf("decode release receipt payload: %w", err)
	}
	canonical, err := trust.EncodePayload(value)
	if err != nil {
		return value, err
	}
	if !bytes.Equal(canonical, encoded) {
		return value, fmt.Errorf("%w: payload is not canonical JSON", ErrInvalidReceipt)
	}
	return value, nil
}

func proofFor(envelope trust.Envelope) (receiptProof, error) {
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return receiptProof{}, err
	}
	if !digestPattern.MatchString(fingerprint) {
		return receiptProof{}, fmt.Errorf("%w: canonical envelope fingerprint", ErrInvalidReceipt)
	}
	return receiptProof{
		envelopeSHA256: fingerprint, keyID: envelope.KeyID,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true,
	}, nil
}

func delegationPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxDelegationLifetime, ClockSkew: clockSkew}
}

func receiptPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxReceiptLifetime, ClockSkew: clockSkew}
}

func validateEnvironment(environment string) error {
	if !ValidEnvironment(environment) {
		return fmt.Errorf("%w: unsupported environment", ErrInvalidReceipt)
	}
	return nil
}

func validateImageExpectation(expected ImageExpectation) error {
	if err := validateEnvironment(expected.Environment); err != nil {
		return err
	}
	if !ValidRegion(expected.LogicalRegion) {
		return fmt.Errorf("%w: unsupported logical image region", ErrInvalidReceipt)
	}
	if expected.OCIImageOCID != "" && !ValidOCIImageIDForRegion(expected.OCIImageOCID, expected.LogicalRegion) {
		return fmt.Errorf("%w: expected image OCID is invalid for logical region", ErrExpectationMismatch)
	}
	if expected.Architecture != "" && expected.Architecture != "amd64" && expected.Architecture != "arm64" {
		return fmt.Errorf("%w: expected image architecture is not a receipt architecture", ErrExpectationMismatch)
	}
	return nil
}

func matchImageExpectation(receipt ImageReceipt, expected ImageExpectation) error {
	if receipt.OCIRegion != expected.LogicalRegion || expected.OCIImageOCID != "" && receipt.OCIImageOCID != expected.OCIImageOCID ||
		expected.Architecture != "" && receipt.Architecture != expected.Architecture {
		return ErrExpectationMismatch
	}
	return nil
}

func oracleRegion(region string) string {
	return catalog.OCIRegion(region)
}

func validKernelRelease(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+-", character)) {
			return false
		}
	}
	return true
}
