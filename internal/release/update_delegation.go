package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// A binary update delegation is the scoped auto-sign grant: the offline root
// authorizes one online leaf key to sign binary update receipts for any
// CI-qualified descendant of a pinned main revision, limited to explicit
// environment, cells and architectures, for a short bounded interval. It is
// a distinct root-signed document, so the per-source release delegation
// keeps its exact meaning, and consumers accept update receipts only behind
// an explicit configuration flag.
const (
	UpdateDelegationDomain = "terrascale.release.binary-update-delegation"
	UpdateDelegationSchema = "terrascale.release.binary-update-delegation.v1"
	UpdateReceiptDomain    = "terrascale.release.binary-update"
	UpdateReceiptSchema    = "terrascale.release.binary-update.v1"

	// LineageRef is the only branch whose descendants a delegation covers.
	LineageRef = "refs/heads/main"

	// MaxUpdateDelegationLifetime keeps the online grant short-lived; the
	// root re-issues it offline rather than granting a long-lived key.
	MaxUpdateDelegationLifetime = 31 * 24 * time.Hour
	// MaxUpdateReceiptLifetime bounds one automatically signed receipt.
	MaxUpdateReceiptLifetime = 31 * 24 * time.Hour

	updateDelegationDeployment = "binary-update"
	updateDelegationCell       = "global"
	updateDelegationRole       = "release-signer"
	updateDelegationSlot       = "lineage"
	maxUpdateDelegationCells   = 8
)

var ErrLineage = errors.New("release source lineage is not authorized")

// BinaryUpdateDelegation is the root-signed payload of a scoped auto-sign
// grant. LineageBase is a reviewed main revision; every signed source must
// descend from it on LineageRef and be qualified by Workflow.
type BinaryUpdateDelegation struct {
	Schema           string   `json:"schema"`
	SubjectKeyID     string   `json:"subject_key_id"`
	SubjectPublicKey string   `json:"subject_public_key"`
	Environment      string   `json:"environment"`
	Cells            []string `json:"cells"`
	Architectures    []string `json:"architectures"`
	Repository       string   `json:"repository"`
	Workflow         string   `json:"workflow"`
	Ref              string   `json:"ref"`
	LineageBase      string   `json:"lineage_base"`
}

// SourceLineage is the leaf's signed statement of how the source was
// qualified. The signer establishes it with a LineageChecker before signing.
type SourceLineage struct {
	Repository          string `json:"repository"`
	Workflow            string `json:"workflow"`
	Ref                 string `json:"ref"`
	LineageBase         string `json:"lineage_base"`
	QualificationRunID  int64  `json:"qualification_run_id"`
	QualificationRunNum int64  `json:"qualification_run_number"`
}

// BinaryUpdateReceipt binds one qualified binary to a cell and to the exact
// delegation that authorized its automatic signature.
type BinaryUpdateReceipt struct {
	Schema           string        `json:"schema"`
	Binary           BinaryReceipt `json:"binary"`
	Cell             string        `json:"cell"`
	Lineage          SourceLineage `json:"lineage"`
	DelegationSHA256 string        `json:"delegation_sha256"`
}

// UpdateExpectation names the consumer's own environment, cell and
// architecture; none is taken from the receipt.
type UpdateExpectation struct {
	Environment  string
	Cell         string
	Architecture string
}

// LineageChecker proves that revision descends from base on ref. The
// operator-host signer implements it against its verified main checkout.
type LineageChecker interface {
	CheckLineage(base, revision, ref string) error
}

// Validate checks the delegation's subject key and scope lists.
func (delegation BinaryUpdateDelegation) Validate() error {
	if delegation.Schema != UpdateDelegationSchema || !ValidEnvironment(delegation.Environment) ||
		delegation.Repository != QualificationRepository || delegation.Workflow != QualificationWorkflow ||
		delegation.Ref != LineageRef || !revisionPattern.MatchString(delegation.LineageBase) ||
		len(delegation.Cells) == 0 || len(delegation.Cells) > maxUpdateDelegationCells ||
		len(delegation.Architectures) == 0 || len(delegation.Architectures) > 2 {
		return fmt.Errorf("%w: binary update delegation scope", ErrInvalidReceipt)
	}
	if !sortedUnique(delegation.Cells, ValidRegion) ||
		!sortedUnique(delegation.Architectures, func(value string) bool { return value == "amd64" || value == "arm64" }) {
		return fmt.Errorf("%w: binary update delegation cells or architectures", ErrInvalidReceipt)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(delegation.SubjectPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: delegated public key", ErrInvalidReceipt)
	}
	keyID, err := trust.KeyID(ed25519.PublicKey(publicKey))
	if err != nil || keyID != delegation.SubjectKeyID {
		return trust.ErrKeyMismatch
	}
	return nil
}

func sortedUnique(values []string, valid func(string) bool) bool {
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

// Validate checks the receipt payload's own fields.
func (receipt BinaryUpdateReceipt) Validate() error {
	if receipt.Schema != UpdateReceiptSchema || !ValidRegion(receipt.Cell) || !digestPattern.MatchString(receipt.DelegationSHA256) ||
		receipt.Lineage.Repository != QualificationRepository || receipt.Lineage.Workflow != QualificationWorkflow ||
		receipt.Lineage.Ref != LineageRef || !revisionPattern.MatchString(receipt.Lineage.LineageBase) ||
		receipt.Lineage.QualificationRunID <= 0 || receipt.Lineage.QualificationRunNum <= 0 {
		return fmt.Errorf("%w: binary update receipt scope or lineage", ErrInvalidReceipt)
	}
	return receipt.Binary.Validate()
}

// UpdateDelegationScope is the root signature scope of a delegation for one
// environment.
func UpdateDelegationScope(environment string) trust.Scope {
	return trust.Scope{
		Domain: UpdateDelegationDomain, DeploymentID: updateDelegationDeployment, Cell: updateDelegationCell,
		Environment: environment, Role: updateDelegationRole, Slot: updateDelegationSlot,
	}
}

// UpdateReceiptScope is the leaf signature scope of one update receipt.
func UpdateReceiptScope(receipt BinaryUpdateReceipt, environment string) trust.Scope {
	return trust.Scope{
		Domain: UpdateReceiptDomain, DeploymentID: receipt.Binary.SourceRevision, Cell: receipt.Cell,
		Environment: environment, Role: "artifact", Slot: "linux-" + receipt.Binary.GOARCH,
	}
}

// SignUpdateDelegation is the offline root operation that issues a grant.
func SignUpdateDelegation(delegation BinaryUpdateDelegation, issuedAt, expiresAt time.Time,
	rootPrivateKey ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := delegation.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxUpdateDelegationLifetime {
		return trust.Envelope{}, fmt.Errorf("binary update delegation must expire within %s", MaxUpdateDelegationLifetime)
	}
	payload, err := trust.EncodePayload(delegation)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, UpdateDelegationScope(delegation.Environment), issuedAt, expiresAt, rootPrivateKey)
}

type verifiedUpdateDelegation struct {
	delegation BinaryUpdateDelegation
	envelope   trust.Envelope
	digest     string
	publicKey  ed25519.PublicKey
}

func verifyUpdateDelegationCurrent(envelope trust.Envelope, roots trust.Keyring, environment string,
	now time.Time,
) (verifiedUpdateDelegation, error) {
	payload, err := trust.VerifyCurrent(envelope, UpdateDelegationScope(environment), roots, now,
		trust.Policy{MaxLifetime: MaxUpdateDelegationLifetime, ClockSkew: clockSkew})
	if err != nil {
		return verifiedUpdateDelegation{}, fmt.Errorf("verify binary update delegation: %w", err)
	}
	delegation, err := decodeCanonicalPayload[BinaryUpdateDelegation](payload)
	if err != nil {
		return verifiedUpdateDelegation{}, err
	}
	if err := delegation.Validate(); err != nil {
		return verifiedUpdateDelegation{}, err
	}
	if delegation.Environment != environment {
		return verifiedUpdateDelegation{}, ErrExpectationMismatch
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return verifiedUpdateDelegation{}, err
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(delegation.SubjectPublicKey)
	return verifiedUpdateDelegation{delegation: delegation, envelope: envelope, digest: digest, publicKey: publicKey}, nil
}

func (verified verifiedUpdateDelegation) authorize(receipt BinaryUpdateReceipt) error {
	delegation := verified.delegation
	if !slices.Contains(delegation.Cells, receipt.Cell) || !slices.Contains(delegation.Architectures, receipt.Binary.GOARCH) {
		return fmt.Errorf("%w: cell or architecture is outside the delegation", trust.ErrCapabilityDenied)
	}
	if receipt.DelegationSHA256 != verified.digest || receipt.Lineage.Repository != delegation.Repository ||
		receipt.Lineage.Workflow != delegation.Workflow || receipt.Lineage.Ref != delegation.Ref ||
		receipt.Lineage.LineageBase != delegation.LineageBase {
		return ErrLineage
	}
	return nil
}

// SignBinaryUpdateReceipt is the online leaf operation. It verifies the
// current delegation, binds the receipt to the exact qualification manifest
// and its successful ci.yml run, proves the source lineage with checker, and
// re-verifies the signed result through the consumer policy.
func SignBinaryUpdateReceipt(binary BinaryReceipt, qualification Qualification, qualificationSHA256, cell, environment string,
	checker LineageChecker, delegationEnvelope trust.Envelope, roots trust.Keyring, privateKey ed25519.PrivateKey,
	now time.Time, validFor time.Duration,
) (trust.Envelope, error) {
	if checker == nil {
		return trust.Envelope{}, fmt.Errorf("%w: no lineage checker", ErrLineage)
	}
	if validFor <= 0 || validFor > MaxUpdateReceiptLifetime {
		return trust.Envelope{}, fmt.Errorf("update receipt validity must be positive and no longer than %s", MaxUpdateReceiptLifetime)
	}
	if err := qualification.MatchBinary(binary, qualificationSHA256); err != nil {
		return trust.Envelope{}, err
	}
	verified, err := verifyUpdateDelegationCurrent(delegationEnvelope, roots, environment, now)
	if err != nil {
		return trust.Envelope{}, err
	}
	signerKeyID, err := trust.KeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || signerKeyID != verified.delegation.SubjectKeyID {
		return trust.Envelope{}, trust.ErrKeyMismatch
	}
	if err := checker.CheckLineage(verified.delegation.LineageBase, binary.SourceRevision, verified.delegation.Ref); err != nil {
		return trust.Envelope{}, fmt.Errorf("%w: %w", ErrLineage, err)
	}
	receipt := BinaryUpdateReceipt{
		Schema: UpdateReceiptSchema, Binary: binary, Cell: cell, DelegationSHA256: verified.digest,
		Lineage: SourceLineage{
			Repository: qualification.Repository, Workflow: qualification.Verification.Workflow, Ref: verified.delegation.Ref,
			LineageBase: verified.delegation.LineageBase, QualificationRunID: qualification.Verification.RunID,
			QualificationRunNum: qualification.Verification.RunNumber,
		},
	}
	if err := receipt.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if err := verified.authorize(receipt); err != nil {
		return trust.Envelope{}, err
	}
	expiresAt := now.Add(validFor)
	if delegationEnvelope.ExpiresAt.Before(expiresAt) {
		// The receipt is capped at its delegation's expiry. Refuse a cap
		// that would leave a receipt consumers reject almost at once.
		if remaining := delegationEnvelope.ExpiresAt.Sub(now); remaining < min(validFor, MinUpdateReceiptValidity) {
			return trust.Envelope{}, fmt.Errorf("update delegation expires in %s, less than the %s minimum receipt validity; renew the delegation",
				remaining.Round(time.Second), min(validFor, MinUpdateReceiptValidity))
		}
		expiresAt = delegationEnvelope.ExpiresAt
	}
	payload, err := trust.EncodePayload(receipt)
	if err != nil {
		return trust.Envelope{}, err
	}
	envelope, err := trust.Sign(payload, UpdateReceiptScope(receipt, environment), now, expiresAt, privateKey)
	if err != nil {
		return trust.Envelope{}, err
	}
	envelopeWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return trust.Envelope{}, err
	}
	delegationWire, err := trust.EncodeEnvelope(delegationEnvelope)
	if err != nil {
		return trust.Envelope{}, err
	}
	if _, err := VerifyBinaryUpdateCurrent(envelopeWire, delegationWire, roots,
		UpdateExpectation{Environment: environment, Cell: cell, Architecture: binary.GOARCH}, now); err != nil {
		return trust.Envelope{}, fmt.Errorf("signed update receipt fails consumer verification: %w", err)
	}
	return envelope, nil
}

// MinUpdateReceiptValidity is the shortest validity an update receipt is
// signed with when its delegation's expiry caps the requested validity.
const MinUpdateReceiptValidity = time.Hour

// VerifyBinaryUpdateCurrent verifies an automatically signed update receipt
// against a currently valid root delegation, the consumer's environment,
// cell and architecture, and the delegation's pinned lineage. It returns the
// same VerifiedBinary type as the per-source path.
func VerifyBinaryUpdateCurrent(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected UpdateExpectation, now time.Time,
) (VerifiedBinary, error) {
	if err := validateEnvironment(expected.Environment); err != nil {
		return VerifiedBinary{}, err
	}
	if !ValidRegion(expected.Cell) || expected.Architecture != "amd64" && expected.Architecture != "arm64" {
		return VerifiedBinary{}, fmt.Errorf("%w: update expectation", ErrExpectationMismatch)
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return VerifiedBinary{}, err
	}
	verified, err := verifyUpdateDelegationCurrent(delegationEnvelope, roots, expected.Environment, now)
	if err != nil {
		return VerifiedBinary{}, err
	}
	receipt, err := decodeCanonicalPayload[BinaryUpdateReceipt](envelope.Payload)
	if err != nil {
		return VerifiedBinary{}, err
	}
	if err := receipt.Validate(); err != nil {
		return VerifiedBinary{}, err
	}
	if receipt.Cell != expected.Cell || receipt.Binary.GOARCH != expected.Architecture {
		return VerifiedBinary{}, ErrExpectationMismatch
	}
	if err := verified.authorize(receipt); err != nil {
		return VerifiedBinary{}, err
	}
	if envelope.IssuedAt.Before(delegationEnvelope.IssuedAt) || envelope.ExpiresAt.After(delegationEnvelope.ExpiresAt) {
		return VerifiedBinary{}, trust.ErrDelegationTime
	}
	if _, err := trust.VerifyCurrent(envelope, UpdateReceiptScope(receipt, expected.Environment),
		trust.Keyring{verified.delegation.SubjectKeyID: verified.publicKey}, now,
		trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime, ClockSkew: clockSkew}); err != nil {
		return VerifiedBinary{}, fmt.Errorf("verify binary update receipt: %w", err)
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedBinary{}, err
	}
	return VerifiedBinary{receipt: receipt.Binary, proof: proof}, nil
}
