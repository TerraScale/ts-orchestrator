package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// A binary update delegation is the scoped auto-sign grant: the offline root
// authorizes one online leaf key to sign binary update receipts for any
// CI-qualified descendant of a pinned main revision, limited to an explicit
// environment and architectures, for a short bounded interval. It also names
// the service roles the leaf may release in every region of that environment.
// It is a distinct root-signed document, so the per-source release delegation
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

	updateDelegationDeployment  = "0000000000TA7Q4JYMWMMHHMPQ"
	updateDelegationCell        = "global"
	updateDelegationRole        = "release-signer"
	updateDelegationSlot        = "lineage"
	maxUpdateDelegationServices = 16
)

// DelegatedReleaseActorPrefix starts the actor of every claim signed by a
// delegated release key; DelegatedReleaseActor appends the key's identity, so
// an actor names exactly one key and its delegation.
const DelegatedReleaseActorPrefix = "release-"

// DelegatedReleaseActor is the actor claims signed by publicKey carry.
func DelegatedReleaseActor(publicKey ed25519.PublicKey) (string, error) {
	keyID, err := trust.KeyID(publicKey)
	if err != nil {
		return "", err
	}
	return DelegatedReleaseActorPrefix + strings.TrimPrefix(keyID, "sha256:")[:16], nil
}

var (
	ErrLineage = errors.New("release source lineage is not authorized")

	serviceRolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// BinaryUpdateDelegation is the root-signed payload of a scoped auto-sign
// grant. LineageBase is a reviewed main revision; every signed source must
// descend from it on LineageRef and be qualified by Workflow.
type BinaryUpdateDelegation struct {
	Schema           string         `json:"schema"`
	SubjectKeyID     string         `json:"subject_key_id"`
	SubjectPublicKey string         `json:"subject_public_key"`
	Environment      string         `json:"environment"`
	Architectures    []string       `json:"architectures"`
	Services         []ServiceGrant `json:"services"`
	Repository       string         `json:"repository"`
	Workflow         string         `json:"workflow"`
	Ref              string         `json:"ref"`
	LineageBase      string         `json:"lineage_base"`
}

// ServiceGrant names one service role and its repository the delegated key may release.
type ServiceGrant struct {
	Role       string `json:"role"`
	Repository string `json:"repository"`
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
	ReleaseSequence         uint64        `json:"release_sequence,omitzero"`
	SequenceMigrationSHA256 string        `json:"sequence_migration_sha256,omitempty"`
	Schema                  string        `json:"schema"`
	Binary                  BinaryReceipt `json:"binary"`
	Cell                    string        `json:"cell"`
	Lineage                 SourceLineage `json:"lineage"`
	DelegationSHA256        string        `json:"delegation_sha256"`
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
		len(delegation.Architectures) == 0 || len(delegation.Architectures) > 2 || len(delegation.Services) > maxUpdateDelegationServices {
		return fmt.Errorf("%w: binary update delegation scope", ErrInvalidReceipt)
	}
	if !sortedUnique(delegation.Architectures, func(value string) bool { return value == "amd64" || value == "arm64" }) {
		return fmt.Errorf("%w: binary update delegation architectures", ErrInvalidReceipt)
	}
	if err := validateServiceGrants(delegation.Services); err != nil {
		return err
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

// validateServiceGrants requires grants sorted by strictly ascending role, so each role appears once.
func validateServiceGrants(services []ServiceGrant) error {
	for index, service := range services {
		repository, err := url.Parse(service.Repository)
		if !serviceRolePattern.MatchString(service.Role) || index > 0 && services[index-1].Role >= service.Role ||
			err != nil || repository.Scheme != "https" || repository.Host == "" || len(service.Repository) > 512 {
			return fmt.Errorf("%w: binary update delegation services", ErrInvalidReceipt)
		}
	}
	return nil
}

// MayRelease reports whether the delegation names exactly this role and repository.
func (delegation BinaryUpdateDelegation) MayRelease(role, repository string) bool {
	return slices.Contains(delegation.Services, ServiceGrant{Role: role, Repository: repository})
}

// Validate checks the receipt payload's own fields.
func (receipt BinaryUpdateReceipt) Validate() error {
	if (receipt.ReleaseSequence == 0) != (receipt.SequenceMigrationSHA256 == "") || receipt.SequenceMigrationSHA256 != "" && !digestPattern.MatchString(receipt.SequenceMigrationSHA256) {
		return fmt.Errorf("%w: release order", ErrInvalidReceipt)
	}
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
		Domain: UpdateReceiptDomain, DeploymentID: entityid.Derive("build", receipt.Binary.SourceRevision), Cell: receipt.Cell,
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

// envelopeCheck is trust.VerifyHistorical or, through currentAt, trust.VerifyCurrent.
type envelopeCheck func(trust.Envelope, trust.Scope, trust.Keyring, trust.Policy) ([]byte, error)

func currentAt(now time.Time) envelopeCheck {
	return func(envelope trust.Envelope, scope trust.Scope, keys trust.Keyring, policy trust.Policy) ([]byte, error) {
		return trust.VerifyCurrent(envelope, scope, keys, now, policy)
	}
}

func verifyUpdateDelegation(envelope trust.Envelope, roots trust.Keyring, environment string,
	check envelopeCheck,
) (verifiedUpdateDelegation, error) {
	payload, err := check(envelope, UpdateDelegationScope(environment), roots,
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
	if !slices.Contains(delegation.Architectures, receipt.Binary.GOARCH) {
		return fmt.Errorf("%w: architecture is outside the delegation", trust.ErrCapabilityDenied)
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
	return signBinaryUpdateReceipt(binary, qualification, qualificationSHA256, cell, environment, checker, delegationEnvelope, roots, privateKey, now, validFor, 0, "")
}

// SignBinaryUpdateReceiptSequenced binds the signer-owned order and its exact
// root-authorized migration without changing historical CI provenance.
func SignBinaryUpdateReceiptSequenced(binary BinaryReceipt, qualification Qualification, qualificationSHA256, cell, environment string,
	checker LineageChecker, delegationEnvelope trust.Envelope, roots trust.Keyring, privateKey ed25519.PrivateKey,
	now time.Time, validFor time.Duration, sequence uint64, migrationSHA256 string,
) (trust.Envelope, error) {
	if sequence == 0 || !digestPattern.MatchString(migrationSHA256) {
		return trust.Envelope{}, fmt.Errorf("%w: release order", ErrInvalidReceipt)
	}
	return signBinaryUpdateReceipt(binary, qualification, qualificationSHA256, cell, environment, checker, delegationEnvelope, roots, privateKey, now, validFor, sequence, migrationSHA256)
}

func signBinaryUpdateReceipt(binary BinaryReceipt, qualification Qualification, qualificationSHA256, cell, environment string,
	checker LineageChecker, delegationEnvelope trust.Envelope, roots trust.Keyring, privateKey ed25519.PrivateKey,
	now time.Time, validFor time.Duration, sequence uint64, migrationSHA256 string,
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
	verified, err := verifyUpdateDelegation(delegationEnvelope, roots, environment, currentAt(now))
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
		ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA256,
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
	receipt, proof, err := verifyBinaryUpdate(envelopeWire, delegationWire, roots, expected, currentAt(now))
	if err != nil {
		return VerifiedBinary{}, err
	}
	return VerifiedBinary{receipt: receipt, proof: proof}, nil
}

// VerifyReleaseDelegationCurrent verifies the root-signed update delegation for
// the consumer's environment against a currently valid root. It returns the
// delegation, the leaf key it authorizes and when the grant expires.
func VerifyReleaseDelegationCurrent(delegationWire []byte, roots trust.Keyring, environment string, now time.Time,
) (BinaryUpdateDelegation, ed25519.PublicKey, time.Time, error) {
	envelope, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return BinaryUpdateDelegation{}, nil, time.Time{}, err
	}
	verified, err := verifyUpdateDelegation(envelope, roots, environment, currentAt(now))
	if err != nil {
		return BinaryUpdateDelegation{}, nil, time.Time{}, err
	}
	return verified.delegation, verified.publicKey, envelope.ExpiresAt, nil
}

// VerifyBinaryUpdateHistorical verifies that an update receipt was signed
// within its root delegation for the consumer's environment, cell and
// architecture, without requiring either to be valid now. It proves the
// identity of a binary staged earlier under a current receipt; it never
// authorizes staging.
func VerifyBinaryUpdateHistorical(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected UpdateExpectation,
) (HistoricalBinary, error) {
	receipt, proof, err := verifyBinaryUpdate(envelopeWire, delegationWire, roots, expected, trust.VerifyHistorical)
	if err != nil {
		return HistoricalBinary{}, err
	}
	return HistoricalBinary{receipt: receipt, proof: proof}, nil
}

func verifyBinaryUpdate(envelopeWire, delegationWire []byte, roots trust.Keyring, expected UpdateExpectation,
	check envelopeCheck,
) (BinaryReceipt, receiptProof, error) {
	if err := validateEnvironment(expected.Environment); err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	if !ValidRegion(expected.Cell) || expected.Architecture != "amd64" && expected.Architecture != "arm64" {
		return BinaryReceipt{}, receiptProof{}, fmt.Errorf("%w: update expectation", ErrExpectationMismatch)
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	verified, err := verifyUpdateDelegation(delegationEnvelope, roots, expected.Environment, check)
	if err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	receipt, err := decodeCanonicalPayload[BinaryUpdateReceipt](envelope.Payload)
	if err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	if err := receipt.Validate(); err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	if receipt.Cell != expected.Cell || receipt.Binary.GOARCH != expected.Architecture {
		return BinaryReceipt{}, receiptProof{}, ErrExpectationMismatch
	}
	if err := verified.authorize(receipt); err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	if envelope.IssuedAt.Before(delegationEnvelope.IssuedAt) || envelope.ExpiresAt.After(delegationEnvelope.ExpiresAt) {
		return BinaryReceipt{}, receiptProof{}, trust.ErrDelegationTime
	}
	if _, err := check(envelope, UpdateReceiptScope(receipt, expected.Environment),
		trust.Keyring{verified.delegation.SubjectKeyID: verified.publicKey},
		trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime, ClockSkew: clockSkew}); err != nil {
		return BinaryReceipt{}, receiptProof{}, fmt.Errorf("verify binary update receipt: %w", err)
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return BinaryReceipt{}, receiptProof{}, err
	}
	return receipt.Binary, proof, nil
}
