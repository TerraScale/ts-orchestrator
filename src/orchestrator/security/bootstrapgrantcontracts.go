// This file ports Security/SystemProjectBootstrap/BootstrapGrantContracts.cs.
package security

import (
	"regexp"
	"time"
)

// ArgumentError mirrors System.ArgumentException.
type ArgumentError struct {
	Param   string
	Message string
}

func (e *ArgumentError) Error() string { return e.Message }

// ArgumentOutOfRangeError mirrors System.ArgumentOutOfRangeException.
type ArgumentOutOfRangeError struct {
	Param   string
	Message string
}

func (e *ArgumentOutOfRangeError) Error() string { return e.Message }

// InvalidOperationError mirrors System.InvalidOperationException.
type InvalidOperationError struct {
	Message string
}

func (e *InvalidOperationError) Error() string { return e.Message }

// InvalidDataError mirrors System.IO.InvalidDataException.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

// PlatformNotSupportedError mirrors System.PlatformNotSupportedException.
type PlatformNotSupportedError struct {
	Message string
}

func (e *PlatformNotSupportedError) Error() string { return e.Message }

// OverflowError mirrors System.OverflowException raised by checked arithmetic.
type OverflowError struct {
	Message string
}

func (e *OverflowError) Error() string { return e.Message }

var bootstrapTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

// BootstrapValueRules ports the internal BootstrapValueRules static class.
var BootstrapValueRules bootstrapValueRules

type bootstrapValueRules struct{}

// Token validates a bounded canonical bootstrap token.
func (bootstrapValueRules) Token(value string, name string) (string, error) {
	if len(value) < 1 || len(value) > 128 || !bootstrapTokenPattern.MatchString(value) {
		return "", &ArgumentError{
			Param:   name,
			Message: "Bootstrap value must be a bounded canonical token.",
		}
	}
	return value, nil
}

// Thumbprint validates a lowercase SHA-256 thumbprint.
func (bootstrapValueRules) Thumbprint(value string, name string) (string, error) {
	if len(value) != 64 || !isLowercaseHex(value) {
		return "", &ArgumentError{
			Param:   name,
			Message: "Certificate thumbprint must be a lowercase SHA-256 value.",
		}
	}
	return value, nil
}

func isLowercaseHex(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// BootstrapGrantId identifies one bootstrap grant.
type BootstrapGrantId struct {
	Value string
}

// NewBootstrapGrantId validates the bounded canonical token.
func NewBootstrapGrantId(value string) (BootstrapGrantId, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapGrantId{}, err
	}
	return BootstrapGrantId{Value: validated}, nil
}

func (id BootstrapGrantId) String() string { return id.Value }

// BootstrapNonce is the single-use grant nonce.
type BootstrapNonce struct {
	Value string
}

// NewBootstrapNonce validates the bounded canonical token.
func NewBootstrapNonce(value string) (BootstrapNonce, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapNonce{}, err
	}
	return BootstrapNonce{Value: validated}, nil
}

func (id BootstrapNonce) String() string { return id.Value }

// BootstrapAudience names the intended grant audience.
type BootstrapAudience struct {
	Value string
}

// NewBootstrapAudience validates the bounded canonical token.
func NewBootstrapAudience(value string) (BootstrapAudience, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapAudience{}, err
	}
	return BootstrapAudience{Value: validated}, nil
}

func (id BootstrapAudience) String() string { return id.Value }

// BootstrapOrganizationId identifies the system organization.
type BootstrapOrganizationId struct {
	Value string
}

// NewBootstrapOrganizationId validates the bounded canonical token.
func NewBootstrapOrganizationId(value string) (BootstrapOrganizationId, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapOrganizationId{}, err
	}
	return BootstrapOrganizationId{Value: validated}, nil
}

func (id BootstrapOrganizationId) String() string { return id.Value }

// BootstrapProjectId identifies the system project.
type BootstrapProjectId struct {
	Value string
}

// NewBootstrapProjectId validates the bounded canonical token.
func NewBootstrapProjectId(value string) (BootstrapProjectId, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapProjectId{}, err
	}
	return BootstrapProjectId{Value: validated}, nil
}

func (id BootstrapProjectId) String() string { return id.Value }

// BootstrapDatabaseId identifies the system database.
type BootstrapDatabaseId struct {
	Value string
}

// NewBootstrapDatabaseId validates the bounded canonical token.
func NewBootstrapDatabaseId(value string) (BootstrapDatabaseId, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapDatabaseId{}, err
	}
	return BootstrapDatabaseId{Value: validated}, nil
}

func (id BootstrapDatabaseId) String() string { return id.Value }

// BootstrapTrustBundleKeyId identifies one trust-bundle signing key.
type BootstrapTrustBundleKeyId struct {
	Value string
}

// NewBootstrapTrustBundleKeyId validates the bounded canonical token.
func NewBootstrapTrustBundleKeyId(value string) (BootstrapTrustBundleKeyId, error) {
	validated, err := BootstrapValueRules.Token(value, "value")
	if err != nil {
		return BootstrapTrustBundleKeyId{}, err
	}
	return BootstrapTrustBundleKeyId{Value: validated}, nil
}

func (id BootstrapTrustBundleKeyId) String() string { return id.Value }

// BootstrapCertificateThumbprint is a redacted-by-construction certificate
// thumbprint: its string form never exposes the value.
type BootstrapCertificateThumbprint struct {
	Value string
}

// NewBootstrapCertificateThumbprint validates the lowercase SHA-256 thumbprint.
func NewBootstrapCertificateThumbprint(value string) (BootstrapCertificateThumbprint, error) {
	validated, err := BootstrapValueRules.Thumbprint(value, "value")
	if err != nil {
		return BootstrapCertificateThumbprint{}, err
	}
	return BootstrapCertificateThumbprint{Value: validated}, nil
}

func (t BootstrapCertificateThumbprint) String() string { return "[redacted]" }

// BootstrapTrustBundleVersion is a positive trust-bundle version.
type BootstrapTrustBundleVersion struct {
	Value uint64
}

// NewBootstrapTrustBundleVersion requires a positive version.
func NewBootstrapTrustBundleVersion(value uint64) (BootstrapTrustBundleVersion, error) {
	if value == 0 {
		return BootstrapTrustBundleVersion{}, &ArgumentOutOfRangeError{Param: "value"}
	}
	return BootstrapTrustBundleVersion{Value: value}, nil
}

// BootstrapOperation enumerates the idempotent bootstrap operations.
type BootstrapOperation int

const (
	BootstrapOperationEnsureSystemOrganization BootstrapOperation = 1 + iota
	BootstrapOperationEnsureSystemProject
	BootstrapOperationEnsureSystemDatabase
	BootstrapOperationEnsureSystemProjectConfiguration
	BootstrapOperationReadCustomerProject
)

func (o BootstrapOperation) defined() bool {
	return o >= BootstrapOperationEnsureSystemOrganization && o <= BootstrapOperationReadCustomerProject
}

// BootstrapGrantSignatureStatus is the verified signature status.
type BootstrapGrantSignatureStatus int

const (
	BootstrapGrantSignatureStatusValid BootstrapGrantSignatureStatus = 1 + iota
	BootstrapGrantSignatureStatusInvalid
	BootstrapGrantSignatureStatusUnavailable
	BootstrapGrantSignatureStatusUnknown
)

func (s BootstrapGrantSignatureStatus) defined() bool {
	return s >= BootstrapGrantSignatureStatusValid && s <= BootstrapGrantSignatureStatusUnknown
}

// BootstrapReplayConsumeResult is the replay consumer's verdict.
type BootstrapReplayConsumeResult int

const (
	BootstrapReplayConsumeResultConsumed BootstrapReplayConsumeResult = 1 + iota
	BootstrapReplayConsumeResultAlreadyConsumed
	BootstrapReplayConsumeResultRejected
	BootstrapReplayConsumeResultUnavailable
)

func (r BootstrapReplayConsumeResult) defined() bool {
	return r >= BootstrapReplayConsumeResultConsumed && r <= BootstrapReplayConsumeResultUnavailable
}

// BootstrapReplayAuditOutcome is the audit projection of the replay result.
type BootstrapReplayAuditOutcome int

const (
	BootstrapReplayAuditOutcomeNotAttempted BootstrapReplayAuditOutcome = 1 + iota
	BootstrapReplayAuditOutcomeConsumed
	BootstrapReplayAuditOutcomeAlreadyConsumed
	BootstrapReplayAuditOutcomeRejected
	BootstrapReplayAuditOutcomeUnavailable
)

func (o BootstrapReplayAuditOutcome) defined() bool {
	return o >= BootstrapReplayAuditOutcomeNotAttempted && o <= BootstrapReplayAuditOutcomeUnavailable
}

// BootstrapGrantDecisionCode is the closed decision vocabulary.
type BootstrapGrantDecisionCode int

const (
	BootstrapGrantDecisionCodeAuthorized BootstrapGrantDecisionCode = 1 + iota
	BootstrapGrantDecisionCodeInvalidSignature
	BootstrapGrantDecisionCodeSignatureKeyMismatch
	BootstrapGrantDecisionCodeOperationMismatch
	BootstrapGrantDecisionCodeOperationNotIdempotent
	BootstrapGrantDecisionCodeAudienceMismatch
	BootstrapGrantDecisionCodeCertificateMismatch
	BootstrapGrantDecisionCodeCustomerProjectDenied
	BootstrapGrantDecisionCodeSystemProjectMismatch
	BootstrapGrantDecisionCodeTrustBundleKeyMismatch
	BootstrapGrantDecisionCodeNotYetValid
	BootstrapGrantDecisionCodeExpired
	BootstrapGrantDecisionCodeInvalidValidityWindow
	BootstrapGrantDecisionCodeLifetimeExceeded
	BootstrapGrantDecisionCodeReplayConsumerUnavailable
	BootstrapGrantDecisionCodeReplayDetected
	BootstrapGrantDecisionCodeReplayRejected
)

func (c BootstrapGrantDecisionCode) defined() bool {
	return c >= BootstrapGrantDecisionCodeAuthorized && c <= BootstrapGrantDecisionCodeReplayRejected
}

// BootstrapSystemProjectIdentity pins the exact system Project target.
type BootstrapSystemProjectIdentity struct {
	OrganizationId BootstrapOrganizationId
	ProjectId      BootstrapProjectId
	DatabaseId     BootstrapDatabaseId
}

// BootstrapSystemProjectAllowlist is the fixed, bounded system Project allowlist.
type BootstrapSystemProjectAllowlist struct {
	entries []BootstrapSystemProjectIdentity
}

// NewBootstrapSystemProjectAllowlist validates the bounded, duplicate-free list.
func NewBootstrapSystemProjectAllowlist(entries []BootstrapSystemProjectIdentity) (*BootstrapSystemProjectAllowlist, error) {
	if len(entries) < 1 || len(entries) > 20 {
		return nil, &ArgumentError{
			Param:   "entries",
			Message: "The fixed system Project allowlist must be bounded and non-empty.",
		}
	}
	for index := range entries {
		for other := index + 1; other < len(entries); other++ {
			if entries[index] == entries[other] {
				return nil, &ArgumentError{
					Param:   "entries",
					Message: "The fixed system Project allowlist cannot contain duplicates.",
				}
			}
		}
	}
	snapshot := make([]BootstrapSystemProjectIdentity, len(entries))
	copy(snapshot, entries)
	return &BootstrapSystemProjectAllowlist{entries: snapshot}, nil
}

// Entries returns the immutable allowlist snapshot.
func (a *BootstrapSystemProjectAllowlist) Entries() []BootstrapSystemProjectIdentity {
	snapshot := make([]BootstrapSystemProjectIdentity, len(a.entries))
	copy(snapshot, a.entries)
	return snapshot
}

// Contains reports whether the identity is allowlisted.
func (a *BootstrapSystemProjectAllowlist) Contains(identity BootstrapSystemProjectIdentity) bool {
	for _, entry := range a.entries {
		if entry == identity {
			return true
		}
	}
	return false
}

// BootstrapTrustBundleKey pins the key id and version of a grant signature.
type BootstrapTrustBundleKey struct {
	KeyId   BootstrapTrustBundleKeyId
	Version BootstrapTrustBundleVersion
}

// NewBootstrapTrustBundleKey validates the key parts.
func NewBootstrapTrustBundleKey(keyId BootstrapTrustBundleKeyId, version BootstrapTrustBundleVersion) (BootstrapTrustBundleKey, error) {
	return BootstrapTrustBundleKey{KeyId: keyId, Version: version}, nil
}

// BootstrapTrustBundleRotation is the current/overlap trust-bundle rotation.
type BootstrapTrustBundleRotation struct {
	Current BootstrapTrustBundleKey
	Overlap *BootstrapTrustBundleKey
}

// NewBootstrapTrustBundleRotation validates that the overlap key is distinct
// and older than the current key.
func NewBootstrapTrustBundleRotation(current BootstrapTrustBundleKey, overlap *BootstrapTrustBundleKey) (BootstrapTrustBundleRotation, error) {
	if overlap != nil && (overlap.KeyId == current.KeyId || overlap.Version.Value >= current.Version.Value) {
		return BootstrapTrustBundleRotation{}, &ArgumentError{
			Param:   "overlap",
			Message: "An overlap key must be distinct and older than the current key.",
		}
	}
	return BootstrapTrustBundleRotation{Current: current, Overlap: overlap}, nil
}

// Accepts reports whether key is the current or overlap key.
func (r BootstrapTrustBundleRotation) Accepts(key BootstrapTrustBundleKey) bool {
	return key == r.Current || (r.Overlap != nil && key == *r.Overlap)
}

// BootstrapGrant is the typed, unsigned bootstrap grant.
type BootstrapGrant struct {
	GrantId               BootstrapGrantId
	Nonce                 BootstrapNonce
	Audience              BootstrapAudience
	CertificateThumbprint BootstrapCertificateThumbprint
	Target                BootstrapSystemProjectIdentity
	Operation             BootstrapOperation
	IssuedAt              time.Time
	ExpiresAt             time.Time
	TrustBundleKey        BootstrapTrustBundleKey
}

// NewBootstrapGrant validates the grant shape.
func NewBootstrapGrant(
	grantId BootstrapGrantId,
	nonce BootstrapNonce,
	audience BootstrapAudience,
	certificateThumbprint BootstrapCertificateThumbprint,
	target BootstrapSystemProjectIdentity,
	operation BootstrapOperation,
	issuedAt time.Time,
	expiresAt time.Time,
	trustBundleKey BootstrapTrustBundleKey,
) (BootstrapGrant, error) {
	if !operation.defined() {
		return BootstrapGrant{}, &ArgumentOutOfRangeError{Param: "operation"}
	}
	return BootstrapGrant{
		GrantId:               grantId,
		Nonce:                 nonce,
		Audience:              audience,
		CertificateThumbprint: certificateThumbprint,
		Target:                target,
		Operation:             operation,
		IssuedAt:              issuedAt,
		ExpiresAt:             expiresAt,
		TrustBundleKey:        trustBundleKey,
	}, nil
}

// BootstrapGrantSignatureEvidence carries the verified signature status.
type BootstrapGrantSignatureEvidence struct {
	Status       BootstrapGrantSignatureStatus
	VerifiedWith *BootstrapTrustBundleKey
}

// NewBootstrapGrantSignatureEvidence validates the status vocabulary.
func NewBootstrapGrantSignatureEvidence(status BootstrapGrantSignatureStatus, verifiedWith *BootstrapTrustBundleKey) (BootstrapGrantSignatureEvidence, error) {
	if !status.defined() {
		return BootstrapGrantSignatureEvidence{}, &ArgumentOutOfRangeError{Param: "status"}
	}
	return BootstrapGrantSignatureEvidence{Status: status, VerifiedWith: verifiedWith}, nil
}

// BootstrapGrantReplayKey is the durable replay key of one grant.
type BootstrapGrantReplayKey struct {
	GrantId BootstrapGrantId
	Nonce   BootstrapNonce
}

// BootstrapGrantReplayConsumer is the durable replay boundary port.
type BootstrapGrantReplayConsumer interface {
	TryConsume(key BootstrapGrantReplayKey, expiresAt time.Time) (BootstrapReplayConsumeResult, error)
}

// BootstrapGrantVerificationContext pins every expected value of one verify.
type BootstrapGrantVerificationContext struct {
	RequestedOperation            BootstrapOperation
	ExpectedAudience              BootstrapAudience
	ExpectedCertificateThumbprint BootstrapCertificateThumbprint
	ExpectedTarget                BootstrapSystemProjectIdentity
	SystemProjectAllowlist        *BootstrapSystemProjectAllowlist
	TrustBundle                   BootstrapTrustBundleRotation
	Now                           time.Time
	MaximumLifetime               time.Duration
}

// NewBootstrapGrantVerificationContext validates the context.
func NewBootstrapGrantVerificationContext(
	requestedOperation BootstrapOperation,
	expectedAudience BootstrapAudience,
	expectedCertificateThumbprint BootstrapCertificateThumbprint,
	expectedTarget BootstrapSystemProjectIdentity,
	systemProjectAllowlist *BootstrapSystemProjectAllowlist,
	trustBundle BootstrapTrustBundleRotation,
	now time.Time,
	maximumLifetime time.Duration,
) (BootstrapGrantVerificationContext, error) {
	if !requestedOperation.defined() {
		return BootstrapGrantVerificationContext{}, &ArgumentOutOfRangeError{Param: "requestedOperation"}
	}
	if maximumLifetime <= 0 {
		return BootstrapGrantVerificationContext{}, &ArgumentOutOfRangeError{Param: "maximumLifetime"}
	}
	if systemProjectAllowlist == nil {
		return BootstrapGrantVerificationContext{}, &ArgumentError{Param: "systemProjectAllowlist"}
	}
	return BootstrapGrantVerificationContext{
		RequestedOperation:            requestedOperation,
		ExpectedAudience:              expectedAudience,
		ExpectedCertificateThumbprint: expectedCertificateThumbprint,
		ExpectedTarget:                expectedTarget,
		SystemProjectAllowlist:        systemProjectAllowlist,
		TrustBundle:                   trustBundle,
		Now:                           now,
		MaximumLifetime:               maximumLifetime,
	}, nil
}

// BootstrapGrantVerificationInput bundles one verification request.
type BootstrapGrantVerificationInput struct {
	Grant             BootstrapGrant
	Context           BootstrapGrantVerificationContext
	SignatureEvidence *BootstrapGrantSignatureEvidence
	ReplayConsumer    BootstrapGrantReplayConsumer
}

// NewBootstrapGrantVerificationInput validates the required inputs.
func NewBootstrapGrantVerificationInput(
	grant BootstrapGrant,
	context BootstrapGrantVerificationContext,
	signatureEvidence *BootstrapGrantSignatureEvidence,
	replayConsumer BootstrapGrantReplayConsumer,
) (*BootstrapGrantVerificationInput, error) {
	return &BootstrapGrantVerificationInput{
		Grant:             grant,
		Context:           context,
		SignatureEvidence: signatureEvidence,
		ReplayConsumer:    replayConsumer,
	}, nil
}

// BootstrapGrantAuditFacts is the redacted audit projection of one verify.
type BootstrapGrantAuditFacts struct {
	Code                  BootstrapGrantDecisionCode
	Operation             *BootstrapOperation
	TrustBundleKeyId      *string
	TrustBundleVersion    *uint64
	TargetAllowlisted     bool
	CustomerProjectDenied bool
	AudienceMatched       bool
	CertificateMatched    bool
	TimeWindowValid       bool
	SignatureStatus       BootstrapGrantSignatureStatus
	ReplayOutcome         BootstrapReplayAuditOutcome
}

func newBootstrapGrantAuditFacts(
	code BootstrapGrantDecisionCode,
	operation *BootstrapOperation,
	trustBundleKeyId *BootstrapTrustBundleKeyId,
	trustBundleVersion *uint64,
	targetAllowlisted bool,
	customerProjectDenied bool,
	audienceMatched bool,
	certificateMatched bool,
	timeWindowValid bool,
	signatureStatus BootstrapGrantSignatureStatus,
	replayOutcome BootstrapReplayAuditOutcome,
) BootstrapGrantAuditFacts {
	facts := BootstrapGrantAuditFacts{
		Code:                  code,
		Operation:             operation,
		TrustBundleVersion:    trustBundleVersion,
		TargetAllowlisted:     targetAllowlisted,
		CustomerProjectDenied: customerProjectDenied,
		AudienceMatched:       audienceMatched,
		CertificateMatched:    certificateMatched,
		TimeWindowValid:       timeWindowValid,
		SignatureStatus:       signatureStatus,
		ReplayOutcome:         replayOutcome,
	}
	if trustBundleKeyId != nil {
		value := trustBundleKeyId.Value
		facts.TrustBundleKeyId = &value
	}
	return facts
}

// BootstrapGrantVerificationResult is the typed verify outcome.
type BootstrapGrantVerificationResult struct {
	Authorized bool
	Code       BootstrapGrantDecisionCode
	Audit      BootstrapGrantAuditFacts
}

func newBootstrapGrantVerificationResult(
	authorized bool,
	code BootstrapGrantDecisionCode,
	audit BootstrapGrantAuditFacts,
) BootstrapGrantVerificationResult {
	audit.Code = code
	return BootstrapGrantVerificationResult{Authorized: authorized, Code: code, Audit: audit}
}
