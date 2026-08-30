// Port of src/TerraScale.Orchestrator/Protocol/CommandValidation.cs.
package protocol

import (
	"errors"
	"strconv"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
)

// VerificationOutcome mirrors the VerificationOutcome enum.
type VerificationOutcome int

const (
	VerificationOutcomeInvalid VerificationOutcome = 0
	VerificationOutcomeValid   VerificationOutcome = 1
)

// IPayloadDigestVerifier is the one-method port of the C# interface of the
// same name; the interface keeps its C# name.
type IPayloadDigestVerifier interface {
	Verify(payload OpaquePayload, expectedDigest PayloadDigest) VerificationOutcome
}

// ICommandSignatureVerifier is the one-method port of the C# interface of the
// same name.
type ICommandSignatureVerifier interface {
	Verify(signedMaterial CommandSignedMaterial, signature OpaqueSignature) VerificationOutcome
}

// CommandValidationError mirrors the CommandValidationError enum.
type CommandValidationError int

const (
	CommandValidationErrorUninitialized               CommandValidationError = 0
	CommandValidationErrorNone                        CommandValidationError = 1
	CommandValidationErrorInvalidValidationContext    CommandValidationError = 2
	CommandValidationErrorMalformedEnvelope           CommandValidationError = 3
	CommandValidationErrorUnsupportedProtocolVersion  CommandValidationError = 4
	CommandValidationErrorInvalidValidityWindow       CommandValidationError = 5
	CommandValidationErrorNotYetValid                 CommandValidationError = 6
	CommandValidationErrorExpired                     CommandValidationError = 7
	CommandValidationErrorWrongCell                   CommandValidationError = 8
	CommandValidationErrorWrongAggregateIdentity      CommandValidationError = 9
	CommandValidationErrorStaleGeneration             CommandValidationError = 10
	CommandValidationErrorStaleWriterEpoch            CommandValidationError = 11
	CommandValidationErrorPayloadDigestMismatch       CommandValidationError = 12
	CommandValidationErrorPayloadDigestVerificationFailed CommandValidationError = 13
	CommandValidationErrorInvalidSignature            CommandValidationError = 14
	CommandValidationErrorSignatureVerificationFailed CommandValidationError = 15
)

func (e CommandValidationError) String() string {
	switch e {
	case CommandValidationErrorUninitialized:
		return "Uninitialized"
	case CommandValidationErrorNone:
		return "None"
	case CommandValidationErrorInvalidValidationContext:
		return "InvalidValidationContext"
	case CommandValidationErrorMalformedEnvelope:
		return "MalformedEnvelope"
	case CommandValidationErrorUnsupportedProtocolVersion:
		return "UnsupportedProtocolVersion"
	case CommandValidationErrorInvalidValidityWindow:
		return "InvalidValidityWindow"
	case CommandValidationErrorNotYetValid:
		return "NotYetValid"
	case CommandValidationErrorExpired:
		return "Expired"
	case CommandValidationErrorWrongCell:
		return "WrongCell"
	case CommandValidationErrorWrongAggregateIdentity:
		return "WrongAggregateIdentity"
	case CommandValidationErrorStaleGeneration:
		return "StaleGeneration"
	case CommandValidationErrorStaleWriterEpoch:
		return "StaleWriterEpoch"
	case CommandValidationErrorPayloadDigestMismatch:
		return "PayloadDigestMismatch"
	case CommandValidationErrorPayloadDigestVerificationFailed:
		return "PayloadDigestVerificationFailed"
	case CommandValidationErrorInvalidSignature:
		return "InvalidSignature"
	case CommandValidationErrorSignatureVerificationFailed:
		return "SignatureVerificationFailed"
	default:
		return strconv.Itoa(int(e))
	}
}

// CommandValidationResult mirrors the readonly record struct of the same name.
// Acceptance is nil unless the envelope was accepted.
type CommandValidationResult struct {
	Error      CommandValidationError
	Acceptance *CommandAcceptance
}

// IsValid reports whether validation accepted the envelope.
func (r CommandValidationResult) IsValid() bool { return r.Error == CommandValidationErrorNone }

// Equal mirrors the record-struct value equality (acceptance compares by value).
func (r CommandValidationResult) Equal(other CommandValidationResult) bool {
	if r.Error != other.Error {
		return false
	}

	if r.Acceptance == nil || other.Acceptance == nil {
		return r.Acceptance == other.Acceptance
	}

	return r.Acceptance.Equal(*other.Acceptance)
}

func (r CommandValidationResult) String() string {
	if r.Acceptance != nil {
		return r.Acceptance.String()
	}

	return "CommandValidationResult { Error = " + r.Error.String() + " }"
}

func commandValidationAccepted(envelope *CommandEnvelope, validatedAt time.Time) CommandValidationResult {
	return CommandValidationResult{
		Error:      CommandValidationErrorNone,
		Acceptance: newCommandAcceptance(envelope, validatedAt),
	}
}

func commandValidationRejected(err CommandValidationError) CommandValidationResult {
	return CommandValidationResult{Error: err}
}

// CommandAcceptance is the exact secret-safe receipt for the signed command
// envelope accepted by validation. It intentionally does not retain the opaque
// payload, verifier implementations, or the complete validation-context
// policy.
type CommandAcceptance struct {
	ProtocolVersion   ProtocolRevision
	Cell              contracts.CellId
	AggregateId       contracts.AggregateId
	DesiredGeneration DesiredGeneration
	WriterEpoch       WriterEpoch
	OperationId       contracts.OperationId
	IdempotencyKey    contracts.IdempotencyKey
	IssuedAt          time.Time
	ExpiresAt         time.Time
	Attempt           DeliveryAttempt
	PayloadDigest     PayloadDigest
	Signature         OpaqueSignature
	ValidatedAt       time.Time
}

func newCommandAcceptance(envelope *CommandEnvelope, validatedAt time.Time) *CommandAcceptance {
	return &CommandAcceptance{
		ProtocolVersion:   envelope.ProtocolVersion,
		Cell:              envelope.Cell,
		AggregateId:       envelope.AggregateId,
		DesiredGeneration: envelope.DesiredGeneration,
		WriterEpoch:       envelope.WriterEpoch,
		OperationId:       envelope.OperationId,
		IdempotencyKey:    envelope.IdempotencyKey,
		IssuedAt:          envelope.IssuedAt,
		ExpiresAt:         envelope.ExpiresAt,
		Attempt:           envelope.Attempt,
		PayloadDigest:     envelope.PayloadDigest,
		Signature:         envelope.Signature,
		ValidatedAt:       validatedAt,
	}
}

// Equal mirrors CommandAcceptance.Equals (field-by-field value equality;
// instants compare as instants).
func (a CommandAcceptance) Equal(other CommandAcceptance) bool {
	return a.ProtocolVersion == other.ProtocolVersion &&
		a.Cell == other.Cell &&
		a.AggregateId == other.AggregateId &&
		a.DesiredGeneration == other.DesiredGeneration &&
		a.WriterEpoch == other.WriterEpoch &&
		a.OperationId == other.OperationId &&
		a.IdempotencyKey == other.IdempotencyKey &&
		a.IssuedAt.Equal(other.IssuedAt) &&
		a.ExpiresAt.Equal(other.ExpiresAt) &&
		a.Attempt == other.Attempt &&
		a.PayloadDigest.Equal(other.PayloadDigest) &&
		a.Signature.Equal(other.Signature) &&
		a.ValidatedAt.Equal(other.ValidatedAt)
}

// String mirrors the C# ToString: digest and signature are redacted.
func (a CommandAcceptance) String() string {
	return "CommandAcceptance { ProtocolVersion = " + a.ProtocolVersion.String() +
		", Cell = " + a.Cell.String() +
		", AggregateId = " + a.AggregateId.String() +
		", DesiredGeneration = " + a.DesiredGeneration.String() +
		", WriterEpoch = " + a.WriterEpoch.String() +
		", OperationId = " + a.OperationId.String() +
		", IdempotencyKey = " + a.IdempotencyKey.String() +
		", IssuedAt = " + formatDotNetRoundTrip(a.IssuedAt) +
		", ExpiresAt = " + formatDotNetRoundTrip(a.ExpiresAt) +
		", Attempt = " + a.Attempt.String() +
		", PayloadDigest = <redacted>, Signature = <redacted>, ValidatedAt = " +
		formatDotNetRoundTrip(a.ValidatedAt) + " }"
}

// CommandValidationContext is the frozen admission context of one validator.
type CommandValidationContext struct {
	ExpectedCell              contracts.CellId
	ExpectedAggregateId       contracts.AggregateId
	MinimumDesiredGeneration  DesiredGeneration
	MinimumWriterEpoch        WriterEpoch
	acceptedProtocolVersions  map[ProtocolRevision]struct{}
	AllowedClockSkew          time.Duration
	PayloadDigestVerifier     IPayloadDigestVerifier
	SignatureVerifier         ICommandSignatureVerifier
}

// NewCommandValidationContext mirrors the C# constructor; it defensively
// copies the accepted protocol versions and fails when they cannot be captured
// within the technical input bound (the C# ArgumentException).
func NewCommandValidationContext(
	expectedCell contracts.CellId,
	expectedAggregateId contracts.AggregateId,
	minimumDesiredGeneration DesiredGeneration,
	minimumWriterEpoch WriterEpoch,
	acceptedProtocolVersions []ProtocolRevision,
	allowedClockSkew time.Duration,
	payloadDigestVerifier IPayloadDigestVerifier,
	signatureVerifier ICommandSignatureVerifier,
) (*CommandValidationContext, error) {
	captured, err := captureAcceptedProtocolVersions(acceptedProtocolVersions)
	if err != nil {
		return nil, err
	}

	return &CommandValidationContext{
		ExpectedCell:             expectedCell,
		ExpectedAggregateId:      expectedAggregateId,
		MinimumDesiredGeneration: minimumDesiredGeneration,
		MinimumWriterEpoch:       minimumWriterEpoch,
		acceptedProtocolVersions: captured,
		AllowedClockSkew:         allowedClockSkew,
		PayloadDigestVerifier:    payloadDigestVerifier,
		SignatureVerifier:        signatureVerifier,
	}, nil
}

// IsWellFormed mirrors the internal context well-formedness gate.
func (c *CommandValidationContext) IsWellFormed() bool {
	if c == nil {
		return false
	}

	if !c.ExpectedCell.IsValid() || !c.ExpectedAggregateId.IsValid() ||
		!c.MinimumDesiredGeneration.IsValid() || !c.MinimumWriterEpoch.IsValid() ||
		len(c.acceptedProtocolVersions) == 0 || c.AllowedClockSkew < 0 ||
		c.PayloadDigestVerifier == nil || c.SignatureVerifier == nil {
		return false
	}

	for version := range c.acceptedProtocolVersions {
		if !version.IsValid() {
			return false
		}
	}

	return true
}

// Accepts reports whether the context admits the given protocol revision.
func (c *CommandValidationContext) Accepts(version ProtocolRevision) bool {
	_, ok := c.acceptedProtocolVersions[version]
	return ok
}

func captureAcceptedProtocolVersions(source []ProtocolRevision) (map[ProtocolRevision]struct{}, error) {
	captured := make(map[ProtocolRevision]struct{}, len(source))
	for _, version := range source {
		if len(captured) == ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount() {
			return nil, errors.New(
				"Accepted protocol versions could not be captured within the technical input bound. " +
					"(Parameter 'acceptedProtocolVersions')")
		}

		captured[version] = struct{}{}
	}

	return captured, nil
}

// CommandEnvelopeValidator mirrors the C# static class: the pure, deterministic
// INV-005 command admission validation.
var CommandEnvelopeValidator commandEnvelopeValidator

type commandEnvelopeValidator struct{}

// Validate admits or rejects one command envelope against one context.
func (commandEnvelopeValidator) Validate(
	envelope *CommandEnvelope,
	context *CommandValidationContext,
	now time.Time,
) CommandValidationResult {
	if context == nil || !context.IsWellFormed() {
		return commandValidationRejected(CommandValidationErrorInvalidValidationContext)
	}

	payloadDigestVerifier := context.PayloadDigestVerifier
	signatureVerifier := context.SignatureVerifier
	if payloadDigestVerifier == nil || signatureVerifier == nil {
		return commandValidationRejected(CommandValidationErrorInvalidValidationContext)
	}

	if envelope == nil || !commandEnvelopeIsWellFormed(envelope) {
		return commandValidationRejected(CommandValidationErrorMalformedEnvelope)
	}

	if !context.Accepts(envelope.ProtocolVersion) {
		return commandValidationRejected(CommandValidationErrorUnsupportedProtocolVersion)
	}

	if envelope.ExpiresAt.Before(envelope.IssuedAt) {
		return commandValidationRejected(CommandValidationErrorInvalidValidityWindow)
	}

	if envelope.IssuedAt.Sub(now) > context.AllowedClockSkew {
		return commandValidationRejected(CommandValidationErrorNotYetValid)
	}

	if now.Sub(envelope.ExpiresAt) > context.AllowedClockSkew {
		return commandValidationRejected(CommandValidationErrorExpired)
	}

	if envelope.Cell != context.ExpectedCell {
		return commandValidationRejected(CommandValidationErrorWrongCell)
	}

	if envelope.AggregateId != context.ExpectedAggregateId {
		return commandValidationRejected(CommandValidationErrorWrongAggregateIdentity)
	}

	if envelope.DesiredGeneration.Value < context.MinimumDesiredGeneration.Value {
		return commandValidationRejected(CommandValidationErrorStaleGeneration)
	}

	if envelope.WriterEpoch.Value < context.MinimumWriterEpoch.Value {
		return commandValidationRejected(CommandValidationErrorStaleWriterEpoch)
	}

	var digestOutcome VerificationOutcome
	if failed := protocolExceptionPolicy.recoverVerifierFailure(func() {
		digestOutcome = payloadDigestVerifier.Verify(envelope.Payload, envelope.PayloadDigest)
	}); failed {
		return commandValidationRejected(CommandValidationErrorPayloadDigestVerificationFailed)
	}

	if digestOutcome == VerificationOutcomeInvalid {
		return commandValidationRejected(CommandValidationErrorPayloadDigestMismatch)
	}

	if digestOutcome != VerificationOutcomeValid {
		return commandValidationRejected(CommandValidationErrorPayloadDigestVerificationFailed)
	}

	var signatureOutcome VerificationOutcome
	if failed := protocolExceptionPolicy.recoverVerifierFailure(func() {
		signatureOutcome = signatureVerifier.Verify(envelope.SignedMaterial, envelope.Signature)
	}); failed {
		return commandValidationRejected(CommandValidationErrorSignatureVerificationFailed)
	}

	switch signatureOutcome {
	case VerificationOutcomeValid:
		return commandValidationAccepted(envelope, now)
	case VerificationOutcomeInvalid:
		return commandValidationRejected(CommandValidationErrorInvalidSignature)
	default:
		return commandValidationRejected(CommandValidationErrorSignatureVerificationFailed)
	}
}

func commandEnvelopeIsWellFormed(envelope *CommandEnvelope) bool {
	return envelope.ProtocolVersion.IsValid() &&
		envelope.Cell.IsValid() &&
		envelope.AggregateId.IsValid() &&
		envelope.DesiredGeneration.IsValid() &&
		envelope.WriterEpoch.IsValid() &&
		envelope.OperationId.IsValid() &&
		envelope.IdempotencyKey.IsValid() &&
		envelope.Attempt.IsValid() &&
		envelope.Payload.IsPresent() &&
		envelope.PayloadDigest.IsValid() &&
		envelope.Signature.IsValid()
}
