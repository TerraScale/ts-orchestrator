package protocol

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MessagingSchemaVersion is the schema version of the messaging envelope
// contract: additive minor, breaking major.
type MessagingSchemaVersion struct {
	Major int
	Minor int
}

// MessagingSchemaVersionCurrent mirrors MessagingSchemaVersion.Current.
var MessagingSchemaVersionCurrent = MessagingSchemaVersion{Major: 1, Minor: 0}

// IsWellFormed reports whether both components are valid (positive major,
// nonnegative minor).
func (v MessagingSchemaVersion) IsWellFormed() bool { return v.Major > 0 && v.Minor >= 0 }

func (v MessagingSchemaVersion) String() string {
	return "v" + strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor)
}

// MessageIdentityToken is one bounded message identity token: message id,
// correlation id, and causation id. Identical rules as the command
// identifiers: nonempty, no control characters, bounded. TryCreate accepts an
// empty value (mirroring the C#); IsValid is the gate that rejects it.
type MessageIdentityToken struct {
	Value string
}

// IsValid reports whether the token is nonempty, valid UTF-8, at most 128 v1
// UTF-16 code units, and free of NUL and control characters.
func (t MessageIdentityToken) IsValid() bool {
	if t.Value == "" || !utf8.ValidString(t.Value) || v1UTF16CodeUnitCount(t.Value) > 128 {
		return false
	}

	if strings.ContainsRune(t.Value, '\x00') {
		return false
	}

	for _, character := range t.Value {
		if unicode.IsControl(character) {
			return false
		}
	}

	return true
}

// MessageIdentityTokenTryCreate mirrors MessageIdentityToken.TryCreate.
func MessageIdentityTokenTryCreate(value string) (MessageIdentityToken, bool) {
	if value == "" {
		return MessageIdentityToken{Value: value}, true
	}

	if !utf8.ValidString(value) || v1UTF16CodeUnitCount(value) > 128 ||
		strings.ContainsRune(value, '\x00') || hasControlRune(value) {
		return MessageIdentityToken{}, false
	}

	return MessageIdentityToken{Value: value}, true
}

func hasControlRune(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}

	return false
}

func (t MessageIdentityToken) String() string { return t.Value }

// MessagingTraceContext is the W3C-shaped trace context; both identifiers are
// bounded hex strings.
type MessagingTraceContext struct {
	TraceId string
	SpanId  string
}

// IsWellFormed reports whether both identifiers have the exact length and hex
// alphabet of the W3C shape.
func (c MessagingTraceContext) IsWellFormed() bool {
	return len(c.TraceId) == 32 && isAsciiHexDigitString(c.TraceId) &&
		len(c.SpanId) == 16 && isAsciiHexDigitString(c.SpanId)
}

func isAsciiHexDigitString(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}

	return true
}

// MessagingSource is where the message came from: the exact instance,
// session, cell, and cluster.
type MessagingSource struct {
	Instance string
	Session  string
	Cell     string
	Cluster  string
}

// IsWellFormed mirrors the C# rule: bounded token alphabet per field.
func (s MessagingSource) IsWellFormed() bool {
	return isMessagingSourceToken(s.Instance, 128) &&
		isMessagingSourceToken(s.Session, 128) &&
		isMessagingSourceToken(s.Cell, 63) &&
		isMessagingSourceToken(s.Cluster, 128)
}

func isMessagingSourceToken(value string, maximumLength int) bool {
	if value == "" || len(value) > maximumLength {
		return false
	}

	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}

		return false
	}

	return true
}

// MessagingTargetScope is where the message is addressed: taxonomy namespace,
// concrete subject, and optional cell scope. The namespace is validated
// against the subject's derived classification, so it can never drift into an
// ignored decorative field.
type MessagingTargetScope struct {
	Namespace NatsSubjectNamespace
	Subject   string
	Cell      *string
}

// IsWellFormed mirrors the C# rule.
func (s MessagingTargetScope) IsWellFormed() bool {
	if len(s.Subject) < 1 || len(s.Subject) > 512 {
		return false
	}

	if s.Cell == nil {
		return true
	}

	return len(*s.Cell) >= 1 && len(*s.Cell) <= 63
}

// MessagingEnvelope is the versioned messaging envelope. It does NOT
// duplicate the signed command contract: Command carries the canonical
// CommandEnvelope (protocol version, cell, aggregate, generation, writer
// epoch, operation id, idempotency key, issued/expiry times, delivery
// attempt, payload, digest, signature). This envelope adds the
// messaging-correlation, source/target, trace, payload-type, and observation
// metadata.
type MessagingEnvelope struct {
	SchemaVersion MessagingSchemaVersion
	MessageId     MessageIdentityToken
	CorrelationId *MessageIdentityToken
	CausationId   *MessageIdentityToken
	Source        MessagingSource
	Target        MessagingTargetScope
	PayloadType   string
	Command       *CommandEnvelope
	TraceContext  *MessagingTraceContext
	ObservedAt    time.Time
}

// String mirrors the C# ToString: the message id is redacted.
func (e MessagingEnvelope) String() string {
	return "MessagingEnvelope { SchemaVersion = " + e.SchemaVersion.String() +
		", MessageId = <redacted>, Target = " + e.Target.Subject +
		", PayloadType = " + e.PayloadType +
		", Command = " + e.Command.String() + " }"
}

// MessagingEnvelopeError mirrors the MessagingEnvelopeError enum.
type MessagingEnvelopeError int

const (
	MessagingEnvelopeErrorNone                         MessagingEnvelopeError = 0
	MessagingEnvelopeErrorNullEnvelope                 MessagingEnvelopeError = 1
	MessagingEnvelopeErrorUnknownMajorVersion          MessagingEnvelopeError = 2
	MessagingEnvelopeErrorMalformedEnvelope            MessagingEnvelopeError = 3
	MessagingEnvelopeErrorMalformedSubject             MessagingEnvelopeError = 4
	MessagingEnvelopeErrorSubjectOutsideClosedTaxonomy MessagingEnvelopeError = 5
	// MessagingEnvelopeErrorDeclaredNamespaceMismatch reports that the declared
	// target namespace disagrees with the subject's derived classification.
	MessagingEnvelopeErrorDeclaredNamespaceMismatch MessagingEnvelopeError = 6
	MessagingEnvelopeErrorSubjectCellMismatch       MessagingEnvelopeError = 7
	MessagingEnvelopeErrorSourceCellMismatch        MessagingEnvelopeError = 8
	MessagingEnvelopeErrorPayloadTypeNotPermitted   MessagingEnvelopeError = 9
	MessagingEnvelopeErrorInvalidTraceContext       MessagingEnvelopeError = 10
	// MessagingEnvelopeErrorCommandRejected reports that the signed command
	// contract rejected the envelope; CommandError carries the exact reason.
	MessagingEnvelopeErrorCommandRejected MessagingEnvelopeError = 11
)

// MessagingEnvelopeResult mirrors the readonly record struct of the same name.
type MessagingEnvelopeResult struct {
	Error        MessagingEnvelopeError
	CommandError CommandValidationError
	Envelope     *MessagingEnvelope
}

// IsAccepted reports whether the envelope was admitted.
func (r MessagingEnvelopeResult) IsAccepted() bool {
	return r.Error == MessagingEnvelopeErrorNone && r.Envelope != nil
}

func messagingEnvelopeAccepted(envelope *MessagingEnvelope) MessagingEnvelopeResult {
	return MessagingEnvelopeResult{
		Error:        MessagingEnvelopeErrorNone,
		CommandError: CommandValidationErrorNone,
		Envelope:     envelope,
	}
}

func messagingEnvelopeRejected(
	errorKind MessagingEnvelopeError,
	commandError CommandValidationError,
) MessagingEnvelopeResult {
	if commandError == 0 {
		commandError = CommandValidationErrorUninitialized
	}

	return MessagingEnvelopeResult{Error: errorKind, CommandError: commandError}
}

// MessagingValidationContext is the frozen admission context: accepted schema
// majors, permitted payload types, and the signed-command context.
type MessagingValidationContext struct {
	AcceptedSchemaMajorVersions map[int]struct{}
	PermittedPayloadTypes       map[string]struct{}
	CommandContext              *CommandValidationContext
}

// NewMessagingValidationContext mirrors the C# constructor (no validation;
// IsWellFormed is the admission gate).
func NewMessagingValidationContext(
	acceptedSchemaMajorVersions map[int]struct{},
	permittedPayloadTypes map[string]struct{},
	commandContext *CommandValidationContext,
) *MessagingValidationContext {
	return &MessagingValidationContext{
		AcceptedSchemaMajorVersions: acceptedSchemaMajorVersions,
		PermittedPayloadTypes:       permittedPayloadTypes,
		CommandContext:              commandContext,
	}
}

// IsWellFormed mirrors the internal context well-formedness rule.
func (c *MessagingValidationContext) IsWellFormed() bool {
	if c == nil {
		return false
	}

	if len(c.AcceptedSchemaMajorVersions) == 0 || len(c.PermittedPayloadTypes) == 0 {
		return false
	}

	for payloadType := range c.PermittedPayloadTypes {
		if len(payloadType) < 1 || len(payloadType) > 64 {
			return false
		}
	}

	return true
}

// MessagingEnvelopeValidator mirrors the C# static class: the pure, fail-closed
// messaging-envelope admission. Every check is deterministic and
// infrastructure-free: unknown major versions, malformed or off-taxonomy
// subjects, declared-namespace disagreement with the derived classification,
// subject/cell disagreement, unpermitted payload types, malformed trace
// context, and every signed-command rejection (expiry, wrong cell, stale
// epoch, signature, digest) fail closed with typed errors.
var MessagingEnvelopeValidator messagingEnvelopeValidator

type messagingEnvelopeValidator struct{}

// Validate admits or rejects one messaging envelope against one context.
func (messagingEnvelopeValidator) Validate(
	envelope *MessagingEnvelope,
	context *MessagingValidationContext,
) MessagingEnvelopeResult {
	if context == nil || !context.IsWellFormed() {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorMalformedEnvelope, CommandValidationErrorUninitialized)
	}

	if envelope == nil {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorNullEnvelope, CommandValidationErrorUninitialized)
	}

	if !envelope.SchemaVersion.IsWellFormed() {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorUnknownMajorVersion, CommandValidationErrorUninitialized)
	}

	if _, majorAccepted := context.AcceptedSchemaMajorVersions[envelope.SchemaVersion.Major]; !majorAccepted {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorUnknownMajorVersion, CommandValidationErrorUninitialized)
	}

	if !envelope.MessageId.IsValid() ||
		(envelope.CorrelationId != nil && !envelope.CorrelationId.IsValid()) ||
		(envelope.CausationId != nil && !envelope.CausationId.IsValid()) ||
		!envelope.Source.IsWellFormed() ||
		!envelope.Target.IsWellFormed() ||
		strings.TrimSpace(envelope.PayloadType) == "" ||
		len(envelope.PayloadType) > 64 ||
		envelope.Command == nil {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorMalformedEnvelope, CommandValidationErrorUninitialized)
	}

	if envelope.TraceContext != nil && !envelope.TraceContext.IsWellFormed() {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorInvalidTraceContext, CommandValidationErrorUninitialized)
	}

	// Source and signed command must agree on the cell before any subject coupling check.
	if envelope.Source.Cell != envelope.Command.Cell.Value {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorSourceCellMismatch, CommandValidationErrorUninitialized)
	}

	if _, err := ConcreteSubjectTryParse(envelope.Target.Subject, NatsSubjectTaxonomy.GrammarLimits()); err != SubjectGrammarErrorNone {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorMalformedSubject, CommandValidationErrorUninitialized)
	}

	ns := NatsSubjectTaxonomy.Classify(envelope.Target.Subject)
	if !NatsSubjectTaxonomy.IsControlNamespace(ns) {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorSubjectOutsideClosedTaxonomy, CommandValidationErrorUninitialized)
	}

	// The declared namespace must equal the classification derived from the subject;
	// disagreement is a typed rejection rather than a silently ignored decorative field.
	if envelope.Target.Namespace != ns {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorDeclaredNamespaceMismatch, CommandValidationErrorUninitialized)
	}

	if subjectCell, scoped := extractCellScope(envelope.Target.Subject); scoped &&
		subjectCell != envelope.Command.Cell.Value {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorSubjectCellMismatch, CommandValidationErrorUninitialized)
	}

	if envelope.Target.Cell != nil && *envelope.Target.Cell != envelope.Command.Cell.Value {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorSubjectCellMismatch, CommandValidationErrorUninitialized)
	}

	if _, permitted := context.PermittedPayloadTypes[envelope.PayloadType]; !permitted {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorPayloadTypeNotPermitted, CommandValidationErrorUninitialized)
	}

	commandResult := CommandEnvelopeValidator.Validate(envelope.Command, context.CommandContext, envelope.ObservedAt)
	if !commandResult.IsValid() {
		return messagingEnvelopeRejected(MessagingEnvelopeErrorCommandRejected, commandResult.Error)
	}

	return messagingEnvelopeAccepted(envelope)
}

// extractCellScope mirrors the internal ExtractCellScope: it extracts the cell
// token of a cell-scoped subject: the regional shape
// (ts.orch.v2.<cell>..., token 4) and, as defense in depth, the canonical
// global per-cell shape (ts.orch.v2.global.desired.gitops.<cell>). Any other
// global subject carries no cell scope.
func extractCellScope(subject string) (string, bool) {
	tokens := strings.Split(subject, ".")
	if len(tokens) >= 4 && strings.HasPrefix(subject, NatsSubjectTaxonomy.Root()+".") {
		if tokens[3] == "global" {
			if len(tokens) == 7 && tokens[4] == "desired" && tokens[5] == "gitops" {
				return tokens[6], true
			}

			return "", false
		}

		return tokens[3], true
	}

	return "", false
}
