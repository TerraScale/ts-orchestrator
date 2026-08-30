package control

// Command ingress is the only transport seam allowed to hand a signed
// command to a runtime dispatcher. It deliberately stops at the typed,
// admitted envelope: lifecycle/runtime code remains an injected dependency.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const (
	// A command must fit within the protocol's canonical payload bound plus a
	// small, fixed metadata envelope. This is a transport limit, not a reason
	// to increase the protocol's payload limit.
	NatsCommandIngressMaximumMessageBytes = 2 * 1024 * 1024
	NatsCommandIngressMaximumSubjectBytes = 256
)

// NatsCommandEnvelope is the bounded JSON representation carried on the
// command subject. []byte fields use encoding/json's standard base64 form;
// no credential or exception field exists on this wire type.
type NatsCommandEnvelope struct {
	ProtocolVersion   int64     `json:"protocolVersion"`
	Cell              string    `json:"cell"`
	AggregateID       string    `json:"aggregateId"`
	DesiredGeneration int64     `json:"desiredGeneration"`
	WriterEpoch       int64     `json:"writerEpoch"`
	OperationID       string    `json:"operationId"`
	IdempotencyKey    string    `json:"idempotencyKey"`
	IssuedAt          time.Time `json:"issuedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	Attempt           int64     `json:"attempt"`
	Payload           []byte    `json:"payload"`
	PayloadDigest     []byte    `json:"payloadDigest"`
	Signature         []byte    `json:"signature"`
}

// EncodeNatsCommandEnvelope emits the strict ingress wire shape from the
// protocol-owned envelope. It reuses copies of opaque bytes and never mutates
// an admitted command.
func EncodeNatsCommandEnvelope(envelope protocol.CommandEnvelope) ([]byte, error) {
	if len(envelope.Payload.Bytes()) > NatsCommandIngressMaximumMessageBytes {
		return nil, errors.New("command payload exceeds the ingress bound")
	}
	wire := NatsCommandEnvelope{
		ProtocolVersion: envelope.ProtocolVersion.Value, Cell: envelope.Cell.Value,
		AggregateID: envelope.AggregateId.Value, DesiredGeneration: envelope.DesiredGeneration.Value,
		WriterEpoch: envelope.WriterEpoch.Value, OperationID: envelope.OperationId.Value,
		IdempotencyKey: envelope.IdempotencyKey.Value, IssuedAt: envelope.IssuedAt,
		ExpiresAt: envelope.ExpiresAt, Attempt: envelope.Attempt.Value,
		Payload: envelope.Payload.Bytes(), PayloadDigest: envelope.PayloadDigest.Bytes(),
		Signature: envelope.Signature.Bytes(),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, errors.New("command envelope could not be encoded")
	}
	if len(encoded) > NatsCommandIngressMaximumMessageBytes {
		return nil, errors.New("command envelope exceeds the ingress bound")
	}
	return encoded, nil
}

func decodeNatsCommandEnvelope(data []byte) (protocol.CommandEnvelope, error) {
	if len(data) == 0 || len(data) > NatsCommandIngressMaximumMessageBytes {
		return protocol.CommandEnvelope{}, errors.New("command envelope exceeds the ingress bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire NatsCommandEnvelope
	if err := decoder.Decode(&wire); err != nil {
		return protocol.CommandEnvelope{}, errors.New("command envelope is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return protocol.CommandEnvelope{}, errors.New("command envelope contains trailing data")
	}
	version, ok := protocol.ProtocolRevisionTryCreate(wire.ProtocolVersion)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid protocol version")
	}
	cell, ok := contracts.CellIdTryCreate(wire.Cell)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid cell")
	}
	aggregate, ok := contracts.AggregateIdTryCreate(wire.AggregateID)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid aggregate")
	}
	generation, ok := protocol.DesiredGenerationTryCreate(wire.DesiredGeneration)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid generation")
	}
	epoch, ok := protocol.WriterEpochTryCreate(wire.WriterEpoch)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid writer epoch")
	}
	operation, ok := contracts.OperationIdTryCreate(wire.OperationID)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid operation")
	}
	idempotency, ok := contracts.IdempotencyKeyTryCreate(wire.IdempotencyKey)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid idempotency key")
	}
	attempt, ok := protocol.DeliveryAttemptTryCreate(wire.Attempt)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid attempt")
	}
	payload := protocol.OpaquePayloadCopyFrom(wire.Payload)
	digest, ok := protocol.PayloadDigestTryCopyFrom(wire.PayloadDigest)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid payload digest")
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(wire.Signature)
	if !ok {
		return protocol.CommandEnvelope{}, errors.New("command envelope has invalid signature")
	}
	return protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation,
		idempotency, wire.IssuedAt, wire.ExpiresAt, attempt, payload, digest, signature), nil
}

// CommandIngressDispatcher is called only after protocol and security
// admission has accepted the envelope and atomically consumed its replay key.
type CommandIngressDispatcher func(context.Context, protocol.CommandEnvelope) error

// NatsCommandIngressConfiguration is a complete, bounded command admission
// composition. Identity is loaded once at construction; Replay is injected so
// a multi-instance process cannot silently choose process-local memory.
type NatsCommandIngressConfiguration struct {
	Connection    *nats.Conn
	Subject       string
	Identity      *security.CommandIdentityConfiguration
	Boundary      *security.CommandSecurityBoundary
	Replay        security.CommandReplayStore
	MultiInstance bool

	ExpectedCell             contracts.CellId
	ExpectedAggregateID      contracts.AggregateId
	MinimumDesiredGeneration protocol.DesiredGeneration
	MinimumWriterEpoch       protocol.WriterEpoch
	AcceptedProtocolVersions []protocol.ProtocolRevision
	AllowedClockSkew         time.Duration
	PayloadDigestVerifier    protocol.IPayloadDigestVerifier
	Now                      func() time.Time
	Dispatch                 CommandIngressDispatcher
}

// NatsCommandIngress owns one exact-subject subscriber and its identity
// runtime. It has no lifecycle executor of its own.
type NatsCommandIngress struct {
	connection   *nats.Conn
	subjectValue string
	subscription *nats.Subscription
	lifetime     context.Context
	cancel       context.CancelFunc
	identity     *security.CommandIdentityRuntime
	boundary     *security.CommandSecurityBoundary
	validation   *protocol.CommandValidationContext
	dispatch     CommandIngressDispatcher
	now          func() time.Time
	closeOnce    sync.Once
	closeErr     error
}

// NewNatsCommandIngress validates configuration and creates the admission
// boundary without subscribing. Start must be called explicitly.
func NewNatsCommandIngress(configuration NatsCommandIngressConfiguration) (*NatsCommandIngress, error) {
	if configuration.Connection == nil {
		return nil, errors.New("a NATS connection is required for command ingress")
	}
	if len(configuration.Subject) == 0 || len(configuration.Subject) > NatsCommandIngressMaximumSubjectBytes ||
		!commandIngressSubjectIsExact(configuration.Subject, configuration.ExpectedCell.Value) {
		return nil, errors.New("command ingress subject is invalid")
	}
	if configuration.Dispatch == nil {
		return nil, errors.New("a command ingress dispatcher is required")
	}
	if configuration.PayloadDigestVerifier == nil {
		return nil, errors.New("a command payload digest verifier is required")
	}
	if configuration.AllowedClockSkew < 0 {
		return nil, errors.New("command ingress clock skew is invalid")
	}
	if configuration.MultiInstance && configuration.Replay == nil {
		return nil, errors.New("multi-instance command ingress requires an injected durable replay store")
	}
	if configuration.MultiInstance && configuration.Replay != nil {
		if err := security.RequireDurableCommandReplayStore(configuration.Replay); err != nil {
			return nil, err
		}
	}
	if len(configuration.AcceptedProtocolVersions) == 0 {
		return nil, errors.New("command ingress requires accepted protocol versions")
	}

	boundary := configuration.Boundary
	var identityRuntime *security.CommandIdentityRuntime
	var err error
	if boundary == nil {
		if configuration.Identity == nil {
			return nil, errors.New("command identity configuration is required")
		}
		if configuration.MultiInstance {
			identityRuntime, err = configuration.Identity.OpenForMultiInstanceProduction(configuration.Replay)
		} else if configuration.Replay != nil {
			identityRuntime, err = configuration.Identity.OpenWithReplay(configuration.Replay)
		} else {
			identityRuntime, err = configuration.Identity.Open()
		}
		if err != nil {
			return nil, errors.New("command identity could not be opened")
		}
		boundary, err = security.NewCommandSecurityBoundary(identityRuntime.Verifier, identityRuntime.Replay, configuration.AllowedClockSkew)
		if err != nil {
			_ = identityRuntime.Close()
			return nil, errors.New("command security boundary is invalid")
		}
	} else if configuration.Identity != nil {
		return nil, errors.New("command identity and security boundary cannot both be supplied")
	}
	if configuration.MultiInstance && !boundary.UsesDurableReplay() {
		if identityRuntime != nil {
			_ = identityRuntime.Close()
		}
		return nil, errors.New("multi-instance command ingress requires a durable security replay boundary")
	}
	if boundary == nil || boundary.Verifier() == nil {
		if identityRuntime != nil {
			_ = identityRuntime.Close()
		}
		return nil, errors.New("command security boundary verifier is required")
	}
	validation, err := protocol.NewCommandValidationContext(configuration.ExpectedCell, configuration.ExpectedAggregateID,
		configuration.MinimumDesiredGeneration, configuration.MinimumWriterEpoch,
		configuration.AcceptedProtocolVersions, configuration.AllowedClockSkew,
		configuration.PayloadDigestVerifier, boundary.Verifier())
	if err != nil || !validation.IsWellFormed() {
		if identityRuntime != nil {
			_ = identityRuntime.Close()
		}
		return nil, errors.New("command ingress validation context is invalid")
	}
	now := configuration.Now
	if now == nil {
		now = time.Now
	}
	return &NatsCommandIngress{connection: configuration.Connection, identity: identityRuntime,
		boundary: boundary, validation: validation, dispatch: configuration.Dispatch, now: now,
		subjectValue: configuration.Subject}, nil
}

func commandIngressSubjectIsExact(subject, cell string) bool {
	if strings.TrimSpace(subject) != subject || cell == "" {
		return false
	}
	parsed, grammarError := protocol.ConcreteSubjectTryParse(subject, protocol.NatsSubjectTaxonomy.GrammarLimits())
	if grammarError != protocol.SubjectGrammarErrorNone || parsed == nil {
		return false
	}
	prefix := protocol.NatsSubjectTaxonomy.Root() + "." + cell + ".command."
	return strings.HasPrefix(subject, prefix) && len(strings.TrimPrefix(subject, prefix)) > 0 &&
		!strings.Contains(strings.TrimPrefix(subject, prefix), ".")
}

// Start subscribes to the exact command subject. A wildcard is rejected at
// construction, preventing one ingress from accidentally crossing tenants.
func (i *NatsCommandIngress) Start(ctx context.Context) error {
	if i == nil || i.connection == nil || i.boundary == nil {
		return errors.New("command ingress is unavailable")
	}
	if ctx == nil {
		return errors.New("a command ingress context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	i.lifetime, i.cancel = context.WithCancel(ctx)
	subscription, err := i.connection.Subscribe(i.subject(), i.handleMessage)
	if err != nil {
		i.cancel()
		return errors.New("command ingress subscription could not be started")
	}
	i.subscription = subscription
	return nil
}

func (i *NatsCommandIngress) subject() string {
	// The exact subject is retained by the subscription; this helper exists to
	// keep the runtime struct's sensitive state deliberately small.
	return i.subjectValue
}

func (i *NatsCommandIngress) handleMessage(message *nats.Msg) {
	if message == nil {
		return
	}
	decision, _ := i.Handle(i.lifetime, message.Data)
	if message.Reply != "" {
		_ = message.Respond(decision.response())
	}
}

// Handle admits one already-received payload. It is exported for transports
// that need to own request/reply mechanics while retaining the same security
// boundary. Errors are infrastructure/dispatch failures and contain no
// underlying verifier, replay, payload, or credential text.
func (i *NatsCommandIngress) Handle(ctx context.Context, data []byte) (CommandIngressDecision, error) {
	if i == nil || i.boundary == nil || i.validation == nil {
		return CommandIngressDecision{}, errors.New("command ingress is unavailable")
	}
	if ctx == nil {
		return CommandIngressDecision{}, errors.New("command ingress context is required")
	}
	if err := ctx.Err(); err != nil {
		return CommandIngressDecision{Code: CommandIngressCodeCanceled}, err
	}
	envelope, err := decodeNatsCommandEnvelope(data)
	if err != nil {
		return CommandIngressDecision{Code: CommandIngressCodeMalformed}, nil
	}
	now := i.now().UTC()
	validated := protocol.CommandEnvelopeValidator.Validate(&envelope, i.validation, now)
	if !validated.IsValid() {
		return CommandIngressDecision{Code: CommandIngressCodeRejected, ValidationError: validated.Error}, nil
	}
	outcome, err := i.boundary.VerifyAndConsumeContext(ctx, envelope.SignedMaterial, envelope.Signature, now)
	if err != nil {
		return CommandIngressDecision{Code: CommandIngressCodeSecurityUnavailable}, errors.New("command security infrastructure failed")
	}
	if outcome != security.CommandSecurityAccepted {
		return CommandIngressDecision{Code: CommandIngressCodeRejected, SecurityOutcome: outcome}, nil
	}
	if err := ctx.Err(); err != nil {
		return CommandIngressDecision{Code: CommandIngressCodeCanceled}, err
	}
	if err := i.dispatch(ctx, envelope); err != nil {
		return CommandIngressDecision{Code: CommandIngressCodeDispatchFailed}, errors.New("command dispatch failed")
	}
	return CommandIngressDecision{Code: CommandIngressCodeAccepted, SecurityOutcome: outcome}, nil
}

// CommandIngressCode is a stable, credential-free reply projection.
type CommandIngressCode string

const (
	CommandIngressCodeAccepted            CommandIngressCode = "accepted"
	CommandIngressCodeRejected            CommandIngressCode = "rejected"
	CommandIngressCodeMalformed           CommandIngressCode = "malformed"
	CommandIngressCodeSecurityUnavailable CommandIngressCode = "security-unavailable"
	CommandIngressCodeDispatchFailed      CommandIngressCode = "dispatch-failed"
	CommandIngressCodeCanceled            CommandIngressCode = "canceled"
)

type CommandIngressDecision struct {
	Code            CommandIngressCode
	ValidationError protocol.CommandValidationError
	SecurityOutcome security.CommandSecurityOutcome
}

func (d CommandIngressDecision) response() []byte { return []byte(d.Code) }
func (d CommandIngressDecision) String() string {
	return fmt.Sprintf("CommandIngressDecision{code=%s}", d.Code)
}

// Close stops admission before releasing identities. In-flight dispatches
// receive cancellation through the lifetime context.
func (i *NatsCommandIngress) Close() error {
	if i == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		if i.cancel != nil {
			i.cancel()
		}
		if i.subscription != nil {
			if err := i.subscription.Unsubscribe(); err != nil {
				i.closeErr = errors.New("command ingress subscription close failed")
			}
		}
		if i.identity != nil {
			_ = i.identity.Close()
		}
	})
	return i.closeErr
}
func (i *NatsCommandIngress) Dispose() error { return i.Close() }
