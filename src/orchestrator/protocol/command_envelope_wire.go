package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"time"
)

const MaximumCommandEnvelopeBytes = 2 * 1024 * 1024

// CommandEnvelopeWire is the bounded JSON representation carried on the
// command subject. []byte fields use encoding/json's standard base64 form;
// no credential or exception field exists on this wire type.
type CommandEnvelopeWire struct {
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

// EncodeCommandEnvelope emits the strict ingress wire shape from the
// protocol-owned envelope. It reuses copies of opaque bytes and never mutates
// an admitted command.
func EncodeCommandEnvelope(envelope CommandEnvelope) ([]byte, error) {
	if len(envelope.Payload.Bytes()) > MaximumCommandEnvelopeBytes {
		return nil, errors.New("command payload exceeds the ingress bound")
	}
	wire := CommandEnvelopeWire{
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
	if len(encoded) > MaximumCommandEnvelopeBytes {
		return nil, errors.New("command envelope exceeds the ingress bound")
	}
	return encoded, nil
}

func DecodeCommandEnvelope(data []byte) (CommandEnvelope, error) {
	if len(data) == 0 || len(data) > MaximumCommandEnvelopeBytes {
		return CommandEnvelope{}, errors.New("command envelope exceeds the ingress bound")
	}
	required := map[string]bool{"protocolVersion": true, "cell": true, "aggregateId": true, "desiredGeneration": true, "writerEpoch": true, "operationId": true, "idempotencyKey": true, "issuedAt": true, "expiresAt": true, "attempt": true, "payload": true, "payloadDigest": true, "signature": true}
	strict := json.NewDecoder(bytes.NewReader(data))
	token, err := strict.Token()
	if err != nil || token != json.Delim('{') {
		return CommandEnvelope{}, errors.New("command envelope must be an object")
	}
	seen := map[string]bool{}
	for strict.More() {
		token, err := strict.Token()
		if err != nil {
			return CommandEnvelope{}, err
		}
		key, ok := token.(string)
		if !ok || !required[key] || seen[key] {
			return CommandEnvelope{}, errors.New("command envelope contains unknown or duplicate field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := strict.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return CommandEnvelope{}, errors.New("command envelope contains invalid field")
		}
	}
	if _, err := strict.Token(); err != nil || len(seen) != len(required) {
		return CommandEnvelope{}, errors.New("command envelope is incomplete")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire CommandEnvelopeWire
	if err := decoder.Decode(&wire); err != nil {
		return CommandEnvelope{}, errors.New("command envelope is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CommandEnvelope{}, errors.New("command envelope contains trailing data")
	}
	version, ok := ProtocolRevisionTryCreate(wire.ProtocolVersion)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid protocol version")
	}
	cell, ok := contracts.CellIdTryCreate(wire.Cell)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid cell")
	}
	aggregate, ok := contracts.AggregateIdTryCreate(wire.AggregateID)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid aggregate")
	}
	generation, ok := DesiredGenerationTryCreate(wire.DesiredGeneration)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid generation")
	}
	epoch, ok := WriterEpochTryCreate(wire.WriterEpoch)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid writer epoch")
	}
	operation, ok := contracts.OperationIdTryCreate(wire.OperationID)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid operation")
	}
	idempotency, ok := contracts.IdempotencyKeyTryCreate(wire.IdempotencyKey)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid idempotency key")
	}
	attempt, ok := DeliveryAttemptTryCreate(wire.Attempt)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid attempt")
	}
	payload := OpaquePayloadCopyFrom(wire.Payload)
	digest, ok := PayloadDigestTryCopyFrom(wire.PayloadDigest)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid payload digest")
	}
	signature, ok := OpaqueSignatureTryCopyFrom(wire.Signature)
	if !ok {
		return CommandEnvelope{}, errors.New("command envelope has invalid signature")
	}
	return NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation,
		idempotency, wire.IssuedAt, wire.ExpiresAt, attempt, payload, digest, signature), nil
}
