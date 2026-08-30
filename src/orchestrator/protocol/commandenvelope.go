// Port of src/TerraScale.Orchestrator/Protocol/CommandEnvelope.cs. The file
// also carries the small .NET DateTimeOffset helpers the port relies on
// (round-trip formatting and .NET-epoch ticks), which the C# side got from the
// BCL.
package protocol

import (
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
)

const (
	dotNetTicksPerSecond = int64(10_000_000)
	// dotNetEpochTickOffset is the tick count between 0001-01-01T00:00:00Z and
	// 1970-01-01T00:00:00Z, the .NET TimeSpan/DateTimeOffset epoch difference.
	dotNetEpochTickOffset = int64(621355968000000000)
)

// dotNetTicks returns the .NET DateTimeOffset tick count (100-nanosecond units
// since 0001-01-01) of the instant t.
func dotNetTicks(t time.Time) int64 {
	return t.Unix()*dotNetTicksPerSecond + int64(t.Nanosecond())/100 + dotNetEpochTickOffset
}

// dotNetOffsetTicks returns the .NET tick count of t's UTC offset.
func dotNetOffsetTicks(t time.Time) int64 {
	return int64(t.Offset()) / 100
}

// formatDotNetRoundTrip mirrors the C# DateTimeOffset "O" format string:
// yyyy-MM-ddTHH:mm:ss.fffffffzzz with exactly seven fractional digits and a
// signed ±hh:mm offset.
func formatDotNetRoundTrip(t time.Time) string {
	var builder strings.Builder
	utc := t.UTC()
	builder.WriteString(utc.Format("2006-01-02T15:04:05"))
	builder.WriteByte('.')
	fraction := utc.Nanosecond() / 100 // 100ns ticks, exactly seven digits
	builder.WriteString(padLeft(strconv.Itoa(fraction), 7, '0'))
	offset := t.Offset()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	builder.WriteString(sign)
	builder.WriteString(padLeft(strconv.Itoa(int(offset/time.Hour)), 2, '0'))
	builder.WriteByte(':')
	builder.WriteString(padLeft(strconv.Itoa(int((offset%time.Hour)/time.Minute)), 2, '0'))
	return builder.String()
}

func padLeft(value string, width int, padding byte) string {
	if len(value) >= width {
		return value
	}

	filled := make([]byte, width)
	for index := range filled {
		filled[index] = padding
	}

	copy(filled[width-len(value):], value)
	return string(filled)
}

// CommandEnvelope is the signed command envelope of the control protocol.
type CommandEnvelope struct {
	ProtocolVersion  ProtocolRevision
	Cell             contracts.CellId
	AggregateId      contracts.AggregateId
	DesiredGeneration DesiredGeneration
	WriterEpoch      WriterEpoch
	OperationId      contracts.OperationId
	IdempotencyKey   contracts.IdempotencyKey
	IssuedAt         time.Time
	ExpiresAt        time.Time
	Attempt          DeliveryAttempt
	Payload          OpaquePayload
	PayloadDigest    PayloadDigest
	Signature        OpaqueSignature
	SignedMaterial   CommandSignedMaterial
}

// NewCommandEnvelope mirrors the CommandEnvelope constructor; it derives the
// signed material from every covered field.
func NewCommandEnvelope(
	protocolVersion ProtocolRevision,
	cell contracts.CellId,
	aggregateId contracts.AggregateId,
	desiredGeneration DesiredGeneration,
	writerEpoch WriterEpoch,
	operationId contracts.OperationId,
	idempotencyKey contracts.IdempotencyKey,
	issuedAt time.Time,
	expiresAt time.Time,
	attempt DeliveryAttempt,
	payload OpaquePayload,
	payloadDigest PayloadDigest,
	signature OpaqueSignature,
) CommandEnvelope {
	return CommandEnvelope{
		ProtocolVersion:   protocolVersion,
		Cell:              cell,
		AggregateId:       aggregateId,
		DesiredGeneration: desiredGeneration,
		WriterEpoch:       writerEpoch,
		OperationId:       operationId,
		IdempotencyKey:    idempotencyKey,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
		Attempt:           attempt,
		Payload:           payload,
		PayloadDigest:     payloadDigest,
		Signature:         signature,
		SignedMaterial: CommandSignedMaterial{
			ProtocolVersion:   protocolVersion,
			Cell:              cell,
			AggregateId:       aggregateId,
			DesiredGeneration: desiredGeneration,
			WriterEpoch:       writerEpoch,
			OperationId:       operationId,
			IdempotencyKey:    idempotencyKey,
			IssuedAt:          issuedAt,
			ExpiresAt:         expiresAt,
			Attempt:           attempt,
			Payload:           payload,
			PayloadDigest:     payloadDigest,
		},
	}
}

// String mirrors the C# ToString: payload, digest, and signature are redacted.
func (e CommandEnvelope) String() string {
	return "CommandEnvelope { ProtocolVersion = " + e.ProtocolVersion.String() +
		", Cell = " + e.Cell.String() +
		", AggregateId = " + e.AggregateId.String() +
		", DesiredGeneration = " + e.DesiredGeneration.String() +
		", WriterEpoch = " + e.WriterEpoch.String() +
		", OperationId = " + e.OperationId.String() +
		", IdempotencyKey = " + e.IdempotencyKey.String() +
		", IssuedAt = " + formatDotNetRoundTrip(e.IssuedAt) +
		", ExpiresAt = " + formatDotNetRoundTrip(e.ExpiresAt) +
		", Attempt = " + e.Attempt.String() +
		", Payload = <redacted>, PayloadDigest = <redacted>, Signature = <redacted> }"
}

// CommandSignedMaterial is the complete algorithm-neutral material that a
// caller-supplied verifier must authenticate. The protocol owns canonical
// serialization; the verifier owns signing and trust policy. No field may be
// omitted.
type CommandSignedMaterial struct {
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
	Payload           OpaquePayload
	PayloadDigest     PayloadDigest
}

// String mirrors the C# ToString: the material never renders its contents.
func (CommandSignedMaterial) String() string { return "<command-signed-material>" }
