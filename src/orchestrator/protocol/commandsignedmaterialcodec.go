// Port of src/TerraScale.Orchestrator/Protocol/CommandSignedMaterialCodec.cs.
package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// InvalidDataError mirrors System.IO.InvalidDataException for callers that
// distinguish malformed signing material from other failures.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

func invalidData(message string) error {
	return &InvalidDataError{Message: message}
}

// CommandSignedMaterialCodec mirrors the C# internal static class (exported
// here because the Go package boundary replaces the C# assembly boundary):
// the canonical versioned representation of every command field covered by a
// signature. Length prefixes and big-endian integers make the representation
// unambiguous across implementations.
var CommandSignedMaterialCodec commandSignedMaterialCodec

type commandSignedMaterialCodec struct{}

const (
	maximumIdentifierCharacters = 16 * 1024
	maximumIdentifierBytes      = 48 * 1024
	maximumPayloadBytes         = 1024 * 1024
	maximumDigestBytes          = 128
	maximumEncodedBytes         = 2 * 1024 * 1024
)

var commandSignedMaterialMagic = []byte("TS-COMMAND-SIGNED-V1\x00")

// Encode produces the canonical signing bytes for the given material.
func (commandSignedMaterialCodec) Encode(material *CommandSignedMaterial) ([]byte, error) {
	if material == nil {
		return nil, errors.New("Value cannot be null. (Parameter 'material')")
	}

	if err := validateCommandSignedMaterial(material); err != nil {
		return nil, err
	}

	writer := newBigEndianWriter(1024)
	writer.writeRaw(commandSignedMaterialMagic)
	writer.writeInt64(material.ProtocolVersion.Value)
	if err := writer.writeString(material.Cell.Value); err != nil {
		return nil, err
	}

	if err := writer.writeString(material.AggregateId.Value); err != nil {
		return nil, err
	}

	writer.writeInt64(material.DesiredGeneration.Value)
	writer.writeInt64(material.WriterEpoch.Value)
	if err := writer.writeString(material.OperationId.Value); err != nil {
		return nil, err
	}

	if err := writer.writeString(material.IdempotencyKey.Value); err != nil {
		return nil, err
	}

	writer.writeInt64(dotNetTicks(material.IssuedAt))
	writer.writeInt64(dotNetOffsetTicks(material.IssuedAt))
	writer.writeInt64(dotNetTicks(material.ExpiresAt))
	writer.writeInt64(dotNetOffsetTicks(material.ExpiresAt))
	writer.writeInt64(material.Attempt.Value)
	writer.writeBytes(material.Payload.Bytes())
	writer.writeBytes(material.PayloadDigest.Bytes)
	if writer.written > maximumEncodedBytes {
		return nil, invalidData("The canonical command signing material exceeded its bound.")
	}

	return writer.bytes(), nil
}

// Hash returns the SHA-256 digest of the canonical signing bytes.
func (commandSignedMaterialCodec) Hash(material *CommandSignedMaterial) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	encoded, err := CommandSignedMaterialCodec.Encode(material)
	if err != nil {
		return digest, err
	}

	return sha256.Sum256(encoded), nil
}

func validateCommandSignedMaterial(material *CommandSignedMaterial) error {
	if !material.ProtocolVersion.IsValid() || !material.Cell.IsValid() || !material.AggregateId.IsValid() ||
		!material.DesiredGeneration.IsValid() || !material.WriterEpoch.IsValid() ||
		!material.OperationId.IsValid() || !material.IdempotencyKey.IsValid() || !material.Attempt.IsValid() ||
		material.ExpiresAt.Before(material.IssuedAt) ||
		!material.Payload.IsPresent() ||
		material.Payload.Length() < 1 || material.Payload.Length() > maximumPayloadBytes ||
		!material.PayloadDigest.IsValid() ||
		material.PayloadDigest.Length() > maximumDigestBytes {
		return invalidData("The command signing material is invalid.")
	}

	return nil
}

// bigEndianWriter mirrors ArrayBufferWriter<byte> plus the Write helpers.
type bigEndianWriter struct {
	buffer []byte
	written int
}

func newBigEndianWriter(capacity int) *bigEndianWriter {
	return &bigEndianWriter{buffer: make([]byte, 0, capacity)}
}

func (w *bigEndianWriter) bytes() []byte {
	return w.buffer
}

func (w *bigEndianWriter) writeRaw(value []byte) {
	w.buffer = append(w.buffer, value...)
	w.written += len(value)
}

func (w *bigEndianWriter) writeInt64(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	w.buffer = append(w.buffer, encoded[:]...)
	w.written += 8
}

func (w *bigEndianWriter) writeLength(value int) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(value))
	w.buffer = append(w.buffer, encoded[:]...)
	w.written += 4
}

func (w *bigEndianWriter) writeBytes(value []byte) {
	w.writeLength(len(value))
	w.buffer = append(w.buffer, value...)
	w.written += len(value)
}

func (w *bigEndianWriter) writeString(value string) error {
	// The C# UTF8Encoding(false, true) throws EncoderFallbackException for
	// invalid UTF-16 input; a Go string that is not valid UTF-8 is the same
	// failure mode.
	if !utf8.ValidString(value) {
		return invalidData("A command signing identity is not valid UTF-8.")
	}

	if utf16Length(value) > maximumIdentifierCharacters {
		return invalidData("A command signing identity exceeded its bound.")
	}

	count := len(value)
	if count > maximumIdentifierBytes {
		return invalidData("A command signing identity exceeded its bound.")
	}

	w.writeLength(count)
	w.buffer = append(w.buffer, value...)
	w.written += count
	return nil
}

// utf16Length returns the length of value in UTF-16 code units, mirroring the
// C# string.Length measurement used by every bound in the protocol.
func utf16Length(value string) int {
	length := 0
	for _, r := range value {
		if r > 0xFFFF {
			length += 2
		} else {
			length++
		}
	}

	return length
}
