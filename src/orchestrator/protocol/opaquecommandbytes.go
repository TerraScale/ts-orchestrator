// Port of src/TerraScale.Orchestrator/Protocol/OpaqueCommandBytes.cs.
package protocol

import "crypto/subtle"

// OpaquePayload is the secret-safe opaque command payload. Its bytes are never
// rendered by String. The zero value stands in for the C# null reference
// (IsPresent reports false); CopyFrom of an empty slice is a present, empty
// payload, which the C# allows.
type OpaquePayload struct {
	bytes   []byte
	present bool
}

// Length returns the payload byte length.
func (p OpaquePayload) Length() int { return len(p.bytes) }

// Bytes returns a copy of the payload bytes. Go slices cannot enforce a
// read-only view, so returning the backing slice would let a caller mutate
// already-admitted signed material after validation.
func (p OpaquePayload) Bytes() []byte { return append([]byte(nil), p.bytes...) }

// IsPresent distinguishes the zero value (the C# null payload) from a payload
// constructed through CopyFrom, including an empty one.
func (p OpaquePayload) IsPresent() bool { return p.present }

// OpaquePayloadCopyFrom mirrors OpaquePayload.CopyFrom: it copies the input so
// later mutation of the caller's slice cannot change the stored payload.
func OpaquePayloadCopyFrom(source []byte) OpaquePayload {
	copied := make([]byte, len(source))
	copy(copied, source)
	return OpaquePayload{bytes: copied, present: true}
}

// Equal mirrors OpaquePayload.Equals: a fixed-time content comparison.
func (p OpaquePayload) Equal(other OpaquePayload) bool {
	return opaqueBytesEqual(p.bytes, other.bytes)
}

func (p OpaquePayload) String() string { return "<opaque-payload>" }

// PayloadDigest is the opaque digest of an OpaquePayload. An empty digest is
// representable only by the zero value and reports IsValid() == false.
type PayloadDigest struct {
	bytes []byte
}

// Length returns the digest byte length.
func (d PayloadDigest) Length() int { return len(d.bytes) }

// Bytes returns a read-only view of the digest bytes; callers must not mutate it.
func (d PayloadDigest) Bytes() []byte { return append([]byte(nil), d.bytes...) }

// IsValid reports whether the digest is nonempty.
func (d PayloadDigest) IsValid() bool { return len(d.bytes) > 0 }

// PayloadDigestTryCopyFrom mirrors PayloadDigest.TryCopyFrom: empty input is
// rejected and yields the zero digest.
func PayloadDigestTryCopyFrom(source []byte) (PayloadDigest, bool) {
	if len(source) == 0 {
		return PayloadDigest{}, false
	}

	copied := make([]byte, len(source))
	copy(copied, source)
	return PayloadDigest{bytes: copied}, true
}

// Equal mirrors PayloadDigest.Equals: a fixed-time content comparison.
func (d PayloadDigest) Equal(other PayloadDigest) bool {
	return opaqueBytesEqual(d.bytes, other.bytes)
}

func (d PayloadDigest) String() string { return "<payload-digest>" }

// OpaqueSignature is the opaque signature over the command signed material.
type OpaqueSignature struct {
	bytes []byte
}

// Length returns the signature byte length.
func (s OpaqueSignature) Length() int { return len(s.bytes) }

// Bytes returns a read-only view of the signature bytes; callers must not mutate it.
func (s OpaqueSignature) Bytes() []byte { return append([]byte(nil), s.bytes...) }

// IsValid reports whether the signature is nonempty.
func (s OpaqueSignature) IsValid() bool { return len(s.bytes) > 0 }

// OpaqueSignatureTryCopyFrom mirrors OpaqueSignature.TryCopyFrom: empty input
// is rejected and yields the zero signature.
func OpaqueSignatureTryCopyFrom(source []byte) (OpaqueSignature, bool) {
	if len(source) == 0 {
		return OpaqueSignature{}, false
	}

	copied := make([]byte, len(source))
	copy(copied, source)
	return OpaqueSignature{bytes: copied}, true
}

// Equal mirrors OpaqueSignature.Equals: a fixed-time content comparison.
func (s OpaqueSignature) Equal(other OpaqueSignature) bool {
	return opaqueBytesEqual(s.bytes, other.bytes)
}

func (s OpaqueSignature) String() string { return "<opaque-signature>" }

// opaqueBytesEqual mirrors CryptographicOperations.FixedTimeEquals.
func opaqueBytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}

	return subtle.ConstantTimeCompare(left, right) == 1
}
