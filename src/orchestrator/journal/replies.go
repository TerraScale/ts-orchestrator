package journal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// RuntimeLifecycleNatsProtocolSchemaVersion is the schema version for the
// private runtime-lifecycle journal reply.
const RuntimeLifecycleNatsProtocolSchemaVersion = 2

// NatsRuntimeLifecycleJournalReply is a signed lifecycle-journal result.
type NatsRuntimeLifecycleJournalReply struct {
	SchemaVersion int
	Status        int
	Revision      uint64
	Checkpoint    *string
	RequestDigest string
	Signature     string
}

// Payload returns the canonical lifecycle-journal reply signing material.
func (r NatsRuntimeLifecycleJournalReply) Payload() string {
	checkpoint := ""
	if r.Checkpoint != nil {
		checkpoint = *r.Checkpoint
	}
	return strings.Join([]string{strconv.Itoa(r.SchemaVersion), strconv.Itoa(r.Status),
		strconv.FormatUint(r.Revision, 10), checkpoint, r.RequestDigest}, "|")
}

// NatsOperationJournalMutationReplySigner signs mutation replies.
type NatsOperationJournalMutationReplySigner struct {
	key *ecdsa.PrivateKey
}

// NewNatsOperationJournalMutationReplySigner creates a reply signer. It
// returns nil when key is unavailable or is not a P-256 ECDSA key; callers
// that require a signer must treat nil as an admission failure.
func NewNatsOperationJournalMutationReplySigner(
	key *ecdsa.PrivateKey,
) *NatsOperationJournalMutationReplySigner {
	if !isUsableP256PrivateKey(key) {
		return nil
	}
	return &NatsOperationJournalMutationReplySigner{key: cloneP256PrivateKey(key)}
}

func isUsableP256PrivateKey(key *ecdsa.PrivateKey) bool {
	if key == nil || !isP256(&key.PublicKey) || key.D == nil || key.X == nil || key.Y == nil {
		return false
	}
	params := key.Curve.Params()
	if params == nil || params.N == nil || key.D.Sign() <= 0 || key.D.Cmp(params.N) >= 0 ||
		!key.Curve.IsOnCurve(key.X, key.Y) {
		return false
	}
	expectedX, expectedY := key.Curve.ScalarBaseMult(key.D.Bytes())
	return expectedX != nil && expectedY != nil && key.X.Cmp(expectedX) == 0 && key.Y.Cmp(expectedY) == 0
}

func cloneP256PrivateKey(key *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).Set(key.X),
			Y:     new(big.Int).Set(key.Y),
		},
		D: new(big.Int).Set(key.D),
	}
}

// Sign creates a signed operation-journal reply.
func (s *NatsOperationJournalMutationReplySigner) Sign(
	succeeded bool,
	revision uint64,
	requestDigest string,
) NatsOperationJournalMutationReply {
	reply := NatsOperationJournalMutationReply{
		SchemaVersion: protocol.ProtocolVersion.Current(),
		Succeeded:     succeeded,
		Revision:      revision,
		RequestDigest: requestDigest,
		Signature:     "",
	}

	if s == nil || s.key == nil {
		return reply
	}
	if signature, err := ecdsa.SignASN1(rand.Reader, s.key, sha256Sum([]byte(reply.Payload()))); err == nil {
		reply.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return reply
}

// SignRuntime creates a signed lifecycle-journal reply.
func (s *NatsOperationJournalMutationReplySigner) SignRuntime(
	status int,
	revision uint64,
	checkpoint *string,
	requestDigest string,
) NatsRuntimeLifecycleJournalReply {
	reply := NatsRuntimeLifecycleJournalReply{
		SchemaVersion: RuntimeLifecycleNatsProtocolSchemaVersion,
		Status:        status,
		Revision:      revision,
		Checkpoint:    checkpoint,
		RequestDigest: requestDigest,
		Signature:     "",
	}

	if s == nil || s.key == nil {
		return reply
	}
	if signature, err := ecdsa.SignASN1(rand.Reader, s.key, sha256Sum([]byte(reply.Payload()))); err == nil {
		reply.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return reply
}

// ExportPublicKey returns the signer's PKIX public key.
func (s *NatsOperationJournalMutationReplySigner) ExportPublicKey() ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("The reply signing key is unavailable.")
	}
	return x509.MarshalPKIXPublicKey(&s.key.PublicKey)
}

// Dispose releases signer resources.
func (s *NatsOperationJournalMutationReplySigner) Dispose() {}

// NatsOperationJournalMutationReplyVerifier verifies signed journal replies.
type NatsOperationJournalMutationReplyVerifier struct {
	publicKey []byte
}

// NewNatsOperationJournalMutationReplyVerifier creates a reply verifier.
func NewNatsOperationJournalMutationReplyVerifier(
	publicKey []byte,
) *NatsOperationJournalMutationReplyVerifier {
	copied := append([]byte(nil), publicKey...)
	return &NatsOperationJournalMutationReplyVerifier{publicKey: copied}
}

// Verify checks an operation-journal reply and its request binding.
func (v *NatsOperationJournalMutationReplyVerifier) Verify(
	reply *NatsOperationJournalMutationReply,
	requestDigest string,
) bool {
	if reply == nil || reply.SchemaVersion != protocol.ProtocolVersion.Current() ||
		reply.RequestDigest != requestDigest ||
		strings.TrimSpace(reply.Signature) == "" {
		return false
	}

	return v.verifySignature(sha256Sum([]byte(reply.Payload())), reply.Signature)
}

// VerifyRuntime checks a lifecycle-journal reply and its request binding.
func (v *NatsOperationJournalMutationReplyVerifier) VerifyRuntime(
	reply *NatsRuntimeLifecycleJournalReply,
	requestDigest string,
) bool {
	if reply == nil || reply.SchemaVersion != RuntimeLifecycleNatsProtocolSchemaVersion ||
		reply.RequestDigest != requestDigest ||
		strings.TrimSpace(reply.Signature) == "" {
		return false
	}

	return v.verifySignature(sha256Sum([]byte(reply.Payload())), reply.Signature)
}

func (v *NatsOperationJournalMutationReplyVerifier) verifySignature(
	digest []byte,
	signature string,
) bool {
	if v == nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(v.publicKey)
	if err != nil {
		return false
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !isP256(key) {
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(key, digest, signatureBytes)
}
