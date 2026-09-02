package journal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const (
	operationJournalKeyPrefix         = "operation."
	operationJournalDigestHexBytes    = sha256.Size * 2
	operationJournalMaximumValueBytes = 16 * 1024
	natsNonceBytes                    = 16
)

// NatsOperationJournalCreateRequest is a versioned create request.
type NatsOperationJournalCreateRequest struct {
	SchemaVersion int                                        `json:"SchemaVersion"`
	Key           string                                     `json:"Key"`
	Value         string                                     `json:"Value"`
	Authority     NatsOperationJournalMutationAuthorityProof `json:"Authority"`
}

// NatsOperationJournalUpdateRequest is a versioned conditional update request.
type NatsOperationJournalUpdateRequest struct {
	SchemaVersion int                                        `json:"SchemaVersion"`
	Key           string                                     `json:"Key"`
	Value         string                                     `json:"Value"`
	Revision      uint64                                     `json:"Revision"`
	Authority     NatsOperationJournalMutationAuthorityProof `json:"Authority"`
}

// NatsOperationJournalMutationReply is a signed versioned mutation result.
type NatsOperationJournalMutationReply struct {
	SchemaVersion int    `json:"SchemaVersion"`
	Succeeded     bool   `json:"Succeeded"`
	Revision      uint64 `json:"Revision"`
	RequestDigest string `json:"RequestDigest"`
	Signature     string `json:"Signature"`
}

// Payload returns the canonical reply signing material.
func (r NatsOperationJournalMutationReply) Payload() string {
	return strings.Join([]string{
		strconv.Itoa(r.SchemaVersion),
		strconv.FormatBool(r.Succeeded),
		strconv.FormatUint(r.Revision, 10),
		r.RequestDigest,
	}, "|")
}

// NatsOperationJournalMutationAuthorityProof binds a caller to one journal mutation.
type NatsOperationJournalMutationAuthorityProof struct {
	Cell             string    `json:"Cell"`
	CallerIdentity   string    `json:"CallerIdentity"`
	Action           string    `json:"Action"`
	Key              string    `json:"Key"`
	Revision         uint64    `json:"Revision"`
	CiphertextDigest string    `json:"CiphertextDigest"`
	Lease            string    `json:"Lease"`
	ExpiresAt        time.Time `json:"ExpiresAt"`
	Nonce            string    `json:"Nonce"`
	Signature        string    `json:"Signature"`
}

// Payload returns the canonical authority-proof signing material.
func (p NatsOperationJournalMutationAuthorityProof) Payload() string {
	return strings.Join([]string{
		p.Cell,
		p.CallerIdentity,
		p.Action,
		p.Key,
		strconv.FormatUint(p.Revision, 10),
		p.CiphertextDigest,
		p.Lease,
		strconv.FormatInt(p.ExpiresAt.UTC().Unix(), 10),
		p.Nonce,
	}, "|")
}

// IsValidMutation checks the closed operation key and value contract.
func IsValidMutation(key, value string) bool {
	if len(key) != len(operationJournalKeyPrefix)+operationJournalDigestHexBytes ||
		!strings.HasPrefix(key, operationJournalKeyPrefix) {
		return false
	}

	for index := len(operationJournalKeyPrefix); index < len(key); index++ {
		character := key[index]
		isHex := character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'f' ||
			character >= 'A' && character <= 'F'
		if !isHex {
			return false
		}
	}

	return utf8.ValidString(value) && len(value) <= operationJournalMaximumValueBytes
}

// RandomNatsNonce returns a 128-bit random token. Entropy failure returns an
// empty token so all subject and proof validation fails closed.
func RandomNatsNonce() string {
	return randomNatsNonce(rand.Reader)
}

func randomNatsNonce(reader io.Reader) string {
	if isNilBoundary(reader) {
		return ""
	}
	value := make([]byte, natsNonceBytes)
	if _, err := io.ReadFull(reader, value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}

// NatsOperationJournalMutationAuthoritySigner issues mutation proofs.
type NatsOperationJournalMutationAuthoritySigner struct {
	CallerIdentity string
	key            *ecdsa.PrivateKey
}

// NewNatsOperationJournalMutationAuthoritySigner creates an authority signer.
func NewNatsOperationJournalMutationAuthoritySigner(
	callerIdentity string,
	key *ecdsa.PrivateKey,
) *NatsOperationJournalMutationAuthoritySigner {
	return &NatsOperationJournalMutationAuthoritySigner{CallerIdentity: callerIdentity, key: key}
}

// Issue signs a short-lived proof for one mutation.
func (s *NatsOperationJournalMutationAuthoritySigner) Issue(
	cell string,
	action string,
	keyName string,
	revision uint64,
	value string,
) NatsOperationJournalMutationAuthorityProof {
	return s.issue(cell, action, keyName, revision, value, time.Now().UTC(), rand.Reader)
}

func (s *NatsOperationJournalMutationAuthoritySigner) issue(
	cell string,
	action string,
	keyName string,
	revision uint64,
	value string,
	now time.Time,
	reader io.Reader,
) NatsOperationJournalMutationAuthorityProof {
	digest := sha256.Sum256([]byte(value))
	callerIdentity := ""
	if s != nil {
		callerIdentity = s.CallerIdentity
	}
	proof := NatsOperationJournalMutationAuthorityProof{
		Cell:             cell,
		CallerIdentity:   callerIdentity,
		Action:           action,
		Key:              keyName,
		Revision:         revision,
		CiphertextDigest: hex.EncodeToString(digest[:]),
		Lease:            randomNatsNonce(reader),
		ExpiresAt:        now.UTC().Add(2 * time.Minute),
		Nonce:            randomNatsNonce(reader),
		Signature:        "",
	}

	if s == nil || s.key == nil || isNilBoundary(reader) || proof.Lease == "" || proof.Nonce == "" {
		return proof
	}
	signature, err := ecdsa.SignASN1(reader, s.key, sha256Sum([]byte(proof.Payload())))
	if err == nil {
		proof.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return proof
}

// NatsOperationJournalMutationAuthorityVerifier verifies mutation proofs.
type NatsOperationJournalMutationAuthorityVerifier struct {
	publicKey []byte
}

// NewNatsOperationJournalMutationAuthorityVerifier creates an authority verifier.
func NewNatsOperationJournalMutationAuthorityVerifier(
	publicKey []byte,
) *NatsOperationJournalMutationAuthorityVerifier {
	copied := append([]byte(nil), publicKey...)
	return &NatsOperationJournalMutationAuthorityVerifier{publicKey: copied}
}

// Verify checks a proof against the exact requested mutation.
func (v *NatsOperationJournalMutationAuthorityVerifier) Verify(
	proof *NatsOperationJournalMutationAuthorityProof,
	cell string,
	callers map[string]struct{},
	action string,
	keyName string,
	revision uint64,
	value string,
) bool {
	if v == nil || proof == nil {
		return false
	}

	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(value))
	_, callerKnown := callers[proof.CallerIdentity]
	if proof.Cell != cell || !callerKnown || proof.Action != action ||
		proof.Key != keyName || proof.Revision != revision ||
		proof.CiphertextDigest != hex.EncodeToString(digest[:]) ||
		strings.TrimSpace(proof.Lease) == "" || strings.TrimSpace(proof.Nonce) == "" ||
		!proof.ExpiresAt.After(now) || proof.ExpiresAt.After(now.Add(5*time.Minute)) {
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

	signature, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(key, sha256Sum([]byte(proof.Payload())), signature)
}

func isP256(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256()
}

// NatsOperationJournalMutationRequestDigest exposes the request-digest contract.
var NatsOperationJournalMutationRequestDigest natsOperationJournalMutationRequestDigest

type natsOperationJournalMutationRequestDigest struct{}

// NatsOperationJournalMutationRequestDigestCreate hashes a signed authority proof.
func NatsOperationJournalMutationRequestDigestCreate(
	proof NatsOperationJournalMutationAuthorityProof,
) string {
	material := proof.Payload() + "|" + proof.Signature
	return hex.EncodeToString(sha256Sum([]byte(material)))
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// NatsOperationJournalMutationProofConsumptionResult classifies a proof-ledger write.
type NatsOperationJournalMutationProofConsumptionResult int

const (
	NatsOperationJournalMutationProofConsumptionResultConsumed NatsOperationJournalMutationProofConsumptionResult = iota + 1
	NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed
	NatsOperationJournalMutationProofConsumptionResultUnavailable
)

// NatsOperationJournalMutationProofConsumption exposes the R3 create-only proof
// ledger. Entries expire within the maximum accepted proof lifetime.
var NatsOperationJournalMutationProofConsumption natsOperationJournalMutationProofConsumption

type natsOperationJournalMutationProofConsumption struct{}

// NatsOperationJournalMutationProofConsumptionTryConsumeAsync consumes a proof once.
func NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (bool, error) {
	result, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(ctx, store, proof)
	if err != nil {
		return false, err
	}

	return result == NatsOperationJournalMutationProofConsumptionResultConsumed, nil
}

// NatsOperationJournalMutationProofConsumptionConsumeAsync classifies a proof consumption attempt.
func NatsOperationJournalMutationProofConsumptionConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (NatsOperationJournalMutationProofConsumptionResult, error) {
	if isNilBoundary(ctx) {
		return NatsOperationJournalMutationProofConsumptionResultUnavailable, &errs.Argument{
			Param: "ctx", Message: "(Parameter 'ctx')",
		}
	}
	if isNilBoundary(store) {
		return NatsOperationJournalMutationProofConsumptionResultUnavailable, &errs.Argument{
			Param: "store", Message: "(Parameter 'store')",
		}
	}

	key, err := NatsOperationJournalMutationProofConsumptionKey(proof)
	if err != nil {
		return NatsOperationJournalMutationProofConsumptionResultUnavailable, err
	}

	_, err = store.Create(ctx, key, []byte("consumed"))
	if err == nil {
		return NatsOperationJournalMutationProofConsumptionResultConsumed, nil
	}

	if errorsIsKeyCollision(err) {
		return NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed, nil
	}

	// A failed proof-ledger write must fail closed before the operation KV is
	// touched; callers receive no mutation authorization from this outcome.
	return NatsOperationJournalMutationProofConsumptionResultUnavailable, nil
}

func errorsIsKeyCollision(err error) bool {
	return errors.Is(err, jetstream.ErrKeyExists) ||
		errors.Is(err, jetstream.ErrKeyRevisionMismatch)
}

// NatsOperationJournalMutationProofConsumptionKey derives the proof-ledger key.
func NatsOperationJournalMutationProofConsumptionKey(
	proof NatsOperationJournalMutationAuthorityProof,
) (string, error) {
	values := []string{proof.Cell, proof.CallerIdentity, proof.Lease, proof.Nonce}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || !utf8.ValidString(value) ||
			uint64(len(value)) > uint64(^uint32(0)) {
			return "", &errs.Argument{
				Param:   "proof",
				Message: "The proof consumption identity is invalid. (Parameter 'proof')",
			}
		}
	}

	hash := sha256.New()
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}

	return "proof." + hex.EncodeToString(hash.Sum(nil)), nil
}
