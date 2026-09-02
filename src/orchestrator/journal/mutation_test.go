package journal

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func operationMutationKey() string {
	return operationJournalKeyPrefix + strings.Repeat("a", operationJournalDigestHexBytes)
}

func TestMutationKeyAndValueContractIsClosed(t *testing.T) {
	key := operationMutationKey()
	if len(key) != 74 || !IsValidMutation(key, strings.Repeat("v", operationJournalMaximumValueBytes)) {
		t.Fatal("exact operation key and maximum valid UTF-8 value were rejected")
	}
	if !IsValidMutation(operationJournalKeyPrefix+strings.Repeat("A", operationJournalDigestHexBytes), "") {
		t.Fatal("uppercase hexadecimal operation digest was rejected")
	}

	invalidKeys := []string{
		key[:len(key)-1],
		key + "a",
		"operations" + key[len(operationJournalKeyPrefix):],
		operationJournalKeyPrefix + strings.Repeat("g", operationJournalDigestHexBytes),
		operationJournalKeyPrefix + strings.Repeat("a", operationJournalDigestHexBytes-2) + "é",
	}
	for index, invalid := range invalidKeys {
		if IsValidMutation(invalid, "value") {
			t.Fatalf("invalid key case %d was accepted", index)
		}
	}
	if IsValidMutation(key, strings.Repeat("v", operationJournalMaximumValueBytes+1)) {
		t.Fatal("oversized value was accepted")
	}
	if IsValidMutation(key, string([]byte{0xff})) {
		t.Fatal("invalid UTF-8 value was accepted")
	}
}

func TestMutationContractsHaveStablePayloadsAndDigestBinding(t *testing.T) {
	proof := NatsOperationJournalMutationAuthorityProof{
		Cell: "gru", CallerIdentity: "controller-a", Action: "update",
		Key: operationMutationKey(), Revision: 7, CiphertextDigest: "digest",
		Lease: "lease", ExpiresAt: time.Unix(1_800_000_000, 999).UTC(),
		Nonce: "nonce", Signature: "signature",
	}
	wantProof := "gru|controller-a|update|" + operationMutationKey() +
		"|7|digest|lease|1800000000|nonce"
	if proof.Payload() != wantProof {
		t.Fatalf("proof payload = %q, want %q", proof.Payload(), wantProof)
	}

	reply := NatsOperationJournalMutationReply{
		SchemaVersion: 2, Succeeded: true, Revision: 8, RequestDigest: "request",
	}
	if reply.Payload() != "2|true|8|request" {
		t.Fatalf("reply payload = %q", reply.Payload())
	}

	first := NatsOperationJournalMutationRequestDigestCreate(proof)
	proof.Signature = "different"
	second := NatsOperationJournalMutationRequestDigestCreate(proof)
	if len(first) != sha256.Size*2 || first == second {
		t.Fatal("request digest did not bind the authority signature")
	}
}

func TestAuthorityProofVerificationIsExactAndP256Only(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewNatsOperationJournalMutationAuthoritySigner("controller-a", key)
	proof := signer.Issue("gru", "update", operationMutationKey(), 7, "value")
	verifier := NewNatsOperationJournalMutationAuthorityVerifier(publicKey)
	callers := map[string]struct{}{"controller-a": {}}
	if !verifier.Verify(&proof, "gru", callers, "update", operationMutationKey(), 7, "value") {
		t.Fatal("valid P-256 authority proof was rejected")
	}

	tests := []struct {
		name     string
		proof    NatsOperationJournalMutationAuthorityProof
		cell     string
		callers  map[string]struct{}
		action   string
		key      string
		revision uint64
		value    string
	}{
		{name: "tampered-signature", proof: mutateProof(proof, func(p *NatsOperationJournalMutationAuthorityProof) {
			p.Signature = base64.StdEncoding.EncodeToString([]byte("tampered"))
		}), cell: "gru", callers: callers, action: "update", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "expired", proof: resignProof(t, key, mutateProof(proof, func(p *NatsOperationJournalMutationAuthorityProof) {
			p.ExpiresAt = time.Now().UTC().Add(-time.Second)
		})), cell: "gru", callers: callers, action: "update", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "too-far-future", proof: resignProof(t, key, mutateProof(proof, func(p *NatsOperationJournalMutationAuthorityProof) {
			p.ExpiresAt = time.Now().UTC().Add(5*time.Minute + time.Second)
		})), cell: "gru", callers: callers, action: "update", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "unknown-caller", proof: proof, cell: "gru", callers: map[string]struct{}{"other": {}}, action: "update", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "wrong-cell", proof: proof, cell: "sfo", callers: callers, action: "update", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "wrong-action", proof: proof, cell: "gru", callers: callers, action: "create", key: operationMutationKey(), revision: 7, value: "value"},
		{name: "wrong-key", proof: proof, cell: "gru", callers: callers, action: "update", key: operationJournalKeyPrefix + strings.Repeat("b", operationJournalDigestHexBytes), revision: 7, value: "value"},
		{name: "wrong-revision", proof: proof, cell: "gru", callers: callers, action: "update", key: operationMutationKey(), revision: 8, value: "value"},
		{name: "wrong-value", proof: proof, cell: "gru", callers: callers, action: "update", key: operationMutationKey(), revision: 7, value: "other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if verifier.Verify(&test.proof, test.cell, test.callers, test.action, test.key, test.revision, test.value) {
				t.Fatal("invalid authority proof was accepted")
			}
		})
	}

	wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyBytes, err := x509.MarshalPKIXPublicKey(wrongPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if NewNatsOperationJournalMutationAuthorityVerifier(wrongKeyBytes).Verify(
		&proof, "gru", callers, "update", operationMutationKey(), 7, "value") {
		t.Fatal("non-ECDSA authority key was accepted")
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Bytes, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384Proof := NewNatsOperationJournalMutationAuthoritySigner("controller-a", p384).
		Issue("gru", "update", operationMutationKey(), 7, "value")
	if NewNatsOperationJournalMutationAuthorityVerifier(p384Bytes).Verify(
		&p384Proof, "gru", callers, "update", operationMutationKey(), 7, "value") {
		t.Fatal("non-P-256 ECDSA authority key was accepted")
	}
}

func mutateProof(
	proof NatsOperationJournalMutationAuthorityProof,
	mutate func(*NatsOperationJournalMutationAuthorityProof),
) NatsOperationJournalMutationAuthorityProof {
	mutate(&proof)
	return proof
}

func resignProof(
	t *testing.T,
	key *ecdsa.PrivateKey,
	proof NatsOperationJournalMutationAuthorityProof,
) NatsOperationJournalMutationAuthorityProof {
	t.Helper()
	signature, err := ecdsa.SignASN1(rand.Reader, key, sha256Sum([]byte(proof.Payload())))
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature = base64.StdEncoding.EncodeToString(signature)
	return proof
}

type entropyFailureReader struct{}

func (entropyFailureReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRandomNatsNonceFailsClosedWithInjectedReader(t *testing.T) {
	if nonce := randomNatsNonce(strings.NewReader(strings.Repeat("a", natsNonceBytes))); nonce != strings.Repeat("61", natsNonceBytes) {
		t.Fatalf("deterministic nonce = %q", nonce)
	}
	if nonce := randomNatsNonce(entropyFailureReader{}); nonce != "" {
		t.Fatalf("entropy failure returned %q, want empty fail-closed token", nonce)
	}
	if nonce := randomNatsNonce(strings.NewReader("short")); nonce != "" {
		t.Fatalf("short entropy read returned %q, want empty fail-closed token", nonce)
	}
	var typedNil *entropyFailureReader
	if nonce := randomNatsNonce(typedNil); nonce != "" {
		t.Fatalf("typed-nil entropy reader returned %q", nonce)
	}
}

func TestAuthoritySignerFailsClosedWhenEntropyOrKeyIsUnavailable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	signer := NewNatsOperationJournalMutationAuthoritySigner("controller-a", key)
	verifier := NewNatsOperationJournalMutationAuthorityVerifier(publicKey)
	callers := map[string]struct{}{"controller-a": {}}
	proof := signer.issue(
		"gru", "create", operationMutationKey(), 0, "value", now, entropyFailureReader{})
	if proof.Lease != "" || proof.Nonce != "" || proof.Signature != "" {
		t.Fatalf("entropy failure produced lease %q, nonce %q, signature %q",
			proof.Lease, proof.Nonce, proof.Signature)
	}
	if !proof.ExpiresAt.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("expiry = %v, want %v", proof.ExpiresAt, now.Add(2*time.Minute))
	}
	if verifier.Verify(
		&proof,
		"gru",
		callers,
		"create",
		operationMutationKey(),
		0,
		"value",
	) {
		t.Fatal("entropy-failed proof verified")
	}

	// Go 1.26 and later use global randomness unless this compatibility mode is
	// enabled, so opt in to exercise the Issue reader's signing-failure path.
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	signingFailureProof := signer.issue(
		"gru",
		"create",
		operationMutationKey(),
		0,
		"value",
		now,
		io.MultiReader(
			strings.NewReader(strings.Repeat("a", 2*natsNonceBytes)),
			entropyFailureReader{},
		),
	)
	if signingFailureProof.Lease == "" || signingFailureProof.Nonce == "" {
		t.Fatal("signing-failure proof did not retain valid lease and nonce")
	}
	if signingFailureProof.Signature != "" {
		t.Fatalf("signing failure produced signature %q", signingFailureProof.Signature)
	}
	if verifier.Verify(
		&signingFailureProof,
		"gru",
		callers,
		"create",
		operationMutationKey(),
		0,
		"value",
	) {
		t.Fatal("unsigned proof verified after signing entropy failure")
	}

	tests := []struct {
		name   string
		signer *NatsOperationJournalMutationAuthoritySigner
	}{
		{name: "nil-signer"},
		{name: "nil-key", signer: NewNatsOperationJournalMutationAuthoritySigner("controller-a", nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := test.signer.issue(
				"gru",
				"create",
				operationMutationKey(),
				0,
				"value",
				now,
				strings.NewReader(strings.Repeat("a", 2*natsNonceBytes)),
			)
			if proof.Signature != "" {
				t.Fatalf("unavailable signing key produced signature %q", proof.Signature)
			}
		})
	}
}

func proofConsumptionIdentity(cell, caller string) NatsOperationJournalMutationAuthorityProof {
	return NatsOperationJournalMutationAuthorityProof{
		Cell: cell, CallerIdentity: caller, Lease: "lease", Nonce: "nonce",
	}
}

func TestProofConsumptionKeyUsesLengthPrefixedIdentity(t *testing.T) {
	first, err := NatsOperationJournalMutationProofConsumptionKey(
		proofConsumptionIdentity("a", "bc"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NatsOperationJournalMutationProofConsumptionKey(
		proofConsumptionIdentity("ab", "c"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("length-ambiguous proof identities produced the same key")
	}
	if !strings.HasPrefix(first, "proof.") || len(first) != len("proof.")+sha256.Size*2 {
		t.Fatalf("proof key = %q", first)
	}
}

func TestProofConsumptionBoundariesReturnTypedArguments(t *testing.T) {
	proof := proofConsumptionIdentity("gru", "controller-a")
	var typedNilContext *nilBoundaryContext
	var typedNilStore *mutationKeyValue

	tests := []struct {
		name  string
		param string
		call  func() error
	}{
		{"nil-context", "ctx", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(nil, &mutationKeyValue{}, proof)
			return err
		}},
		{"typed-nil-context", "ctx", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
				typedNilContext, &mutationKeyValue{}, proof)
			return err
		}},
		{"nil-store", "store", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
				context.Background(), nil, proof)
			return err
		}},
		{"typed-nil-store", "store", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
				context.Background(), typedNilStore, proof)
			return err
		}},
		{"invalid-proof", "proof", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
				context.Background(), &mutationKeyValue{}, NatsOperationJournalMutationAuthorityProof{})
			return err
		}},
		{"invalid-proof-key", "proof", func() error {
			_, err := NatsOperationJournalMutationProofConsumptionKey(
				proofConsumptionIdentity("gru", string([]byte{0xff})))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertArgument(t, test.call(), test.param) })
	}
}

type mutationKeyValue struct {
	jetstream.KeyValue
	createErr error
	key       string
	value     []byte
}

func (s *mutationKeyValue) Create(_ context.Context, key string, value []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
	s.key = key
	s.value = append([]byte(nil), value...)
	return 1, s.createErr
}

func TestProofConsumptionClassifiesStoreOutcomes(t *testing.T) {
	proof := proofConsumptionIdentity("gru", "controller-a")
	tests := []struct {
		name   string
		err    error
		result NatsOperationJournalMutationProofConsumptionResult
	}{
		{"consumed", nil, NatsOperationJournalMutationProofConsumptionResultConsumed},
		{"key-exists", jetstream.ErrKeyExists, NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed},
		{"revision-mismatch", jetstream.ErrKeyRevisionMismatch, NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed},
		{"unavailable", errors.New("unavailable"), NatsOperationJournalMutationProofConsumptionResultUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &mutationKeyValue{createErr: test.err}
			result, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
				context.Background(), store, proof)
			if err != nil {
				t.Fatal(err)
			}
			if result != test.result {
				t.Fatalf("result = %v, want %v", result, test.result)
			}
			if store.key == "" || string(store.value) != "consumed" {
				t.Fatal("proof ledger did not receive the closed consumed record")
			}
		})
	}

	consumed, err := NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
		context.Background(), &mutationKeyValue{}, proof)
	if err != nil || !consumed {
		t.Fatalf("try-consume = %v, %v", consumed, err)
	}
}
