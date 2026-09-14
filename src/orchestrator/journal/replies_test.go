package journal

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestReplyPayloadsAreCanonical(t *testing.T) {
	operation := NatsOperationJournalMutationReply{
		SchemaVersion: protocol.ProtocolVersion.Current(), Succeeded: true,
		Revision: 9, RequestDigest: "request",
	}
	if got, want := operation.Payload(), "2|true|9|request"; got != want {
		t.Fatalf("operation payload = %q, want %q", got, want)
	}

	checkpoint := "checkpoint"
	runtime := NatsRuntimeLifecycleJournalReply{
		SchemaVersion: RuntimeLifecycleNatsProtocolSchemaVersion, Status: 3,
		Revision: 4, Checkpoint: &checkpoint, RequestDigest: "request",
	}
	if got, want := runtime.Payload(), "2|3|4|checkpoint|request"; got != want {
		t.Fatalf("runtime payload = %q, want %q", got, want)
	}
	runtime.Checkpoint = nil
	if got, want := runtime.Payload(), "2|3|4||request"; got != want {
		t.Fatalf("nil-checkpoint payload = %q, want %q", got, want)
	}
}

func TestReplySignerAndVerifierBindOperationReply(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	signer := NewNatsOperationJournalMutationReplySigner(key)
	verifier := NewNatsOperationJournalMutationReplyVerifier(publicKey)
	reply := signer.Sign(true, 7, "request")
	if reply.Signature == "" || !verifier.Verify(&reply, "request") {
		t.Fatal("valid operation reply was rejected")
	}
	if exported, err := signer.ExportPublicKey(); err != nil || len(exported) == 0 {
		t.Fatalf("exported public key = %d bytes, err %v", len(exported), err)
	}

	tests := []struct {
		name   string
		mutate func(*NatsOperationJournalMutationReply)
	}{
		{name: "schema", mutate: func(value *NatsOperationJournalMutationReply) {
			value.SchemaVersion++
		}},
		{name: "revision", mutate: func(value *NatsOperationJournalMutationReply) {
			value.Revision++
		}},
		{name: "digest", mutate: func(value *NatsOperationJournalMutationReply) {
			value.RequestDigest = "other"
		}},
		{name: "signature", mutate: func(value *NatsOperationJournalMutationReply) {
			value.Signature = "tampered"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := reply
			test.mutate(&mutated)
			if verifier.Verify(&mutated, "request") {
				t.Fatal("tampered operation reply was accepted")
			}
		})
	}
}

func TestReplySignerAndVerifierBindRuntimeReply(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	checkpoint := "checkpoint"
	signer := NewNatsOperationJournalMutationReplySigner(key)
	verifier := NewNatsOperationJournalMutationReplyVerifier(publicKey)
	reply := signer.SignRuntime(1, 4, &checkpoint, "request")
	if reply.Signature == "" || !verifier.VerifyRuntime(&reply, "request") {
		t.Fatal("valid runtime reply was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*NatsRuntimeLifecycleJournalReply)
	}{
		{name: "schema", mutate: func(value *NatsRuntimeLifecycleJournalReply) {
			value.SchemaVersion++
		}},
		{name: "status", mutate: func(value *NatsRuntimeLifecycleJournalReply) {
			value.Status++
		}},
		{name: "checkpoint", mutate: func(value *NatsRuntimeLifecycleJournalReply) {
			changed := "other"
			value.Checkpoint = &changed
		}},
		{name: "digest", mutate: func(value *NatsRuntimeLifecycleJournalReply) {
			value.RequestDigest = "other"
		}},
		{name: "signature", mutate: func(value *NatsRuntimeLifecycleJournalReply) {
			value.Signature = "tampered"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := reply
			test.mutate(&mutated)
			if verifier.VerifyRuntime(&mutated, "request") {
				t.Fatal("tampered runtime reply was accepted")
			}
		})
	}
}

func TestReplySignerCopiesPrivateKeyMaterial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewNatsOperationJournalMutationReplySigner(key)
	publicKey, err := signer.ExportPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewNatsOperationJournalMutationReplyVerifier(publicKey)

	key.PublicKey.Curve = elliptic.P384()
	key.PublicKey.X = nil
	key.PublicKey.Y = nil
	key.D = nil

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("signing panicked after caller key mutation: %v", recovered)
		}
	}()
	reply := signer.Sign(true, 8, "request")
	if reply.Signature == "" || !verifier.Verify(&reply, "request") {
		t.Fatal("signer did not retain an independent usable key")
	}
}

func TestReplyVerifierRejectsWrongKeysAndUnavailableInputs(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reply := NewNatsOperationJournalMutationReplySigner(p256).Sign(true, 1, "request")

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Bytes, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if NewNatsOperationJournalMutationReplyVerifier(p384Bytes).Verify(&reply, "request") {
		t.Fatal("P-384 reply verifier accepted a P-256 reply")
	}
	if signer := NewNatsOperationJournalMutationReplySigner(p384); signer != nil {
		t.Fatal("P-384 reply signer was admitted")
	}
	malformed := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
	if signer := NewNatsOperationJournalMutationReplySigner(malformed); signer != nil {
		t.Fatal("malformed P-256 reply signer was admitted")
	}

	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Bytes, err := x509.MarshalPKIXPublicKey(ed25519Private.Public())
	if err != nil {
		t.Fatal(err)
	}
	if NewNatsOperationJournalMutationReplyVerifier(ed25519Bytes).Verify(&reply, "request") {
		t.Fatal("Ed25519 reply verifier accepted an ECDSA reply")
	}
	if NewNatsOperationJournalMutationReplyVerifier(nil).Verify(&reply, "request") {
		t.Fatal("invalid reply public key was accepted")
	}

	var nilSigner *NatsOperationJournalMutationReplySigner
	if unsigned := nilSigner.Sign(true, 1, "request"); unsigned.Signature != "" {
		t.Fatal("nil signer produced a signature")
	}
	if _, err := nilSigner.ExportPublicKey(); err == nil {
		t.Fatal("nil signer exported a public key")
	}
	if unsigned := NewNatsOperationJournalMutationReplySigner(nil).Sign(true, 1, "request"); unsigned.Signature != "" {
		t.Fatal("unavailable signer produced a signature")
	}

	var nilVerifier *NatsOperationJournalMutationReplyVerifier
	if nilVerifier.Verify(&reply, "request") {
		t.Fatal("nil verifier accepted a reply")
	}
}
