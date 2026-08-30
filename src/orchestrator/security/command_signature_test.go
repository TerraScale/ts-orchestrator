package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestCommandSignatureVerifierUsesCanonicalMaterialAndPinsKey(t *testing.T) {
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, err := NewCommandSignatureSignerFromKey(first)
	if err != nil {
		t.Fatal(err)
	}
	secondSigner, err := NewCommandSignatureSignerFromKey(second)
	if err != nil {
		t.Fatal(err)
	}
	firstSPKI, _ := x509.MarshalPKIXPublicKey(&first.PublicKey)
	secondSPKI, _ := x509.MarshalPKIXPublicKey(&second.PublicKey)
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{
		{KeyID: firstSigner.PublicKeyID(), Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: firstSPKI},
	})
	if err != nil {
		t.Fatal(err)
	}
	material := commandTestMaterial("aggregate-a")
	signature, err := firstSigner.Sign(material)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Verify(material, signature) != protocol.VerificationOutcomeValid {
		t.Fatal("valid signature was rejected")
	}
	if verifier.Verify(commandTestMaterial("aggregate-b"), signature) != protocol.VerificationOutcomeInvalid {
		t.Fatal("changed signed material was accepted")
	}
	otherSignature, err := secondSigner.Sign(material)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Verify(material, otherSignature) != protocol.VerificationOutcomeInvalid {
		t.Fatal("wrong key was accepted")
	}
	if len(secondSPKI) == 0 || !strings.HasPrefix(firstSigner.Identity(), CommandSignatureAlgorithm+"-") {
		t.Fatal("identity seam is malformed")
	}
}

func TestCommandSignatureVerifierRejectsAlgorithmAndHostileEnvelopes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: "hmac-sha256", PublicKeySPKI: spki,
	}}); err == nil {
		t.Fatal("unsupported algorithm was accepted")
	}
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: spki,
	}})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(commandTestMaterial("hostile"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := signature.Bytes()
	encoded[5] = 2
	bad, _ := protocol.OpaqueSignatureTryCopyFrom(encoded)
	if verifier.Verify(commandTestMaterial("hostile"), bad) != protocol.VerificationOutcomeInvalid {
		t.Fatal("unknown algorithm envelope was accepted")
	}
	encoded = signature.Bytes()
	encoded[38], encoded[39] = 0xff, 0xff
	bad, _ = protocol.OpaqueSignatureTryCopyFrom(encoded)
	if verifier.Verify(commandTestMaterial("hostile"), bad) != protocol.VerificationOutcomeInvalid {
		t.Fatal("oversized signature length was accepted")
	}
	if strings.Contains(verifier.String(), signer.PublicKeyID()) || strings.Contains(signature.String(), "hostile") {
		t.Fatal("diagnostics exposed key or signed material")
	}
}

func TestCommandSignatureVerifierChecksTrustKeyWindowAtBoundary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	start := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: spki,
		NotBefore: start, NotAfter: end,
	}})
	if err != nil {
		t.Fatal(err)
	}
	material := commandTestMaterialAt("window", start)
	signature, err := signer.Sign(material)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.VerifyAt(material, signature, start.Add(-time.Nanosecond)) != protocol.VerificationOutcomeInvalid {
		t.Fatal("not-before boundary was ignored")
	}
	if verifier.VerifyAt(material, signature, end) != protocol.VerificationOutcomeInvalid {
		t.Fatal("not-after boundary was ignored")
	}
	if verifier.VerifyAt(material, signature, start.Add(time.Minute)) != protocol.VerificationOutcomeValid {
		t.Fatal("valid trust-key window was rejected")
	}
}

func commandTestMaterial(aggregate string) protocol.CommandSignedMaterial {
	return commandTestMaterialAt(aggregate, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC))
}

func commandTestMaterialAt(aggregate string, issued time.Time) protocol.CommandSignedMaterial {
	protocolVersion, _ := protocol.ProtocolRevisionTryCreate(1)
	cell, _ := contracts.CellIdTryCreate("global")
	aggregateID, _ := contracts.AggregateIdTryCreate(aggregate)
	generation, _ := protocol.DesiredGenerationTryCreate(7)
	epoch, _ := protocol.WriterEpochTryCreate(5)
	operation, _ := contracts.OperationIdTryCreate("dispatch/job")
	idempotency, _ := contracts.IdempotencyKeyTryCreate("command-test")
	attempt, _ := protocol.DeliveryAttemptTryCreate(1)
	payload := protocol.OpaquePayloadCopyFrom([]byte("payload"))
	digestBytes := sha256.Sum256(payload.Bytes())
	digest, _ := protocol.PayloadDigestTryCopyFrom(digestBytes[:])
	return protocol.CommandSignedMaterial{
		ProtocolVersion: protocolVersion, Cell: cell, AggregateId: aggregateID,
		DesiredGeneration: generation, WriterEpoch: epoch, OperationId: operation,
		IdempotencyKey: idempotency, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour),
		Attempt: attempt, Payload: payload, PayloadDigest: digest,
	}
}
