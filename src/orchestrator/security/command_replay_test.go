package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestCommandSecurityBoundaryRejectsExpiryAndCancellationBeforeReplay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: spki,
	}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	replay, err := NewMemoryCommandReplayStoreWithClock(4, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := NewCommandSecurityBoundary(verifier, replay, 0)
	if err != nil {
		t.Fatal(err)
	}
	expired := commandTestMaterialAt("expired", clock.Add(-2*time.Hour))
	expiredSignature, err := signer.Sign(expired)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := boundary.VerifyAndConsume(expired, expiredSignature, clock)
	if err != nil || outcome != CommandSecurityExpired {
		t.Fatalf("unexpected expired result: %v, %v", outcome, err)
	}
	if replay.Len() != 0 {
		t.Fatal("expired command consumed replay state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	valid := commandTestMaterialAt("canceled", clock)
	validSignature, err := signer.Sign(valid)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = boundary.VerifyAndConsumeContext(ctx, valid, validSignature, clock)
	if err == nil || outcome != CommandSecurityInvalidMaterial {
		t.Fatalf("canceled admission was not stopped: %v, %v", outcome, err)
	}
	if replay.Len() != 0 {
		t.Fatal("canceled command consumed replay state")
	}
}

func TestCommandSecurityBoundaryAtomicallySuppressesConcurrentReplay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{
		KeyID: signer.PublicKeyID(), Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: spki,
	}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	replay, err := NewMemoryCommandReplayStoreWithClock(128, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := NewCommandSecurityBoundary(verifier, replay, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	material := commandTestMaterial("concurrent")
	signature, err := signer.Sign(material)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 32
	results := make(chan CommandSecurityOutcome, attempts)
	var group sync.WaitGroup
	group.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer group.Done()
			outcome, verifyErr := boundary.VerifyAndConsume(material, signature, clock)
			if verifyErr != nil {
				results <- CommandSecurityInvalidMaterial
				return
			}
			results <- outcome
		}()
	}
	group.Wait()
	close(results)
	accepted, replayed := 0, 0
	for outcome := range results {
		switch outcome {
		case CommandSecurityAccepted:
			accepted++
		case CommandSecurityReplayDetected:
			replayed++
		default:
			t.Fatalf("unexpected concurrent result: %v", outcome)
		}
	}
	if accepted != 1 || replayed != attempts-1 || replay.Len() != 1 {
		t.Fatalf("replay race was not atomic: accepted=%d replayed=%d len=%d", accepted, replayed, replay.Len())
	}
}

func TestMemoryCommandReplayStoreExpiresAndRefusesCapacityOverflow(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	replay, err := NewMemoryCommandReplayStoreWithClock(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first := CommandReplayKey{1}
	second := CommandReplayKey{2}
	if result, err := replay.TryConsume(first, now.Add(time.Minute)); err != nil || result != CommandReplayConsumeConsumed {
		t.Fatalf("first claim failed: %v, %v", result, err)
	}
	if result, err := replay.TryConsume(first, now.Add(time.Minute)); err != nil || result != CommandReplayConsumeAlreadyConsumed {
		t.Fatalf("duplicate claim failed: %v, %v", result, err)
	}
	if result, err := replay.TryConsume(second, now.Add(time.Minute)); err == nil || result != CommandReplayConsumeRejected {
		t.Fatalf("capacity overflow was accepted: %v, %v", result, err)
	}
	now = now.Add(2 * time.Minute)
	if result, err := replay.TryConsume(second, now.Add(time.Minute)); err != nil || result != CommandReplayConsumeConsumed {
		t.Fatalf("expired entry was not reclaimed: %v, %v", result, err)
	}
}

var _ protocol.ICommandSignatureVerifier = (*CommandSignatureVerifier)(nil)
