package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

type rejectingWireVerifier struct{ calls int }

func (v *rejectingWireVerifier) Verify(context.Context, []byte) (VerifiedEnvelope, error) {
	v.calls++
	return VerifiedEnvelope{}, errors.New("invalid signature")
}

func TestOperationCannotImpersonateVerifiedWireCache(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	wire := []byte("untrusted signed wire")
	sum := sha256.Sum256(wire)
	cacheKey := entityid.Derive("delivery-verified", hex.EncodeToString(sum[:]))
	intent := testIntent(t, s, ctx)
	intent.OperationID = cacheKey
	data, err := json.Marshal(operation{Intent: intent, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	key := operationKey(intent.OperationID)
	if !entityid.Valid(key) || key == cacheKey {
		t.Fatal("operation key aliases the verification cache")
	}
	if _, err := s.operations.Create(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	verifier := &rejectingWireVerifier{}
	s.config.Verifier = verifier
	if _, _, err := s.verifiedIntent(ctx, wire); !errors.Is(err, ErrInvalid) || verifier.calls != 1 {
		t.Fatalf("verification error=%v calls=%d", err, verifier.calls)
	}
}
