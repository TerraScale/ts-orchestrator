package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func rootKeys(keys ...ed25519.PrivateKey) []ed25519.PrivateKey { return keys }

func newRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

// signTestRotation signs the statement that replaces base's roots with next.
func signTestRotation(t *testing.T, id trust.ChainIdentity, base trust.VerifiedRoots, next []ed25519.PrivateKey,
	signers ...ed25519.PrivateKey,
) trust.SignedRotation {
	t.Helper()
	publics := make([]ed25519.PublicKey, 0, len(next))
	for _, key := range next {
		publics = append(publics, key.Public().(ed25519.PublicKey))
	}
	rotation, err := trust.NextRotation(base, publics...)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	now := time.Now().UTC().Truncate(time.Second)
	for _, key := range signers {
		envelope, err := trust.SignRotation(rotation, id, now.Add(-time.Minute), now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	return signed
}
