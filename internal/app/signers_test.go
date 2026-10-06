package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// A controller's signers can change while it runs: every check, the
// delivery codec's included, reads the current set, and an invalid set
// leaves the current one in force.
func TestSignerPolicyReplacesItsSignersLive(t *testing.T) {
	signer := func(actor string) (TrustedSignerConfig, string) {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := protocol.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		return TrustedSignerConfig{Actor: actor, PublicKey: base64.StdEncoding.EncodeToString(public),
			Roles: []string{"ts-auth"}, Environments: []string{"canary"}}, keyID
	}
	old, oldKey := signer("ops")
	next, nextKey := signer("ci")
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{old}}})
	if err != nil {
		t.Fatal(err)
	}
	copied := policy
	if _, ok := copied.trusted(oldKey); !ok || !policy.mayRelease("ops", "ts-auth", "canary", "") {
		t.Fatal("the signed signer is not trusted")
	}
	if err := policy.replaceSigners([]TrustedSignerConfig{next}); err != nil {
		t.Fatal(err)
	}
	// Copies share the set, as every handler holds a copy of the policy.
	if _, ok := copied.trusted(oldKey); ok {
		t.Fatal("a replaced signer is still trusted")
	}
	if _, ok := copied.grant("ops"); ok || copied.mayRelease("ops", "ts-auth", "canary", "") {
		t.Fatal("a replaced signer still has its grant")
	}
	if trusted, ok := copied.codec.Lookup(nextKey); !ok || trusted.Actor != "ci" {
		t.Fatalf("delivery codec lookup of the new signer = %+v, %v", trusted, ok)
	}
	duplicate := next
	if err := policy.replaceSigners([]TrustedSignerConfig{next, duplicate}); err == nil {
		t.Fatal("a set with a repeated actor replaced the signers")
	}
	if err := policy.replaceSigners(nil); err == nil {
		t.Fatal("an empty set replaced the signers")
	}
	if _, ok := policy.trusted(nextKey); !ok {
		t.Fatal("a refused set changed the signers")
	}
}
