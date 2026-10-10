package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
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

// The root-delegated release key releases only the roles and repositories its
// delegation names, in its environment, and no cell signer may take its actor.
func TestDelegatedReleaseKeyReleasesOnlyItsDelegation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	ops, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(ops),
		Roles: []string{"ts-auth"}, Environments: []string{"canary"}}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	repository := "https://git.terrascale.tech/TerraScale/terrabase"
	record := delivery.ArtifactRecord{Cell: "gru", Role: "terrabase", Environment: "canary",
		Source: delivery.ArtifactSource{Repository: repository}}
	actor, err := release.DelegatedReleaseActor(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.authorizeArtifact(t.Context(), actor, record); err == nil {
		t.Fatal("a claim was released before any release delegation was loaded")
	}
	delegation := release.BinaryUpdateDelegation{Environment: "canary",
		Services: []release.ServiceGrant{{Role: "terrabase", Repository: repository}}}
	if err := policy.setReleaseDelegation(delegation, public, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if trusted, ok := policy.codec.Lookup(keyID); !ok || trusted.Actor != actor {
		t.Fatalf("delegated key lookup = %+v, %v", trusted, ok)
	}
	if err := policy.authorizeArtifact(t.Context(), actor, record); err != nil {
		t.Fatalf("delegated release refused: %v", err)
	}
	for name, refused := range map[string]delivery.ArtifactRecord{
		"role outside the delegation": {Cell: "gru", Role: "ts-auth", Environment: "canary", Source: record.Source},
		"repository outside it":       {Cell: "gru", Role: "terrabase", Environment: "canary", Source: delivery.ArtifactSource{Repository: repository + "-fork"}},
		"environment outside it":      {Cell: "gru", Role: "terrabase", Environment: "production", Source: record.Source},
	} {
		if err := policy.authorizeArtifact(t.Context(), actor, refused); !errors.Is(err, delivery.ErrUnauthorized) {
			t.Errorf("%s released: %v", name, err)
		}
	}
	// Another delegated key's actor gets nothing from this delegation.
	if err := policy.authorizeArtifact(t.Context(), release.DelegatedReleaseActorPrefix+"0000000000000000", record); err == nil {
		t.Fatal("a claim was authorized by another key's delegation")
	}
	cellSigner := TrustedSignerConfig{Actor: actor, PublicKey: grant.PublicKey,
		Roles: []string{"terrabase"}, Environments: []string{"canary"}}
	if err := ValidateTrustedSignerGrant(cellSigner); err == nil {
		t.Fatal("a cell signer took the delegated release actor")
	}
	// An expired delegation authorizes nothing, though nothing replaced it.
	if err := policy.setReleaseDelegation(delegation, public, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := policy.codec.Lookup(keyID); ok {
		t.Fatal("an expired delegation's key is still trusted")
	}
	if err := policy.authorizeArtifact(t.Context(), actor, record); err == nil {
		t.Fatal("an expired delegation released a claim")
	}
}
