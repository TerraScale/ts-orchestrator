package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// A cell spec's signers replace the signed config's on running controllers:
// only a root may change them, the controller's signer policy swaps them in
// as the spec is adopted, and a spec that stops trusting the key applying it
// is refused so the cell always keeps an operator.
func TestCellSpecSignersReplaceTheSignedSigners(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
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
			Roles: []string{"web"}, Environments: []string{"canary"}}, keyID
	}
	ops, opsKey := signer("ops")
	ci, ciKey := signer("ci")
	dir := t.TempDir()
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "canary"})
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{SpecTrust: keys.config(), TrustedSigners: []TrustedSignerConfig{ops}}}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	registry.replaceSigners = policy.replaceSigners
	if err := registry.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	fence := rolloutTestFence{epoch: 3}
	apply := func(path, keyID string) (specReply, error) {
		return registry.apply(t.Context(), mustRead(t, path), keyID, fence.epoch, fence, nil)
	}
	spec := func(generation uint64, signers ...TrustedSignerConfig) cellspec.Spec {
		return cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: generation, RequiresBinary: 8,
			Signers: signers}
	}

	both := spec(1, ci, ops)
	if _, err := apply(keys.sign(t, dir, both), opsKey); err == nil || !strings.Contains(err.Error(), "signer ci") {
		t.Fatalf("leaf-signed signers: %v", err)
	}
	if reply, err := apply(keys.signRoot(t, dir, both), opsKey); err != nil || reply.Status != "applied" {
		t.Fatalf("root-signed signers: %+v, %v", reply, err)
	}
	if _, ok := policy.trusted(ciKey); !ok {
		t.Fatal("an added signer is not trusted after the spec was adopted")
	}

	// Dropping the key that applies the spec is refused; the new signer may
	// drop the old one.
	ciOnly := spec(2, ci)
	if _, err := apply(keys.signRoot(t, dir, ciOnly), opsKey); err == nil || !strings.Contains(err.Error(), "no longer trust") {
		t.Fatalf("a spec dropping its applying key: %v", err)
	}
	if reply, err := apply(keys.signRoot(t, dir, ciOnly), ciKey); err != nil || reply.Status != "applied" {
		t.Fatalf("the new signer drops the old: %+v, %v", reply, err)
	}
	if _, ok := policy.trusted(opsKey); ok {
		t.Fatal("a removed signer is still trusted")
	}

	// A releaser must be a signer of the spec itself, and an invalid set is
	// refused before it is stored.
	releasing := spec(3, ci)
	releasing.Services = []cellspec.Service{{Role: "web", Releasers: []string{"ops"}}}
	if err := registry.validate(releasing); err == nil || !strings.Contains(err.Error(), "not a trusted signer") {
		t.Fatalf("releaser outside the spec's signers: %v", err)
	}
	invalid := ci
	invalid.PublicKey = "not-a-key"
	if err := registry.validate(spec(3, invalid)); err == nil {
		t.Fatal("a signer without a valid key was accepted")
	}

	// Dropping the section returns to the signed signers, which a root signs.
	signed := spec(3)
	signed.RequiresBinary = 1
	if _, err := apply(keys.sign(t, dir, signed), ciKey); err == nil || !strings.Contains(err.Error(), "a root must sign it") {
		t.Fatalf("leaf-signed return to the signed signers: %v", err)
	}
}

// Adoption swaps the signers before it publishes the spec, and a spec whose
// signers are refused is not adopted, so no consumer sees one generation's
// spec with another's signers.
func TestCellSpecAdoptionSwapsSignersFirst(t *testing.T) {
	registry, err := newSpecRegistry(Config{NATS: natscell.Config{Cell: "gru", Lab: true}}, "")
	if err != nil {
		t.Fatal(err)
	}
	var seen []uint64
	refuse := false
	registry.replaceSigners = func([]TrustedSignerConfig) error {
		seen = append(seen, registry.current.Generation)
		if refuse {
			return errors.New("refused")
		}
		return nil
	}
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 8,
		Signers: []TrustedSignerConfig{{Actor: "ops"}}}
	registry.adopt(spec, 1)
	if registry.current.Generation != 1 || !slices.Equal(seen, []uint64{0}) {
		t.Fatalf("adopted generation %d, signers swapped at %v", registry.current.Generation, seen)
	}
	refuse = true
	spec.Generation = 2
	registry.adopt(spec, 2)
	if registry.current.Generation != 1 {
		t.Fatalf("a spec whose signers were refused was adopted: generation %d", registry.current.Generation)
	}
}
