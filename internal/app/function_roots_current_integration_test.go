package app

import (
	"bytes"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

func publishFunctionRootHistory(t *testing.T, js jetstream.JetStream, roots *rootRegistry) {
	t.Helper()
	if err := roots.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeRootChain(roots.reply("").Chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roots.kv.Put(t.Context(), rootChainKey, wire); err != nil {
		t.Fatal(err)
	}
}

func TestFunctionIntentRequiresCurrentLeaderRoots(t *testing.T) {
	fixture := newFunctionRootAdmissionFixture(t)
	config := fixture.controller.config
	ctx := t.Context()
	proof := fixture.signer.proof(t, 42, "first")
	if _, err := config.Material.Reader.Artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader(proof.Module())); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Authority.CommitFunctionIntent(ctx, config.Authority.Current().Epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	head := config.Roots.reply("").Head
	source := functionIntentSource{reader: config.Material.Reader, js: config.JS, authority: config.Authority,
		epoch: config.Authority.Current().Epoch, roots: config.Roots, rootHead: head}
	claim := proof.Claim()
	if _, err := source.CurrentFunction(ctx, claim.TenantID, claim.FunctionID); err == nil {
		t.Fatal("missing root history preserved function authority through local genesis")
	}
	publishFunctionRootHistory(t, config.JS, config.Roots)
	current, err := source.CurrentFunction(ctx, claim.TenantID, claim.FunctionID)
	if err != nil || current.EnvelopeSHA256() != proof.EnvelopeSHA256() {
		t.Fatalf("exact current signed function was rejected: %v", err)
	}
	var rotation trust.SignedRotation
	if err := protocol.DecodeStrict(fixture.rotation, &rotation, trust.MaxRootChainBytes); err != nil {
		t.Fatal(err)
	}
	rotated, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{rotation}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Roots.kv.Put(ctx, rootChainKey, rotated); err != nil {
		t.Fatal(err)
	}
	if config.Roots.reply("").Head != head {
		t.Fatal("fixture adopted the committed rotation before checking the function source")
	}
	if _, err := source.CurrentFunction(ctx, claim.TenantID, claim.FunctionID); err == nil {
		t.Fatal("function accepted roots superseded before local watcher adoption")
	}
	if _, err := config.Roots.kv.Put(ctx, rootChainKey, []byte("invalid root chain")); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CurrentFunction(ctx, claim.TenantID, claim.FunctionID); err == nil {
		t.Fatal("invalid committed root history preserved function authority")
	}
	if err := config.Roots.kv.Delete(ctx, rootChainKey); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CurrentFunction(ctx, claim.TenantID, claim.FunctionID); err == nil {
		t.Fatal("deleted root history preserved function authority")
	}
}
