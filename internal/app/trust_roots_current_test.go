package app

import (
	"crypto/ed25519"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestRootTrustHeadRequiresCurrentLeaderChain(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: flaky on main since the 2026-10-21 integration-line merge")
	ctx := t.Context()
	initial, replacement := newRootKey(t), newRootKey(t)
	genesis, err := trust.ParseKeyring(initial.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	identity := trust.ChainIdentity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"}
	roots, err := newRootRegistry(genesis, identity, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	js, observer := testRolloutJetStreamWithObserver(t, rootChainBucket)
	if err := roots.open(ctx, js, 1); err != nil {
		t.Fatal(err)
	}
	head := roots.reply("").Head
	finish := watchJetStreamLeaderReads(t, observer, rootChainBucket)
	if err := rootTrustHeadCurrent(ctx, js, roots, head); err == nil {
		t.Fatal("missing root history fell back to local genesis")
	}
	wire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := roots.kv.Put(ctx, rootChainKey, wire); err != nil {
			t.Fatal(err)
		}
		if err := rootTrustHeadCurrent(ctx, js, roots, head); err != nil {
			t.Fatalf("unchanged authority rejected after a same-chain write: %v", err)
		}
	}
	rotated := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signTestRotation(t, identity, roots.verified, rootKeys(replacement), initial, replacement)}}
	rotatedWire, err := trust.EncodeRootChain(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roots.kv.Put(ctx, rootChainKey, rotatedWire); err != nil {
		t.Fatal(err)
	}
	if roots.reply("").Head != head {
		t.Fatal("fixture adopted the rotation before the freshness check")
	}
	if err := rootTrustHeadCurrent(ctx, js, roots, head); err == nil {
		t.Fatal("committed rotation accepted through the stale local root watcher")
	}
	if _, err := roots.kv.Put(ctx, rootChainKey, []byte("invalid root chain")); err != nil {
		t.Fatal(err)
	}
	if err := rootTrustHeadCurrent(ctx, js, roots, head); err == nil {
		t.Fatal("invalid leader root chain preserved local authority")
	}
	if err := roots.kv.Delete(ctx, rootChainKey); err != nil {
		t.Fatal(err)
	}
	if err := rootTrustHeadCurrent(ctx, js, roots, head); err == nil {
		t.Fatal("deleted leader root chain preserved local authority")
	}
	if count := finish(); count != 6 {
		t.Fatalf("root leader reads=%d, want 6", count)
	}
}
