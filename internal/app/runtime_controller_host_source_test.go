package app

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestControllerHostSpecRequiresExactLeaderRevision(t *testing.T) {
	ctx := t.Context()
	keys := newTestSpecTrust(t, t.TempDir(), cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: "test"})
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{SpecTrust: keys.config()}}
	newAcceptedSpecTrust(t, &cfg)
	services, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	js, observer := testRolloutJetStreamWithObserver(t, cellSpecBucket)
	if err := services.open(ctx, js, 1); err != nil {
		t.Fatal(err)
	}
	if err := services.roots.open(ctx, js, 1); err != nil {
		t.Fatal(err)
	}
	rootWire, err := trust.EncodeRootChain(services.roots.reply("").Chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.roots.kv.Put(ctx, rootChainKey, rootWire); err != nil {
		t.Fatal(err)
	}
	wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: 1, RequiresBinary: 1},
		nil, keys.roots, time.Now(), time.Hour, keys.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.kv.Put(ctx, cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	entry, err := services.kv.Get(ctx, cellSpecKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := services.load(entry); err != nil {
		t.Fatal(err)
	}
	finish := watchJetStreamLeaderReads(t, observer, cellSpecBucket)
	head := services.roots.reply("").Head
	if err := controllerHostSpecCurrent(ctx, js, services, entry, head); err != nil {
		t.Fatalf("current signed profile rejected: %v", err)
	}
	if _, err := services.kv.Put(ctx, cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	if err := controllerHostSpecCurrent(ctx, js, services, entry, head); err == nil {
		t.Fatal("identical bytes at a newer unadopted revision preserved old recipient authority")
	}
	if err := services.kv.Delete(ctx, cellSpecKey); err != nil {
		t.Fatal(err)
	}
	if err := controllerHostSpecCurrent(ctx, js, services, entry, head); err == nil {
		t.Fatal("deleted signed profile preserved retained recipient authority")
	}
	if count := finish(); count != 3 {
		t.Fatalf("profile leader reads=%d, want 3", count)
	}
}
