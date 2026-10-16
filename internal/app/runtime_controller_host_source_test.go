package app

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
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
	js := testRolloutJetStream(t)
	if err := services.open(ctx, js, 1); err != nil {
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
	options := js.Options()
	prefix := strings.TrimSuffix(options.APIPrefix, ".")
	if options.Domain != "" {
		prefix = "$JS." + options.Domain + ".API"
	} else if prefix == "" {
		prefix = "$JS.API"
	}
	leader, err := js.Conn().SubscribeSync(prefix + ".STREAM.MSG.GET.KV_" + cellSpecBucket)
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Unsubscribe()
	direct, err := js.Conn().SubscribeSync(prefix + ".DIRECT.GET.>")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Unsubscribe()
	if err := js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
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
	if err := js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if count, _, err := leader.Pending(); err != nil || count != 3 {
		t.Fatalf("profile leader reads=%d, want 3: %v", count, err)
	}
	if count, _, err := direct.Pending(); err != nil || count != 0 {
		t.Fatalf("profile authorization used follower reads=%d: %v", count, err)
	}
}
