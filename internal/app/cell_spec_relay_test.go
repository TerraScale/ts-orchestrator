package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// TestRelayedCellSpecNeedsTheTargetsOwnTrust relays specs for SFO through
// the home region's global stream and lets SFO's leader follow them. One
// JetStream stands in for both regions; the cross-region mirror is covered
// by natscell's two-region test.
func TestRelayedCellSpecNeedsTheTargetsOwnTrust(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(dir, "jetstream")})
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
	lead := func(scope string) *authority.Runtime {
		t.Helper()
		runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: scope, CandidateID: entityid.Derive("test-controller", scope), Replicas: 1,
			LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtime.Close() })
		for !runtime.Current().CanMutate() {
			if ctx.Err() != nil {
				t.Fatalf("%s authority never became leader", scope)
			}
			time.Sleep(20 * time.Millisecond)
		}
		return runtime
	}
	global, regional := lead(protocol.GlobalScope), lead("sfo")
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", []string{"sfo"}, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	home := &globalControl{authority: global, writer: writer, reader: &writer.Reader}

	// "ops" is trusted in both regions, "gru-ops" only at the home.
	opsPublic, opsPrivate := testEd25519(t, dir, "ops.key")
	homePublic, homePrivate := testEd25519(t, dir, "gru-ops.key")
	grant := func(actor string, public ed25519.PublicKey) TrustedSignerConfig {
		return TrustedSignerConfig{Actor: actor, PublicKey: base64.StdEncoding.EncodeToString(public),
			Roles: []string{"web"}, Environments: []string{"test"}}
	}
	homePolicy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant("ops", opsPublic), grant("gru-ops", homePublic)}}})
	if err != nil {
		t.Fatal(err)
	}
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "0000000000TV3Q06FF4VNZW415", Cell: "sfo", Environment: "test"})
	sfoConfig := Config{NATS: natscell.Config{Cell: "sfo", Lab: true}, Controller: ControllerConfig{
		TrustedSigners: []TrustedSignerConfig{grant("ops", opsPublic)}, SpecTrust: keys.config()}}
	sfoPolicy, err := buildSignerPolicy(sfoConfig)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newSpecRegistry(sfoConfig, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.open(ctx, js, 1); err != nil {
		t.Fatal(err)
	}
	go func() { _ = registry.followRelayedSpecs(ctx, home.reader, sfoPolicy, regional, nil) }()

	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}
	spec := func(generation uint64, mode string) []byte {
		t.Helper()
		next := cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: generation, RequiresBinary: 1,
			Services: []cellspec.Service{{Role: "web", Profile: WorkloadProfile{Resources: resources,
				Env: map[string]string{"MODE": mode}}}}}
		return mustRead(t, keys.sign(t, dir, next))
	}
	publish := func(actor string, private ed25519.PrivateKey, region string, signed []byte) (specReply, error) {
		t.Helper()
		now := time.Now().UTC()
		relay, err := protocol.SignEnvelope(signed, protocol.EnvelopeScope{Region: region, Kind: cellSpecRelayKind,
			Actor: actor, OperationID: entityid.New(), Generation: 1,
		}, now, now.Add(cellspec.MaxSpecLifetime), private)
		if err != nil {
			t.Fatal(err)
		}
		relayWire, err := protocol.EncodeJSON(relay)
		if err != nil {
			t.Fatal(err)
		}
		request, err := protocol.SignEnvelope(relayWire, protocol.EnvelopeScope{Region: "gru", Kind: cellSpecPublishKind,
			Actor: actor, OperationID: entityid.New(), Generation: 1, Epoch: global.Current().Epoch,
		}, now, now.Add(time.Minute), private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(request)
		if err != nil {
			t.Fatal(err)
		}
		return relayCellSpec(ctx, wire, homePolicy, home, []string{"sfo"})
	}
	adopted := func(generation uint64) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			registry.mu.Lock()
			current := registry.current.Generation
			registry.mu.Unlock()
			if current == generation {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("SFO is at generation %d, want %d", current, generation)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	first := spec(1, "a")
	if reply, err := publish("ops", opsPrivate, "sfo", first); err != nil || reply.Status != "relayed" || reply.Spec.Generation != 1 {
		t.Fatalf("relay generation 1 = %+v, %v", reply, err)
	}
	adopted(1)
	if entry, err := registry.kv.Get(ctx, cellSpecKey); err != nil || entry.Revision() == 0 {
		t.Fatalf("SFO did not store the relayed spec: %v", err)
	}

	// The home checks what it can without SFO's trust.
	other := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "00000000003DX3MNPA6WHG6PR2", Cell: "fra", Environment: "test"})
	fraSpec := mustRead(t, other.sign(t, dir, cellspec.Spec{Schema: cellspec.Schema, Identity: other.identity,
		Generation: 1, RequiresBinary: 1}))
	// A signed envelope for SFO's spec scope whose payload is no spec.
	now := time.Now().UTC().Truncate(time.Second)
	garbageEnvelope, err := trust.Sign([]byte(`{"generation":5}`), keys.identity.Scope(), now, now.Add(time.Hour), keys.root)
	if err != nil {
		t.Fatal(err)
	}
	garbageSpec, err := trust.EncodeEnvelope(garbageEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	garbage, err := protocol.EncodeJSON(cellspec.Signed{Spec: garbageSpec})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		region string
		signed []byte
		want   string
	}{
		"not a peer":          {"fra", fraSpec, "not an interregion peer"},
		"another cell's spec": {"sfo", fraSpec, `is for cell "fra"`},
		"not a spec":          {"sfo", []byte(`{"spec":"x"}`), "cell spec envelope"},
		"undecodable spec":    {"sfo", garbage, "decode the relayed cell spec"},
	} {
		if _, err := publish("ops", opsPrivate, tc.region, tc.signed); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: relay = %v, want %q", name, err, tc.want)
		}
	}
	if _, err := publish("ops", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), "sfo", spec(2, "x")); err == nil {
		t.Error("an untrusted operator relayed a spec")
	}

	// SFO refuses what only its own trust can judge and keeps its spec: an
	// operator the home trusts but SFO does not, and a spec that skips a
	// generation. Each refused record is replaced by the next relay; an
	// equal generation may replace a waiting one (a renewed signature).
	if _, err := publish("gru-ops", homePrivate, "sfo", spec(2, "b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	adopted(1)
	if _, err := publish("ops", opsPrivate, "sfo", spec(2, "d")); err != nil {
		t.Fatal(err)
	}
	adopted(2)
	if _, err := publish("ops", opsPrivate, "sfo", spec(4, "e")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	adopted(2)
	// An older spec never displaces the one waiting.
	if _, err := publish("ops", opsPrivate, "sfo", first); err == nil || !strings.Contains(err.Error(), "is older") {
		t.Fatalf("relaying an older spec = %v", err)
	}
	if profiles := registry.profiles(); profiles["web"].Env["MODE"] != "d" {
		t.Fatalf("SFO profiles = %+v", profiles)
	}
}
