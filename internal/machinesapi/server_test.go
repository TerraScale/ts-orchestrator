package machinesapi

import (
	"context"
	"encoding/json/v2"

	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/machines"

	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/tenant"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// leader is a fence that always holds epoch 1.
type leader struct{}

func (leader) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}
func (leader) Guard(context.Context, uint64) error { return nil }

type fixture struct {
	server  *Server
	issuer  *issuer
	nats    *server.Server
	apps    *machines.Store
	machine machines.Machine
}

// newFixture serves a cell with a platform app, an app of acme's tenant and
// one of globex's, and one machine of the acme app.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL(), nats.MaxReconnects(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	apps, err := machines.OpenStore(ctx, js, "gru", 1, leader{})
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenant.OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	for id, org := range map[string]string{"0000000000MNX6KE9QZGK3VB63": "0000000000WXB90H7AGW4BG94H", "0000000000E8KV3X6DYHPWSWC1": "0000000000RWJTCANH5947CM6T"} {
		record, err := tenant.New(id, org, entityid.Derive("fixture-project", id), "gru", tenant.Spec{Plan: "starter", Members: 1, TerraBase: digest}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tenants.Create(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	config := machines.MachineConfig{Role: "terrabase", Digest: digest,
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}}
	put := func(name string, class machines.Class, owner string) machines.App {
		app, err := apps.PutApp(ctx, 1, machines.App{Name: name, Class: class, Tenant: owner, Config: config,
			Regions: map[string]int{"gru": 1}})
		if err != nil {
			t.Fatal(err)
		}
		return app
	}
	put("ts-auth", machines.ClassPlatform, "")
	acme := put("t-acme-db", machines.ClassTenant, "0000000000MNX6KE9QZGK3VB63")
	put("t-globex-db", machines.ClassTenant, "0000000000E8KV3X6DYHPWSWC1")
	put("t-gone-db", machines.ClassTenant, "000000000050XVKQQF0BK88ENZ")
	machine, err := apps.PutMachine(ctx, 1, machines.Machine{ID: machines.NewMachineID(), App: acme.Name, AppID: acme.ID,
		Region: "gru", Version: 1, Config: config, Desired: machines.DesiredStarted})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.PutStatus(ctx, 1, machines.Status{ID: machine.ID, App: acme.Name, State: machines.StateStarted,
		UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	i := newIssuer(t)
	s, err := NewServer(Config{ListenAddress: "127.0.0.1:0", Issuer: testIssuer, Audience: testAudience,
		JWKSURLs: []string{i.server.URL}, Clients: []string{"00000000006HEQR9ARBF6BV9X9"},
		PlatformOrganizationID: PlatformOrg, Members: map[string][]string{PlatformOrg: {"0000000000FT4JKN5QV2BGQ38B"}, "0000000000WXB90H7AGW4BG94H": {"0000000000Z4WVDND9E6R945JB", "0000000000MB95NQ0RR1N1GQNJ"}, "0000000000RWJTCANH5947CM6T": {"00000000000N2RBS80K3HN7R4B"}}},
		apps, tenants, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.verifier.client = i.server.Client()
	return &fixture{server: s, issuer: i, nats: srv, apps: apps, machine: machine}
}

func (f *fixture) token(subject string) string {
	return f.issuer.sign("skey_one", nil, map[string]any{"sub": subject})
}

func call(t *testing.T, server http.Handler, token, path string) (int, map[string]any, http.Header) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body %q: %v", path, recorder.Body, err)
	}
	return recorder.Code, body, recorder.Header()
}

func names(body map[string]any, list string) []string {
	var result []string
	for _, item := range body[list].([]any) {
		object := item.(map[string]any)
		name, _ := object["name"].(string)
		if name == "" {
			name, _ = object["id"].(string)
		}
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

func TestTenancy(t *testing.T) {
	f := newFixture(t)
	token := f.token("0000000000Z4WVDND9E6R945JB")
	code, body, _ := call(t, f.server, token, "/v1/apps")
	if code != http.StatusOK || strings.Join(names(body, "apps"), ",") != "t-acme-db" {
		t.Fatalf("tenant app listing: %d %v", code, body)
	}
	path := "/v1/apps/t-acme-db/machines/" + f.machine.ID
	code, body, _ = call(t, f.server, token, path)
	if code != http.StatusOK {
		t.Fatalf("tenant machine read: %d %v", code, body)
	}
	machine := body
	if machine["id"] != f.machine.ID || machine["desired"] != "started" {
		t.Fatalf("machine view: %v", machine)
	}
	foreign := f.token("00000000000N2RBS80K3HN7R4B")
	if code, body, _ := call(t, f.server, foreign, path); code != http.StatusNotFound || body["error"] != "not_found" {
		t.Fatalf("cross-tenant machine read: %d %v", code, body)
	}
}

func TestAuthorizationFailures(t *testing.T) {
	f := newFixture(t)
	code, body, header := call(t, f.server, "", "/v1/apps")
	if code != http.StatusUnauthorized || body["error"] != "unauthenticated" || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no token: %d %v %v", code, body, header)
	}
	token := f.issuer.sign("skey_one", nil, map[string]any{"sub": "0000000000FT4JKN5QV2BGQ38B", "client_id": "ts-dashboard"})
	code, _, header = call(t, f.server, token, "/v1/apps")
	if code != http.StatusUnauthorized || !strings.Contains(header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("foreign client token: %d %v", code, header)
	}
}

const PlatformOrg = "0000000000N2TZG5XH1FX62SDF"
