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
	for subject, want := range map[string]string{
		"0000000000FT4JKN5QV2BGQ38B": "t-acme-db,t-globex-db,t-gone-db,ts-auth",
		"0000000000Z4WVDND9E6R945JB": "t-acme-db",
		"00000000000N2RBS80K3HN7R4B": "t-globex-db",
	} {
		code, body, _ := call(t, f.server, f.token(subject), "/v1/apps")
		if code != http.StatusOK || strings.Join(names(body, "apps"), ",") != want {
			t.Fatalf("%s lists %d %v, want %s", subject, code, body, want)
		}
	}
	machine := "/v1/apps/t-acme-db/machines/" + f.machine.ID
	for _, path := range []string{"/v1/apps/t-acme-db", "/v1/apps/t-acme-db/machines", machine} {
		for _, subject := range []string{"0000000000Z4WVDND9E6R945JB", "0000000000MB95NQ0RR1N1GQNJ", "0000000000FT4JKN5QV2BGQ38B"} {
			if code, body, _ := call(t, f.server, f.token(subject), path); code != http.StatusOK {
				t.Fatalf("%s reads %s: %d %v", subject, path, code, body)
			}
		}
		// Another tenant's app is missing, not forbidden, so names do not
		// leak.
		if code, body, _ := call(t, f.server, f.token("00000000000N2RBS80K3HN7R4B"), path); code != http.StatusNotFound || body["error"] != "not_found" {
			t.Fatalf("gina reads %s: %d %v", path, code, body)
		}
	}
	// Tenants see no platform app, nor an app whose tenant record is gone.
	for _, path := range []string{"/v1/apps/ts-auth", "/v1/apps/ts-auth/machines", "/v1/apps/t-gone-db", "/v1/apps/nothing"} {
		if code, _, _ := call(t, f.server, f.token("0000000000Z4WVDND9E6R945JB"), path); code != http.StatusNotFound {
			t.Fatalf("alice reads %s: %d", path, code)
		}
	}
	code, body, _ := call(t, f.server, f.token("0000000000Z4WVDND9E6R945JB"), "/v1/apps/t-acme-db/machines")
	machines := body["machines"].([]any)
	if code != http.StatusOK || len(machines) != 1 {
		t.Fatalf("machines: %d %v", code, body)
	}
	view := machines[0].(map[string]any)
	status, _ := view["status"].(map[string]any)
	if view["id"] != f.machine.ID || view["desired"] != "started" || status["state"] != "started" {
		t.Fatalf("machine view %v", view)
	}
	if code, _, _ := call(t, f.server, f.token("0000000000Z4WVDND9E6R945JB"), "/v1/apps/t-acme-db/machines/00000000000000000000000009"); code != http.StatusNotFound {
		t.Fatalf("missing machine: %d", code)
	}
}

func TestAuthorizationFailures(t *testing.T) {
	f := newFixture(t)
	code, body, header := call(t, f.server, "", "/v1/apps")
	if code != http.StatusUnauthorized || body["error"] != "unauthenticated" || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no token: %d %v %v", code, body, header)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	request.Header.Set("Authorization", "Basic YWRtaW46eA==")
	recorder := httptest.NewRecorder()
	f.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("basic auth: %d", recorder.Code)
	}
	sign := func(header, claims map[string]any) string {
		return f.issuer.sign("skey_one", header, claims)
	}
	for name, token := range map[string]string{
		"id token": sign(map[string]any{"typ": "JWT"}, map[string]any{"sub": "0000000000FT4JKN5QV2BGQ38B"}),
		// Every ts-auth token carries every audience; the dashboard's
		// tokens must still not work here.
		"other client": sign(nil, map[string]any{"sub": "0000000000FT4JKN5QV2BGQ38B", "client_id": "ts-dashboard"}),
		"no client":    sign(nil, map[string]any{"sub": "0000000000FT4JKN5QV2BGQ38B", "client_id": nil}),
	} {
		code, _, header := call(t, f.server, token, "/v1/apps")
		if code != http.StatusUnauthorized || !strings.Contains(header.Get("WWW-Authenticate"), "invalid_token") {
			t.Fatalf("%s: %d %v", name, code, header)
		}
	}
	code, body, header = call(t, f.server, sign(nil, map[string]any{"sub": "0000000000FT4JKN5QV2BGQ38B", "scope": "openid email profile"}), "/v1/apps")
	if code != http.StatusForbidden || body["error"] != "insufficient_scope" || !strings.Contains(header.Get("WWW-Authenticate"), `scope="orch:read"`) {
		t.Fatalf("no scope: %d %v %v", code, body, header)
	}
	code, body, _ = call(t, f.server, f.token("0000000000V6BWY7K2F98QGXZR"), "/v1/apps")
	if code != http.StatusForbidden || body["error"] != "no_organization" {
		t.Fatalf("no organization: %d %v", code, body)
	}
	// A path value becomes part of a KV key only after it matches the
	// model's rules, so it cannot widen a key filter.
	for _, path := range []string{"/v1/apps/Bad_Name", "/v1/apps/a.%3E", "/v1/apps/t-acme-db/machines/*", "/v1/apps/t-acme-db/machines/ABC"} {
		if code, body, _ := call(t, f.server, f.token("0000000000FT4JKN5QV2BGQ38B"), path); code != http.StatusBadRequest || body["error"] != "invalid_name" {
			t.Fatalf("%s: %d %v", path, code, body)
		}
	}
}

func TestStoreOutageIsUnavailable(t *testing.T) {
	f := newFixture(t)
	token := f.token("0000000000FT4JKN5QV2BGQ38B")
	f.nats.Shutdown()
	f.nats.WaitForShutdown()
	for _, path := range []string{"/v1/apps", "/v1/apps/ts-auth"} {
		code, body, _ := call(t, f.server, token, path)
		if code != http.StatusServiceUnavailable || body["error"] != "unavailable" {
			t.Fatalf("%s: %d %v", path, code, body)
		}
	}
}

func TestPublicRoutes(t *testing.T) {
	f := newFixture(t)
	if code, body, _ := call(t, f.server, "", "/healthz"); code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("healthz: %d %v", code, body)
	}
	code, body, _ := call(t, f.server, "", "/v1/openapi.json")
	paths, _ := body["paths"].(map[string]any)
	if code != http.StatusOK || body["openapi"] != "3.1.0" {
		t.Fatalf("openapi: %d", code)
	}
	// Every route the server mounts is documented.
	for _, path := range []string{"/healthz", "/v1/openapi.json", "/v1/apps", "/v1/apps/{app}", "/v1/apps/{app}/machines",
		"/v1/apps/{app}/machines/{id}"} {
		if paths[path] == nil {
			t.Fatalf("openapi lacks %s", path)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{ListenAddress: "10.0.0.1:8444", TLSCertFile: "cert.pem", TLSKeyFile: "key.pem", Issuer: testIssuer, Audience: testAudience,
		JWKSURLs: []string{"http://127.0.0.1:8080/terrascale/.well-known/jwks.json", "http://10.0.0.2:8080/x",
			"https://gru.auth.terrascale.tech/terrascale/.well-known/jwks.json"},
		Clients: []string{"00000000006HEQR9ARBF6BV9X9"}, PlatformOrganizationID: PlatformOrg, Members: map[string][]string{PlatformOrg: {"0000000000KY2MH9DQN7Q13VKZ"}, "0000000000WV4QPGXCC2FFPXNC": {"0000000000N2SKNEF20MN4NV3V"}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"hostname listen":   func(c *Config) { c.ListenAddress = "localhost:8443" },
		"plain issuer":      func(c *Config) { c.Issuer = "http://gru.auth.terrascale.tech/terrascale" },
		"issuer with query": func(c *Config) { c.Issuer = testIssuer + "?x=1" },
		"no audience":       func(c *Config) { c.Audience = "" },
		"no clients":        func(c *Config) { c.Clients = nil },
		"empty client":      func(c *Config) { c.Clients = []string{""} },
		"no jwks":           func(c *Config) { c.JWKSURLs = nil },
		"public http jwks":  func(c *Config) { c.JWKSURLs = []string{"http://203.0.113.5/jwks.json"} },
		"named http jwks":   func(c *Config) { c.JWKSURLs = []string{"http://gru.auth.terrascale.tech/jwks.json"} },
		"file jwks":         func(c *Config) { c.JWKSURLs = []string{"file:///etc/jwks.json"} },
		"tls half":          func(c *Config) { c.TLSKeyFile = "" },
		"plaintext private": func(c *Config) { c.TLSCertFile, c.TLSKeyFile = "", "" },
		"bad org":           func(c *Config) { c.Members = map[string][]string{"a.b": {"0000000000KY2MH9DQN7Q13VKZ"}} },
		"subject twice": func(c *Config) {
			c.Members = map[string][]string{PlatformOrg: {"0000000000KY2MH9DQN7Q13VKZ"}, "0000000000MNX6KE9QZGK3VB63": {"0000000000KY2MH9DQN7Q13VKZ"}}
		},
		"empty subject": func(c *Config) { c.Members = map[string][]string{"0000000000MNX6KE9QZGK3VB63": {""}} },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

const PlatformOrg = "0000000000N2TZG5XH1FX62SDF"
