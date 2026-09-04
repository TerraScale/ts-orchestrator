package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func snippetZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", SnippetRules: []SnippetRule{{
		SnippetName: GateSnippetName, Hostname: "sync.api.terrascale.tech",
		PathPrefix: "/api/v1/reactive/", Enabled: true,
	}}}
}

// Escaped for embedding inside JSON string values in the fixtures below.
const declaredSnippetRule = `(http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/api/v1/reactive/\"))`

// planSnippetRule is the same expression as it appears in plan details (real
// quotes, after the JSON round-trip).
const planSnippetRule = `(http.host eq "sync.api.terrascale.tech" and starts_with(http.request.uri.path, "/api/v1/reactive/"))`

func TestSnippetRulesReconcile(t *testing.T) {
	cases := []struct {
		name       string
		live       string
		wantPlan   []string
		wantMethod []string
	}{
		{
			name: "no-op when the deployed rule matches",
			live: `[{"snippet_name":"ts-gate","rules":[{"expression":"` + declaredSnippetRule + `","description":"terrascale:ts-gate","enabled":true}]}]`,
		},
		{
			name:       "drift on expression is repaired on the deployed snippet",
			live:       `[{"snippet_name":"ts-gate","rules":[{"expression":"http.host eq \"sync.api.terrascale.tech\"","description":"terrascale:ts-gate","enabled":true}]}]`,
			wantPlan:   []string{"update snippet-rule " + planSnippetRule},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:       "disabled rule is re-enabled",
			live:       `[{"snippet_name":"ts-gate","rules":[{"expression":"` + declaredSnippetRule + `","description":"terrascale:ts-gate","enabled":false}]}]`,
			wantPlan:   []string{"update snippet-rule " + planSnippetRule},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:     "snippet code not deployed is an alert, never a create",
			live:     `[]`,
			wantPlan: []string{"alert snippet-rule snippet code not deployed (ships with ts-proxy releases, X-2)"},
		},
		{
			name: "other snippets are not ours",
			live: `[{"snippet_name":"somebody-elses","rules":[{"expression":"true","enabled":true}]},` +
				`{"snippet_name":"ts-gate","rules":[{"expression":"` + declaredSnippetRule + `","description":"terrascale:ts-gate","enabled":true}]}]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var puts []string
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch {
				case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/snippets"):
					return okEnvelope(tc.live)
				case call.Method == http.MethodPut:
					puts = append(puts, call.Path)
					return okEnvelope("null")
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
			})
			z := snippetZone()
			p := &Plan{}
			if err := z.reconcileSnippets(context.Background(), c, p); err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}
			if got := summarize(p); !reflect.DeepEqual(got, tc.wantPlan) {
				t.Fatalf("plan = %v\nwant %v", got, tc.wantPlan)
			}
			if err := Apply(context.Background(), p); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			// Alerts never mutate; repairs hit the snippet-rules endpoint.
			if len(puts) != len(tc.wantMethod) {
				t.Fatalf("PUTs = %v, want %d", puts, len(tc.wantMethod))
			}
			for _, path := range puts {
				if !strings.Contains(path, "/snippets/ts-gate/rules") {
					t.Fatalf("wrong snippet-rules path: %s", path)
				}
			}
		})
	}
}

// TestGateDeclarationGuards pins the D-55 fail-closed guards on the declared
// zone: the reconcile pass refuses to run when a Worker route covers a gate
// hostname, and a snippet may not be declared twice.
func TestGateDeclarationGuards(t *testing.T) {
	rejects := []struct {
		name   string
		routes []WorkerRoute
		rules  func(*Zone)
	}{
		{
			name:   "worker route exactly on the gate hostname",
			routes: []WorkerRoute{{Pattern: "sync.api.terrascale.tech/*", Script: ProxyWorkerScript}},
		},
		{
			name:   "wildcard worker route covers the gate hostname",
			routes: []WorkerRoute{{Pattern: "*.terrascale.tech/*", Script: "stray"}},
		},
		{
			name: "snippet declared twice",
			rules: func(z *Zone) {
				z.SnippetRules = append(z.SnippetRules, z.SnippetRules[0])
			},
		},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				// The guard must fire before any API call.
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
			})
			z := snippetZone()
			z.WorkerRoutes = tc.routes
			if tc.rules != nil {
				tc.rules(z)
			}
			if err := z.reconcileSnippets(context.Background(), c, &Plan{}); err == nil {
				t.Fatal("declaration must fail the pass (D-55 fail closed)")
			}
		})
	}

	// The declared production zone passes: api./app. Worker routes never
	// cover the gate hostname.
	z, err := Production(Members{"gru": {"198.51.100.10"}}, testEgress())
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	if err := z.validateGateDeclaration(); err != nil {
		t.Fatalf("declared production zone must pass the gate guards: %v", err)
	}
}

func TestRouteCoversHost(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"sync.api.terrascale.tech/*", true},
		{"sync.api.terrascale.tech", true},
		{"sync.api.terrascale.tech/api/*", true},
		{"*.terrascale.tech/*", true},
		{"*api.terrascale.tech/*", true},
		{"sync.*", true},
		{"terrascale.tech/*", false}, // an exact host does not cover subdomains
		{"api.terrascale.tech/*", false},
		{"app.terrascale.tech/*", false},
		{"gru.api.terrascale.tech/*", false},
		{"app.*", false},
		{"*", true},
	}
	for _, tc := range cases {
		if got := routeCoversHost(tc.pattern, "sync.api.terrascale.tech"); got != tc.want {
			t.Errorf("routeCoversHost(%q, sync.api.terrascale.tech) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}
