package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func snippetZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech", SnippetRules: []SnippetRule{{
		SnippetName: GateSnippetName, Hostnames: []string{"sync.api.terrascale.tech"},
		PathPrefix: "/api/v1/reactive/", Enabled: true,
	}}}
}

// Escaped for embedding inside JSON string values in the fixtures below.
const declaredSnippetRule = `((http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/api/v1/reactive/\"))) or ((http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/.well-known/terrascale-capability-generation\")))`

// planSnippetRule is the same expression as it appears in plan details (real
// quotes, after the JSON round-trip).
const planSnippetRule = `((http.host eq "sync.api.terrascale.tech" and starts_with(http.request.uri.path, "/api/v1/reactive/"))) or ((http.host eq "sync.api.terrascale.tech" and starts_with(http.request.uri.path, "/.well-known/terrascale-capability-generation")))`

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
			var fixture []struct {
				Name  string            `json:"snippet_name"`
				Rules []SnippetRuleWire `json:"rules"`
			}
			if err := json.Unmarshal([]byte(tc.live), &fixture); err != nil {
				t.Fatal(err)
			}
			rules := []zoneSnippetRule{}
			for _, snippet := range fixture {
				for _, rule := range snippet.Rules {
					rules = append(rules, zoneSnippetRule{SnippetName: snippet.Name, SnippetRuleWire: rule})
				}
			}

			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch {
				case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/snippets"):
					return okEnvelope(tc.live)
				case call.Method == http.MethodGet && strings.HasSuffix(call.Path, "/snippets/snippet_rules"):
					return okEnvelope(mustJSON(map[string]any{"rules": rules}))
				case call.Method == http.MethodPut:
					var updated struct {
						Rules []zoneSnippetRule `json:"rules"`
					}
					if err := json.Unmarshal([]byte(call.Body), &updated); err != nil {
						t.Fatal(err)
					}
					rules = updated.Rules

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
				if !strings.Contains(path, "/snippets/snippet_rules") {
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

func TestSnippetGateExpressionBindsRegionalAliases(t *testing.T) {
	expression := snippetGateExpression([]string{"sync.api.terrascale.tech", "gru.sync.api.terrascale.tech"}, "/api/v1/reactive/")
	for _, host := range []string{"sync.api.terrascale.tech", "gru.sync.api.terrascale.tech"} {
		if !strings.Contains(expression, `http.host eq "`+host+`"`) {
			t.Fatalf("gate expression omits %s: %s", host, expression)
		}
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

// Cloudflare's zone rules endpoint replaces the complete ordered list. The
// response model is also documented by terraform-provider-cloudflare's
// internal/services/snippet_rules/model.go (result.rules, with snippet_name).
func TestSnippetZoneRulesPreserveOtherOwnersAndHonorETag(t *testing.T) {
	for _, mode := range []string{"preserve", "etag-conflict", "unowned-target"} {
		t.Run(mode, func(t *testing.T) {
			current := []zoneSnippetRule{
				{SnippetName: "other-before", SnippetRuleWire: SnippetRuleWire{Expression: "true", Description: "owned by another system", Enabled: true}},
				{SnippetName: "ts-gate", SnippetRuleWire: SnippetRuleWire{Expression: "false", Description: "terrascale:ts-gate", Enabled: false}},
				{SnippetName: "other-after", SnippetRuleWire: SnippetRuleWire{Expression: "http.host eq \"other.example\"", Description: "foreign", Enabled: false}},
			}
			if mode == "unowned-target" {
				current[1].Description = "another owner"
			}
			wanted := SnippetRuleWire{Expression: "http.host eq \"sync.api.terrascale.tech\"", Description: "terrascale:ts-gate", Enabled: true}
			puts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/zones/zone/snippets/snippet_rules" {
					t.Errorf("wrong path %s", r.URL)
					http.NotFound(w, r)
					return
				}
				if r.Method == http.MethodGet {
					w.Header().Set("ETag", `"zone-revision"`)
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"rules": current}})
					return
				}
				if r.Method != http.MethodPut {
					t.Errorf("unexpected method %s", r.Method)
					w.WriteHeader(405)
					return
				}
				puts++
				if r.Header.Get("If-Match") != `"zone-revision"` {
					t.Errorf("If-Match = %q", r.Header.Get("If-Match"))
				}
				if mode == "etag-conflict" {
					w.WriteHeader(412)
					fmt.Fprint(w, `{"success":false,"errors":[{"code":1008,"message":"changed"}]}`)
					return
				}
				var replacement struct {
					Rules []zoneSnippetRule `json:"rules"`
				}
				if err := json.NewDecoder(r.Body).Decode(&replacement); err != nil {
					t.Error(err)
				}
				if len(replacement.Rules) != 3 || replacement.Rules[0] != current[0] || replacement.Rules[2] != current[2] || replacement.Rules[1].SnippetRuleWire != wanted {
					t.Errorf("replacement changed another owner's rules or order: %+v", replacement.Rules)
				}
				current = replacement.Rules
				fmt.Fprint(w, `{"success":true,"result":{}}`)
			}))
			defer server.Close()
			client := NewClient("token", "zone", "account")
			client.BaseURL = server.URL
			err := client.PutSnippetRules(t.Context(), "ts-gate", []SnippetRuleWire{wanted})
			if mode == "preserve" && err != nil {
				t.Fatal(err)
			}
			if mode != "preserve" && err == nil {
				t.Fatal("conflicting mutation accepted")
			}
			if mode == "unowned-target" && puts != 0 {
				t.Fatal("attempted to overwrite unowned rule")
			}
			if mode != "unowned-target" && puts != 1 {
				t.Fatalf("PUT calls = %d", puts)
			}
		})
	}
}
