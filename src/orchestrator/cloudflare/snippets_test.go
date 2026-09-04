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
