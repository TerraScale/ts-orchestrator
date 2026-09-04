package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func cacheZone(tieredLive string) *Zone {
	return &Zone{ZoneName: "terrascale.tech", SmartTieredCache: true,
		CacheRules: []CacheRule{{
			Ref: "sync-reactive", Hostname: "sync.api.terrascale.tech",
			PathPrefix: reactiveViewsPath, PathSuffix: reactiveLogLeaf, PathSegment: reactiveSnapshotPart,
			Eligible: true, EdgeTTLMode: "respect_origin",
		}}}
}

// The declared rule's expression with real quotes, as it appears in plan
// details after the JSON round-trip.
const declaredCacheExpression = `(http.host eq "sync.api.terrascale.tech" and starts_with(http.request.uri.path, "/api/v1/reactive/views/") and (ends_with(http.request.uri.path, "/log") or contains(http.request.uri.path, "/snapshot/")))`

const declaredCacheRule = `{"id":"c1","description":"terrascale:sync-reactive","expression":"(http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/api/v1/reactive/views/\") and (ends_with(http.request.uri.path, \"/log\") or contains(http.request.uri.path, \"/snapshot/\")))","action":"set_cache_settings","action_parameters":{"cache":true,"edge_ttl":{"mode":"respect_origin"}},"enabled":true}`

func TestCacheRulesReconcile(t *testing.T) {
	cases := []struct {
		name       string
		phaseGet   int    // status for GET entrypoint
		phaseBody  string // entrypoint rules payload
		tiered     string // smart tiered cache value
		wantPlan   []string
		wantMethod []string
	}{
		{
			name:       "create when phase unconfigured (404)",
			phaseGet:   http.StatusNotFound,
			phaseBody:  `{"code":10004,"message":"not found"}`,
			tiered:     "on",
			wantPlan:   []string{"create cache-rule " + declaredCacheExpression},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:      "no-op when declared",
			phaseGet:  http.StatusOK,
			phaseBody: `[` + declaredCacheRule + `]`,
			tiered:    "on",
		},
		{
			name:       "blanket reactive-prefix rule is drift and gets narrowed",
			phaseGet:   http.StatusOK,
			phaseBody:  `[{"id":"c1","description":"terrascale:sync-reactive","expression":"(http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/api/v1/reactive/\"))","action":"set_cache_settings","action_parameters":{"cache":true,"edge_ttl":{"mode":"respect_origin"}},"enabled":true}]`,
			tiered:     "on",
			wantPlan:   []string{"update cache-rule " + declaredCacheExpression},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:       "drift on edge ttl mode is repaired",
			phaseGet:   http.StatusOK,
			phaseBody:  `[{"id":"c1","description":"terrascale:sync-reactive","expression":"(http.host eq \"sync.api.terrascale.tech\" and starts_with(http.request.uri.path, \"/api/v1/reactive/views/\") and (ends_with(http.request.uri.path, \"/log\") or contains(http.request.uri.path, \"/snapshot/\")))","action":"set_cache_settings","action_parameters":{"cache":true,"edge_ttl":{"mode":"override_origin","default":60}},"enabled":true}]`,
			tiered:     "on",
			wantPlan:   []string{"update cache-rule " + declaredCacheExpression},
			wantMethod: []string{http.MethodPut},
		},
		{
			name:      "foreign and retired rules are deleted",
			phaseGet:  http.StatusOK,
			phaseBody: `[` + declaredCacheRule + `,{"id":"c2","description":"someone clicked a console","expression":"true","action":"set_cache_settings","enabled":true},{"id":"c3","description":"terrascale:retired","expression":"http.host eq \"old\"","action":"set_cache_settings","enabled":true}]`,
			tiered:    "on",
			wantPlan: []string{
				"delete cache-rule true",
				"delete cache-rule http.host eq \"old\"",
			},
			wantMethod: []string{http.MethodPut, http.MethodPut},
		},
		{
			name:       "smart tiered cache drift",
			phaseGet:   http.StatusOK,
			phaseBody:  `[` + declaredCacheRule + `]`,
			tiered:     "off",
			wantPlan:   []string{"update tiered-cache smart tiered cache -> true"},
			wantMethod: []string{http.MethodPut},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				switch {
				case call.Method == http.MethodGet && strings.Contains(call.Path, "/rulesets/phases/http_request_cache_settings/entrypoint"):
					result := `{"rules":` + tc.phaseBody + `}` // phase entrypoints return a ruleset object
					success := "false"
					if tc.phaseGet == http.StatusOK {
						success = "true"
					}
					return tc.phaseGet, `{"success":` + success + `,"result":` + result + `}`, nil
				case call.Method == http.MethodGet && strings.Contains(call.Path, "/cache/tiered_cache_smart_topology_enable"):
					return okEnvelope(`{"value":"` + tc.tiered + `"}`)
				case call.Method == http.MethodPut:
					methods = append(methods, call.Method)
					return okEnvelope("null")
				}
				return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
			})
			z := cacheZone(tc.tiered)
			p := &Plan{}
			if err := z.reconcileCache(context.Background(), c, p); err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}
			if got := summarize(p); !reflect.DeepEqual(got, tc.wantPlan) {
				t.Fatalf("plan = %v\nwant %v", got, tc.wantPlan)
			}
			if err := Apply(context.Background(), p); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			if !reflect.DeepEqual(methods, tc.wantMethod) {
				t.Fatalf("applied methods = %v, want %v", methods, tc.wantMethod)
			}
		})
	}
}

func TestCacheRulePutSendsWholeDeclaredList(t *testing.T) {
	var body string
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		switch {
		case call.Method == http.MethodGet && strings.Contains(call.Path, "/rulesets/phases/"):
			return http.StatusNotFound, `{"success":false,"errors":[{"code":10004}]}`, nil
		case call.Method == http.MethodGet:
			return okEnvelope(`{"value":"on"}`)
		case call.Method == http.MethodPut:
			body = call.Body
			return okEnvelope("null")
		}
		return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected")
	})
	z := cacheZone("on")
	p := &Plan{}
	if err := z.reconcileCache(context.Background(), c, p); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if err := Apply(context.Background(), p); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	// Whole-list semantics: exactly the declared rules, description-carried
	// identity, eligible, respect-origin, and the snapshot/log leaves as
	// the only admitted paths.
	for _, want := range []string{
		`"description":"terrascale:sync-reactive"`, `"cache":true`,
		`"edge_ttl":{"mode":"respect_origin"}`, `"action":"set_cache_settings"`,
		`starts_with(http.request.uri.path, \"/api/v1/reactive/views/\")`,
		`ends_with(http.request.uri.path, \"/log\")`,
		`contains(http.request.uri.path, \"/snapshot/\")`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PUT body missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"id"`) {
		t.Fatalf("declared rules carry no live id: %s", body)
	}
}

// TestProductionCacheRuleMarksExactlySnapshotAndLog pins the declared
// eligibility to D-55's words: the snapshot-chunk and log leaves of the D-14
// surface, on the sync hostname, with the origin owning the TTL.
func TestProductionCacheRuleMarksExactlySnapshotAndLog(t *testing.T) {
	z, err := Production(Members{"gru": {"198.51.100.10"}}, testEgress())
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	if len(z.CacheRules) != 1 {
		t.Fatalf("want one cache rule, got %d", len(z.CacheRules))
	}
	if got := z.CacheRules[0].rule().Expression; got != declaredCacheExpression {
		t.Fatalf("declared expression:\n %s\nwant:\n %s", got, declaredCacheExpression)
	}
	if !z.SmartTieredCache {
		t.Error("Smart Tiered Cache must be declared on (D-55: tiers bound origin fills)")
	}
}
