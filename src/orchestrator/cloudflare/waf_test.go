package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func wafZone() *Zone {
	return &Zone{ZoneName: "terrascale.tech",
		FirewallRules: []FirewallRule{{
			Ref: "admin-tailscale-only", Hostname: "app.terrascale.tech", PathPrefix: "/admin",
			AllowCIDRs: []string{"100.64.0.0/10"}, Action: "block",
		}},
		RateRules: []RateRule{{
			Ref: "api-per-ip", Hostname: "api.terrascale.tech",
			RequestsPerPeriod: 1200, PeriodSeconds: 60, MitigationSeconds: 600,
		}},
	}
}

// The declared /admin rule: exactly the admin route tree (D-79), never
// sibling paths like "/administrator".
const declaredAdminExpression = `((http.host eq "app.terrascale.tech" and (http.request.uri.path eq "/admin" or starts_with(http.request.uri.path, "/admin/"))) and not ip.src in {100.64.0.0/10})`

const adminRule = `{"id":"f1","description":"terrascale:admin-tailscale-only","expression":"((http.host eq \"app.terrascale.tech\" and (http.request.uri.path eq \"/admin\" or starts_with(http.request.uri.path, \"/admin/\"))) and not ip.src in {100.64.0.0/10})","action":"block","enabled":true}`

const apiRateRule = `{"id":"f2","description":"terrascale:api-per-ip","expression":"(http.host eq \"api.terrascale.tech\" and starts_with(http.request.uri.path, \"/\"))","action":"block","action_parameters":{"characteristics":["ip.src"],"requests_per_period":1200,"period":60,"mitigation_timeout":600},"enabled":true}`

func wafFake(t *testing.T, firewall, rate string, statuses ...int) (*Client, *[]string) {
	t.Helper()
	firewallStatus, rateStatus := http.StatusOK, http.StatusOK
	if len(statuses) > 0 {
		firewallStatus = statuses[0]
	}
	if len(statuses) > 1 {
		rateStatus = statuses[1]
	}
	var methods []string
	success := func(status int) string {
		if status == http.StatusOK {
			return "true"
		}
		return "false"
	}
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		switch {
		case call.Method == http.MethodGet && strings.Contains(call.Path, "/rulesets/phases/http_request_firewall_custom/entrypoint"):
			return firewallStatus, `{"success":` + success(firewallStatus) + `,"result":{"rules":[` + firewall + `]}}`, nil
		case call.Method == http.MethodGet && strings.Contains(call.Path, "/rulesets/phases/http_ratelimit/entrypoint"):
			return rateStatus, `{"success":` + success(rateStatus) + `,"result":{"rules":[` + rate + `]}}`, nil
		case call.Method == http.MethodPut:
			methods = append(methods, call.Path)
			return okEnvelope("null")
		}
		return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
	})
	return c, &methods
}

func TestWAFAndRateRulesReconcile(t *testing.T) {
	cases := []struct {
		name       string
		firewall   string
		rate       string
		firewallSt int
		rateSt     int
		wantPlan   []string
		wantPuts   int
	}{
		{
			name:       "create both phases",
			firewallSt: http.StatusNotFound,
			rateSt:     http.StatusNotFound,
			wantPlan: []string{
				"create waf-rule " + declaredAdminExpression,
				"create rate-rule (http.host eq \"api.terrascale.tech\" and starts_with(http.request.uri.path, \"/\"))",
			},
			wantPuts: 2,
		},
		{
			name:     "no-op when declared",
			firewall: adminRule,
			rate:     apiRateRule,
		},
		{
			name:     "drift on the egress set is repaired",
			firewall: `{"id":"f1","description":"terrascale:admin-tailscale-only","expression":"((http.host eq \"app.terrascale.tech\" and (http.request.uri.path eq \"/admin\" or starts_with(http.request.uri.path, \"/admin/\"))) and not ip.src in {0.0.0.0/0})","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"update waf-rule " + declaredAdminExpression,
			},
			wantPuts: 1,
		},
		{
			name:     "a broad prefix rule is narrowed to the admin route tree",
			firewall: `{"id":"f1","description":"terrascale:admin-tailscale-only","expression":"((http.host eq \"app.terrascale.tech\" and starts_with(http.request.uri.path, \"/admin\")) and not ip.src in {100.64.0.0/10})","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"update waf-rule " + declaredAdminExpression,
			},
			wantPuts: 1,
		},
		{
			name:     "drift on the rate threshold is repaired",
			firewall: adminRule,
			rate:     `{"id":"f2","description":"terrascale:api-per-ip","expression":"(http.host eq \"api.terrascale.tech\" and starts_with(http.request.uri.path, \"/\"))","action":"block","action_parameters":{"characteristics":["ip.src"],"requests_per_period":50,"period":60,"mitigation_timeout":600},"enabled":true}`,
			wantPlan: []string{
				"update rate-rule (http.host eq \"api.terrascale.tech\" and starts_with(http.request.uri.path, \"/\"))",
			},
			wantPuts: 1,
		},
		{
			name:     "unowned console-clicked rules are preserved with an alert",
			firewall: adminRule + `,{"id":"fx","expression":"http.request.uri.path eq \"/wp-login.php\"","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"alert waf-rule preserving unowned Cloudflare rule fx",
			},
		},
		{
			name:     "an unowned rule blocking sync.api is preserved with an alert",
			firewall: adminRule + `,{"id":"fs","expression":"http.host eq \"sync.api.terrascale.tech\"","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"alert waf-rule preserving unowned Cloudflare rule fs",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firewall, rate := tc.firewall, tc.rate
			if tc.firewallSt == 0 {
				tc.firewallSt = http.StatusOK
			}
			if tc.rateSt == 0 {
				tc.rateSt = http.StatusOK
			}
			c, methods := wafFake(t, firewall, rate, tc.firewallSt, tc.rateSt)
			z := wafZone()
			p := &Plan{}
			if err := z.reconcileWAFAndRateRules(context.Background(), c, p); err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}
			if got := summarize(p); !reflect.DeepEqual(got, tc.wantPlan) {
				t.Fatalf("plan = %v\nwant %v", got, tc.wantPlan)
			}
			if err := Apply(context.Background(), p); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			if len(*methods) != tc.wantPuts {
				t.Fatalf("PUTs = %v, want %d", *methods, tc.wantPuts)
			}
		})
	}
}

// TestWAFAndRateRulesRefuseInvalidDeclarations pins the fail-closed side of
// the seam: a declaration that cannot express the D-79 restriction or a
// meaningful rate limit errors before any provider call or planned change.
func TestWAFAndRateRulesRefuseInvalidDeclarations(t *testing.T) {
	admin := FirewallRule{Ref: "admin-tailscale-only", Hostname: "app.terrascale.tech",
		PathPrefix: "/admin", AllowCIDRs: []string{"100.64.0.0/10"}, Action: "block"}
	rate := RateRule{Ref: "api-per-ip", Hostname: "api.terrascale.tech",
		RequestsPerPeriod: 1200, PeriodSeconds: 60, MitigationSeconds: 600}
	firewallZone := func(mutate func(*FirewallRule)) *Zone {
		r := admin
		if mutate != nil {
			mutate(&r)
		}
		return &Zone{ZoneName: "terrascale.tech", FirewallRules: []FirewallRule{r}, RateRules: []RateRule{rate}}
	}
	rateZone := func(mutate func(*RateRule)) *Zone {
		r := rate
		if mutate != nil {
			mutate(&r)
		}
		return &Zone{ZoneName: "terrascale.tech", FirewallRules: []FirewallRule{admin}, RateRules: []RateRule{r}}
	}
	cases := []struct {
		name    string
		zone    *Zone
		wantErr string
	}{
		{"firewall rule without a ref", firewallZone(func(r *FirewallRule) { r.Ref = "" }), "need a ref"},
		{"firewall rule without a hostname", firewallZone(func(r *FirewallRule) { r.Hostname = "" }), "needs a hostname"},
		{"firewall rule with a relative path prefix", firewallZone(func(r *FirewallRule) { r.PathPrefix = "admin" }), "must start with /"},
		{"firewall rule with an empty allowlist", firewallZone(func(r *FirewallRule) { r.AllowCIDRs = nil }), "at least one allowed CIDR"},
		{"firewall rule with a malformed CIDR", firewallZone(func(r *FirewallRule) { r.AllowCIDRs = []string{"100.64.0.0/10", "not-a-cidr"} }), "malformed CIDR"},
		{"firewall rule with a non-blocking action", firewallZone(func(r *FirewallRule) { r.Action = "log" }), `want block`},
		{"rate rule without a ref", rateZone(func(r *RateRule) { r.Ref = "" }), "need a ref"},
		{"rate rule without a threshold", rateZone(func(r *RateRule) { r.RequestsPerPeriod = 0 }), "must be positive"},
		{"rate rule with a zero period", rateZone(func(r *RateRule) { r.PeriodSeconds = 0 }), "outside 1..3600"},
		{"rate rule beyond the period limit", rateZone(func(r *RateRule) { r.PeriodSeconds = 3601 }), "outside 1..3600"},
		{"rate rule without a mitigation timeout", rateZone(func(r *RateRule) { r.MitigationSeconds = 0 }), "must be positive"},
		{"two firewall rules sharing a ref", &Zone{ZoneName: "terrascale.tech",
			FirewallRules: []FirewallRule{admin, admin}, RateRules: []RateRule{rate}}, "duplicate declared ref"},
		{"two rate rules sharing a ref", &Zone{ZoneName: "terrascale.tech",
			FirewallRules: []FirewallRule{admin}, RateRules: []RateRule{rate, rate}}, "duplicate declared ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
				t.Errorf("invalid declaration must not reach the provider: %v", call)
				return failEnvelope(http.StatusTeapot, 0, "unexpected")
			})
			p := &Plan{}
			err := tc.zone.reconcileWAFAndRateRules(context.Background(), c, p)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if len(p.Changes) != 0 {
				t.Fatalf("a refused declaration must plan nothing: %v", summarize(p))
			}
			if calls := ft.recorded(); len(calls) != 0 {
				t.Fatalf("a refused declaration must make no provider calls: %v", calls)
			}
		})
	}
}

func TestRateRuleParametersWire(t *testing.T) {
	var body string
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		switch {
		case call.Method == http.MethodGet:
			return http.StatusNotFound, `{"success":false}`, nil
		case call.Method == http.MethodPut && strings.Contains(call.Path, "http_ratelimit"):
			body = call.Body
			return okEnvelope("null")
		case call.Method == http.MethodPut:
			return okEnvelope("null")
		}
		return failEnvelope(http.StatusMethodNotAllowed, 0, "unexpected "+call.String())
	})
	z := wafZone()
	p := &Plan{}
	if err := z.reconcileWAFAndRateRules(context.Background(), c, p); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if err := Apply(context.Background(), p); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	for _, want := range []string{`"characteristics":["ip.src"]`, `"requests_per_period":1200`, `"period":60`, `"mitigation_timeout":600`} {
		if !strings.Contains(body, want) {
			t.Fatalf("rate rule body missing %s: %s", want, body)
		}
	}
}
