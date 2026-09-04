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

const adminRule = `{"id":"f1","description":"terrascale:admin-tailscale-only","expression":"((http.host eq \"app.terrascale.tech\" and starts_with(http.request.uri.path, \"/admin\")) and not ip.src in {100.64.0.0/10})","action":"block","enabled":true}`

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
				"create waf-rule ((http.host eq \"app.terrascale.tech\" and starts_with(http.request.uri.path, \"/admin\")) and not ip.src in {100.64.0.0/10})",
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
			firewall: `{"id":"f1","description":"terrascale:admin-tailscale-only","expression":"((http.host eq \"app.terrascale.tech\" and starts_with(http.request.uri.path, \"/admin\")) and not ip.src in {0.0.0.0/0})","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"update waf-rule ((http.host eq \"app.terrascale.tech\" and starts_with(http.request.uri.path, \"/admin\")) and not ip.src in {100.64.0.0/10})",
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
			name:     "orphan console-clicked rules are deleted",
			firewall: adminRule + `,{"id":"fx","expression":"http.request.uri.path eq \"/wp-login.php\"","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"delete waf-rule http.request.uri.path eq \"/wp-login.php\"",
			},
			wantPuts: 1,
		},
		{
			name:     "a foreign rule blocking sync.api is deleted",
			firewall: adminRule + `,{"id":"fs","expression":"http.host eq \"sync.api.terrascale.tech\"","action":"block","enabled":true}`,
			rate:     apiRateRule,
			wantPlan: []string{
				"delete waf-rule http.host eq \"sync.api.terrascale.tech\"",
			},
			wantPuts: 1,
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
