package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// FirewallRule declares one WAF custom rule. The /admin rule (D-79) blocks
// every request that does not arrive from the declared Tailscale egress
// ranges.
type FirewallRule struct {
	Ref        string
	Hostname   string
	PathPrefix string
	AllowCIDRs []string // requests from these CIDRs pass; everything else is blocked
	Action     string   // "block"
}

func (r FirewallRule) rule() Rule {
	return Rule{
		Ref:     r.Ref,
		Action:  r.Action,
		Enabled: true,
		Expression: fmt.Sprintf("(%s and not ip.src in {%s})",
			hostPathExpression(r.Hostname, r.PathPrefix), strings.Join(r.AllowCIDRs, " ")),
	}
}

// RateRule declares one per-IP rate limiting rule. It is a coarse edge
// backstop; the real guards live in the engine per database (D-64).
type RateRule struct {
	Ref               string
	Hostname          string
	RequestsPerPeriod int
	PeriodSeconds     int
	MitigationSeconds int
}

func (r RateRule) rule() Rule {
	params, _ := json.Marshal(map[string]any{
		"characteristics":     []string{"ip.src"},
		"requests_per_period": r.RequestsPerPeriod,
		"period":              r.PeriodSeconds,
		"mitigation_timeout":  r.MitigationSeconds,
	})
	return Rule{Ref: r.Ref, Expression: hostPathExpression(r.Hostname, "/"),
		Action: "block", ActionParameters: params, Enabled: true}
}

func (z *Zone) reconcileWAFAndRateRules(ctx context.Context, c *Client, p *Plan) error {
	firewall := make([]Rule, 0, len(z.FirewallRules))
	for _, r := range z.FirewallRules {
		firewall = append(firewall, r.rule())
	}
	if err := reconcilePhase(ctx, c, p, "http_request_firewall_custom", "waf-rule", firewall); err != nil {
		return err
	}
	rates := make([]Rule, 0, len(z.RateRules))
	for _, r := range z.RateRules {
		rates = append(rates, r.rule())
	}
	return reconcilePhase(ctx, c, p, "http_ratelimit", "rate-rule", rates)
}
