package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
			r.expression(), strings.Join(r.AllowCIDRs, " ")),
	}
}

// expression anchors the rule to the host and to exactly the route tree at
// PathPrefix: "/admin" itself and everything below "/admin/" — never sibling
// paths such as "/administrator" that merely share the string prefix (D-79
// restricts the admin console, not the alphabet after it).
func (r FirewallRule) expression() string {
	return fmt.Sprintf("(http.host eq %q and %s)", r.Hostname, pathTree(r.PathPrefix))
}

// pathTree matches exactly a path and its subtree. A trailing slash on the
// declared prefix is normalized away; "/" is the whole host.
func pathTree(prefix string) string {
	base := strings.TrimSuffix(prefix, "/")
	if base == "" {
		return `starts_with(http.request.uri.path, "/")`
	}
	return fmt.Sprintf("(http.request.uri.path eq %q or starts_with(http.request.uri.path, %q))",
		base, base+"/")
}

// validate fails closed before anything is planned: a rule without identity,
// with an empty or malformed allowlist, or with any action but block would
// either be rejected by Cloudflare or silently disarm the D-79 restriction.
func (r FirewallRule) validate() error {
	if r.Ref == "" {
		return fmt.Errorf("waf rule: declared rules need a ref")
	}
	if r.Hostname == "" {
		return fmt.Errorf("waf rule %s: needs a hostname", r.Ref)
	}
	if !strings.HasPrefix(r.PathPrefix, "/") {
		return fmt.Errorf("waf rule %s: path prefix %q must start with /", r.Ref, r.PathPrefix)
	}
	if len(r.AllowCIDRs) == 0 {
		return fmt.Errorf("waf rule %s: needs at least one allowed CIDR; an empty allowlist blocks staff too (D-79)", r.Ref)
	}
	for _, cidr := range r.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("waf rule %s: malformed CIDR %q", r.Ref, cidr)
		}
	}
	if r.Action != "block" {
		return fmt.Errorf("waf rule %s: action %q not supported, want block", r.Ref, r.Action)
	}
	return nil
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

// validate fails closed before anything is planned: a rate rule with no
// threshold or window is meaningless, and Cloudflare accepts periods of
// 1..3600 seconds.
func (r RateRule) validate() error {
	if r.Ref == "" {
		return fmt.Errorf("rate rule: declared rules need a ref")
	}
	if r.Hostname == "" {
		return fmt.Errorf("rate rule %s: needs a hostname", r.Ref)
	}
	if r.RequestsPerPeriod <= 0 {
		return fmt.Errorf("rate rule %s: requests per period must be positive", r.Ref)
	}
	if r.PeriodSeconds < 1 || r.PeriodSeconds > 3600 {
		return fmt.Errorf("rate rule %s: period %d outside 1..3600 seconds", r.Ref, r.PeriodSeconds)
	}
	if r.MitigationSeconds <= 0 {
		return fmt.Errorf("rate rule %s: mitigation timeout must be positive", r.Ref)
	}
	return nil
}

func (z *Zone) reconcileWAFAndRateRules(ctx context.Context, c *Client, p *Plan) error {
	for _, r := range z.FirewallRules {
		if err := r.validate(); err != nil {
			return err
		}
	}
	for _, r := range z.RateRules {
		if err := r.validate(); err != nil {
			return err
		}
	}
	firewall := make([]Rule, 0, len(z.FirewallRules))
	for _, r := range z.FirewallRules {
		firewall = append(firewall, r.rule())
	}
	rates := make([]Rule, 0, len(z.RateRules))
	for _, r := range z.RateRules {
		rates = append(rates, r.rule())
	}
	if err := uniqueDeclaredRefs("http_request_firewall_custom", firewall); err != nil {
		return err
	}
	if err := uniqueDeclaredRefs("http_ratelimit", rates); err != nil {
		return err
	}
	if err := reconcilePhase(ctx, c, p, "http_request_firewall_custom", "waf-rule", firewall); err != nil {
		return err
	}
	return reconcilePhase(ctx, c, p, "http_ratelimit", "rate-rule", rates)
}
