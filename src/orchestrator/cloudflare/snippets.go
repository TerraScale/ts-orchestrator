package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// SnippetRule declares the RULE that runs the sync.api gate Snippet (D-55).
// The snippet code itself lives in ts-proxy. ts-deploy submits the signed
// candidate and the orchestrator uploads it. This reconciler installs and
// updates the rule on the deployed snippet. Pro allows 25 snippets per zone
// (D-63) — one gate is all we need.
type SnippetRule struct {
	SnippetName string
	Hostname    string
	PathPrefix  string
	Enabled     bool
}

// SnippetRuleWire is the wire shape of one snippet rule.
type SnippetRuleWire struct {
	Expression  string `json:"expression"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type Snippet struct {
	Name  string            `json:"snippet_name"`
	Rules []SnippetRuleWire `json:"-"`
}

// SnippetAPI is the snippet-rules surface.
type SnippetAPI interface {
	ListSnippets(ctx context.Context) ([]Snippet, error)
	PutSnippetRules(ctx context.Context, snippet string, rules []SnippetRuleWire) error
}

var _ SnippetAPI = (*Client)(nil)

// zoneSnippetRule is Cloudflare's zone-wide snippet_rules wire contract.
// Snippet.Rules above is a local join, never embedded in the metadata API.
type zoneSnippetRule struct {
	SnippetName string `json:"snippet_name"`
	SnippetRuleWire
}

func (c *Client) ListSnippets(ctx context.Context) ([]Snippet, error) {
	var out []Snippet
	if err := c.do(ctx, "list snippets", http.MethodGet, c.zonePath("/snippets"), nil, &out); err != nil {
		return nil, err
	}
	rules, _, err := c.snippetRules(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		for _, rule := range rules {
			if rule.SnippetName == out[i].Name {
				out[i].Rules = append(out[i].Rules, rule.SnippetRuleWire)
			}
		}
	}
	return out, nil
}

func (c *Client) snippetRules(ctx context.Context) ([]zoneSnippetRule, string, error) {
	status, headers, raw, err := c.roundtripContent(ctx, "list zone snippet rules", http.MethodGet, c.zonePath("/snippets/snippet_rules"), nil, "", "application/json")
	if err != nil {
		return nil, "", err
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		return nil, "", &APIError{Op: "list zone snippet rules", Status: status, Message: "malformed response envelope"}
	}
	if status < 200 || status >= 300 || !env.Success {
		return nil, "", apiErrorFromEnvelope("list zone snippet rules", status, raw)
	}
	var result struct {
		Rules *[]zoneSnippetRule `json:"rules"`
	}
	if err := json.Unmarshal(env.Result, &result); err != nil {
		return nil, "", err
	}
	if result.Rules == nil {
		return nil, "", errors.New("cloudflare: zone snippet rules response is missing the rule list")
	}
	return *result.Rules, headers.Get("ETag"), nil
}

// PutSnippetRules replaces only rules owned by the named TerraScale snippet.
// Cloudflare replaces the entire zone list, so retain unrelated rules and their
// order. Use the provider ETag when supplied; a conflict must be re-observed by
// the next reconciliation, never retried with a fresh tag and a stale payload.
func (c *Client) PutSnippetRules(ctx context.Context, snippet string, rules []SnippetRuleWire) error {
	if strings.TrimSpace(snippet) == "" {
		return errors.New("cloudflare: snippet name is required")
	}
	for _, rule := range rules {
		if rule.Description != refDescription(snippet) || strings.TrimSpace(rule.Expression) == "" {
			return errors.New("cloudflare: snippet rule must carry the declared ownership description")
		}
	}
	c.snippetMu.Lock()
	defer c.snippetMu.Unlock()
	current, etag, err := c.snippetRules(ctx)
	if err != nil {
		return err
	}
	desired := make([]zoneSnippetRule, 0, len(current)+len(rules))
	inserted := false
	insert := func() {
		for _, rule := range rules {
			desired = append(desired, zoneSnippetRule{SnippetName: snippet, SnippetRuleWire: rule})
		}
		inserted = true
	}
	for _, rule := range current {
		if rule.SnippetName != snippet {
			desired = append(desired, rule)
			continue
		}
		if rule.Description != refDescription(snippet) {
			return errors.New("cloudflare: refusing to replace an unowned snippet rule")
		}
		if !inserted {
			insert()
		}
	}
	if !inserted {
		insert()
	}
	payload, err := json.Marshal(map[string]any{"rules": desired})
	if err != nil {
		return err
	}
	headers := http.Header{}
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	status, _, raw, err := c.roundtripContent(ctx, "update zone snippet rules", http.MethodPut, c.zonePath("/snippets/snippet_rules"), payload, "application/json", "application/json", headers)
	if err != nil {
		return err
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		return &APIError{Op: "update zone snippet rules", Status: status, Message: "malformed response envelope"}
	}
	if status < 200 || status >= 300 || !env.Success {
		return apiErrorFromEnvelope("update zone snippet rules", status, raw)
	}
	observed, _, err := c.snippetRules(ctx)
	if err != nil {
		return err
	}
	if len(observed) != len(desired) {
		return errors.New("cloudflare: snippet rule readback changed the zone list")
	}
	for i := range desired {
		if observed[i] != desired[i] {
			return errors.New("cloudflare: snippet rule readback differs from requested zone list")
		}
	}
	return nil
}

func (z *Zone) reconcileSnippets(ctx context.Context, c *Client, p *Plan) error {
	if err := z.validateGateDeclaration(); err != nil {
		return err
	}
	live, err := c.ListSnippets(ctx)
	if err != nil {
		return err
	}
	byName := make(map[string]Snippet, len(live))
	for _, s := range live {
		byName[s.Name] = s
	}
	for _, want := range z.SnippetRules {
		s, ok := byName[want.SnippetName]
		if !ok {
			// The gate code arrives with a ts-proxy release; a missing
			// snippet is drift we surface, never something this reconciler
			// can create.
			p.Changes = append(p.Changes, Change{Action: Alert, Resource: "snippet-rule", Ref: want.SnippetName,
				Detail: "snippet code not deployed (ships with ts-proxy releases, X-2)"})
			continue
		}
		rules := []SnippetRuleWire{{
			Expression:  hostPathExpression(want.Hostname, want.PathPrefix),
			Description: refDescription(want.SnippetName),
			Enabled:     want.Enabled,
		}}
		if len(s.Rules) == 1 && s.Rules[0] == rules[0] {
			continue
		}
		snippet, rules := want.SnippetName, rules
		p.Changes = append(p.Changes, Change{Action: Update, Resource: "snippet-rule", Ref: snippet,
			Detail: rules[0].Expression,
			apply:  func(ctx context.Context) error { return c.PutSnippetRules(ctx, snippet, rules) }})
	}
	return nil
}

// validateGateDeclaration enforces the D-55 gate invariants on the declared
// zone before anything is planned (fail closed): no Worker route may cover a
// hostname the gate Snippet serves — every Worker request is billed even on a
// cache hit, which free fan-out cannot carry — and one snippet carries at
// most one declared binding, because two rules PUT against the same snippet
// would oscillate instead of converging.
func (z *Zone) validateGateDeclaration() error {
	seen := make(map[string]bool, len(z.SnippetRules))
	for _, want := range z.SnippetRules {
		if seen[want.SnippetName] {
			return fmt.Errorf("cloudflare: snippet %q declared twice; one snippet carries one binding", want.SnippetName)
		}
		seen[want.SnippetName] = true
		for _, route := range z.WorkerRoutes {
			if routeCoversHost(route.Pattern, want.Hostname) {
				return fmt.Errorf("cloudflare: worker route %q covers gate hostname %s; no Worker runs on the reactive path (D-55)",
					route.Pattern, want.Hostname)
			}
		}
	}
	return nil
}

// routeCoversHost reports whether a Cloudflare Worker route pattern matches
// requests for host. Patterns are "<host>", "<host>/*", or "<host>/*path";
// a leading or trailing "*" on the host part is a wildcard ("*.zone" covers
// every subdomain, "sync.*" covers every name with that prefix). An exact
// host matches itself, not its subdomains.
func routeCoversHost(pattern, host string) bool {
	hostPart := pattern
	if i := strings.Index(hostPart, "/"); i >= 0 {
		hostPart = hostPart[:i]
	}
	switch {
	case len(hostPart) >= 2 && strings.HasPrefix(hostPart, "*") && strings.HasSuffix(hostPart, "*"):
		return strings.Contains(host, strings.Trim(hostPart, "*"))
	case strings.HasPrefix(hostPart, "*"):
		return strings.HasSuffix(host, strings.TrimPrefix(hostPart, "*"))
	case strings.HasSuffix(hostPart, "*"):
		return strings.HasPrefix(host, strings.TrimSuffix(hostPart, "*"))
	default:
		return hostPart == host
	}
}
