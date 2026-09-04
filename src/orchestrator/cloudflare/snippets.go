package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SnippetRule declares the RULE that runs the sync.api gate Snippet (D-55).
// The snippet code itself lives in ts-proxy and is deployed through the
// Cloudflare API by ts-deploy (X-2); this reconciler only installs and
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
	Name   string            `json:"snippet_name"`
	Digest string            `json:"digest,omitempty"`
	Rules  []SnippetRuleWire `json:"rules"`
}

// SnippetAPI is the snippet-rules surface.
type SnippetAPI interface {
	ListSnippets(ctx context.Context) ([]Snippet, error)
	PutSnippetRules(ctx context.Context, snippet string, rules []SnippetRuleWire) error
}

var _ SnippetAPI = (*Client)(nil)

func (c *Client) ListSnippets(ctx context.Context) ([]Snippet, error) {
	var out []Snippet
	err := c.do(ctx, "list snippets", http.MethodGet, c.zonePath("/snippets"), nil, &out)
	return out, err
}

func (c *Client) PutSnippetRules(ctx context.Context, snippet string, rules []SnippetRuleWire) error {
	path := c.zonePath("/snippets/" + url.PathEscape(snippet) + "/rules")
	return c.do(ctx, "update snippet rules", http.MethodPut, path, map[string]any{"rules": rules}, nil)
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
