package cloudflare

import (
	"context"
	"net/http"
	"net/url"
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
	Name  string            `json:"snippet_name"`
	Rules []SnippetRuleWire `json:"rules"`
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
