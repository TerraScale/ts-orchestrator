package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Rule is one rule inside a zone phase ruleset. Cache Rules, WAF custom
// rules, and rate limiting rules all share this shape; the phase decides the
// semantics. Our rules carry their identity in the rule description
// ("terrascale:<ref>"); a live rule without that prefix is foreign and gets
// deleted — the whole zone is declared state (D-67).
type Rule struct {
	ID               string
	Ref              string // empty when the live rule is foreign
	Expression       string
	Action           string
	ActionParameters json.RawMessage
	Enabled          bool
}

type wireRule struct {
	ID               string          `json:"id,omitempty"`
	Description      string          `json:"description,omitempty"`
	Expression       string          `json:"expression"`
	Action           string          `json:"action"`
	ActionParameters json.RawMessage `json:"action_parameters,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
}

const refPrefix = "terrascale:"

func refDescription(ref string) string { return refPrefix + ref }

func (r Rule) wire() wireRule {
	enabled := r.Enabled
	return wireRule{ID: r.ID, Description: refDescription(r.Ref), Expression: r.Expression,
		Action: r.Action, ActionParameters: r.ActionParameters, Enabled: &enabled}
}

// RulesetAPI is the phase-ruleset surface shared by the Cache Rules and
// WAF/rate reconcilers.
type RulesetAPI interface {
	// PhaseRules returns the rules of a phase entrypoint; nil when the phase
	// was never configured.
	PhaseRules(ctx context.Context, phase string) ([]Rule, error)
	PutPhaseRules(ctx context.Context, phase string, rules []Rule) error
}

var _ RulesetAPI = (*Client)(nil)

func (c *Client) PhaseRules(ctx context.Context, phase string) ([]Rule, error) {
	var rs struct {
		Rules []wireRule `json:"rules"`
	}
	path := c.zonePath("/rulesets/phases/" + url.PathEscape(phase) + "/entrypoint")
	if err := c.do(ctx, "list "+phase+" rules", http.MethodGet, path, nil, &rs); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Rule, 0, len(rs.Rules))
	for _, w := range rs.Rules {
		ref := ""
		if strings.HasPrefix(w.Description, refPrefix) {
			ref = strings.TrimPrefix(w.Description, refPrefix)
		}
		enabled := w.Enabled != nil && *w.Enabled
		out = append(out, Rule{ID: w.ID, Ref: ref, Expression: w.Expression, Action: w.Action,
			ActionParameters: w.ActionParameters, Enabled: enabled})
	}
	return out, nil
}

// PutPhaseRules replaces the phase entrypoint's rule list with exactly the
// declared rules — whole-list semantics, which is the declared-state model.
func (c *Client) PutPhaseRules(ctx context.Context, phase string, rules []Rule) error {
	wire := make([]wireRule, 0, len(rules))
	for _, r := range rules {
		wire = append(wire, r.wire())
	}
	path := c.zonePath("/rulesets/phases/" + url.PathEscape(phase) + "/entrypoint")
	return c.do(ctx, "update "+phase+" rules", http.MethodPut, path, map[string]any{"rules": wire}, nil)
}

// reconcilePhase diffs one phase ruleset against the declared rules. Every
// change's apply PUTs the full declared list: phase entrypoint writes are
// whole-list anyway, so a second apply in the same pass is an idempotent
// no-op.
func reconcilePhase(ctx context.Context, api RulesetAPI, p *Plan, phase, resource string, want []Rule) error {
	live, err := api.PhaseRules(ctx, phase)
	if err != nil {
		return err
	}
	key := func(r Rule) string {
		if r.Ref != "" {
			return r.Ref
		}
		return "\x00foreign:" + r.ID // foreign rules are all deletes; ID keeps keys unique
	}
	eq := func(a, b Rule) bool {
		return a.Expression == b.Expression && a.Action == b.Action &&
			a.Enabled == b.Enabled && jsonEqual(a.ActionParameters, b.ActionParameters)
	}
	creates, deletes, updates := diff(live, want, key, eq)
	apply := func(ctx context.Context) error { return api.PutPhaseRules(ctx, phase, want) }
	for _, r := range creates {
		p.Changes = append(p.Changes, Change{Action: Create, Resource: resource, Ref: r.Ref, Detail: r.Expression, apply: apply})
	}
	for _, u := range updates {
		p.Changes = append(p.Changes, Change{Action: Update, Resource: resource, Ref: u.Want.Ref, Detail: u.Want.Expression, apply: apply})
	}
	for _, r := range deletes {
		p.Changes = append(p.Changes, Change{Action: Delete, Resource: resource, Ref: r.Ref, Detail: r.Expression, apply: apply})
	}
	return nil
}
