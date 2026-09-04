package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Rule is one rule inside a zone phase ruleset. Cache Rules, WAF custom
// rules, and rate limiting rules all share this shape; the phase decides the
// semantics. Our rules carry their identity in the rule description
// ("terrascale:<ref>"). A live rule without that prefix is foreign and is
// preserved: whole-list PUTs must not turn an incomplete observation into
// authority to delete someone else's rule.
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

// uniqueDeclaredRefs fails closed when two declared rules share a ref: they
// would collide in the phase diff and drift forever, so a declaration that
// cannot converge never reaches the provider.
func uniqueDeclaredRefs(phase string, rules []Rule) error {
	refs := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if _, dup := refs[r.Ref]; dup {
			return fmt.Errorf("%s rules: duplicate declared ref %q", phase, r.Ref)
		}
		refs[r.Ref] = struct{}{}
	}
	return nil
}

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
	if !validRulesetPhase(phase) {
		return nil, fmt.Errorf("cloudflare: ruleset phase is invalid")
	}
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
		candidate := strings.TrimPrefix(w.Description, refPrefix)
		if strings.HasPrefix(w.Description, refPrefix) && validRuleRef(candidate) && validCloudflareResourceID(w.ID) {
			ref = candidate
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
	if !validRulesetPhase(phase) {
		return fmt.Errorf("cloudflare: ruleset phase is invalid")
	}
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
	if err := uniqueDeclaredRefs(phase, want); err != nil {
		return err
	}
	live, err := api.PhaseRules(ctx, phase)
	if err != nil {
		return err
	}
	key := func(r Rule) string {
		if validRuleRef(r.Ref) && (r.ID == "" || ruleOwned(r)) {
			return r.Ref
		}
		return "\x00foreign:" + r.ID // foreign rules are all deletes; ID keeps keys unique
	}
	eq := func(a, b Rule) bool {
		return a.Expression == b.Expression && a.Action == b.Action &&
			a.Enabled == b.Enabled && jsonEqual(a.ActionParameters, b.ActionParameters)
	}
	owned := make([]Rule, 0, len(live))
	for _, rule := range live {
		if ruleOwned(rule) {
			owned = append(owned, rule)
		} else {
			p.Changes = append(p.Changes, Change{Action: Alert, Resource: resource, Ref: rule.Ref,
				Detail: "preserving unowned Cloudflare rule " + rule.ID})
		}
	}
	creates, deletes, updates := diff(owned, want, key, eq)
	// A ruleset PUT replaces the complete list. Re-observe immediately before
	// the first PUT, verify every owned input used by this plan is unchanged,
	// and merge the latest foreign rules into the write.
	applied := false
	apply := func(ctx context.Context) error {
		if applied {
			return nil
		}
		current, err := api.PhaseRules(ctx, phase)
		if err != nil {
			return err
		}
		for _, expected := range owned {
			found := false
			for _, candidate := range current {
				if candidate.ID != expected.ID {
					continue
				}
				found = true
				if !sameRule(candidate, expected) || !ruleOwned(candidate) {
					return fmt.Errorf("cloudflare: refusing stale or ownership-changed ruleset mutation for %s", expected.ID)
				}
				break
			}
			if !found {
				return fmt.Errorf("cloudflare: refusing ruleset mutation after owned rule %s disappeared", expected.ID)
			}
		}
		merged := make([]Rule, 0, len(current)+len(want))
		for _, rule := range current {
			if !ruleOwned(rule) {
				merged = append(merged, rule)
			}
		}
		merged = append(merged, want...)
		if err := api.PutPhaseRules(ctx, phase, merged); err != nil {
			return err
		}
		applied = true
		return nil
	}
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

func validRulesetPhase(phase string) bool {
	if len(phase) == 0 || len(phase) > 96 {
		return false
	}
	for _, r := range phase {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validRuleRef(ref string) bool {
	if len(ref) == 0 || len(ref) > 96 {
		return false
	}
	for _, r := range ref {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func ruleOwned(rule Rule) bool {
	return validCloudflareResourceID(rule.ID) && validRuleRef(rule.Ref)
}

func sameRule(a, b Rule) bool {
	return a.ID == b.ID && a.Ref == b.Ref && a.Expression == b.Expression && a.Action == b.Action &&
		a.Enabled == b.Enabled && jsonEqual(a.ActionParameters, b.ActionParameters)
}
