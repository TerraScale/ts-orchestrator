// Package seclist reconciles the rules of one owned OCI security list
// against a desired rule set.
//
// OCI replaces a security list's ingress and egress rules as a whole, so a
// spec owns every rule of its list. The list itself must already carry the
// controller's ownership tags for the desired key; otherwise it is foreign
// and nothing is changed. The reconciler never creates or deletes the list,
// and a tombstone relinquishes management without touching the rules: a
// subnet keeps its traffic when the reconciler stops managing it.
package seclist

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
)

// Kind is the desired-state kind for security list rule sets.
const Kind = "security-list-rules"

// maxRulesPerDirection is OCI's limit of ingress or egress rules per list.
const maxRulesPerDirection = 200

// Spec is the desired rule set of one security list. Rules use the NSG rule
// model; NSG peers are not valid in a security list.
type Spec struct {
	SecurityListID string     `json:"securityListId"`
	Rules          []nsg.Rule `json:"rules"`
	// AllowEmpty must be set to enforce a list with no rules in a
	// direction, which drops every packet that direction.
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// Validate rejects malformed, duplicated or NSG-peered rules and an empty
// direction unless explicitly allowed.
func (s Spec) Validate() error {
	if !strings.HasPrefix(s.SecurityListID, "ocid1.securitylist.") {
		return errors.New("security list spec requires a security list OCID")
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, rule := range s.Rules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if rule.EffectivePeerType() == nsg.PeerNSG {
			return errors.New("security list rules cannot name an NSG peer")
		}
		if seen[rule.Identity()] {
			return errors.New("security list spec repeats a rule")
		}
		seen[rule.Identity()] = true
		counts[rule.Direction]++
	}
	for direction, count := range counts {
		if count > maxRulesPerDirection {
			return fmt.Errorf("security list spec has %d %s rules, more than OCI's %d", count, direction, maxRulesPerDirection)
		}
	}
	if !s.AllowEmpty && (counts[nsg.DirectionIngress] == 0 || counts[nsg.DirectionEgress] == 0) {
		return errors.New("security list spec leaves a direction empty without allowEmpty")
	}
	return nil
}

// List is an observed security list.
type List struct {
	ID    string
	ETag  string
	Tags  ociresource.Tags
	Rules []nsg.Rule
}

// API is the narrow OCI seam.
type API interface {
	GetList(ctx context.Context, id string) (List, error)
	// UpdateList replaces every rule and the tags under If-Match etag.
	UpdateList(ctx context.Context, id, etag string, rules []nsg.Rule, tags ociresource.Tags) error
}

// Reconciler is the ociresource.Resource for security list rule sets.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, List] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (List, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return List{}, false, err
	}
	if target.Deleting {
		// Deletion relinquishes management and never strips the list.
		return List{}, false, nil
	}
	list, err := r.API.GetList(ctx, target.Spec.SecurityListID)
	if err != nil {
		return List{}, false, err
	}
	if list.ID != target.Spec.SecurityListID || !target.Ownership.Owns(target.Key, list.Tags) {
		return List{}, true, ociresource.ErrForeign
	}
	return list, true, nil
}

func identities(rules []nsg.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Identity())
	}
	slices.Sort(out)
	return out
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed List, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "security list %s is not visible", target.Spec.SecurityListID)
		return plan
	}
	want, have := identities(target.Spec.Rules), identities(observed.Rules)
	for _, identity := range want {
		if _, ok := slices.BinarySearch(have, identity); !ok {
			plan.Add("add-rule", "%s", identity)
		}
	}
	for index, identity := range have {
		if _, ok := slices.BinarySearch(want, identity); !ok || index > 0 && have[index-1] == identity {
			plan.Add("remove-rule", "%s", identity)
		}
	}
	if target.Ownership.Stale(observed.Tags, target.Generation, target.SpecDigest) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

// Apply writes the whole desired rule set and the restamped ownership tags in
// one If-Match update, so a concurrent out-of-band edit fails the write
// instead of being overwritten blind.
func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed List, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("security list %s is not visible; the reconciler never creates lists", target.Spec.SecurityListID)
	}
	if observed.ETag == "" {
		return errors.New("security list has no ETag; refusing an unconditional replace")
	}
	tags := observed.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
	if err := target.Fence(ctx); err != nil {
		return err
	}
	if err := r.API.UpdateList(ctx, target.Spec.SecurityListID, observed.ETag, slices.Clone(target.Spec.Rules), tags); err != nil {
		return fmt.Errorf("replace security list rules: %w", err)
	}
	return nil
}

// Delete is never reached: Observe reports a tombstoned list as not found so
// the record is purged without touching the cloud.
func (Reconciler) Delete(context.Context, ociresource.Target[Spec], List) error { return nil }
