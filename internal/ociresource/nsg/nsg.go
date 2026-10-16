// Package nsg reconciles the security rules of one owned OCI network security
// group against a desired rule set.
//
// The NSG itself must carry the controller's ownership tags for the desired
// key; otherwise it is foreign and nothing is changed. Rules created by the
// reconciler carry a description marker. A non-exclusive spec manages only
// marked rules and leaves rules created by other tools alone; an exclusive
// spec owns the whole rule set and removes every rule it does not want.
package nsg

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

// Kind is the desired-state kind for NSG rule sets.
const Kind = "nsg-rules"

// maxRulesPerCall is OCI's batch limit for add/remove security rule calls.
const maxRulesPerCall = 25

// maxRulesPerNSG is OCI's limit of security rules in one NSG; a larger spec
// could only ever be applied partway.
const maxRulesPerNSG = 120

const (
	DirectionIngress = "INGRESS"
	DirectionEgress  = "EGRESS"

	PeerCIDR    = "CIDR_BLOCK"
	PeerService = "SERVICE_CIDR_BLOCK"
	PeerNSG     = "NETWORK_SECURITY_GROUP"

	ProtocolAll  = "all"
	ProtocolTCP  = "6"
	ProtocolUDP  = "17"
	ProtocolICMP = "1"
)

// Rule is one normalized stateful or stateless security rule. Peer is the
// source for ingress and the destination for egress.
type Rule struct {
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	Peer        string `json:"peer"`
	PeerType    string `json:"peerType,omitempty"`
	PortMin     int    `json:"portMin,omitempty"`
	PortMax     int    `json:"portMax,omitempty"`
	Stateless   bool   `json:"stateless,omitempty"`
	Description string `json:"description,omitempty"`
	// unsupported marks an observed rule using features Rule does not model.
	unsupported bool
}

func (r Rule) peerType() string { return cmp.Or(r.PeerType, PeerCIDR) }

// EffectivePeerType is the peer type with the CIDR_BLOCK default applied.
func (r Rule) EffectivePeerType() string { return r.peerType() }

// identity is the rule's semantic tuple; descriptions do not affect matching.
func (r Rule) identity() string {
	return fmt.Sprintf("%s|%s|%s|%s|%d-%d|%t|%t", r.Direction, r.Protocol, r.peerType(), r.Peer, r.PortMin, r.PortMax,
		r.Stateless, r.unsupported)
}

// Identity is the rule's semantic tuple. The security-list reconciler models
// the same rule shape and matches rules by it.
func (r Rule) Identity() string { return r.identity() }

// MarkUnsupported returns the rule flagged as using OCI features Rule does
// not model (source ports, ICMP filters), so it never matches a desired rule.
func (r Rule) MarkUnsupported() Rule {
	r.unsupported = true
	return r
}

// Validate checks one rule in isolation.
func (r Rule) Validate() error { return r.validate() }

func (r Rule) validate() error {
	if r.Direction != DirectionIngress && r.Direction != DirectionEgress {
		return errors.New("NSG rule direction must be INGRESS or EGRESS")
	}
	switch r.Protocol {
	case ProtocolAll, ProtocolICMP:
		if r.PortMin != 0 || r.PortMax != 0 {
			return errors.New("NSG rule ports require TCP or UDP")
		}
	case ProtocolTCP, ProtocolUDP:
		if (r.PortMin == 0) != (r.PortMax == 0) || r.PortMin < 0 || r.PortMax > 65535 || r.PortMin > r.PortMax {
			return errors.New("NSG rule port range is invalid")
		}
	default:
		return fmt.Errorf("NSG rule protocol %q is unsupported", r.Protocol)
	}
	switch r.peerType() {
	case PeerCIDR:
		prefix, err := netip.ParsePrefix(r.Peer)
		if err != nil {
			return fmt.Errorf("NSG rule CIDR %q is invalid", r.Peer)
		}
		// OCI stores the masked network; a CIDR with host bits set would
		// never match the stored rule and be re-added on every pass.
		if canonical := prefix.Masked().String(); canonical != r.Peer {
			return fmt.Errorf("NSG rule CIDR %q is not canonical; use %q", r.Peer, canonical)
		}
	case PeerNSG:
		if !strings.HasPrefix(r.Peer, "ocid1.networksecuritygroup.") {
			return errors.New("NSG rule peer is not an NSG OCID")
		}
	case PeerService:
		if r.Peer == "" {
			return errors.New("NSG rule service peer is empty")
		}
	default:
		return fmt.Errorf("NSG rule peer type %q is unsupported", r.PeerType)
	}
	if len(r.Description) > 128 {
		return errors.New("NSG rule description is too long")
	}
	return nil
}

// Spec is the desired rule set of one NSG.
type Spec struct {
	NSGID     string `json:"nsgId"`
	Rules     []Rule `json:"rules"`
	Exclusive bool   `json:"exclusive,omitempty"`
}

// Validate rejects malformed or duplicated rules.
func (s Spec) Validate() error {
	if !strings.HasPrefix(s.NSGID, "ocid1.networksecuritygroup.") {
		return errors.New("NSG spec requires an NSG OCID")
	}
	if len(s.Rules) > maxRulesPerNSG {
		return fmt.Errorf("NSG spec has %d rules, more than OCI's %d per NSG", len(s.Rules), maxRulesPerNSG)
	}
	seen := map[string]bool{}
	for _, rule := range s.Rules {
		if err := rule.validate(); err != nil {
			return err
		}
		if seen[rule.identity()] {
			return errors.New("NSG spec repeats a rule")
		}
		seen[rule.identity()] = true
	}
	return nil
}

// Group is an observed NSG.
type Group struct {
	ID   string
	ETag string
	Tags ociresource.Tags
}

// ObservedRule is a rule as it exists in OCI.
type ObservedRule struct {
	ID   string
	Rule Rule
}

// API is the narrow OCI seam.
type API interface {
	GetGroup(ctx context.Context, id string) (Group, error)
	ListRules(ctx context.Context, id string) ([]ObservedRule, error)
	AddRules(ctx context.Context, id string, rules []Rule) error
	RemoveRules(ctx context.Context, id string, ruleIDs []string) error
	UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) error
}

// Observed is the group and its current rules.
type Observed struct {
	Group Group
	Rules []ObservedRule
}

// Reconciler is the ociresource.Resource for NSG rule sets.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, Observed] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

func marker(key ociresource.Key) string { return "terrascale/" + key.Name + ":" }

func managedDescription(key ociresource.Key, rule Rule) string {
	return strings.TrimSpace(marker(key) + " " + rule.Description)
}

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (Observed, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return Observed{}, false, err
	}
	group, err := r.API.GetGroup(ctx, target.Spec.NSGID)
	if target.Deleting && errors.Is(err, ociresource.ErrGone) {
		// The NSG and therefore every managed rule is gone.
		return Observed{}, false, nil
	}
	if err != nil {
		return Observed{}, false, err
	}
	if group.ID != target.Spec.NSGID || !target.Ownership.Owns(target.Key, group.Tags) {
		return Observed{}, true, ociresource.ErrForeign
	}
	rules, err := r.API.ListRules(ctx, target.Spec.NSGID)
	if err != nil {
		return Observed{}, false, err
	}
	if target.Deleting && !slices.ContainsFunc(rules, func(rule ObservedRule) bool { return deletable(target, rule) }) {
		return Observed{Group: group}, false, nil
	}
	return Observed{Group: group, Rules: rules}, true, nil
}

// deletable reports a rule a tombstoned spec removes: every rule carrying its
// marker, and under an exclusive spec also an unmarked rule the spec itself
// asked for (kept unmarked because it already existed when enforced). Rules
// the spec never named are left alone even in exclusive mode: a deletion
// relinquishes management and must not strip an NSG that member VNICs use.
func deletable(target ociresource.Target[Spec], rule ObservedRule) bool {
	if strings.HasPrefix(rule.Rule.Description, marker(target.Key)) {
		return true
	}
	return target.Spec.Exclusive && slices.ContainsFunc(target.Spec.Rules, func(wanted Rule) bool {
		return wanted.identity() == rule.Rule.identity()
	})
}

// changes computes rules to add and rule IDs to remove.
func changes(target ociresource.Target[Spec], observed Observed) (add []Rule, remove []ObservedRule) {
	want := map[string]Rule{}
	for _, rule := range target.Spec.Rules {
		want[rule.identity()] = rule
	}
	have := map[string]bool{}
	for _, existing := range observed.Rules {
		managed := target.Spec.Exclusive || strings.HasPrefix(existing.Rule.Description, marker(target.Key))
		identity := existing.Rule.identity()
		if _, wanted := want[identity]; wanted && !have[identity] {
			have[identity] = true
			continue
		}
		if managed {
			remove = append(remove, existing)
		}
	}
	for _, rule := range target.Spec.Rules {
		if !have[rule.identity()] {
			add = append(add, rule)
		}
	}
	slices.SortFunc(add, func(a, b Rule) int { return strings.Compare(a.identity(), b.identity()) })
	slices.SortFunc(remove, func(a, b ObservedRule) int { return strings.Compare(a.ID, b.ID) })
	return add, remove
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed Observed, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "NSG %s is not visible", target.Spec.NSGID)
		return plan
	}
	add, remove := changes(target, observed)
	for _, rule := range add {
		plan.Add("add-rule", "%s", rule.identity())
	}
	for _, rule := range remove {
		plan.Add("remove-rule", "%s %s", rule.ID, rule.Rule.identity())
	}
	if target.Ownership.Stale(observed.Group.Tags, target.Generation, target.SpecDigest) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed Observed, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("NSG %s is not visible; the reconciler never creates NSGs", target.Spec.NSGID)
	}
	add, remove := changes(target, observed)
	// Add before remove so a rule whose description changed never leaves a
	// window without the permission.
	for chunk := range slices.Chunk(add, maxRulesPerCall) {
		marked := make([]Rule, 0, len(chunk))
		for _, rule := range chunk {
			rule.Description = managedDescription(target.Key, rule)
			marked = append(marked, rule)
		}
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.AddRules(ctx, target.Spec.NSGID, marked); err != nil {
			return fmt.Errorf("add NSG rules: %w", err)
		}
	}
	for chunk := range slices.Chunk(remove, maxRulesPerCall) {
		ids := make([]string, 0, len(chunk))
		for _, rule := range chunk {
			ids = append(ids, rule.ID)
		}
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.RemoveRules(ctx, target.Spec.NSGID, ids); err != nil {
			return fmt.Errorf("remove NSG rules: %w", err)
		}
	}
	if target.Ownership.Stale(observed.Group.Tags, target.Generation, target.SpecDigest) {
		group := observed.Group
		if len(add)+len(remove) > 0 {
			// The rule changes advanced the NSG's ETag; restamp against a
			// fresh read, and only while it is still owned.
			fresh, err := r.API.GetGroup(ctx, target.Spec.NSGID)
			if err != nil {
				return fmt.Errorf("re-read NSG before restamp: %w", err)
			}
			if fresh.ID != target.Spec.NSGID || !target.Ownership.Owns(target.Key, fresh.Tags) {
				return ociresource.ErrForeign
			}
			group = fresh
		}
		tags := group.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.UpdateTags(ctx, target.Spec.NSGID, group.ETag, tags); err != nil {
			return fmt.Errorf("restamp NSG ownership: %w", err)
		}
	}
	return nil
}

// Delete removes the reconciler's rules. The NSG itself is not deleted: it is
// referenced by member host VNICs and owned by the region foundation.
func (r Reconciler) Delete(ctx context.Context, target ociresource.Target[Spec], observed Observed) error {
	var ids []string
	for _, rule := range observed.Rules {
		if deletable(target, rule) {
			ids = append(ids, rule.ID)
		}
	}
	for chunk := range slices.Chunk(ids, maxRulesPerCall) {
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.RemoveRules(ctx, target.Spec.NSGID, chunk); err != nil {
			return fmt.Errorf("remove NSG rules: %w", err)
		}
	}
	return nil
}
