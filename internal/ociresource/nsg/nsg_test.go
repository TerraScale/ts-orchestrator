package nsg

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const nsgID = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller"

type fakeAPI struct {
	group  Group
	rules  []ObservedRule
	nextID int
	calls  []string
	gone   bool
}

func (f *fakeAPI) GetGroup(context.Context, string) (Group, error) {
	if f.gone {
		return Group{}, fmt.Errorf("get OCI NSG: %w", ociresource.ErrGone)
	}
	return f.group, nil
}
func (f *fakeAPI) ListRules(context.Context, string) ([]ObservedRule, error) {
	return slices.Clone(f.rules), nil
}
func (f *fakeAPI) AddRules(_ context.Context, _ string, rules []Rule) error {
	f.calls = append(f.calls, fmt.Sprintf("add %d", len(rules)))
	f.group.ETag += "+" // a rule change advances the NSG's ETag, as OCI does
	for _, rule := range rules {
		f.nextID++
		f.rules = append(f.rules, ObservedRule{ID: fmt.Sprintf("r%d", f.nextID), Rule: rule})
	}
	return nil
}
func (f *fakeAPI) RemoveRules(_ context.Context, _ string, ids []string) error {
	f.calls = append(f.calls, fmt.Sprintf("remove %d", len(ids)))
	f.group.ETag += "-"
	f.rules = slices.DeleteFunc(f.rules, func(rule ObservedRule) bool { return slices.Contains(ids, rule.ID) })
	return nil
}
func (f *fakeAPI) UpdateTags(_ context.Context, _, etag string, tags ociresource.Tags) error {
	if etag != f.group.ETag {
		return fmt.Errorf("etag mismatch")
	}
	f.calls = append(f.calls, "tags")
	f.group.Tags, f.group.ETag = tags, etag+"'"
	return nil
}

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

var key = ociresource.Key{Region: "GRU", Kind: Kind, Name: "controller"}

func owned(owner ociresource.Ownership) Group {
	return Group{ID: nsgID, ETag: "e1", Tags: ociresource.Tags{Freeform: map[string]string{"cost-center": "infra"}}.Merge(owner.Stamp(key, 0, ""))}
}

func https(cidr string) Rule {
	return Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: cidr, PortMin: 443, PortMax: 443, Description: "public API"}
}

func run(t *testing.T, api *fakeAPI, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy, generation uint64) ociresource.Result {
	t.Helper()
	desired, err := ociresource.NewDesired(key, generation, policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := store.Get(t.Context(), key); err != nil || current.SpecDigest != desired.SpecDigest {
		if _, err := store.Put(t.Context(), desired); err != nil {
			t.Fatal(err)
		}
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNSGRulesConvergeAndLeaveForeignRulesAlone(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	foreign := ObservedRule{ID: "manual", Rule: Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/8", PortMin: 22, PortMax: 22, Description: "operator ssh"}}
	api := &fakeAPI{group: owned(owner), rules: []ObservedRule{foreign}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0"), {Direction: DirectionEgress, Protocol: ProtocolAll, Peer: "0.0.0.0/0"}}}

	if result := run(t, api, store, spec, ociresource.PolicyEnforce, 1); result.Applied != 1 {
		t.Fatalf("result=%+v", result)
	}
	if len(api.rules) != 3 || !slices.Contains(api.rules, foreign) {
		t.Fatalf("rules=%+v", api.rules)
	}
	for _, rule := range api.rules[1:] {
		if !strings.HasPrefix(rule.Rule.Description, "terrascale/controller:") {
			t.Fatalf("managed rule lacks marker: %+v", rule)
		}
	}
	if !owner.Owns(key, api.group.Tags) || api.group.Tags.Freeform["cost-center"] != "infra" {
		t.Fatalf("tags=%v", api.group.Tags)
	}
	if result := run(t, api, store, spec, ociresource.PolicyEnforce, 1); result.InSync != 1 {
		t.Fatalf("second pass result=%+v calls=%v", result, api.calls)
	}

	// Someone widens a managed rule out of band; the drift is corrected.
	api.rules[1].Rule.Peer = "0.0.0.0/1"
	if result := run(t, api, store, spec, ociresource.PolicyEnforce, 1); result.Applied != 1 {
		t.Fatalf("drift result=%+v", result)
	}
	if slices.ContainsFunc(api.rules, func(rule ObservedRule) bool { return rule.Rule.Peer == "0.0.0.0/1" }) || !slices.Contains(api.rules, foreign) {
		t.Fatalf("rules=%+v", api.rules)
	}

	// Exclusive ownership removes the operator rule too.
	spec.Exclusive = true
	run(t, api, store, spec, ociresource.PolicyEnforce, 2)
	if slices.Contains(api.rules, foreign) || len(api.rules) != 2 {
		t.Fatalf("exclusive rules=%+v", api.rules)
	}
}

func TestNSGWithoutOwnershipIsNeverChanged(t *testing.T) {
	api := &fakeAPI{group: Group{ID: nsgID, ETag: "e1"}}
	store := ociresource.NewMemoryStore()
	result := run(t, api, store, Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}, Exclusive: true}, ociresource.PolicyEnforce, 1)
	if result.Foreign != 1 || len(api.calls) != 0 {
		t.Fatalf("result=%+v calls=%v", result, api.calls)
	}
}

func TestNSGTombstoneRemovesOnlyMarkedRules(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	foreign := ObservedRule{ID: "manual", Rule: https("10.0.0.0/8")}
	api := &fakeAPI{group: owned(owner), rules: []ObservedRule{foreign}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	if !slices.Equal(api.rules, []ObservedRule{foreign}) {
		t.Fatalf("rules=%+v", api.rules)
	}
	if _, err := store.Get(t.Context(), key); err == nil {
		t.Fatal("tombstone was not purged after the rules were gone")
	}
}

func TestNSGTombstonePurgesWhenTheNSGIsGone(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	api := &fakeAPI{group: owned(owner)}
	store := ociresource.NewMemoryStore()
	spec := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}

	mutations := len(api.calls)
	// A missing NSG is an error while the spec is live: nothing is assumed.
	api.gone = true
	if result, err := controller.Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing NSG: result=%+v err=%v", result, err)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller.Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing NSG: result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), key); err == nil {
		t.Fatal("tombstone was not purged after the NSG was gone")
	}
	if len(api.calls) != mutations {
		t.Fatalf("unexpected mutations: %v", api.calls)
	}
}

func TestSpecValidationAndBatching(t *testing.T) {
	for _, spec := range []Spec{
		{NSGID: "ocid1.subnet.oc1..x"},
		{NSGID: nsgID, Rules: []Rule{{Direction: "SIDEWAYS", Protocol: ProtocolAll, Peer: "0.0.0.0/0"}}},
		{NSGID: nsgID, Rules: []Rule{{Direction: DirectionIngress, Protocol: ProtocolAll, Peer: "0.0.0.0/0", PortMin: 1, PortMax: 2}}},
		{NSGID: nsgID, Rules: []Rule{{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "not-a-cidr", PortMin: 1, PortMax: 2}}},
		{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0"), https("0.0.0.0/0")}},
	} {
		if spec.Validate() == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	api := &fakeAPI{group: owned(owner)}
	spec := Spec{NSGID: nsgID}
	for port := range 30 {
		spec.Rules = append(spec.Rules, Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/16", PortMin: 1000 + port, PortMax: 1000 + port})
	}
	run(t, api, ociresource.NewMemoryStore(), spec, ociresource.PolicyEnforce, 1)
	if !slices.Equal(api.calls, []string{"add 25", "add 5", "tags"}) {
		t.Fatalf("calls=%v", api.calls)
	}
}

func TestNormalizeMarksUnsupportedFeatures(t *testing.T) {
	sourcePorts := core.SecurityRule{Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"), Source: new("0.0.0.0/0"),
		SourceType: core.SecurityRuleSourceTypeCidrBlock, TcpOptions: &core.TcpOptions{SourcePortRange: &core.PortRange{Min: new(1), Max: new(2)}}}
	if rule := normalize(sourcePorts); !rule.unsupported {
		t.Fatal("source port range was modeled")
	}
	plain := core.SecurityRule{Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"), Source: new("0.0.0.0/0"),
		SourceType: core.SecurityRuleSourceTypeCidrBlock, TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(443), Max: new(443)}}}
	got := normalize(plain)
	want := https("0.0.0.0/0")
	if got.identity() != want.identity() {
		t.Fatalf("got %s want %s", got.identity(), want.identity())
	}
	if details := addDetails(want); details.TcpOptions == nil || *details.TcpOptions.DestinationPortRange.Min != 443 ||
		details.SourceType != core.AddSecurityRuleDetailsSourceTypeCidrBlock {
		t.Fatalf("details=%+v", details)
	}
}

func TestExclusiveTombstoneRemovesTheRulesItManaged(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	kept := ObservedRule{ID: "pre-existing", Rule: https("0.0.0.0/0")}
	api := &fakeAPI{group: owned(owner), rules: []ObservedRule{kept}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NSGID: nsgID, Exclusive: true, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	if len(api.rules) != 1 || api.rules[0].ID != "pre-existing" {
		t.Fatalf("an existing matching rule was not kept unmarked: %+v", api.rules)
	}
	// A rule added out of band after enforcement is not part of the spec.
	later := ObservedRule{ID: "later", Rule: Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/8",
		PortMin: 22, PortMax: 22}}
	api.rules = append(api.rules, later)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	}
	if len(api.rules) != 1 || api.rules[0].ID != "later" {
		t.Fatalf("exclusive tombstone left %+v, want only the rule the spec never named", api.rules)
	}
	if _, err := store.Get(t.Context(), key); err == nil {
		t.Fatal("the tombstoned record was not purged")
	}
}

func TestRestampAfterRuleChangesUsesAFreshETag(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	api := &fakeAPI{group: owned(owner)}
	store := ociresource.NewMemoryStore()
	result := run(t, api, store, Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}, ociresource.PolicyEnforce, 1)
	if result.Failed != 0 || !slices.Equal(api.calls, []string{"add 1", "tags"}) {
		t.Fatalf("result=%+v calls=%v", result, api.calls)
	}
}

func TestSpecBoundsRulesAndRequiresCanonicalCIDRs(t *testing.T) {
	var rules []Rule
	for port := range maxRulesPerNSG + 1 {
		rules = append(rules, Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/8", PortMin: port + 1, PortMax: port + 1})
	}
	if err := (Spec{NSGID: nsgID, Rules: rules}).Validate(); err == nil {
		t.Fatal("a spec over OCI's per-NSG rule limit validated")
	}
	if err := (Spec{NSGID: nsgID, Rules: rules[:maxRulesPerNSG]}).Validate(); err != nil {
		t.Fatalf("a spec at the limit failed: %v", err)
	}
	if err := (Spec{NSGID: nsgID, Rules: []Rule{https("10.0.0.1/8")}}).Validate(); err == nil {
		t.Fatal("a CIDR with host bits set validated")
	}
}
