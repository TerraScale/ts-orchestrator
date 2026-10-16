package nsg

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
)

const nsgID = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller"

type providerState struct {
	group        Group
	rules        []ObservedRule
	nextID       int
	calls        []string
	gone         bool
	api          API
	loseResponse bool
	onRead       func()
}

func (f *providerState) GetGroup(context.Context, string) (Group, error) {
	if f.gone {
		return Group{}, fmt.Errorf("get OCI NSG: %w", ociresource.ErrGone)
	}
	return f.group, nil
}
func (f *providerState) ListRules(context.Context, string) ([]ObservedRule, error) {
	return slices.Clone(f.rules), nil
}
func (f *providerState) AddRules(_ context.Context, _ string, rules []Rule) error {
	f.calls = append(f.calls, fmt.Sprintf("add %d", len(rules)))
	f.group.ETag += "+" // a rule change advances the NSG's ETag, as OCI does
	for _, rule := range rules {
		f.nextID++
		f.rules = append(f.rules, ObservedRule{ID: fmt.Sprintf("r%d", f.nextID), Rule: rule})
	}
	return nil
}
func (f *providerState) RemoveRules(_ context.Context, _ string, ids []string) error {
	f.calls = append(f.calls, fmt.Sprintf("remove %d", len(ids)))
	f.group.ETag += "-"
	f.rules = slices.DeleteFunc(f.rules, func(rule ObservedRule) bool { return slices.Contains(ids, rule.ID) })
	return nil
}
func (f *providerState) UpdateTags(_ context.Context, _, etag string, tags ociresource.Tags) error {
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

func run(t *testing.T, api *providerState, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy, generation uint64) ociresource.Result {
	t.Helper()
	confirm(t, api, store)
	desired, err := ociresource.NewDesired(key, generation, policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := store.Get(t.Context(), key); err != nil || current.SpecDigest != desired.SpecDigest {
		if _, err := store.Put(t.Context(), desired); err != nil {
			t.Fatal(err)
		}
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
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
	api := &providerState{group: owned(owner), rules: []ObservedRule{foreign}}
	store := persistentStore(t)
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
	api := &providerState{group: Group{ID: nsgID, ETag: "e1"}}
	store := persistentStore(t)
	result := run(t, api, store, Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}, Exclusive: true}, ociresource.PolicyEnforce, 1)
	if result.Foreign != 1 || len(api.calls) != 0 {
		t.Fatalf("result=%+v calls=%v", result, api.calls)
	}
}

func TestNSGTombstoneRemovesOnlyMarkedRules(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	foreign := ObservedRule{ID: "manual", Rule: https("10.0.0.0/8")}
	api := &providerState{group: owned(owner), rules: []ObservedRule{foreign}}
	store := persistentStore(t)
	spec := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	confirm(t, api, store)
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
	api := &providerState{group: owned(owner)}
	store := persistentStore(t)
	spec := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: allow{}}

	mutations := len(api.calls)
	// A missing NSG is an error while the spec is live: nothing is assumed.
	confirm(t, api, store)
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
		if _, err := ociresource.Publish(t.Context(), persistentStore(t), key, ociresource.PolicyEnforce, spec); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	api := &providerState{group: owned(owner)}
	spec := Spec{NSGID: nsgID}
	for port := range 30 {
		spec.Rules = append(spec.Rules, Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/16", PortMin: 1000 + port, PortMax: 1000 + port})
	}
	run(t, api, persistentStore(t), spec, ociresource.PolicyEnforce, 1)
	if !slices.Equal(api.calls, []string{"add 25", "add 5", "tags"}) {
		t.Fatalf("calls=%v", api.calls)
	}
}

func TestSDKPreservesUnsupportedRulesAndEncodesDestinationPorts(t *testing.T) {
	owner := ociresource.Ownership{Owner: "cell-gru"}
	sourcePorts := core.SecurityRule{Id: new("source"), Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"), Source: new("0.0.0.0/0"), SourceType: core.SecurityRuleSourceTypeCidrBlock, TcpOptions: &core.TcpOptions{SourcePortRange: &core.PortRange{Min: new(1), Max: new(2)}}}
	plain := core.SecurityRule{Id: new("plain"), Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"), Source: new("0.0.0.0/0"), SourceType: core.SecurityRuleSourceTypeCidrBlock, TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(443), Max: new(443)}}}
	var sent core.AddNetworkSecurityGroupSecurityRulesDetails
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		var value any
		switch {
		case r.Method == http.MethodPost:
			if err := json.UnmarshalRead(r.Body, &sent); err != nil {
				t.Error(err)
			}
			value = map[string]any{"securityRules": []any{}}
		case strings.HasSuffix(r.URL.Path, "/securityRules"):
			value = []core.SecurityRule{sourcePorts, plain}
		default:
			value = core.NetworkSecurityGroup{Id: new(nsgID), FreeformTags: owner.Stamp(key, 1, "d").Freeform}
		}
		if err := json.MarshalWrite(w, value); err != nil {
			t.Error(err)
		}
	})
	network, err := factory.Network()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&network.BaseClient, endpoint)
	api := sdkAPI{network: network}
	target := ociresource.Target[Spec]{Key: key, Generation: 1, SpecDigest: "d", Ownership: owner, Spec: Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}}
	observed, found, err := (Reconciler{API: api}).Observe(t.Context(), target)
	if err != nil || !found || len(observed.Rules) != 2 || !observed.Rules[0].Rule.unsupported || observed.Rules[1].Rule.identity() != https("0.0.0.0/0").identity() {
		t.Fatalf("observed=%+v found=%v err=%v", observed, found, err)
	}
	if err := api.AddRules(t.Context(), nsgID, target.Spec.Rules); err != nil {
		t.Fatal(err)
	}
	if len(sent.SecurityRules) != 1 || sent.SecurityRules[0].TcpOptions == nil || *sent.SecurityRules[0].TcpOptions.DestinationPortRange.Min != 443 || sent.SecurityRules[0].SourceType != core.AddSecurityRuleDetailsSourceTypeCidrBlock {
		t.Fatalf("sent=%+v", sent)
	}
}

func TestExclusiveTombstoneRemovesTheRulesItManaged(t *testing.T) {
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	kept := ObservedRule{ID: "pre-existing", Rule: https("0.0.0.0/0")}
	api := &providerState{group: owned(owner), rules: []ObservedRule{kept}}
	store := persistentStore(t)
	spec := Spec{NSGID: nsgID, Exclusive: true, Rules: []Rule{https("0.0.0.0/0")}}
	run(t, api, store, spec, ociresource.PolicyEnforce, 1)
	if len(api.rules) != 1 || api.rules[0].ID != "pre-existing" {
		t.Fatalf("an existing matching rule was not kept unmarked: %+v", api.rules)
	}
	// A rule added out of band after enforcement is not part of the spec.
	later := ObservedRule{ID: "later", Rule: Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/8",
		PortMin: 22, PortMax: 22}}
	confirm(t, api, store)
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
	api := &providerState{group: owned(owner)}
	store := persistentStore(t)
	result := run(t, api, store, Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}, ociresource.PolicyEnforce, 1)
	if result.Failed != 0 || !slices.Equal(api.calls, []string{"add 1", "tags"}) {
		t.Fatalf("result=%+v calls=%v", result, api.calls)
	}
}

func TestPersistentSpecBoundsRulesAndRequiresCanonicalCIDRs(t *testing.T) {
	store := persistentStore(t)
	var rules []Rule
	for port := range maxRulesPerNSG + 1 {
		rules = append(rules, Rule{Direction: DirectionIngress, Protocol: ProtocolTCP, Peer: "10.0.0.0/8", PortMin: port + 1, PortMax: port + 1})
	}
	for _, spec := range []Spec{{NSGID: nsgID, Rules: rules}, {NSGID: nsgID, Rules: []Rule{https("10.0.0.1/8")}}} {
		if _, err := ociresource.Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
			t.Fatal("accepted invalid rule set")
		}
		records, err := store.List(t.Context(), "GRU", Kind)
		if err != nil || len(records) != 0 {
			t.Fatalf("records=%v err=%v", records, err)
		}
	}
	if _, err := ociresource.Publish(t.Context(), store, key, ociresource.PolicyEnforce, Spec{NSGID: nsgID, Rules: rules[:maxRulesPerNSG]}); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	var spec Spec
	if err := json.Unmarshal(record.Spec, &spec); err != nil || len(spec.Rules) != maxRulesPerNSG {
		t.Fatalf("rules=%d err=%v", len(spec.Rules), err)
	}
}

func (f *providerState) client(t *testing.T) API {
	t.Helper()
	if f.api != nil {
		return f.api
	}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && f.onRead != nil {
			hook := f.onRead
			f.onRead = nil
			hook()
		}
		if f.gone {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"NSG not found"}`)
			return
		}
		var err error
		if r.Method != http.MethodGet {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Error(readErr)
				w.WriteHeader(400)
				return
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/actions/addSecurityRules"):
				var details core.AddNetworkSecurityGroupSecurityRulesDetails
				if err = json.Unmarshal(body, &details); err == nil {
					if len(details.SecurityRules) > 25 {
						t.Error("provider batch limit exceeded")
					}
					var rules []Rule
					for _, rule := range details.SecurityRules {
						// Both payloads use the same OCI security-rule fields.
						encoded, marshalErr := json.Marshal(rule)
						if marshalErr != nil {
							t.Error(marshalErr)
							return
						}
						var observed core.SecurityRule
						if decodeErr := json.Unmarshal(encoded, &observed); decodeErr != nil {
							t.Error(decodeErr)
							return
						}
						rules = append(rules, normalize(observed))
					}
					err = f.AddRules(r.Context(), nsgID, rules)
				}
			case strings.HasSuffix(r.URL.Path, "/actions/removeSecurityRules"):
				var details core.RemoveNetworkSecurityGroupSecurityRulesDetails
				if err = json.Unmarshal(body, &details); err == nil {
					err = f.RemoveRules(r.Context(), nsgID, details.SecurityRuleIds)
				}
			case r.Method == http.MethodPut:
				var details core.UpdateNetworkSecurityGroupDetails
				if err = json.Unmarshal(body, &details); err == nil {
					err = f.UpdateTags(r.Context(), nsgID, r.Header.Get("if-match"), ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags})
				}
			default:
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				w.WriteHeader(405)
				return
			}
			if err != nil {
				w.WriteHeader(412)
				_, _ = io.WriteString(w, `{"code":"NoEtagMatch","message":"mutation refused"}`)
				return
			}
			if f.loseResponse {
				f.loseResponse = false
				connection, _, hijackErr := w.(http.Hijacker).Hijack()
				if hijackErr != nil {
					t.Error(hijackErr)
					return
				}
				_ = connection.Close()
				return
			}
		}
		var response any
		if strings.HasSuffix(r.URL.Path, "/securityRules") {
			rules := []core.SecurityRule{}
			for _, observed := range f.rules {
				encoded, marshalErr := json.Marshal(addDetails(observed.Rule))
				if marshalErr != nil {
					t.Error(marshalErr)
					return
				}
				var rule core.SecurityRule
				if decodeErr := json.Unmarshal(encoded, &rule); decodeErr != nil {
					t.Error(decodeErr)
					return
				}
				rule.Id = new(observed.ID)
				rules = append(rules, rule)
			}
			response = rules
		} else if strings.Contains(r.URL.Path, "/actions/") {
			response = map[string]any{"securityRules": []any{}}
		} else {
			w.Header().Set("etag", f.group.ETag)
			response = core.NetworkSecurityGroup{Id: new(f.group.ID), FreeformTags: f.group.Tags.Freeform, DefinedTags: f.group.Tags.Defined}
		}
		body, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			t.Error(marshalErr)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(body)
	})
	network, err := factory.Network()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&network.BaseClient, endpoint)
	f.api = sdkAPI{network: network}
	return f.api
}

func persistentStore(t *testing.T) *ociresource.KVStore {
	t.Helper()
	return ociresourcetest.Store(t)
}

func confirm(t *testing.T, api *providerState, store ociresource.Store) {
	t.Helper()
	current, err := store.Get(t.Context(), key)
	if errors.Is(err, ociresource.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if current.Tombstone != nil || current.Operation == nil || !current.Operation.CompletedAt.IsZero() {
		return
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store, Ownership: ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil || result.InSync != 1 {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
}

func TestTombstoneSupersededDuringSDKObservationCannotDelete(t *testing.T) {
	owner := ociresource.Ownership{Owner: "cell-gru"}
	store := persistentStore(t)
	wanted := Spec{NSGID: nsgID, Rules: []Rule{https("0.0.0.0/0")}}
	desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce, wanted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err = store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	rule := https("0.0.0.0/0")
	rule.Description = managedDescription(key, rule)
	api := &providerState{group: owned(owner), rules: []ObservedRule{{ID: "managed", Rule: rule}}}
	api.onRead = func() {
		revived, err := ociresource.NewDesired(key, 2, ociresource.PolicyEnforce, wanted)
		if err == nil {
			_, err = store.Put(t.Context(), revived)
		}
		if err != nil {
			t.Error(err)
		}
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store, Ownership: owner, Authority: allow{}}
	_, err = controller.Reconcile(t.Context(), 1)
	current, readErr := store.Get(t.Context(), key)
	if !errors.Is(err, ociresource.ErrConflict) || readErr != nil || current.Generation != 2 || current.Tombstone != nil || len(api.calls) != 0 || len(api.rules) != 1 {
		t.Fatalf("err=%v readErr=%v current=%+v calls=%v rules=%v", err, readErr, current, api.calls, api.rules)
	}
}
