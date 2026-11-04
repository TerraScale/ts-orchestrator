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

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/oracle/oci-go-sdk/v65/core"
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
