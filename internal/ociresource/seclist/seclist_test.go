package seclist

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const listID = "ocid1.securitylist.oc1.sa-saopaulo-1.private"

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "private"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

type providerState struct {
	list         List
	updates      int
	api          API
	loseResponse bool
}

func (f *providerState) client(t *testing.T) API {
	t.Helper()
	if f.api != nil {
		return f.api
	}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			if r.Header.Get("if-match") != f.list.ETag {
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = io.WriteString(w, `{"code":"NoEtagMatch","message":"etag mismatch"}`)
				return
			}
			var details core.UpdateSecurityListDetails
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if err := json.Unmarshal(body, &details); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			f.list.Rules = nil
			for _, rule := range details.IngressSecurityRules {
				f.list.Rules = append(f.list.Rules, ingressRule(rule))
			}
			for _, rule := range details.EgressSecurityRules {
				f.list.Rules = append(f.list.Rules, egressRule(rule))
			}
			f.list.Tags = ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags}
			f.updates++
			f.list.ETag += "'"
			if f.loseResponse {
				f.loseResponse = false
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
		} else if r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("etag", f.list.ETag)
		details := updateDetails(f.list.Rules, f.list.Tags)
		body, err := json.Marshal(core.SecurityList{Id: new(f.list.ID), IngressSecurityRules: details.IngressSecurityRules,
			EgressSecurityRules: details.EgressSecurityRules, FreeformTags: details.FreeformTags, DefinedTags: details.DefinedTags})
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(body)
	})
	api, err := newSDKAPI(factory, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.api = api
	return api
}

type fence struct{ calls int }

func (f *fence) Guard(context.Context, uint64) error {
	f.calls++
	return nil
}

func spec() Spec {
	return Spec{SecurityListID: listID, Rules: []nsg.Rule{
		{Direction: nsg.DirectionIngress, Protocol: nsg.ProtocolTCP, Peer: "10.0.0.0/16", PortMin: 4222, PortMax: 4222},
		{Direction: nsg.DirectionEgress, Protocol: nsg.ProtocolAll, Peer: "0.0.0.0/0"},
	}}
}

func reconcile(t *testing.T, api *providerState, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) ociresource.Result {
	t.Helper()
	confirm(t, api, store)
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, List]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: &fence{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSecurityListConvergesInOneConditionalReplace(t *testing.T) {
	ssh := nsg.Rule{Direction: nsg.DirectionIngress, Protocol: nsg.ProtocolTCP, Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22}
	api := &providerState{list: List{ID: listID, ETag: "e1", Rules: []nsg.Rule{ssh},
		Tags: ociresource.Tags{Freeform: map[string]string{"team": "infra"}}.Merge(owner.Stamp(key, 0, ""))}}
	store := persistentStore(t)
	if result := reconcile(t, api, store, spec(), ociresource.PolicyEnforce); result.Applied != 1 || api.updates != 1 {
		t.Fatalf("result=%+v updates=%d", result, api.updates)
	}
	if slices.Contains(api.list.Rules, ssh) || len(api.list.Rules) != 2 {
		t.Fatalf("rules=%+v", api.list.Rules)
	}
	if api.list.Tags.Freeform["team"] != "infra" || ociresource.Ownership.Stale(owner, api.list.Tags, 1, mustDigest(t, store)) {
		t.Fatalf("tags=%v", api.list.Tags)
	}
	if result := reconcile(t, api, store, spec(), ociresource.PolicyEnforce); result.InSync != 1 || api.updates != 1 {
		t.Fatalf("second pass result=%+v updates=%d", result, api.updates)
	}
}

func mustDigest(t *testing.T, store ociresource.Store) string {
	t.Helper()
	desired, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	return desired.SpecDigest
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
	if current.Operation == nil || !current.Operation.CompletedAt.IsZero() {
		return
	}
	controller := &ociresource.Controller[Spec, List]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store, Ownership: owner, Authority: &fence{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil || result.InSync != 1 {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
}
