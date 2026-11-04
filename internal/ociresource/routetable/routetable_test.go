package routetable

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	tableID = "ocid1.routetable.oc1.sa-saopaulo-1.private"
	natID   = "ocid1.natgateway.oc1.sa-saopaulo-1.nat"
	sgwID   = "ocid1.servicegateway.oc1.sa-saopaulo-1.sgw"
)

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "private"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

type providerState struct {
	table        Table
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
			if r.Header.Get("if-match") != f.table.ETag {
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = io.WriteString(w, `{"code":"NoEtagMatch","message":"etag mismatch"}`)
				return
			}
			var details core.UpdateRouteTableDetails
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
			f.table.Routes = nil
			for _, rule := range details.RouteRules {
				destinationType := string(rule.DestinationType)
				if destinationType == DestinationCIDR {
					destinationType = ""
				}
				f.table.Routes = append(f.table.Routes, Route{Destination: deref(rule.Destination), DestinationType: destinationType,
					NetworkEntityID: deref(rule.NetworkEntityId), Description: deref(rule.Description)})
			}
			f.table.Tags = ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags}
			f.updates++
			f.table.ETag += "'"
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
		w.Header().Set("etag", f.table.ETag)
		routes := []core.RouteRule{}
		for _, route := range f.table.Routes {
			routes = append(routes, core.RouteRule{Destination: new(route.Destination), DestinationType: core.RouteRuleDestinationTypeEnum(route.destinationType()),
				NetworkEntityId: new(route.NetworkEntityID), Description: new(route.Description), RouteType: core.RouteRuleRouteTypeStatic})
		}
		body, err := json.Marshal(core.RouteTable{Id: new(f.table.ID), RouteRules: routes, FreeformTags: f.table.Tags.Freeform, DefinedTags: f.table.Tags.Defined})
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

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

func spec() Spec {
	return Spec{RouteTableID: tableID, Routes: []Route{
		{Destination: "0.0.0.0/0", NetworkEntityID: natID},
		{Destination: "all-gru-services-in-oracle-services-network", DestinationType: DestinationService, NetworkEntityID: sgwID},
	}}
}

func reconcile(t *testing.T, api *providerState, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) ociresource.Result {
	t.Helper()
	confirm(t, api, store)
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Table]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRouteTableConvergesAndCorrectsOutOfBandRoutes(t *testing.T) {
	rogue := Route{Destination: "0.0.0.0/0", NetworkEntityID: "ocid1.internetgateway.oc1.sa-saopaulo-1.igw"}
	api := &providerState{table: Table{ID: tableID, ETag: "e1", Routes: []Route{rogue}, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	if result := reconcile(t, api, store, spec(), ociresource.PolicyEnforce); result.Applied != 1 {
		t.Fatalf("result=%+v", result)
	}
	if slices.Contains(api.table.Routes, rogue) || len(api.table.Routes) != 2 {
		t.Fatalf("routes=%+v", api.table.Routes)
	}
	if result := reconcile(t, api, store, spec(), ociresource.PolicyEnforce); result.InSync != 1 || api.updates != 1 {
		t.Fatalf("second pass=%+v updates=%d", result, api.updates)
	}
	// A description edit is not drift.
	api.table.Routes[0].Description = "edited"
	if result := reconcile(t, api, store, spec(), ociresource.PolicyEnforce); result.InSync != 1 {
		t.Fatalf("description drift=%+v", result)
	}
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
	controller := &ociresource.Controller[Spec, Table]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store, Ownership: owner, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil || result.InSync != 1 {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
}
