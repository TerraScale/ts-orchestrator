package routetable

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
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

type fakeAPI struct {
	table   Table
	updates int
}

func (f *fakeAPI) GetTable(context.Context, string) (Table, error) {
	table := f.table
	table.Routes = slices.Clone(table.Routes)
	return table, nil
}

func (f *fakeAPI) UpdateTable(_ context.Context, _, etag string, routes []Route, tags ociresource.Tags) error {
	if etag != f.table.ETag {
		return errors.New("etag mismatch")
	}
	f.updates++
	f.table.Routes, f.table.Tags, f.table.ETag = routes, tags, etag+"'"
	return nil
}

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

func spec() Spec {
	return Spec{RouteTableID: tableID, Routes: []Route{
		{Destination: "0.0.0.0/0", NetworkEntityID: natID},
		{Destination: "all-gru-services-in-oracle-services-network", DestinationType: DestinationService, NetworkEntityID: sgwID},
	}}
}

func reconcile(t *testing.T, api API, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) ociresource.Result {
	t.Helper()
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Table]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRouteTableConvergesAndCorrectsOutOfBandRoutes(t *testing.T) {
	rogue := Route{Destination: "0.0.0.0/0", NetworkEntityID: "ocid1.internetgateway.oc1.sa-saopaulo-1.igw"}
	api := &fakeAPI{table: Table{ID: tableID, ETag: "e1", Routes: []Route{rogue}, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
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

func TestRouteTableForeignReportAndTombstone(t *testing.T) {
	foreign := &fakeAPI{table: Table{ID: tableID, ETag: "e1"}}
	if result := reconcile(t, foreign, ociresource.NewMemoryStore(), spec(), ociresource.PolicyEnforce); result.Foreign != 1 ||
		foreign.updates != 0 {
		t.Fatalf("foreign=%+v", result)
	}
	api := &fakeAPI{table: Table{ID: tableID, ETag: "e1", Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	if result := reconcile(t, api, store, spec(), ociresource.PolicyReport); result.Drifted != 1 || api.updates != 0 {
		t.Fatalf("report=%+v", result)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Table]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
	if result, err := controller.Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 || api.updates != 0 {
		t.Fatalf("tombstone=%+v err=%v updates=%d", result, err, api.updates)
	}
}

func TestRouteTableSpecValidation(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"bad ocid":      func(s *Spec) { s.RouteTableID = "ocid1.subnet.oc1..x" },
		"not canonical": func(s *Spec) { s.Routes[0].Destination = "10.0.0.1/8" },
		"bad target":    func(s *Spec) { s.Routes[0].NetworkEntityID = "nat" },
		"repeat dest":   func(s *Spec) { s.Routes = append(s.Routes, Route{Destination: "0.0.0.0/0", NetworkEntityID: sgwID}) },
		"bad type":      func(s *Spec) { s.Routes[0].DestinationType = "VCN" },
		"empty":         func(s *Spec) { s.Routes = nil },
	} {
		value := spec()
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (Spec{RouteTableID: tableID, AllowEmpty: true}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSDKSkipsLocalRoutesAndReplacesUnderIfMatch(t *testing.T) {
	var sent map[string]any
	var ifMatch string
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"id":"`+tableID+`","etag":"e3","routeRules":[`+
				`{"cidrBlock":"0.0.0.0/0","networkEntityId":"`+natID+`","routeType":"STATIC"},`+
				`{"destination":"10.1.0.0/16","destinationType":"CIDR_BLOCK","networkEntityId":"ocid1.privateip.oc1..p","routeType":"LOCAL"}]}`)
		case http.MethodPut:
			ifMatch = r.Header.Get("if-match")
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Errorf("decode: %v", err)
			}
			_, _ = io.WriteString(w, `{"id":"`+tableID+`"}`)
		}
	})
	api, err := newSDKAPI(factory, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	table, err := api.GetTable(t.Context(), tableID)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Routes) != 1 || table.Routes[0] != (Route{Destination: "0.0.0.0/0", NetworkEntityID: natID}) {
		t.Fatalf("routes=%+v", table.Routes)
	}
	if err := api.UpdateTable(t.Context(), tableID, "e3", nil, table.Tags); err != nil {
		t.Fatal(err)
	}
	if rules, ok := sent["routeRules"].([]any); ifMatch != "e3" || !ok || len(rules) != 0 {
		t.Fatalf("if-match=%q body=%v", ifMatch, sent)
	}
	if err := api.UpdateTable(t.Context(), tableID, "", nil, table.Tags); err == nil {
		t.Fatal("unconditional replace accepted")
	}
}
