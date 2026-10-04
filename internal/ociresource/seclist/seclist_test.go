package seclist

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
)

const listID = "ocid1.securitylist.oc1.sa-saopaulo-1.private"

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "private"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

type fakeAPI struct {
	list    List
	updates int
	fail    error
}

func (f *fakeAPI) GetList(context.Context, string) (List, error) {
	list := f.list
	list.Rules = slices.Clone(list.Rules)
	return list, nil
}

func (f *fakeAPI) UpdateList(_ context.Context, _, etag string, rules []nsg.Rule, tags ociresource.Tags) error {
	if f.fail != nil {
		return f.fail
	}
	if etag != f.list.ETag {
		return errors.New("etag mismatch")
	}
	f.updates++
	f.list.Rules, f.list.Tags, f.list.ETag = rules, tags, etag+"'"
	return nil
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

func reconcile(t *testing.T, api API, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) ociresource.Result {
	t.Helper()
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, List]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: &fence{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSecurityListConvergesInOneConditionalReplace(t *testing.T) {
	ssh := nsg.Rule{Direction: nsg.DirectionIngress, Protocol: nsg.ProtocolTCP, Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22}
	api := &fakeAPI{list: List{ID: listID, ETag: "e1", Rules: []nsg.Rule{ssh},
		Tags: ociresource.Tags{Freeform: map[string]string{"team": "infra"}}.Merge(owner.Stamp(key, 0, ""))}}
	store := ociresource.NewMemoryStore()
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

func TestSecurityListReportOnlyAndForeignAreNeverWritten(t *testing.T) {
	api := &fakeAPI{list: List{ID: listID, ETag: "e1", Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	if result := reconcile(t, api, store, spec(), ociresource.PolicyReport); result.Drifted != 1 || api.updates != 0 {
		t.Fatalf("report result=%+v updates=%d", result, api.updates)
	}
	status, _, _ := store.GetStatus(t.Context(), key)
	if status.Policy != ociresource.PolicyReport || len(status.Drift) != 3 {
		t.Fatalf("status=%+v", status)
	}

	foreign := &fakeAPI{list: List{ID: listID, ETag: "e1"}}
	if result := reconcile(t, foreign, ociresource.NewMemoryStore(), spec(), ociresource.PolicyEnforce); result.Foreign != 1 ||
		foreign.updates != 0 {
		t.Fatalf("foreign result=%+v", result)
	}
}

func TestSecurityListTombstoneReleasesWithoutTouchingRules(t *testing.T) {
	api := &fakeAPI{list: List{ID: listID, ETag: "e1", Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	reconcile(t, api, store, spec(), ociresource.PolicyEnforce)
	rules := slices.Clone(api.list.Rules)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, List]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: &fence{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !slices.Equal(api.list.Rules, rules) || api.updates != 1 {
		t.Fatalf("tombstone touched the list: %+v", api.list.Rules)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record not purged: %v", err)
	}
}

func TestSecurityListSpecValidation(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"bad ocid":  func(s *Spec) { s.SecurityListID = "ocid1.networksecuritygroup.oc1..x" },
		"nsg peer":  func(s *Spec) { s.Rules[0].PeerType, s.Rules[0].Peer = nsg.PeerNSG, "ocid1.networksecuritygroup.oc1..x" },
		"repeat":    func(s *Spec) { s.Rules = append(s.Rules, s.Rules[0]) },
		"no egress": func(s *Spec) { s.Rules = s.Rules[:1] },
		"too many": func(s *Spec) {
			for port := range maxRulesPerDirection {
				s.Rules = append(s.Rules, nsg.Rule{Direction: nsg.DirectionEgress, Protocol: nsg.ProtocolTCP,
					Peer: "10.0.0.0/8", PortMin: port + 1, PortMax: port + 1})
			}
		},
	} {
		value := spec()
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	empty := Spec{SecurityListID: listID, AllowEmpty: true}
	if err := empty.Validate(); err != nil {
		t.Fatalf("explicitly empty spec rejected: %v", err)
	}
}

func TestSDKReplacesBothDirectionsUnderIfMatch(t *testing.T) {
	var sent map[string]any
	var ifMatch string
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("etag", "e7")
			_, _ = io.WriteString(w, `{"id":"`+listID+`","etag":"e7","freeformTags":{"terrascale-owner":"cell-gru"},`+
				`"ingressSecurityRules":[{"protocol":"6","source":"0.0.0.0/0","sourceType":"CIDR_BLOCK",`+
				`"tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},`+
				`{"protocol":"1","source":"0.0.0.0/0","icmpOptions":{"type":3}}],`+
				`"egressSecurityRules":[{"protocol":"all","destination":"0.0.0.0/0","destinationType":"CIDR_BLOCK"}]}`)
		case http.MethodPut:
			ifMatch = r.Header.Get("if-match")
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Errorf("decode body: %v", err)
			}
			_, _ = io.WriteString(w, `{"id":"`+listID+`"}`)
		default:
			t.Errorf("unexpected %s", r.Method)
		}
	})
	api, err := newSDKAPI(factory, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	list, err := api.GetList(t.Context(), listID)
	if err != nil {
		t.Fatal(err)
	}
	if list.ETag != "e7" || len(list.Rules) != 3 || list.Rules[0].PortMin != 22 || list.Rules[0].PeerType != "" ||
		!strings.HasSuffix(list.Rules[1].Identity(), "|true") {
		t.Fatalf("list=%+v", list)
	}
	if err := api.UpdateList(t.Context(), listID, "e7", []nsg.Rule{spec().Rules[1]}, list.Tags); err != nil {
		t.Fatal(err)
	}
	ingress, ok := sent["ingressSecurityRules"].([]any)
	if ifMatch != "e7" || !ok || len(ingress) != 0 || len(sent["egressSecurityRules"].([]any)) != 1 {
		t.Fatalf("if-match=%q body=%v", ifMatch, sent)
	}
}
