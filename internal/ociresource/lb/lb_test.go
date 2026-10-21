package lb

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

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
)

const lbID = "ocid1.loadbalancer.oc1.sa-saopaulo-1.public"

type providerState struct {
	api          API
	loseResponse bool
	retries      map[string]string
	balancer     LoadBalancer
	backends     []Backend
	calls        []string
	pending      map[string]bool
	finished     map[string]bool
	failWR       bool
	seq          int
	gone         bool
	setGone      bool
	// serving is the serving backend count after every mutation.
	serving []int
	// unhealthy names backends whose health is not OK; healthErr fails
	// the health read.
	unhealthy map[string]bool
	healthErr error
}

func (f *providerState) UnhealthyBackends(context.Context, string, string) (map[string]bool, error) {
	return f.unhealthy, f.healthErr
}

func (f *providerState) GetLoadBalancer(context.Context, string) (LoadBalancer, error) {
	if f.gone {
		return LoadBalancer{}, fmt.Errorf("get OCI load balancer: %w", ociresource.ErrGone)
	}
	return f.balancer, nil
}

func (f *providerState) ListBackends(context.Context, string, string) ([]Backend, error) {
	if f.setGone {
		return nil, fmt.Errorf("list OCI load balancer backends: %w", ociresource.ErrGone)
	}
	return slices.Clone(f.backends), nil
}

// workRequest records a mutation; the next one is refused until the previous
// work request was waited on, as OCI serializes load balancer mutations.
func (f *providerState) workRequest(call string) (string, error) {
	if len(f.pending) > 0 {
		return "", errors.New("load balancer has a mutation in progress")
	}
	f.calls = append(f.calls, call)
	f.seq++
	f.balancer.ETag = fmt.Sprintf("etag-%d", f.seq)
	id := fmt.Sprintf("wr%d", f.seq)
	f.pending = map[string]bool{id: true}
	return id, nil
}

func (f *providerState) countServing() {
	n := 0
	for _, b := range f.backends {
		if !b.Drain && !b.backup && !b.offline {
			n++
		}
	}
	f.serving = append(f.serving, n)
}

func (f *providerState) CreateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("create " + backend.key() + " " + state(backend))
	if err == nil {
		f.backends = append(f.backends, Backend{IP: backend.IP, Port: backend.Port, Drain: backend.Drain, weight: 1, name: backend.key()})
		f.countServing()
	}
	return id, err
}

func (f *providerState) UpdateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("update " + backend.Name() + " " + state(backend))
	for i := range f.backends {
		if f.backends[i].Name() == backend.Name() {
			f.backends[i].Drain, f.backends[i].weight, f.backends[i].backup, f.backends[i].offline = backend.Drain, backend.weight, backend.backup, backend.offline
		}
	}
	f.countServing()
	return id, err
}

func (f *providerState) DeleteBackend(_ context.Context, _, _, name string) (string, error) {
	id, err := f.workRequest("delete " + name)
	f.backends = slices.DeleteFunc(f.backends, func(b Backend) bool { return b.Name() == name })
	f.countServing()
	return id, err
}

func (f *providerState) UpdateTags(_ context.Context, _, etag string, tags ociresource.Tags) (string, error) {
	if etag != f.balancer.ETag {
		return "", errors.New("etag mismatch")
	}
	id, err := f.workRequest("tags")
	if err == nil {
		f.balancer.Tags = tags
	}
	return id, err
}

func (f *providerState) WaitWorkRequest(_ context.Context, id string) error {
	if success, ok := f.finished[id]; ok {
		if !success {
			return errors.New("work request FAILED")
		}
		return nil
	}
	if !f.pending[id] {
		return errors.New("unknown work request")
	}
	f.pending = nil
	if f.finished == nil {
		f.finished = map[string]bool{}
	}
	f.finished[id] = !f.failWR
	if f.failWR {
		return errors.New("work request FAILED")
	}
	return nil
}

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "public-terrabase"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

func controller(t *testing.T, api *providerState, store ociresource.Store) *ociresource.Controller[Spec, Observed] {
	return &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: allow{}}
}

func observed(ip string, drain bool) Backend {
	return Backend{IP: ip, Port: 9465, Drain: drain, weight: 1, name: ip + ":9465"}
}

func publishAndReconcile(t *testing.T, api *providerState, store ociresource.Store, backends ...Backend) {
	t.Helper()
	confirm(t, api, store)
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: backends}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.Failed != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestDrainAndServeOneSeat(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)}}
	store := persistentStore(t)

	// Drain flips skip the ownership restamp; the next idle pass does it.
	publishAndReconcile(t, api, store, Backend{IP: "10.251.0.21", Port: 9465, Drain: true}, Backend{IP: "10.251.0.22", Port: 9465})
	if !slices.Equal(api.calls, []string{"update 10.251.0.21:9465 drained"}) {
		t.Fatalf("drain calls=%v", api.calls)
	}
	publishAndReconcile(t, api, store, Backend{IP: "10.251.0.21", Port: 9465}, Backend{IP: "10.251.0.22", Port: 9465})
	if !slices.Equal(api.calls, []string{"update 10.251.0.21:9465 serving"}) {
		t.Fatalf("serve calls=%v", api.calls)
	}
	api.calls = nil
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.Applied != 1 || !slices.Equal(api.calls, []string{"tags"}) {
		t.Fatalf("idle pass result=%+v err=%v calls=%v", result, err, api.calls)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.InSync != 1 {
		t.Fatalf("third pass result=%+v err=%v", result, err)
	}
}

// A serving backend leaves rotation only while another backend that keeps
// serving reports health OK; a backend the same plan creates does not count.
func TestServingBackendLeavesOnlyWithAHealthyPeer(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends:  []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)},
		unhealthy: map[string]bool{"10.251.0.22:9465": true}}
	store := persistentStore(t)
	reconcile := func(backends ...Backend) error {
		t.Helper()
		confirm(t, api, store)
		spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: backends}
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
			t.Fatal(err)
		}
		api.calls = nil
		_, err := controller(t, api, store).Reconcile(t.Context(), 1)
		return err
	}
	if err := reconcile(Backend{IP: "10.251.0.21", Port: 9465, Drain: true}, Backend{IP: "10.251.0.22", Port: 9465}); !errors.Is(err, ErrNoHealthyBackend) || len(api.calls) != 0 {
		t.Fatalf("drained beside a critical peer: err=%v calls=%v", err, api.calls)
	}
	api.healthErr, api.unhealthy = errors.New("throttled"), nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err == nil || len(api.calls) != 0 {
		t.Fatalf("drained without reading health: err=%v calls=%v", err, api.calls)
	}
	api.healthErr = nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || !slices.Equal(api.calls, []string{"update 10.251.0.21:9465 drained"}) {
		t.Fatalf("healthy peer: err=%v calls=%v", err, api.calls)
	}

	// Replacing both with a new backend: it is added at once, but the
	// serving one is removed only after the new one reports OK.
	api.unhealthy = map[string]bool{"10.251.0.23:9465": true}
	if err := reconcile(Backend{IP: "10.251.0.23", Port: 9465}); !errors.Is(err, ErrNoHealthyBackend) ||
		!slices.Equal(api.calls, []string{"create 10.251.0.23:9465 serving"}) {
		t.Fatalf("removed the serving backend before its replacement was healthy: err=%v calls=%v", err, api.calls)
	}
	api.calls, api.unhealthy = nil, nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil ||
		!slices.Equal(api.calls, []string{"delete 10.251.0.21:9465", "delete 10.251.0.22:9465", "tags"}) {
		t.Fatalf("err=%v calls=%v", err, api.calls)
	}

	confirm(t, api, store)
	// AllowEmpty does not lift the guard while the spec still serves.
	api.unhealthy = map[string]bool{"10.251.0.23:9465": true, "10.251.0.24:9465": true}
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", AllowEmpty: true,
		Backends: []Backend{{IP: "10.251.0.23", Port: 9465, Drain: true}, {IP: "10.251.0.24", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); !errors.Is(err, ErrNoHealthyBackend) ||
		!slices.Equal(api.calls, []string{"create 10.251.0.24:9465 serving"}) {
		t.Fatalf("allowEmpty with a serving backend: err=%v calls=%v", err, api.calls)
	}

	// An explicit empty set skips the guard.
	api.unhealthy = map[string]bool{"10.251.0.23:9465": true}
	confirm(t, api, store)
	spec = Spec{LoadBalancerID: lbID, BackendSet: "terrabase", AllowEmpty: true,
		Backends: []Backend{{IP: "10.251.0.23", Port: 9465, Drain: true}, {IP: "10.251.0.24", Port: 9465, Drain: true}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil ||
		!slices.Equal(api.calls, []string{"update 10.251.0.24:9465 drained"}) {
		t.Fatalf("allowEmpty: err=%v calls=%v", err, api.calls)
	}
}

// One plan adds, undrains, drains and removes: the serving backends never
// drop below the two the new spec serves, and a hand-set offline backend the
// spec lists is brought back.
func TestApplyOrderKeepsServingCapacity(t *testing.T) {
	offline := observed("10.251.0.21", false)
	offline.offline = true
	api := &providerState{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{offline, observed("10.251.0.22", false), observed("10.251.0.23", false)}}
	store := persistentStore(t)

	publishAndReconcile(t, api, store,
		Backend{IP: "10.251.0.24", Port: 9465}, Backend{IP: "10.251.0.22", Port: 9465, Drain: true}, Backend{IP: "10.251.0.21", Port: 9465})
	want := []string{"create 10.251.0.24:9465 serving", "update 10.251.0.21:9465 serving", "update 10.251.0.22:9465 drained",
		"delete 10.251.0.23:9465", "tags"}
	if !slices.Equal(api.calls, want) {
		t.Fatalf("calls=%v\nwant %v", api.calls, want)
	}
	if !slices.Equal(api.serving, []int{3, 4, 3, 2}) {
		t.Fatalf("serving backends after each mutation = %v", api.serving)
	}
	// Reweighted or backup backends are normalized in place too.
	api.backends[0].weight, api.backends[1].backup = 5, true
	api.calls = nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 2 {
		t.Fatalf("normalize calls=%v", api.calls)
	}
}

func TestNoServingBackendIsRefused(t *testing.T) {
	store := persistentStore(t)
	for _, backends := range [][]Backend{nil, {{IP: "10.251.0.21", Port: 9465, Drain: true}}} {
		spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: backends}
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
			t.Fatalf("published a set with no serving backend: %+v", backends)
		}
		spec.AllowEmpty = true
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
			t.Fatal(err)
		}
	}
}

// A desired record written straight into the store, past Publish, that would
// drain every backend is refused before any mutation.
func TestTamperedAllDrainedRecordIsNotApplied(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false)}}
	store := persistentStore(t)
	desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce,
		Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465, Drain: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 || len(api.calls) != 0 {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, api.calls)
	}
}

func TestForeignLoadBalancerAndFailedWorkRequests(t *testing.T) {
	store := persistentStore(t)
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []*providerState{
		{balancer: LoadBalancer{ID: lbID, Tags: ociresource.Tags{Freeform: map[string]string{"terrascale-owner": "cell-gru"}}}},
		{balancer: LoadBalancer{ID: lbID, Tags: ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-scl"}.Stamp(key, 0, "")}},
		{balancer: LoadBalancer{ID: lbID + "x", Tags: owner.Stamp(key, 0, "")}},
	} {
		if result, err := controller(t, foreign, store).Reconcile(t.Context(), 1); err != nil || result.Foreign != 1 || len(foreign.calls) != 0 {
			t.Fatalf("result=%+v err=%v calls=%v", result, err, foreign.calls)
		}
	}
	failing := &providerState{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}, failWR: true}
	if _, err := controller(t, failing, store).Reconcile(t.Context(), 1); err == nil {
		t.Fatal("ignored a failed work request")
	}
	if len(failing.calls) != 1 {
		t.Fatalf("continued after a failed work request: %v", failing.calls)
	}
	status, _, _ := store.GetStatus(t.Context(), key)
	if status.Error == "" || status.Applied {
		t.Fatalf("status=%+v", status)
	}
}

// fenceAfter allows a number of guards and then reports lost authority.
type fenceAfter struct{ remaining int }

func (f *fenceAfter) Guard(context.Context, uint64) error {
	if f.remaining <= 0 {
		return errors.New("lost leadership")
	}
	f.remaining--
	return nil
}

func TestApplyReguardsBeforeEveryMutation(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)}}
	store := persistentStore(t)
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{
		{IP: "10.251.0.21", Port: 9465}, {IP: "10.251.0.22", Port: 9465, Drain: true}, {IP: "10.251.0.23", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	// The controller's own guard plus two mutations (seven guards each:
	// controller, write authority and wire authority), then leadership is
	// lost before the restamp.
	fenced := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: &fenceAfter{remaining: 1 + 7*2}}
	if _, err := fenced.Reconcile(t.Context(), 1); err == nil {
		t.Fatal("a fenced pass reported success")
	}
	if !slices.Equal(api.calls, []string{"create 10.251.0.23:9465 serving", "update 10.251.0.22:9465 drained"}) {
		t.Fatalf("mutations after losing authority: %v", api.calls)
	}
}

func TestTombstoneEmptiesTheSetThenPurges(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	publishAndReconcile(t, api, store, Backend{IP: "10.251.0.21", Port: 9465}, Backend{IP: "10.251.0.22", Port: 9465})
	confirm(t, api, store)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if len(api.backends) != 0 {
		t.Fatalf("backends=%+v", api.backends)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
}

func TestTombstonePurgesWhenTheLoadBalancerIsGone(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}, gone: true}
	store := persistentStore(t)
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing load balancer: result=%+v err=%v", result, err)
	}
	confirm(t, api, store)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing load balancer: result=%+v err=%v", result, err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("unexpected mutations: %v", api.calls)
	}
}

func TestSpecValidation(t *testing.T) {
	store := persistentStore(t)
	ok := Backend{IP: "10.0.0.1", Port: 1}
	for _, spec := range []Spec{
		{LoadBalancerID: "ocid1.networkloadbalancer.oc1..x", BackendSet: "terrabase", Backends: []Backend{ok}},
		{LoadBalancerID: lbID, Backends: []Backend{ok}},
		{LoadBalancerID: lbID, BackendSet: "a-backend-set-name-longer-than-32", Backends: []Backend{ok}},
		{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "8.8.8.8", Port: 1}}},
		{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "fd00::1", Port: 1}}},
		{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.0.0.1", Port: 0}}},
		{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{ok, {IP: "10.0.0.1", Port: 1, Drain: true}}},
	} {
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	if _, err := Publish(t.Context(), store, ociresource.Key{Region: "GRU", Kind: "nlb-backends", Name: "x"},
		ociresource.PolicyEnforce, Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{ok}}); err == nil {
		t.Fatal("published under another kind")
	}
	records, err := store.List(t.Context(), "GRU", Kind)
	if err != nil || len(records) != 0 {
		t.Fatalf("invalid input changed persistent state: records=%v err=%v", records, err)
	}
}

// Fenced changes only drain and offline: a fence returns a backend with
// the weight and backup it had, which Shape reads and Shaped sets.
func TestSDKFenceKeepsTheBackendShape(t *testing.T) {
	observed := Backend{IP: "10.0.0.1", Port: 80, weight: 3, offline: true, name: "10.0.0.1:80"}
	state := &providerState{balancer: LoadBalancer{ID: lbID, ETag: "e1", Tags: owner.Stamp(key, 1, "d")}, backends: []Backend{observed}}
	api := state.client(t)
	apply := func(backend Backend) Backend {
		id, err := api.UpdateBackend(t.Context(), lbID, "terrabase", backend)
		if err != nil {
			t.Fatal(err)
		}
		if err := api.WaitWorkRequest(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		backends, err := api.ListBackends(t.Context(), lbID, "terrabase")
		if err != nil || len(backends) != 1 {
			t.Fatalf("backends=%+v err=%v", backends, err)
		}
		return backends[0]
	}
	returned := apply(observed.Fenced(false, false))
	if weight, backup := returned.Shape(); !returned.Serving() || weight != 3 || backup {
		t.Fatalf("returned=%+v", returned)
	}
	fenced := apply(returned.Fenced(true, true))
	if fenced.Serving() || !fenced.Drain || !fenced.offline || fenced.weight != 3 {
		t.Fatalf("fenced=%+v", fenced)
	}
	shaped := apply(fenced.Shaped(3, true))
	if weight, backup := shaped.Shape(); weight != 3 || !backup {
		t.Fatalf("shaped=%+v", shaped)
	}
}

func (f *providerState) client(t *testing.T) API {
	t.Helper()
	if f.api != nil {
		return f.api
	}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		respond := func(value any) {
			body, err := json.Marshal(value)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(body)
		}
		refuse := func(status int, message string) {
			w.WriteHeader(status)
			respond(map[string]string{"code": "ProviderRefused", "message": message})
		}
		path := r.URL.Path
		name := path[strings.LastIndex(path, "/")+1:]
		if f.gone || (f.setGone && strings.Contains(path, "/backendSets/")) {
			refuse(404, "resource gone")
			return
		}
		if strings.Contains(path, "/workRequests/") || strings.Contains(path, "/loadBalancerWorkRequests/") {
			err := f.WaitWorkRequest(r.Context(), name)
			state := "SUCCEEDED"
			if err != nil {
				state = "FAILED"
			}
			respond(map[string]string{"id": name, "lifecycleState": state, "status": state})
			return
		}
		if r.Method == http.MethodGet {
			switch {
			case strings.HasSuffix(path, "/health"):
				if f.healthErr != nil {
					refuse(412, f.healthErr.Error())
					return
				}
				unhealthy := []string{}
				for name, bad := range f.unhealthy {
					if bad {
						unhealthy = append(unhealthy, name)
					}
				}
				respond(map[string]any{"status": "OK", "criticalStateBackendNames": unhealthy, "warningStateBackendNames": []string{}, "unknownStateBackendNames": []string{}})
			case strings.HasSuffix(path, "/backends"):
				backends := []map[string]any{}
				for _, b := range f.backends {
					backends = append(backends, map[string]any{"ipAddress": b.IP, "port": b.Port, "name": b.Name(), "weight": b.weight, "drain": b.Drain, "backup": b.backup, "offline": b.offline})
				}
				respond(backends)
			default:
				w.Header().Set("etag", f.balancer.ETag)
				respond(map[string]any{"id": f.balancer.ID, "freeformTags": f.balancer.Tags.Freeform, "definedTags": f.balancer.Tags.Defined})
			}
			return
		}
		token := r.Header.Get("opc-retry-token")
		if token != "" && f.retries[token] != "" {
			w.Header().Set("opc-work-request-id", f.retries[token])
			w.WriteHeader(202)
			respond(map[string]any{})
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			refuse(400, "body read failed")
			return
		}
		var workRequest string
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/backends"):
			var details loadbalancer.CreateBackendDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.CreateBackend(r.Context(), lbID, "set", Backend{IP: deref(details.IpAddress), Port: deref(details.Port), Drain: deref(details.Drain), offline: deref(details.Offline), weight: deref(details.Weight), backup: deref(details.Backup)})
			}
		case r.Method == http.MethodPut && strings.Contains(path, "/backends/"):
			var details loadbalancer.UpdateBackendDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.UpdateBackend(r.Context(), lbID, "set", Backend{name: name, Drain: deref(details.Drain), offline: deref(details.Offline), weight: deref(details.Weight), backup: deref(details.Backup)})
			}
		case r.Method == http.MethodDelete && strings.Contains(path, "/backends/"):
			workRequest, err = f.DeleteBackend(r.Context(), lbID, "set", name)
		case r.Method == http.MethodPut:
			var details loadbalancer.UpdateLoadBalancerDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.UpdateTags(r.Context(), lbID, r.Header.Get("if-match"), ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags})
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, path)
			refuse(405, "unexpected operation")
			return
		}
		if err != nil {
			refuse(412, err.Error())
			return
		}
		if token != "" {
			if f.retries == nil {
				f.retries = map[string]string{}
			}
			f.retries[token] = workRequest
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
		w.Header().Set("opc-work-request-id", workRequest)
		w.WriteHeader(202)
		respond(map[string]any{})
	})
	client, err := factory.LoadBalancer()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&client.BaseClient, endpoint)
	f.api = sdkAPI{client: client, pause: sleep}
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
	if current.Operation == nil || !current.Operation.CompletedAt.IsZero() {
		return
	}
	for range 3 {
		result, err := controller(t, api, store).Reconcile(t.Context(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if result.InSync == 1 {
			return
		}
	}
	t.Fatal("operation did not converge")
}
