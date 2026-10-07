package lb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

const lbID = "ocid1.loadbalancer.oc1.sa-saopaulo-1.public"

type fakeAPI struct {
	balancer LoadBalancer
	backends []Backend
	calls    []string
	pending  map[string]bool
	failWR   bool
	seq      int
	gone     bool
	setGone  bool
	// serving is the serving backend count after every mutation.
	serving []int
	// unhealthy names backends whose health is not OK; healthErr fails
	// the health read.
	unhealthy map[string]bool
	healthErr error
}

func (f *fakeAPI) UnhealthyBackends(context.Context, string, string) (map[string]bool, error) {
	return f.unhealthy, f.healthErr
}

func (f *fakeAPI) GetLoadBalancer(context.Context, string) (LoadBalancer, error) {
	if f.gone {
		return LoadBalancer{}, fmt.Errorf("get OCI load balancer: %w", ociresource.ErrGone)
	}
	return f.balancer, nil
}

func (f *fakeAPI) ListBackends(context.Context, string, string) ([]Backend, error) {
	if f.setGone {
		return nil, fmt.Errorf("list OCI load balancer backends: %w", ociresource.ErrGone)
	}
	return slices.Clone(f.backends), nil
}

// workRequest records a mutation; the next one is refused until the previous
// work request was waited on, as OCI serializes load balancer mutations.
func (f *fakeAPI) workRequest(call string) (string, error) {
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

func (f *fakeAPI) countServing() {
	n := 0
	for _, b := range f.backends {
		if !b.Drain && !b.backup && !b.offline {
			n++
		}
	}
	f.serving = append(f.serving, n)
}

func (f *fakeAPI) CreateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("create " + backend.key() + " " + state(backend))
	if err == nil {
		f.backends = append(f.backends, Backend{IP: backend.IP, Port: backend.Port, Drain: backend.Drain, weight: 1, name: backend.key()})
		f.countServing()
	}
	return id, err
}

func (f *fakeAPI) UpdateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("update " + backend.Name() + " " + state(backend))
	for i := range f.backends {
		if f.backends[i].Name() == backend.Name() {
			f.backends[i].Drain, f.backends[i].weight, f.backends[i].backup, f.backends[i].offline = backend.Drain, 1, false, false
		}
	}
	f.countServing()
	return id, err
}

func (f *fakeAPI) DeleteBackend(_ context.Context, _, _, name string) (string, error) {
	id, err := f.workRequest("delete " + name)
	f.backends = slices.DeleteFunc(f.backends, func(b Backend) bool { return b.Name() == name })
	f.countServing()
	return id, err
}

func (f *fakeAPI) UpdateTags(_ context.Context, _, etag string, tags ociresource.Tags) (string, error) {
	if etag != f.balancer.ETag {
		return "", errors.New("etag mismatch")
	}
	id, err := f.workRequest("tags")
	if err == nil {
		f.balancer.Tags = tags
	}
	return id, err
}

func (f *fakeAPI) WaitWorkRequest(_ context.Context, id string) error {
	if !f.pending[id] {
		return errors.New("unknown work request")
	}
	f.pending = nil
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

func controller(api API, store ociresource.Store) *ociresource.Controller[Spec, Observed] {
	return &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
}

func observed(ip string, drain bool) Backend {
	return Backend{IP: ip, Port: 9465, Drain: drain, weight: 1, name: ip + ":9465"}
}

func publishAndReconcile(t *testing.T, api *fakeAPI, store ociresource.Store, backends ...Backend) {
	t.Helper()
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: backends}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.Failed != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestDrainAndServeOneSeat(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)}}
	store := ociresource.NewMemoryStore()

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
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.Applied != 1 || !slices.Equal(api.calls, []string{"tags"}) {
		t.Fatalf("idle pass result=%+v err=%v calls=%v", result, err, api.calls)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.InSync != 1 {
		t.Fatalf("third pass result=%+v err=%v", result, err)
	}
}

// A serving backend leaves rotation only while another backend that keeps
// serving reports health OK; a backend the same plan creates does not count.
func TestServingBackendLeavesOnlyWithAHealthyPeer(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends:  []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)},
		unhealthy: map[string]bool{"10.251.0.22:9465": true}}
	store := ociresource.NewMemoryStore()
	reconcile := func(backends ...Backend) error {
		t.Helper()
		spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: backends}
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
			t.Fatal(err)
		}
		api.calls = nil
		_, err := controller(api, store).Reconcile(t.Context(), 1)
		return err
	}
	if err := reconcile(Backend{IP: "10.251.0.21", Port: 9465, Drain: true}, Backend{IP: "10.251.0.22", Port: 9465}); !errors.Is(err, ErrNoHealthyBackend) || len(api.calls) != 0 {
		t.Fatalf("drained beside a critical peer: err=%v calls=%v", err, api.calls)
	}
	api.healthErr, api.unhealthy = errors.New("throttled"), nil
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err == nil || len(api.calls) != 0 {
		t.Fatalf("drained without reading health: err=%v calls=%v", err, api.calls)
	}
	api.healthErr = nil
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || !slices.Equal(api.calls, []string{"update 10.251.0.21:9465 drained"}) {
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
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil ||
		!slices.Equal(api.calls, []string{"delete 10.251.0.21:9465", "delete 10.251.0.22:9465", "tags"}) {
		t.Fatalf("err=%v calls=%v", err, api.calls)
	}

	// AllowEmpty does not lift the guard while the spec still serves.
	api.unhealthy = map[string]bool{"10.251.0.23:9465": true, "10.251.0.24:9465": true}
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", AllowEmpty: true,
		Backends: []Backend{{IP: "10.251.0.23", Port: 9465, Drain: true}, {IP: "10.251.0.24", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(api, store).Reconcile(t.Context(), 1); !errors.Is(err, ErrNoHealthyBackend) ||
		!slices.Equal(api.calls, []string{"create 10.251.0.24:9465 serving"}) {
		t.Fatalf("allowEmpty with a serving backend: err=%v calls=%v", err, api.calls)
	}

	// An explicit empty set skips the guard.
	api.unhealthy = map[string]bool{"10.251.0.23:9465": true}
	spec = Spec{LoadBalancerID: lbID, BackendSet: "terrabase", AllowEmpty: true,
		Backends: []Backend{{IP: "10.251.0.23", Port: 9465, Drain: true}, {IP: "10.251.0.24", Port: 9465, Drain: true}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil ||
		!slices.Equal(api.calls, []string{"update 10.251.0.23:9465 drained", "update 10.251.0.24:9465 drained"}) {
		t.Fatalf("allowEmpty: err=%v calls=%v", err, api.calls)
	}
}

// One plan adds, undrains, drains and removes: the serving backends never
// drop below the two the new spec serves, and a hand-set offline backend the
// spec lists is brought back.
func TestApplyOrderKeepsServingCapacity(t *testing.T) {
	offline := observed("10.251.0.21", false)
	offline.offline = true
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{offline, observed("10.251.0.22", false), observed("10.251.0.23", false)}}
	store := ociresource.NewMemoryStore()

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
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 2 {
		t.Fatalf("normalize calls=%v", api.calls)
	}
}

func TestNoServingBackendIsRefused(t *testing.T) {
	store := ociresource.NewMemoryStore()
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
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false)}}
	store := ociresource.NewMemoryStore()
	desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce,
		Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465, Drain: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 || len(api.calls) != 0 {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, api.calls)
	}
}

func TestForeignLoadBalancerAndFailedWorkRequests(t *testing.T) {
	store := ociresource.NewMemoryStore()
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []*fakeAPI{
		{balancer: LoadBalancer{ID: lbID, Tags: ociresource.Tags{Freeform: map[string]string{"terrascale-owner": "cell-gru"}}}},
		{balancer: LoadBalancer{ID: lbID, Tags: ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-scl"}.Stamp(key, 0, "")}},
		{balancer: LoadBalancer{ID: lbID + "x", Tags: owner.Stamp(key, 0, "")}},
	} {
		if result, err := controller(foreign, store).Reconcile(t.Context(), 1); err != nil || result.Foreign != 1 || len(foreign.calls) != 0 {
			t.Fatalf("result=%+v err=%v calls=%v", result, err, foreign.calls)
		}
	}
	failing := &fakeAPI{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}, failWR: true}
	if _, err := controller(failing, store).Reconcile(t.Context(), 1); err == nil {
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
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{observed("10.251.0.21", false), observed("10.251.0.22", false)}}
	store := ociresource.NewMemoryStore()
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{
		{IP: "10.251.0.21", Port: 9465}, {IP: "10.251.0.22", Port: 9465, Drain: true}, {IP: "10.251.0.23", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	// The controller's own guard plus two mutations, then leadership is
	// lost before the restamp.
	fenced := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: &fenceAfter{remaining: 3}}
	if _, err := fenced.Reconcile(t.Context(), 1); err == nil {
		t.Fatal("a fenced pass reported success")
	}
	if !slices.Equal(api.calls, []string{"create 10.251.0.23:9465 serving", "update 10.251.0.22:9465 drained"}) {
		t.Fatalf("mutations after losing authority: %v", api.calls)
	}
}

func TestTombstoneEmptiesTheSetThenPurges(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	publishAndReconcile(t, api, store, Backend{IP: "10.251.0.21", Port: 9465}, Backend{IP: "10.251.0.22", Port: 9465})
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil {
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
	api := &fakeAPI{balancer: LoadBalancer{ID: lbID, Tags: owner.Stamp(key, 0, "")}, gone: true}
	store := ociresource.NewMemoryStore()
	spec := Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{{IP: "10.251.0.21", Port: 9465}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing load balancer: result=%+v err=%v", result, err)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing load balancer: result=%+v err=%v", result, err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("unexpected mutations: %v", api.calls)
	}
}

func TestSpecValidation(t *testing.T) {
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
		if spec.Validate() == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	if _, err := Publish(t.Context(), ociresource.NewMemoryStore(), ociresource.Key{Region: "GRU", Kind: "nlb-backends", Name: "x"},
		ociresource.PolicyEnforce, Spec{LoadBalancerID: lbID, BackendSet: "terrabase", Backends: []Backend{ok}}); err == nil {
		t.Fatal("published under another kind")
	}
}

// Fenced returns the backend as UpdateBackend writes it: weight 1, never a
// backup, with the fence's drain and offline flags.
func TestFencedIsTheWrittenShape(t *testing.T) {
	observed := Backend{IP: "10.0.0.1", Port: 80, weight: 3, backup: true, offline: true, name: "10.0.0.1:80"}
	if returned := observed.Fenced(false, false); !returned.Serving() || returned.weight != defaultWeight {
		t.Fatalf("returned to rotation: %+v", returned)
	}
	if fenced := observed.Fenced(true, true); fenced.Serving() || !fenced.Drain || !fenced.offline || fenced.backup {
		t.Fatalf("fenced: %+v", fenced)
	}
}
