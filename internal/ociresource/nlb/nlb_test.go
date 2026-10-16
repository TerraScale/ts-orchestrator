package nlb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const nlbID = "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.public"

type fakeAPI struct {
	balancer LoadBalancer
	backends []Backend
	calls    []string
	pending  map[string]bool
	failWR   bool
	seq      int
	gone     bool
	setGone  bool
}

func (f *fakeAPI) GetLoadBalancer(context.Context, string) (LoadBalancer, error) {
	if f.gone {
		return LoadBalancer{}, fmt.Errorf("get OCI NLB: %w", ociresource.ErrGone)
	}
	return f.balancer, nil
}
func (f *fakeAPI) ListBackends(context.Context, string, string) ([]Backend, error) {
	if f.setGone {
		return nil, fmt.Errorf("list OCI NLB backends: %w", ociresource.ErrGone)
	}
	return slices.Clone(f.backends), nil
}

// workRequest records a mutation; the next mutation is refused until the
// previous work request was waited on, mirroring OCI's NLB serialization.
func (f *fakeAPI) workRequest(call string) (string, error) {
	if len(f.pending) > 0 {
		return "", errors.New("NLB has a mutation in progress")
	}
	f.calls = append(f.calls, call)
	f.seq++
	// Every NLB mutation advances its ETag, as OCI does.
	f.balancer.ETag = fmt.Sprintf("etag-%d", f.seq)
	id := fmt.Sprintf("wr%d", f.seq)
	f.pending = map[string]bool{id: true}
	return id, nil
}

func (f *fakeAPI) CreateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("create " + backend.key())
	if err == nil {
		f.backends = append(f.backends, Backend{IP: backend.IP, Port: backend.Port, Weight: backend.weight(), name: backend.key()})
	}
	return id, err
}
func (f *fakeAPI) UpdateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("update " + backend.Name())
	for i := range f.backends {
		if f.backends[i].Name() == backend.Name() {
			f.backends[i].Weight = backend.weight()
		}
	}
	return id, err
}
func (f *fakeAPI) DeleteBackend(_ context.Context, _, _, name string) (string, error) {
	id, err := f.workRequest("delete " + name)
	f.backends = slices.DeleteFunc(f.backends, func(b Backend) bool { return b.Name() == name })
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
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "public-api"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

func controller(api API, store ociresource.Store) *ociresource.Controller[Spec, Observed] {
	return &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
}

func instance(ip, state string) oci.Instance { return oci.Instance{PrivateIP: ip, State: state} }

func TestBackendsFollowPlacement(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{{IP: "10.0.1.9", Port: 8443, Weight: 1, name: "10.0.1.9:8443"}}}
	store := ociresource.NewMemoryStore()
	ctx := t.Context()

	spec := FromPlacement(nlbID, "api", 8443, []oci.Instance{
		instance("10.0.1.12", "RUNNING"), instance("10.0.1.11", "RUNNING"), instance("10.0.1.13", "STOPPED"),
		instance("", "RUNNING"), instance("10.0.1.11", "RUNNING"),
	})
	if len(spec.Backends) != 2 || spec.Backends[0].IP != "10.0.1.11" {
		t.Fatalf("spec=%+v", spec)
	}
	changed, err := Publish(ctx, store, key, ociresource.PolicyEnforce, spec)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if changed, err = Publish(ctx, store, key, ociresource.PolicyEnforce, spec); err != nil || changed {
		t.Fatalf("republished an unchanged spec: changed=%v err=%v", changed, err)
	}
	result, err := controller(api, store).Reconcile(ctx, 1)
	if err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"create 10.0.1.11:8443", "create 10.0.1.12:8443", "delete 10.0.1.9:8443", "tags"}
	if !slices.Equal(api.calls, want) {
		t.Fatalf("calls=%v want %v", api.calls, want)
	}
	if result, err = controller(api, store).Reconcile(ctx, 1); err != nil || result.InSync != 1 {
		t.Fatalf("second pass result=%+v err=%v", result, err)
	}

	// A host scales out; only the new backend is added.
	api.calls = nil
	spec = FromPlacement(nlbID, "api", 8443, []oci.Instance{instance("10.0.1.11", "RUNNING"), instance("10.0.1.12", "RUNNING"), instance("10.0.1.14", "RUNNING")})
	if changed, err := Publish(ctx, store, key, ociresource.PolicyEnforce, spec); err != nil || !changed {
		t.Fatal(err)
	}
	if _, err := controller(api, store).Reconcile(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(api.calls, []string{"create 10.0.1.14:8443", "tags"}) {
		t.Fatalf("calls=%v", api.calls)
	}
}

func TestEmptyPlacementIsNeverPublishedOrApplied(t *testing.T) {
	store := ociresource.NewMemoryStore()
	spec := FromPlacement(nlbID, "api", 8443, []oci.Instance{instance("10.0.1.11", "STOPPED")})
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
		t.Fatal("published an empty backend set")
	}
	spec.AllowEmpty = true
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
}

func TestForeignNLBAndFailedWorkRequests(t *testing.T) {
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	foreign := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: ociresource.Tags{Freeform: map[string]string{"terrascale-owner": "cell-gru"}}}}
	if result, err := controller(foreign, store).Reconcile(t.Context(), 1); err != nil || result.Foreign != 1 || len(foreign.calls) != 0 {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, foreign.calls)
	}
	failing := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}, failWR: true}
	if _, err := controller(failing, store).Reconcile(t.Context(), 1); err == nil {
		t.Fatal("ignored a failed work request")
	}
	status, _, _ := store.GetStatus(t.Context(), key)
	if status.Error == "" || status.Applied {
		t.Fatalf("status=%+v", status)
	}
}

func TestTombstoneDrainsBackendsThenPurges(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443, Weight: 5}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	// Reweighting uses update, not delete and re-add.
	spec.Backends[0].Weight = 7
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(api.calls, []string{"update 10.0.1.11:8443", "tags"}) || api.backends[0].Weight != 7 {
		t.Fatalf("calls=%v backends=%+v", api.calls, api.backends)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
		t.Fatal("published over a tombstone")
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

func TestTombstonePurgesWhenTheNLBIsGone(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.gone = true
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing NLB: result=%+v err=%v", result, err)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing NLB: result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("unexpected mutations: %v", api.calls)
	}
}

func TestSpecValidation(t *testing.T) {
	for _, spec := range []Spec{
		{NLBID: "ocid1.loadbalancer.oc1..x", BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}}},
		{NLBID: nlbID, Backends: []Backend{{IP: "10.0.0.1", Port: 1}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "8.8.8.8", Port: 1}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 0}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}, {IP: "10.0.0.1", Port: 1, Weight: 3}}},
		{NLBID: nlbID, BackendSet: "api"},
	} {
		if spec.Validate() == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	if _, err := Publish(t.Context(), ociresource.NewMemoryStore(), ociresource.Key{Region: "GRU", Kind: "0000000000V4MRM46HP1SNGDYW", Name: "x"},
		ociresource.PolicyEnforce, Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}}}); err == nil {
		t.Fatal("published under another kind")
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
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{
		{IP: "10.0.1.11", Port: 8443}, {IP: "10.0.1.12", Port: 8443}, {IP: "10.0.1.13", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	// The controller's own guard plus one mutation, then leadership is lost.
	fenced := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: &fenceAfter{remaining: 2}}
	if _, err := fenced.Reconcile(t.Context(), 1); err == nil {
		t.Fatal("a fenced pass reported success")
	}
	if len(api.calls) != 1 {
		t.Fatalf("mutations after losing authority: %v", api.calls)
	}
}

func TestRestampAfterBackendChangesUsesAFreshETag(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, ETag: "etag-0", Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	result, err := controller(api, store).Reconcile(t.Context(), 1)
	if err != nil || result.Failed != 0 {
		t.Fatalf("drift with a generation bump: result=%+v err=%v", result, err)
	}
	if !slices.Equal(api.calls, []string{"create 10.0.1.11:8443", "tags"}) {
		t.Fatalf("calls = %v", api.calls)
	}
}

func TestTombstonePurgesWhenTheBackendSetIsGone(t *testing.T) {
	api := &fakeAPI{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := ociresource.NewMemoryStore()
	spec := Spec{NLBID: nlbID, BackendSet: "typo", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.setGone = true
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing backend set: result=%+v err=%v", result, err)
	}
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing backend set: result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
}
