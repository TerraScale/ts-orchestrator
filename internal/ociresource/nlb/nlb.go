// Package nlb reconciles the backends of one backend set on an owned OCI
// network load balancer, so the public API NLB follows the member hosts that
// placement actually runs.
//
// The NLB must carry the controller's ownership tags for the desired key.
// Backend changes are applied one at a time, each waiting for its NLB work
// request, because OCI serializes NLB mutations. A plan that would leave the
// backend set empty is refused unless the spec explicitly allows it, so a
// transient empty placement observation cannot black-hole the public API.
package nlb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

// Kind is the desired-state kind for NLB backend sets.
const Kind = "nlb-backends"

const (
	maxBackends   = 64
	defaultWeight = 1
)

// Backend is one IP backend.
type Backend struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Weight int    `json:"weight,omitempty"`
	// name is the observed OCI backend name, used for update and delete.
	name string
}

func (b Backend) weight() int { return cmp.Or(b.Weight, defaultWeight) }

// key identifies the backend by address for matching.
func (b Backend) key() string { return b.IP + ":" + strconv.Itoa(b.Port) }

// Name is the OCI backend name: the observed name, or the default name OCI
// assigns to an IP backend.
func (b Backend) Name() string { return cmp.Or(b.name, b.key()) }

// Spec is the desired backend set.
type Spec struct {
	NLBID      string    `json:"nlbId"`
	BackendSet string    `json:"backendSet"`
	Backends   []Backend `json:"backends"`
	// AllowEmpty permits removing the last backend.
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// Validate rejects malformed specs.
func (s Spec) Validate() error {
	if !strings.HasPrefix(s.NLBID, "ocid1.networkloadbalancer.") || s.BackendSet == "" || len(s.BackendSet) > 32 {
		return errors.New("NLB spec requires an NLB OCID and backend set name")
	}
	if len(s.Backends) > maxBackends {
		return errors.New("NLB spec exceeds its backend bound")
	}
	seen := map[string]bool{}
	for _, backend := range s.Backends {
		address, err := netip.ParseAddr(backend.IP)
		if err != nil || !address.Is4() || !address.IsPrivate() {
			return fmt.Errorf("NLB backend %q is not a private IPv4 address", backend.IP)
		}
		if backend.Port < 1 || backend.Port > 65535 || backend.Weight < 0 || backend.Weight > 100 {
			return errors.New("NLB backend port or weight is out of range")
		}
		if seen[backend.key()] {
			return errors.New("NLB spec repeats a backend")
		}
		seen[backend.key()] = true
	}
	if len(s.Backends) == 0 && !s.AllowEmpty {
		return errors.New("NLB spec has no backends and does not allow an empty set")
	}
	return nil
}

// LoadBalancer is an observed NLB.
type LoadBalancer struct {
	ID   string
	ETag string
	Tags ociresource.Tags
}

// API is the narrow OCI seam. Mutations return the NLB work request ID.
type API interface {
	GetLoadBalancer(ctx context.Context, id string) (LoadBalancer, error)
	ListBackends(ctx context.Context, id, backendSet string) ([]Backend, error)
	CreateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error)
	UpdateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error)
	DeleteBackend(ctx context.Context, id, backendSet, name string) (string, error)
	UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) (string, error)
	WaitWorkRequest(ctx context.Context, id string) error
}

// Observed is the NLB and the backend set's current backends.
type Observed struct {
	LoadBalancer LoadBalancer
	Backends     []Backend
}

// Reconciler is the ociresource.Resource for NLB backend sets.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, Observed] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (Observed, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return Observed{}, false, err
	}
	balancer, err := r.API.GetLoadBalancer(ctx, target.Spec.NLBID)
	if target.Deleting && errors.Is(err, ociresource.ErrGone) {
		// The NLB and therefore every backend is gone.
		return Observed{}, false, nil
	}
	if err != nil {
		return Observed{}, false, err
	}
	if balancer.ID != target.Spec.NLBID || !target.Ownership.Owns(target.Key, balancer.Tags) {
		return Observed{}, true, ociresource.ErrForeign
	}
	backends, err := r.API.ListBackends(ctx, target.Spec.NLBID, target.Spec.BackendSet)
	if target.Deleting && errors.Is(err, ociresource.ErrGone) {
		// The backend set is gone; there is nothing left to drain.
		return Observed{LoadBalancer: balancer}, false, nil
	}
	if err != nil {
		return Observed{}, false, err
	}
	if target.Deleting && len(backends) == 0 {
		return Observed{LoadBalancer: balancer}, false, nil
	}
	return Observed{LoadBalancer: balancer, Backends: backends}, true, nil
}

type delta struct {
	create, update, remove []Backend
}

func changes(spec Spec, observed []Backend) delta {
	have := map[string]Backend{}
	for _, backend := range observed {
		have[backend.key()] = backend
	}
	want := map[string]bool{}
	var d delta
	for _, backend := range spec.Backends {
		want[backend.key()] = true
		current, ok := have[backend.key()]
		switch {
		case !ok:
			d.create = append(d.create, backend)
		case current.weight() != backend.weight():
			backend.name = current.name
			d.update = append(d.update, backend)
		}
	}
	for _, backend := range observed {
		if !want[backend.key()] {
			d.remove = append(d.remove, backend)
		}
	}
	for _, list := range [][]Backend{d.create, d.update, d.remove} {
		slices.SortFunc(list, func(a, b Backend) int { return strings.Compare(a.key(), b.key()) })
	}
	return d
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed Observed, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "NLB %s is not visible", target.Spec.NLBID)
		return plan
	}
	d := changes(target.Spec, observed.Backends)
	for _, backend := range d.create {
		plan.Add("add-backend", "%s weight %d", backend.Name(), backend.weight())
	}
	for _, backend := range d.update {
		plan.Add("reweight-backend", "%s weight %d", backend.Name(), backend.weight())
	}
	for _, backend := range d.remove {
		plan.Add("remove-backend", "%s", backend.Name())
	}
	if target.Ownership.Stale(observed.LoadBalancer.Tags, target.Generation, target.SpecDigest) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

// mutate fences, runs one NLB mutation and waits for its work request.
func (r Reconciler) mutate(ctx context.Context, target ociresource.Target[Spec], call func() (string, error)) error {
	if err := target.Fence(ctx); err != nil {
		return err
	}
	id, err := call()
	return r.wait(ctx, id, err)
}

func (r Reconciler) wait(ctx context.Context, workRequest string, err error) error {
	if err != nil {
		return err
	}
	if workRequest == "" {
		return errors.New("NLB mutation returned no work request")
	}
	return r.API.WaitWorkRequest(ctx, workRequest)
}

func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed Observed, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("NLB %s is not visible; the reconciler never creates load balancers", target.Spec.NLBID)
	}
	if err := target.Spec.Validate(); err != nil {
		return err
	}
	spec, set := target.Spec, target.Spec.BackendSet
	d := changes(spec, observed.Backends)
	// Add and reweight before removing so capacity never dips below the
	// intersection of the old and new sets.
	for _, backend := range d.create {
		if err := r.mutate(ctx, target, func() (string, error) { return r.API.CreateBackend(ctx, spec.NLBID, set, backend) }); err != nil {
			return fmt.Errorf("add NLB backend %s: %w", backend.Name(), err)
		}
	}
	for _, backend := range d.update {
		if err := r.mutate(ctx, target, func() (string, error) { return r.API.UpdateBackend(ctx, spec.NLBID, set, backend) }); err != nil {
			return fmt.Errorf("reweight NLB backend %s: %w", backend.Name(), err)
		}
	}
	for _, backend := range d.remove {
		if err := r.mutate(ctx, target, func() (string, error) { return r.API.DeleteBackend(ctx, spec.NLBID, set, backend.Name()) }); err != nil {
			return fmt.Errorf("remove NLB backend %s: %w", backend.Name(), err)
		}
	}
	if target.Ownership.Stale(observed.LoadBalancer.Tags, target.Generation, target.SpecDigest) {
		balancer := observed.LoadBalancer
		if len(d.create)+len(d.update)+len(d.remove) > 0 {
			// The backend work requests advanced the NLB's ETag; restamp
			// against a fresh read, and only while it is still owned.
			fresh, err := r.API.GetLoadBalancer(ctx, spec.NLBID)
			if err != nil {
				return fmt.Errorf("re-read NLB before restamp: %w", err)
			}
			if fresh.ID != spec.NLBID || !target.Ownership.Owns(target.Key, fresh.Tags) {
				return ociresource.ErrForeign
			}
			balancer = fresh
		}
		tags := balancer.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
		if err := r.mutate(ctx, target, func() (string, error) { return r.API.UpdateTags(ctx, spec.NLBID, balancer.ETag, tags) }); err != nil {
			return fmt.Errorf("restamp NLB ownership: %w", err)
		}
	}
	return nil
}

// Delete drains the backend set. The NLB and backend set are not deleted:
// they hold the region's reserved public IP.
func (r Reconciler) Delete(ctx context.Context, target ociresource.Target[Spec], observed Observed) error {
	for _, backend := range observed.Backends {
		if err := r.mutate(ctx, target, func() (string, error) {
			return r.API.DeleteBackend(ctx, target.Spec.NLBID, target.Spec.BackendSet, backend.Name())
		}); err != nil {
			return fmt.Errorf("remove NLB backend %s: %w", backend.Name(), err)
		}
	}
	return nil
}

// FromPlacement derives the desired backend set from the member hosts the
// fleet currently observes. Only RUNNING hosts with a verified private IP are
// backends; the order of instances does not affect the result.
func FromPlacement(nlbID, backendSet string, port int, instances []oci.Instance) Spec {
	spec := Spec{NLBID: nlbID, BackendSet: backendSet}
	for _, instance := range instances {
		if instance.State != "RUNNING" || instance.PrivateIP == "" {
			continue
		}
		spec.Backends = append(spec.Backends, Backend{IP: instance.PrivateIP, Port: port})
	}
	slices.SortFunc(spec.Backends, func(a, b Backend) int { return strings.Compare(a.key(), b.key()) })
	spec.Backends = slices.CompactFunc(spec.Backends, func(a, b Backend) bool { return a.key() == b.key() })
	return spec
}

// Publish stores spec as the next generation of key when its digest differs
// from the current record. It returns whether a new generation was written.
// An empty placement observation is never published unless the spec allows
// it, so the previous backend set stays in force.
func Publish(ctx context.Context, store ociresource.Store, key ociresource.Key, policy ociresource.DriftPolicy, spec Spec) (bool, error) {
	if key.Kind != Kind {
		return false, errors.New("NLB backends must be published under the nlb-backends kind")
	}
	return ociresource.Publish(ctx, store, key, policy, spec)
}
