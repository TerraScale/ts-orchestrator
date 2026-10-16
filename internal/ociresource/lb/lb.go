// Package lb reconciles the backends of one backend set on an owned OCI
// flexible (L7) load balancer, so the public API follows the TerraBase seats
// that serve and drains a seat before it restarts.
//
// The load balancer must carry the controller's ownership tags for the
// desired key. Backend changes are applied one at a time, each waiting for
// its work request, because OCI serializes load balancer mutations. They run
// in the order create, undrain, drain, remove, so while a plan applies the
// serving backends never drop below the ones the new spec serves. A spec in
// which no backend serves is refused unless it explicitly allows it, so a
// transient empty observation cannot black-hole the public API, and a plan
// that would take a serving backend out of rotation is held while no backend
// that keeps serving reports health OK.
//
// The reconciler owns the set: every listed backend is weight 1, neither
// backup nor offline, so drain in the spec is the only way to take one out.
package lb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

// Kind is the desired-state kind for L7 load balancer backend sets.
const Kind = "lb-backends"

// PublicTerraBase names the public API load balancer's TerraBase backend set
// under Kind: the controller reconciles it and public-api apply stamps its
// ownership.
const PublicTerraBase = "public-terrabase"

// ErrNoHealthyBackend holds a plan that would drain or remove a serving
// backend while no backend that keeps serving reports health OK.
var ErrNoHealthyBackend = errors.New("no backend that keeps serving reports health OK")

const (
	maxBackends = 64
	// defaultWeight is every managed backend's weight: a backend set
	// round-robins over equal members.
	defaultWeight = 1
)

// Backend is one IP backend. Drain keeps it in the set but sends it no new
// requests.
type Backend struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Drain bool   `json:"drain,omitempty"`
	// The observed weight, backup and offline flags and OCI name; desired
	// backends are always weight 1, neither backup nor offline.
	weight          int
	backup, offline bool
	name            string
}

// key identifies the backend by address for matching.
func (b Backend) key() string { return b.IP + ":" + strconv.Itoa(b.Port) }

// Name is the OCI backend name: the observed name, or the ip:port name OCI
// gives an IP backend.
func (b Backend) Name() string {
	if b.name != "" {
		return b.name
	}
	return b.key()
}

// Spec is the desired backend set.
type Spec struct {
	LoadBalancerID string    `json:"loadBalancerId"`
	BackendSet     string    `json:"backendSet"`
	Backends       []Backend `json:"backends"`
	// AllowEmpty permits a set in which no backend serves: none, or every
	// one drained.
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// Validate rejects malformed specs and, unless AllowEmpty is set, a set with
// no serving backend.
func (s Spec) Validate() error {
	if !strings.HasPrefix(s.LoadBalancerID, "ocid1.loadbalancer.") || s.BackendSet == "" || len(s.BackendSet) > 32 {
		return errors.New("load balancer spec requires a load balancer OCID and backend set name")
	}
	if len(s.Backends) > maxBackends {
		return errors.New("load balancer spec exceeds its backend bound")
	}
	seen := map[string]bool{}
	for _, backend := range s.Backends {
		address, err := netip.ParseAddr(backend.IP)
		if err != nil || !address.Is4() || !address.IsPrivate() {
			return fmt.Errorf("load balancer backend %q is not a private IPv4 address", backend.IP)
		}
		if backend.Port < 1 || backend.Port > 65535 {
			return errors.New("load balancer backend port is out of range")
		}
		if seen[backend.key()] {
			return errors.New("load balancer spec repeats a backend")
		}
		seen[backend.key()] = true
	}
	if !s.serves() && !s.AllowEmpty {
		return errors.New("load balancer spec has no serving backend and does not allow it")
	}
	return nil
}

// serves reports whether any backend is left in rotation.
func (s Spec) serves() bool {
	return slices.ContainsFunc(s.Backends, func(b Backend) bool { return !b.Drain })
}

// LoadBalancer is an observed load balancer.
type LoadBalancer struct {
	ID   string
	ETag string
	Tags ociresource.Tags
}

// API is the narrow OCI seam. Mutations return the work request ID.
type API interface {
	GetLoadBalancer(ctx context.Context, id string) (LoadBalancer, error)
	ListBackends(ctx context.Context, id, backendSet string) ([]Backend, error)
	CreateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error)
	UpdateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error)
	DeleteBackend(ctx context.Context, id, backendSet, name string) (string, error)
	// UnhealthyBackends names the set's backends whose health is not OK.
	UnhealthyBackends(ctx context.Context, id, backendSet string) (map[string]bool, error)
	UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) (string, error)
	WaitWorkRequest(ctx context.Context, id string) error
}

// Observed is the load balancer and the backend set's current backends.
type Observed struct {
	LoadBalancer LoadBalancer
	Backends     []Backend
}

// Reconciler is the ociresource.Resource for L7 load balancer backend sets.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, Observed] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (Observed, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return Observed{}, false, err
	}
	balancer, err := r.API.GetLoadBalancer(ctx, target.Spec.LoadBalancerID)
	if target.Deleting && errors.Is(err, ociresource.ErrGone) {
		return Observed{}, false, nil
	}
	if err != nil {
		return Observed{}, false, err
	}
	if balancer.ID != target.Spec.LoadBalancerID || !target.Ownership.Owns(target.Key, balancer.Tags) {
		return Observed{}, true, ociresource.ErrForeign
	}
	backends, err := r.API.ListBackends(ctx, target.Spec.LoadBalancerID, target.Spec.BackendSet)
	if target.Deleting && errors.Is(err, ociresource.ErrGone) {
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

// delta is a plan's backend changes in the order they are applied.
type delta struct {
	create, undrain, drain, remove []Backend
}

func (d delta) empty() bool { return len(d.create)+len(d.undrain)+len(d.drain)+len(d.remove) == 0 }

// restamp reports whether the plan restamps stale ownership tags. Drain
// flips do not: they are a rollout's critical path and OCI serializes every
// load balancer work request. The next pass that changes nothing restamps.
func (d delta) restamp(target ociresource.Target[Spec], tags ociresource.Tags) bool {
	return (d.empty() || len(d.create)+len(d.remove) > 0) && target.Ownership.Stale(tags, target.Generation, target.SpecDigest)
}

// serving reports whether an observed backend takes requests.
func (b Backend) serving() bool { return !b.Drain && !b.backup && !b.offline }

// Serving reports an observed backend the load balancer may route to:
// neither drained nor offline. A backup serves too, once the primaries
// fail their health checks.
func (b Backend) Serving() bool { return !b.Drain && !b.offline }

// Fenced returns the backend with drain and offline set and its weight and
// backup kept, for UpdateBackend: a release fence takes a node's backend
// out of rotation and returns it as it was.
func (b Backend) Fenced(drain, offline bool) Backend {
	b.Drain, b.offline = drain, offline
	return b
}

// Shape is an observed backend's weight and backup flag.
func (b Backend) Shape() (weight int, backup bool) { return b.weight, b.backup }

// Shaped returns the backend with weight (zero means 1) and backup.
func (b Backend) Shaped(weight int, backup bool) Backend {
	b.weight, b.backup = weight, backup
	return b
}

// outOfRotation lists the currently serving backends the plan drains or
// removes.
func (d delta) outOfRotation(observed []Backend) []Backend {
	current := map[string]Backend{}
	for _, backend := range observed {
		current[backend.key()] = backend
	}
	var out []Backend
	for _, backend := range slices.Concat(d.drain, d.remove) {
		if current[backend.key()].serving() {
			out = append(out, backend)
		}
	}
	return out
}

func changes(spec Spec, observed []Backend) delta {
	have := map[string]Backend{}
	for _, backend := range observed {
		have[backend.key()] = backend
	}
	want := map[string]bool{}
	var d delta
	for _, backend := range spec.Backends {
		backend.weight, backend.backup, backend.offline, backend.name = defaultWeight, false, false, ""
		want[backend.key()] = true
		current, ok := have[backend.key()]
		switch {
		case !ok:
			d.create = append(d.create, backend)
		case current.Drain == backend.Drain && current.weight == defaultWeight && !current.backup && !current.offline:
		case backend.Drain:
			backend.name = current.name
			d.drain = append(d.drain, backend)
		default:
			backend.name = current.name
			d.undrain = append(d.undrain, backend)
		}
	}
	for _, backend := range observed {
		if !want[backend.key()] {
			d.remove = append(d.remove, backend)
		}
	}
	for _, list := range [][]Backend{d.create, d.undrain, d.drain, d.remove} {
		slices.SortFunc(list, func(a, b Backend) int { return strings.Compare(a.key(), b.key()) })
	}
	return d
}

func state(backend Backend) string {
	if backend.Drain {
		return "drained"
	}
	return "serving"
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed Observed, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "load balancer %s is not visible", target.Spec.LoadBalancerID)
		return plan
	}
	d := changes(target.Spec, observed.Backends)
	for _, backend := range d.create {
		plan.Add("add-backend", "%s %s", backend.Name(), state(backend))
	}
	for _, backend := range d.undrain {
		plan.Add("serve-backend", "%s", backend.Name())
	}
	for _, backend := range d.drain {
		plan.Add("drain-backend", "%s", backend.Name())
	}
	for _, backend := range d.remove {
		plan.Add("remove-backend", "%s", backend.Name())
	}
	if d.restamp(target, observed.LoadBalancer.Tags) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

// checkHealthy runs after the plan's creates and undrains. It holds the
// rest of the plan unless a backend the spec keeps serving reports health
// OK. A backend this plan created has never been checked, so it does not
// count.
func (r Reconciler) checkHealthy(ctx context.Context, spec Spec, observed []Backend) error {
	unhealthy, err := r.API.UnhealthyBackends(ctx, spec.LoadBalancerID, spec.BackendSet)
	if err != nil {
		return fmt.Errorf("read load balancer backend health: %w", err)
	}
	existing := map[string]Backend{}
	for _, backend := range observed {
		existing[backend.key()] = backend
	}
	for _, backend := range spec.Backends {
		current, ok := existing[backend.key()]
		if ok && !backend.Drain && !unhealthy[current.Name()] {
			return nil
		}
	}
	return fmt.Errorf("%w: hold draining or removing a serving backend", ErrNoHealthyBackend)
}

// mutate fences, runs one load balancer mutation and waits for its work
// request.
func (r Reconciler) mutate(ctx context.Context, target ociresource.Target[Spec], call func() (string, error)) error {
	if err := target.Fence(ctx); err != nil {
		return err
	}
	id, err := call()
	if err != nil {
		return err
	}
	if id == "" {
		return errors.New("load balancer mutation returned no work request")
	}
	return r.API.WaitWorkRequest(ctx, id)
}

func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed Observed, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("load balancer %s is not visible; the reconciler never creates load balancers", target.Spec.LoadBalancerID)
	}
	if err := target.Spec.Validate(); err != nil {
		return err
	}
	id, set := target.Spec.LoadBalancerID, target.Spec.BackendSet
	d := changes(target.Spec, observed.Backends)
	update := func(b Backend) (string, error) { return r.API.UpdateBackend(ctx, id, set, b) }
	run := func(verb string, backends []Backend, call func(Backend) (string, error)) error {
		for _, backend := range backends {
			if err := r.mutate(ctx, target, func() (string, error) { return call(backend) }); err != nil {
				return fmt.Errorf("%s load balancer backend %s: %w", verb, backend.Name(), err)
			}
		}
		return nil
	}
	if err := run("add", d.create, func(b Backend) (string, error) { return r.API.CreateBackend(ctx, id, set, b) }); err != nil {
		return err
	}
	if err := run("serve", d.undrain, update); err != nil {
		return err
	}
	// Only a spec that serves nothing (allowed by AllowEmpty) skips the
	// guard: no backend could ever satisfy it.
	if len(d.outOfRotation(observed.Backends)) > 0 && target.Spec.serves() {
		if err := r.checkHealthy(ctx, target.Spec, observed.Backends); err != nil {
			return err
		}
	}
	if err := run("drain", d.drain, update); err != nil {
		return err
	}
	if err := run("remove", d.remove, func(b Backend) (string, error) { return r.API.DeleteBackend(ctx, id, set, b.Name()) }); err != nil {
		return err
	}
	if d.restamp(target, observed.LoadBalancer.Tags) {
		balancer := observed.LoadBalancer
		if !d.empty() {
			// The backend work requests advanced the load balancer's ETag;
			// restamp against a fresh read, and only while it is still owned.
			fresh, err := r.API.GetLoadBalancer(ctx, id)
			if err != nil {
				return fmt.Errorf("re-read load balancer before restamp: %w", err)
			}
			if fresh.ID != id || !target.Ownership.Owns(target.Key, fresh.Tags) {
				return ociresource.ErrForeign
			}
			balancer = fresh
		}
		tags := balancer.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
		if err := r.mutate(ctx, target, func() (string, error) { return r.API.UpdateTags(ctx, id, balancer.ETag, tags) }); err != nil {
			return fmt.Errorf("restamp load balancer ownership: %w", err)
		}
	}
	return nil
}

// Delete empties the backend set. The load balancer and backend set are not
// deleted: they hold the cell's public address and listeners.
func (r Reconciler) Delete(ctx context.Context, target ociresource.Target[Spec], observed Observed) error {
	for _, backend := range observed.Backends {
		if err := r.mutate(ctx, target, func() (string, error) {
			return r.API.DeleteBackend(ctx, target.Spec.LoadBalancerID, target.Spec.BackendSet, backend.Name())
		}); err != nil {
			return fmt.Errorf("remove load balancer backend %s: %w", backend.Name(), err)
		}
	}
	return nil
}

// Publish stores spec as the next generation of key when its digest differs
// from the current record, and reports whether it wrote. A spec with no
// serving backend is never published unless it allows it, so the previous
// backend set stays in force.
func Publish(ctx context.Context, store ociresource.Store, key ociresource.Key, policy ociresource.DriftPolicy, spec Spec) (bool, error) {
	if key.Kind != Kind {
		return false, errors.New("load balancer backends must be published under the lb-backends kind")
	}
	return ociresource.Publish(ctx, store, key, policy, spec)
}
