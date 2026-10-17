package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
)

// These keys identify protected backend operations, never ownership of the LB.
type rootTaskTrafficSpec struct {
	LoadBalancerID string                   `json:"loadBalancerId"`
	BackendSet     string                   `json:"backendSet"`
	Port           int                      `json:"port"`
	MinServing     int                      `json:"minServing"`
	Backends       []rootTaskTrafficBackend `json:"backends"`
}

type rootTaskTrafficBackend struct {
	Node         string    `json:"node"`
	IP           string    `json:"ip"`
	Hold         string    `json:"hold,omitempty"`
	UnreadySince time.Time `json:"unreadySince,omitzero"`
	DrainSince   time.Time `json:"drainSince,omitzero"`
	Offline      bool      `json:"offline"`
}

func (s rootTaskTrafficSpec) Validate() error {
	if !strings.HasPrefix(s.LoadBalancerID, "ocid1.loadbalancer.") || s.BackendSet == "" || len(s.BackendSet) > 63 || s.Port < 1024 || s.Port > 65535 || s.MinServing < 1 || s.MinServing > 64 || len(s.Backends) > 64 {
		return errors.New("task traffic exceeds its signed backend-set bounds")
	}
	nodes, addresses := map[string]bool{}, map[string]bool{}
	for _, backend := range s.Backends {
		ip, err := netip.ParseAddr(backend.IP)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || !grantToken.MatchString(backend.Node) || nodes[backend.Node] || addresses[backend.IP] || backend.Offline && backend.Hold == "" || backend.Hold != "" && backend.DrainSince.IsZero() {
			return errors.New("task traffic contains an ambiguous or unbound task endpoint")
		}
		nodes[backend.Node], addresses[backend.IP] = true, true
	}
	return nil
}

type rootTaskTrafficResource struct {
	kind        string
	api         lb.API
	client      loadbalancer.LoadBalancerClient
	region      string
	compartment string
	pins        map[string]rootTaskTrafficSpec
}

func (r rootTaskTrafficResource) Kind() string { return r.kind }

// The original root-signed fence authorizes only these exact existing sets.
// No LB tags, ownership adoption, LB creation or whole-resource deletion occur.
func (r rootTaskTrafficResource) pinned(ctx context.Context, spec rootTaskTrafficSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	pin, ok := r.pins[spec.BackendSet]
	if !ok || spec.LoadBalancerID != pin.LoadBalancerID || spec.Port != pin.Port || spec.MinServing != pin.MinServing || !strings.HasPrefix(spec.LoadBalancerID, "ocid1.loadbalancer.oc1."+r.region+".") {
		return ociresource.ErrFenced
	}
	balancer, err := r.client.GetLoadBalancer(ociclient.RequestContext(ctx), loadbalancer.GetLoadBalancerRequest{LoadBalancerId: new(spec.LoadBalancerID)})
	if err != nil {
		return err
	}
	if balancer.Id == nil || *balancer.Id != spec.LoadBalancerID || balancer.CompartmentId == nil || *balancer.CompartmentId != r.compartment || balancer.LifecycleState != loadbalancer.LoadBalancerLifecycleStateActive {
		return ociresource.ErrForeign
	}
	set, err := r.client.GetBackendSet(ociclient.RequestContext(ctx), loadbalancer.GetBackendSetRequest{LoadBalancerId: new(spec.LoadBalancerID), BackendSetName: new(spec.BackendSet)})
	if err != nil {
		return err
	}
	if set.Name == nil || *set.Name != spec.BackendSet {
		return ociresource.ErrForeign
	}
	return nil
}

func (r rootTaskTrafficResource) Observe(ctx context.Context, target ociresource.Target[rootTaskTrafficSpec]) ([]lb.Backend, bool, error) {
	if target.Deleting {
		return nil, false, errors.New("task traffic never tombstones an entire backend set")
	}
	if err := r.pinned(ctx, target.Spec); err != nil {
		return nil, false, err
	}
	backends, err := r.api.ListBackends(ctx, target.Spec.LoadBalancerID, target.Spec.BackendSet)
	if err != nil {
		return nil, false, err
	}
	if len(backends) > 64 {
		return nil, false, errors.New("task traffic backend observation exceeds its bound")
	}
	seen := map[string]bool{}
	for _, backend := range backends {
		ip, err := netip.ParseAddr(backend.IP)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || backend.Port != target.Spec.Port || backend.Name() != netip.AddrPortFrom(ip, uint16(backend.Port)).String() || seen[backend.IP] {
			return nil, false, errors.New("task traffic backend observation is outside its exact signed port or repeats an endpoint")
		}
		seen[backend.IP] = true
	}
	return backends, true, nil
}

func trafficBackend(spec rootTaskTrafficSpec, want rootTaskTrafficBackend) lb.Backend {
	return lb.Backend{IP: want.IP, Port: spec.Port}.Fenced(want.Hold != "", want.Offline)
}

func trafficBackendEqual(current lb.Backend, want rootTaskTrafficBackend) bool {
	return reflect.DeepEqual(current, current.Fenced(want.Hold != "", want.Offline).Shaped(1, false))
}

func (r rootTaskTrafficResource) Diff(target ociresource.Target[rootTaskTrafficSpec], observed []lb.Backend, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "signed task backend set is unavailable")
		return plan
	}
	for _, want := range target.Spec.Backends {
		index := slices.IndexFunc(observed, func(b lb.Backend) bool { return b.IP == want.IP })
		if index < 0 {
			plan.Add("add-task-backend", "%s", want.Node)
		} else if !trafficBackendEqual(observed[index], want) {
			plan.Add("update-task-backend", "%s", want.Node)
		}
	}
	return plan
}

// quorum counts only current actual ready tasks that this exact protected spec
// keeps serving. Neither a caller's health claim nor an unknown backend counts.
func (r rootTaskTrafficResource) quorum(ctx context.Context, spec rootTaskTrafficSpec, excluded string) error {
	current, err := r.api.ListBackends(ctx, spec.LoadBalancerID, spec.BackendSet)
	if err != nil {
		return err
	}
	if len(current) > 64 {
		return errors.New("task traffic quorum exceeds its bound")
	}
	health, err := r.client.GetBackendSetHealth(ociclient.RequestContext(ctx), loadbalancer.GetBackendSetHealthRequest{LoadBalancerId: new(spec.LoadBalancerID), BackendSetName: new(spec.BackendSet)})
	if err != nil {
		return err
	}
	if health.TotalBackendCount == nil || *health.TotalBackendCount != len(current) || health.Status != loadbalancer.BackendSetHealthStatusOk && health.Status != loadbalancer.BackendSetHealthStatusWarning && health.Status != loadbalancer.BackendSetHealthStatusCritical {
		return lb.ErrNoHealthyBackend
	}
	unhealthy := map[string]bool{}
	for _, name := range slices.Concat(health.WarningStateBackendNames, health.CriticalStateBackendNames, health.UnknownStateBackendNames) {
		if unhealthy[name] || !slices.ContainsFunc(current, func(b lb.Backend) bool { return b.Name() == name }) {
			return errors.New("task traffic quorum health differs from the observed backend set")
		}
		unhealthy[name] = true
	}
	healthy := len(current) - len(unhealthy)
	if health.Status == loadbalancer.BackendSetHealthStatusOk && len(unhealthy) != 0 ||
		health.Status == loadbalancer.BackendSetHealthStatusWarning && (len(unhealthy) == 0 || 2*healthy < len(current)) ||
		health.Status == loadbalancer.BackendSetHealthStatusCritical && (len(unhealthy) == 0 || 2*healthy >= len(current)) ||
		2*len(health.UnknownStateBackendNames) > len(current) {
		return errors.New("task traffic aggregate health contradicts its backend health inventory")
	}
	serving := 0
	seen := map[string]bool{}
	for _, backend := range current {
		if backend.Port != spec.Port || seen[backend.IP] {
			return errors.New("task traffic quorum contains duplicate or foreign-port endpoints")
		}
		seen[backend.IP] = true
		if backend.IP == excluded || !backend.Serving() || unhealthy[backend.Name()] {
			continue
		}
		if slices.ContainsFunc(spec.Backends, func(want rootTaskTrafficBackend) bool {
			return want.IP == backend.IP && want.Hold == "" && want.UnreadySince.IsZero()
		}) {
			serving++
		}
	}
	if serving < spec.MinServing {
		return fmt.Errorf("%w: signed task quorum requires %d other healthy ready backends, observed %d", lb.ErrNoHealthyBackend, spec.MinServing, serving)
	}
	return nil
}

func (r rootTaskTrafficResource) Apply(ctx context.Context, target ociresource.Target[rootTaskTrafficSpec], _ []lb.Backend, found bool, _ ociresource.Plan) error {
	if !found || !reflect.DeepEqual(r.pins[target.Spec.BackendSet], target.Spec) {
		return ociresource.ErrFenced
	}
	// Serving additions precede removals from rotation. Unknown endpoints stay
	// untouched: only a separately authenticated allocation can identify them.
	wanted := slices.Clone(target.Spec.Backends)
	slices.SortStableFunc(wanted, func(a, b rootTaskTrafficBackend) int {
		if (a.Hold == "") != (b.Hold == "") {
			if a.Hold == "" {
				return -1
			}
			return 1
		}
		return strings.Compare(a.IP, b.IP)
	})
	for _, want := range wanted {
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.pinned(ctx, target.Spec); err != nil {
			return err
		}
		current, _, err := r.Observe(ctx, target)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(current, func(b lb.Backend) bool { return b.IP == want.IP })
		if index >= 0 && trafficBackendEqual(current[index], want) {
			continue
		}
		reduces := index >= 0 && want.Hold != ""
		if reduces {
			if err := r.quorum(ctx, target.Spec, want.IP); err != nil {
				return err
			}
		}
		if err := target.Fence(ctx); err != nil {
			return err
		}
		mutationCtx := ociclient.WithRequestGuard(ctx, func(ctx context.Context) error {
			if err := target.Fence(ctx); err != nil {
				return err
			}
			if err := r.pinned(ctx, target.Spec); err != nil {
				return err
			}
			if reduces {
				if err := r.quorum(ctx, target.Spec, want.IP); err != nil {
					return err
				}
			}
			return target.Fence(ctx)
		})
		var request string
		if index < 0 {
			request, err = r.api.CreateBackend(mutationCtx, target.Spec.LoadBalancerID, target.Spec.BackendSet, trafficBackend(target.Spec, want))
		} else {
			backend := current[index].Fenced(want.Hold != "", want.Offline).Shaped(1, false)
			request, err = r.api.UpdateBackend(mutationCtx, target.Spec.LoadBalancerID, target.Spec.BackendSet, backend)
		}
		if err != nil {
			return err
		}
		if request == "" {
			return errors.New("task traffic mutation returned no work request")
		}
		if err := r.api.WaitWorkRequest(ctx, request); err != nil {
			return err
		}
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.pinned(ctx, target.Spec); err != nil {
			return err
		}
		if reduces {
			if err := r.quorum(ctx, target.Spec, want.IP); err != nil {
				return err
			}
		}
	}
	return target.Fence(ctx)
}

func (rootTaskTrafficResource) Delete(context.Context, ociresource.Target[rootTaskTrafficSpec], []lb.Backend) error {
	return errors.New("task traffic cannot delete an entire backend set")
}

func (r rootTaskTrafficResource) RecoverWorkRequests(ctx context.Context, ids []string) error {
	return (lb.Reconciler{API: r.api}).RecoverWorkRequests(ctx, ids)
}

var _ ociresource.Resource[rootTaskTrafficSpec, []lb.Backend] = rootTaskTrafficResource{}
