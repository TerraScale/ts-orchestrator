package app

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// terraBaseSeatMembers lists the seats the signed terrabase profile names.
// A seat is served by the public load balancer backend public_lb publishes
// for it, at the client port. Missing backend authority holds restarts;
// seats explicitly excluded from its signed set serve no public traffic.
// All members share one replication group. No profile means no seats.
//
// A profile the public_lb publisher refuses is refused here too: the
// publisher keeps the backend set it published before, so seats derived
// from the new profile could restart undrained under the old set. The
// error holds every restart until they agree.
func terraBaseSeatMembers(profiles map[string]WorkloadProfile, public *OciReconcileLBConfig) ([]seatrollout.Member, error) {
	profile, ok := profiles[terrabase.Role]
	if !ok {
		if public != nil {
			return nil, errors.New("public load balancer: the cell has no terrabase workload profile")
		}
		return nil, nil
	}
	if public == nil {
		return nil, errors.New("TerraBase seat restarts require signed public load balancer authority")
	}
	if _, err := public.spec(profiles, nil); err != nil {
		return nil, err
	}
	parsed, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		return nil, err
	}
	members := make([]seatrollout.Member, 0, len(parsed.Peers))
	for _, peer := range parsed.Peers {
		member := seatrollout.Member{Node: peer.Name, Group: terrabase.Role}
		if len(public.Seats) == 0 || slices.Contains(public.Seats, peer.Name) {
			member.Backend = peer.Address.Addr().String() + ":" + strconv.Itoa(parsed.ClientPort)
		}
		members = append(members, member)
	}
	return members, nil
}

// newSeatController always sequences restarts; missing backend authority
// holds every seat until the signed configuration and observer are ready.
func newSeatController(cfg Config, store *seatrollout.Store, fencer authority.Fencer, hosts seatrollout.Hosts,
	profiles func() map[string]WorkloadProfile, reconcile *ociReconcileRuntime,
) *seatrollout.Controller {
	var public *OciReconcileLBConfig
	if config := cfg.Controller.OciReconcile; config != nil {
		public = config.PublicLB
	}
	controller := &seatrollout.Controller{Store: store, Fencer: fencer, Hosts: hosts,
		Seats: func() ([]seatrollout.Member, error) {
			members, err := terraBaseSeatMembers(profiles(), public)
			if err != nil || len(members) == 0 {
				return members, err
			}
			if reconcile == nil || reconcile.seatBackends == nil {
				return nil, errors.New("TerraBase seat backend observation is unavailable")
			}
			return members, nil
		}}
	if reconcile != nil && reconcile.seatBackends != nil {
		controller.Backends, controller.Wake = reconcile.seatBackends, reconcile.wakeRunner
	}
	return controller
}

// seatRestartGate rechecks current backend authority before consuming a
// durable permit, so an earlier permit cannot outlive its signed membership.
func seatRestartGate(controller *seatrollout.Controller) func(context.Context, string, host.Desired) (bool, error) {
	return func(ctx context.Context, node string, desired host.Desired) (bool, error) {
		if desired.Role != terrabase.Role {
			return true, nil
		}
		members, err := controller.Seats()
		if err != nil {
			return false, err
		}
		index := slices.IndexFunc(members, func(member seatrollout.Member) bool { return member.Node == node })
		if index < 0 || desired.Node != node {
			return false, errors.New("TerraBase restart is outside the current signed seats")
		}
		backends, err := controller.Backends(ctx)
		if err != nil {
			return false, err
		}
		if backend := members[index].Backend; backend != "" {
			if _, observed := backends[backend]; !observed {
				return false, errors.New("TerraBase restart backend is unobserved")
			}
		}
		return controller.Store.Granted(ctx, node, desired)
	}
}

// lbSeatBackends reads the public load balancer's TerraBase backends by
// ip:port for the seat controller.
func lbSeatBackends(api lb.API, public OciReconcileLBConfig) func(context.Context) (map[string]seatrollout.Backend, error) {
	return func(ctx context.Context) (map[string]seatrollout.Backend, error) {
		backends, err := api.ListBackends(ctx, public.LoadBalancerID, public.BackendSet)
		if err != nil {
			return nil, err
		}
		unhealthy, err := api.UnhealthyBackends(ctx, public.LoadBalancerID, public.BackendSet)
		if err != nil {
			return nil, err
		}
		out := make(map[string]seatrollout.Backend, len(backends))
		for _, backend := range backends {
			out[backend.IP+":"+strconv.Itoa(backend.Port)] = seatrollout.Backend{Drained: backend.Drain, Healthy: !unhealthy[backend.Name()]}
		}
		return out, nil
	}
}
