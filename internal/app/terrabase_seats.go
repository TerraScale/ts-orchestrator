package app

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// TerraBaseSeatsConfig turns on zero-downtime TerraBase rollouts (TS-571):
// a static member's host restarts it into a new desired generation only
// when the leader's seat controller permits it, one seat of the cell at a
// time and, with oci_reconcile.public_lb, drained on the public load
// balancer first. Off unless Enabled.
type TerraBaseSeatsConfig struct {
	Enabled bool `json:"enabled"`
	// DrainGraceSeconds lets in-flight requests finish after the drain
	// before the host may stop the member; zero means 15 seconds.
	DrainGraceSeconds int `json:"drain_grace_seconds,omitzero"`
	// SettleSeconds is how long a restarted member must keep serving
	// before it returns to rotation; zero means 10 seconds.
	SettleSeconds int `json:"settle_seconds,omitzero"`
}

func (c TerraBaseSeatsConfig) durations() (grace, settle time.Duration, err error) {
	if c.DrainGraceSeconds < 0 || c.DrainGraceSeconds > 300 || c.SettleSeconds < 0 || c.SettleSeconds > 300 {
		return 0, 0, errors.New("terrabase_seats drain_grace_seconds and settle_seconds must be between 0 and 300")
	}
	return time.Duration(c.DrainGraceSeconds) * time.Second, time.Duration(c.SettleSeconds) * time.Second, nil
}

// terraBaseSeatMembers lists the seats the signed terrabase profile names.
// A seat is served by the public load balancer backend public_lb publishes
// for it, at the client port; with no public_lb, or outside its seats, it
// has none. Every C# member replicates with every other, so all are one
// group. No terrabase profile means no seats.
//
// A profile the public_lb publisher refuses is refused here too: the
// publisher keeps the backend set it published before, so seats derived
// from the new profile could restart undrained under the old set. The
// error holds every restart until they agree.
func terraBaseSeatMembers(profiles map[string]WorkloadProfile, public *OciReconcileLBConfig) ([]seatrollout.Member, error) {
	if public != nil {
		if _, err := public.spec(profiles, nil); err != nil {
			return nil, err
		}
	}
	profile, ok := profiles[terrabase.Role]
	if !ok {
		return nil, nil
	}
	parsed, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		return nil, err
	}
	members := make([]seatrollout.Member, 0, len(parsed.Peers))
	for _, peer := range parsed.Peers {
		member := seatrollout.Member{Node: peer.Name, Group: terrabase.Role}
		if public != nil && (len(public.Seats) == 0 || slices.Contains(public.Seats, peer.Name)) {
			member.Backend = peer.Address.Addr().String() + ":" + strconv.Itoa(parsed.ClientPort)
		}
		members = append(members, member)
	}
	return members, nil
}

// newSeatController builds the leader's seat controller. With public_lb it
// drains seats on the public load balancer and wakes its reconciler after
// every step; without it seats restart one at a time and nothing is drained.
func newSeatController(cfg Config, store *seatrollout.Store, fencer authority.Fencer, hosts seatrollout.Hosts,
	profiles func() map[string]WorkloadProfile, reconcile *ociReconcileRuntime,
) *seatrollout.Controller {
	grace, settle, _ := cfg.Controller.TerraBaseSeats.durations()
	var public *OciReconcileLBConfig
	if config := cfg.Controller.OciReconcile; config != nil && config.Enabled {
		public = config.PublicLB
	}
	controller := &seatrollout.Controller{Store: store, Fencer: fencer, Hosts: hosts, DrainGrace: grace, Settle: settle,
		Seats: func() ([]seatrollout.Member, error) { return terraBaseSeatMembers(profiles(), public) }}
	if reconcile != nil && reconcile.seatBackends != nil {
		controller.Backends, controller.Wake = reconcile.seatBackends, reconcile.wakeRunner
	}
	return controller
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
