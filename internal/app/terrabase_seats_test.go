package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestTerraBaseSeatPermitsRequireCurrentBackendAuthority(t *testing.T) {
	store := testSeatStore(t)
	node := "gru-1-db-1"
	if _, err := store.Put(t.Context(), seatrollout.Seat{Node: node, Epoch: 1, Permit: 2}, 0); err != nil {
		t.Fatal(err)
	}
	profiles := terraBaseSeats(node + "=10.251.0.21:9443")
	public := &OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	backends := map[string]seatrollout.Backend{"10.251.0.21:9465": {Drained: true, Healthy: true}}
	observer := &ociReconcileRuntime{seatBackends: func(context.Context) (map[string]seatrollout.Backend, error) {
		return backends, nil
	}}
	desired := host.Desired{Node: node, Role: terrabase.Role, Generation: 2}
	for _, tc := range []struct {
		name     string
		public   *OciReconcileLBConfig
		observer *ociReconcileRuntime
		want     bool
	}{
		{name: "no backend authority", observer: observer},
		{name: "no actual observation", public: public},
		{name: "signed and observed", public: public, observer: observer, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Controller: ControllerConfig{OciReconcile: &OciReconcileConfig{PublicLB: tc.public}}}
			controller := newSeatController(cfg, store, leaderFence{}, nil,
				func() map[string]WorkloadProfile { return profiles }, tc.observer)
			granted, err := seatRestartGate(controller)(t.Context(), node, desired)
			if granted != tc.want || (err == nil) != tc.want {
				t.Fatalf("granted=%v err=%v", granted, err)
			}
		})
	}
	cfg := Config{Controller: ControllerConfig{OciReconcile: &OciReconcileConfig{PublicLB: public}}}
	controller := newSeatController(cfg, store, leaderFence{}, nil,
		func() map[string]WorkloadProfile { return profiles }, observer)
	gate := seatRestartGate(controller)
	delete(backends, "10.251.0.21:9465")
	if granted, err := gate(t.Context(), node, desired); granted || err == nil {
		t.Fatalf("prior permit survived missing backend: %v, %v", granted, err)
	}
	backends["10.251.0.21:9465"] = seatrollout.Backend{Drained: true, Healthy: true}
	profiles = terraBaseSeats("gru-1-db-2=10.251.0.22:9443")
	if granted, err := gate(t.Context(), node, desired); granted || err == nil {
		t.Fatalf("prior permit survived changed signed membership: %v, %v", granted, err)
	}
	profiles = terraBaseSeats(node + "=10.251.0.21:9443")
	observer.seatBackends = func(context.Context) (map[string]seatrollout.Backend, error) {
		return nil, errors.New("load balancer unavailable")
	}
	controller = newSeatController(cfg, store, leaderFence{}, nil,
		func() map[string]WorkloadProfile { return profiles }, observer)
	if granted, err := seatRestartGate(controller)(t.Context(), node, desired); granted || err == nil {
		t.Fatalf("prior permit survived observer outage: %v, %v", granted, err)
	}
}

func TestSeatMembersAreTheSignedSeatsWithTheirBackends(t *testing.T) {
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	members, err := terraBaseSeatMembers(profiles, nil)
	if err == nil || members != nil {
		t.Fatalf("missing backend authority granted seats: %+v %v", members, err)
	}
	public := &OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	want := []seatrollout.Member{{Node: "gru-1-db-1", Group: terrabase.Role, Backend: "10.251.0.21:9465"},
		{Node: "gru-1-db-2", Group: terrabase.Role, Backend: "10.251.0.22:9465"}}
	if members, err = terraBaseSeatMembers(profiles, public); err != nil || !slices.Equal(members, want) {
		t.Fatalf("with public_lb: %+v %v", members, err)
	}
	public.Seats = []string{"gru-1-db-1"}
	want[1].Backend = ""
	if members, err = terraBaseSeatMembers(profiles, public); err != nil || !slices.Equal(members, want) {
		t.Fatalf("with seats: %+v %v", members, err)
	}
	if members, err := terraBaseSeatMembers(map[string]WorkloadProfile{}, nil); err != nil || members != nil {
		t.Fatalf("no profile: %+v %v", members, err)
	}
	// A profile the public_lb publisher refuses holds every restart: the
	// publisher keeps its previous backend set, which may still route to
	// members the new profile would leave without a backend.
	noClient := terraBaseSeats("gru-1-db-1=10.251.0.21:9443")
	delete(noClient[terrabase.Role].Env, terrabase.EnvClientPort)
	for name, profiles := range map[string]map[string]WorkloadProfile{
		"no profile":          {},
		"malformed peers":     terraBaseSeats("gru-1-db-1=10.251.0.21"),
		"no client listener":  noClient,
		"listed seat is gone": terraBaseSeats("gru-1-db-2=10.251.0.22:9443"),
	} {
		if members, err := terraBaseSeatMembers(profiles, public); err == nil {
			t.Fatalf("%s: %+v", name, members)
		}
	}
}

type seatLBAPI struct {
	lb.API
	backends  []lb.Backend
	unhealthy map[string]bool
}

func (a seatLBAPI) ListBackends(context.Context, string, string) ([]lb.Backend, error) {
	return a.backends, nil
}

func (a seatLBAPI) UnhealthyBackends(context.Context, string, string) (map[string]bool, error) {
	return a.unhealthy, nil
}

func TestSeatBackendsReadTheLoadBalancer(t *testing.T) {
	api := seatLBAPI{backends: []lb.Backend{{IP: "10.251.0.21", Port: 9465, Drain: true}, {IP: "10.251.0.22", Port: 9465}},
		unhealthy: map[string]bool{"10.251.0.21:9465": true}}
	got, err := lbSeatBackends(api, OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"})(t.Context())
	want := map[string]seatrollout.Backend{"10.251.0.21:9465": {Drained: true}, "10.251.0.22:9465": {Healthy: true}}
	if err != nil || len(got) != 2 || got["10.251.0.21:9465"] != want["10.251.0.21:9465"] || got["10.251.0.22:9465"] != want["10.251.0.22:9465"] {
		t.Fatalf("backends=%+v err=%v", got, err)
	}
}
