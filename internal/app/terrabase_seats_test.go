package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestTerraBaseSeatsConfigDefaultsOffAndBoundsItsTimes(t *testing.T) {
	var cfg ControllerConfig
	if err := json.Unmarshal([]byte(`{"candidate_id":"a"}`), &cfg, json.RejectUnknownMembers(true)); err != nil || cfg.TerraBaseSeats != nil {
		t.Fatalf("seats on by default: %+v %v", cfg.TerraBaseSeats, err)
	}
	wire := `{"terrabase_seats":{"enabled":true,"drain_grace_seconds":30,"settle_seconds":5}}`
	if err := json.Unmarshal([]byte(wire), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if grace, settle, err := cfg.TerraBaseSeats.durations(); err != nil || grace != 30*time.Second || settle != 5*time.Second {
		t.Fatalf("grace=%v settle=%v err=%v", grace, settle, err)
	}
	for _, bad := range []TerraBaseSeatsConfig{{DrainGraceSeconds: -1}, {SettleSeconds: 301}} {
		if _, _, err := bad.durations(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestSeatMembersAreTheSignedSeatsWithTheirBackends(t *testing.T) {
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	members, err := terraBaseSeatMembers(profiles, nil)
	want := []seatrollout.Member{{Node: "gru-1-db-1", Group: terrabase.Role}, {Node: "gru-1-db-2", Group: terrabase.Role}}
	if err != nil || !slices.Equal(members, want) {
		t.Fatalf("without public_lb: %+v %v", members, err)
	}
	public := &OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	want[0].Backend, want[1].Backend = "10.251.0.21:9465", "10.251.0.22:9465"
	if members, err = terraBaseSeatMembers(profiles, public); err != nil || !slices.Equal(members, want) {
		t.Fatalf("with public_lb: %+v %v", members, err)
	}
	public.Seats = []string{"gru-1-db-1"}
	want[1].Backend = ""
	if members, err = terraBaseSeatMembers(profiles, public); err != nil || !slices.Equal(members, want) {
		t.Fatalf("with seats: %+v %v", members, err)
	}
	if members, err := terraBaseSeatMembers(map[string]WorkloadProfile{}, public); err != nil || members != nil {
		t.Fatalf("no profile: %+v %v", members, err)
	}
	if _, err := terraBaseSeatMembers(terraBaseSeats("gru-1-db-1=10.251.0.21"), public); err == nil {
		t.Fatal("accepted a malformed peer list")
	}
}

func TestTerraBaseReleaseWaitsFiveMinutesPerSeat(t *testing.T) {
	for _, c := range []struct {
		role     string
		replicas int
		want     time.Duration
	}{{terrabase.Role, 1, 10 * time.Minute}, {terrabase.Role, 2, 10 * time.Minute}, {terrabase.Role, 3, 15 * time.Minute}, {"ts-auth", 3, 10 * time.Minute}} {
		if got := defaultReleaseWait(c.role, c.replicas); got != c.want {
			t.Fatalf("%s x%d: %v, want %v", c.role, c.replicas, got, c.want)
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
