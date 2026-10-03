package hostpool

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

type captureRecorder struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (c *captureRecorder) Record(_ context.Context, decision decisionlog.Decision) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decisions = append(c.decisions, decision)
	return "id"
}

func (c *captureRecorder) kinds() []decisionlog.Kind {
	c.mu.Lock()
	defer c.mu.Unlock()
	var kinds []decisionlog.Kind
	for _, decision := range c.decisions {
		if decision.Actor.Slice == actor {
			kinds = append(kinds, decision.Kind)
		}
	}
	return kinds
}

// TestScalerJournalsLaunchesReclaimsAndRecommendations is not parallel: it
// installs the process-wide decision recorder.
func TestScalerJournalsLaunchesReclaimsAndRecommendations(t *testing.T) {
	recorder := &captureRecorder{}
	t.Cleanup(decisionlog.SetDefault(recorder))

	view := &fakeView{hosts: []host.HostStatus{registered("general-0", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "general-0", Role: "api"}}}
	clock := now
	prov := &provisioner{}
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{leader: true},
		Provisioner: prov, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	full := generalPool().virtualHost("gru", "general-0", "fd-1")
	full.Allocated = full.Capacity
	scaler.RequestCapacity(workload.ServiceSpec{Role: "api", Environment: "prod"}, apiDemand(1, full))
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	view.hosts = append(view.hosts, registered("general-1", "fd-2"))
	// The demand ages out, general-1 turns idle, and its cooldown passes.
	for _, step := range []time.Duration{DefaultDemandTTL + time.Second, 11 * time.Minute} {
		clock = clock.Add(step)
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := recorder.kinds(); !slices.Equal(got, []decisionlog.Kind{decisionlog.KindHostLaunched, decisionlog.KindHostReclaimed}) {
		t.Fatalf("journaled kinds = %v (launched %v, reclaimed %v)", got, prov.launched, prov.reclaims)
	}
	for _, decision := range recorder.decisions {
		if decision.Region != "gru" || decision.Epoch == 0 || decision.Subject.ID == "" || decision.Rule == "" {
			t.Fatalf("incomplete decision %+v", decision)
		}
	}

	// Recommend-only: a steady recommendation is journaled once.
	recorder.decisions = nil
	recommend, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: &fakeView{},
		Fencer: fencer{leader: true}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := recommend.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := recorder.kinds(); !slices.Equal(got, []decisionlog.Kind{decisionlog.KindScaleUp}) {
		t.Fatalf("recommendation kinds = %v, last = %#v", got, recommend.Last())
	}
	if recorder.decisions[0].Status != decisionlog.StatusPending {
		t.Fatalf("recommendation status = %s", recorder.decisions[0].Status)
	}
}
