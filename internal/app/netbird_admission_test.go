package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func TestNetBirdAdmissionSurvivesFenceAndGrantRemovalWithoutLosingQuorum(t *testing.T) {
	f, cell, api, _, _ := newFenceTest(t)
	// Inventory reads must not simulate an unrelated ts-orch binary rollout.
	cell.gate = func(context.Context, string, host.Desired) (bool, error) { return false, nil }
	n := netbirdRollout{fence: f, services: &specRegistry{}}
	spec, _ := f.spec()
	spec.BackendSets[0].MinServing = 3
	api.sets["terrabase"] = append(api.sets["terrabase"], lb.Backend{IP: "10.0.0.14", Port: 9465})
	record := network.Record{ID: "06RK99WTQK58C48FH8SYH45C8S", Node: "gru-1-ctl-2", Phase: "drain", Deadline: time.Now().Add(time.Minute)}
	if err := saveNetBirdTestAdmission(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	// Neither amendments nor process restart may erase the admitted safety gate.
	spec.BackendSets[0].MinServing = 1
	f.spec = func() (*cellspec.ReleaseFence, map[string]string) { return nil, map[string]string{} }
	restarted := netbirdRollout{fence: f, services: &specRegistry{}, managedAddresses: map[string]string{"expired-host": "10.0.0.99"}}
	if err := restarted.refreshInventory(t.Context()); err != nil || len(restarted.managedAddresses) != 1 || restarted.managedAddresses[record.Node] != fenceAddresses[record.Node] {
		t.Fatalf("recovery needed removed grants or unrelated inventory: addresses=%v error=%v", restarted.managedAddresses, err)
	}
	var admitted cellspec.ReleaseFence
	if err := restarted.load(t.Context(), netbirdRecordKey, &record); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(record.Fence, &admitted); err != nil || len(admitted.BackendSets) != 2 || admitted.BackendSets[0].Min() != 3 {
		t.Fatalf("amendment changed admitted quorum: record=%+v error=%v", record, err)
	}
	record.Phase = "rollback"
	if err := saveNetBirdTestAdmission(t.Context(), &restarted, 3, record); err != nil {
		t.Fatal(err)
	}
	api.down[lb.Backend{IP: fenceAddresses["gru-1-ctl-3"], Port: 9465}.Name()] = true
	limited, cancel := context.WithCancel(t.Context())
	defer cancel()
	waited := false
	sleep := f.sleep
	f.sleep = func(ctx context.Context, delay time.Duration) error {
		if delay != fencePoll {
			t.Fatalf("expected a denied-quorum wait, got %s", delay)
		}
		waited = true
		cancel()
		return ctx.Err()
	}
	err := restarted.drainNode(limited, 3, record.Node)
	f.sleep = sleep
	if !waited || !errors.Is(err, context.Canceled) || len(api.log) != 0 {
		t.Fatalf("removed fence weakened admitted min_serving: log=%v error=%v", api.log, err)
	}
	if err := f.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if held, found, err := f.record(t.Context(), record.Node); err != nil || !found || len(held.holders()) != 1 || held.holders()[0] != netbirdHold {
		t.Fatalf("fence removal abandoned the NetBird hold: record=%+v found=%t error=%v", held, found, err)
	}
	clear(api.down)
	if err := restarted.drainNode(t.Context(), 3, record.Node); err != nil {
		t.Fatalf("rollback could not drain through its persisted admission: %v", err)
	}
	if _, err := f.restore(t.Context(), api, 3, record.Node, netbirdHold, true); err != nil {
		t.Fatalf("healthy recovery could not release the removed-spec fence: %v", err)
	}
	if _, found, err := f.record(t.Context(), record.Node); err != nil || found {
		t.Fatalf("successful recovery left a hold behind: found=%t error=%v", found, err)
	}
}
