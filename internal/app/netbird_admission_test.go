package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func TestNetBirdAdmissionSurvivesFenceAndGrantRemovalWithoutLosingQuorum(t *testing.T) {
	f, cell, api, _, _ := newFenceTest(t)
	// Inventory reads must not simulate an unrelated ts-orch binary rollout.
	cell.gate = func(context.Context, string, host.Desired) (bool, error) { return false, nil }
	n := netbirdRollout{fence: f, services: &specRegistry{}}
	spec, _ := f.spec()
	spec.BackendSets[0].MinServing = 3
	api.sets["terrabase"] = append(api.sets["terrabase"], lb.Backend{IP: "10.0.0.14", Port: 9465})
	record := network.Record{ID: "admitted", Node: "ctl-2", Phase: "drain", Deadline: time.Now().Add(time.Minute)}
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
	api.down[lb.Backend{IP: fenceAddresses["ctl-3"], Port: 9465}.Name()] = true
	limited, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := restarted.drainNode(limited, 3, record.Node); !errors.Is(err, context.DeadlineExceeded) || len(api.log) != 0 {
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

func TestNetBirdAdmissionRequiresVerifiedFenceAndAddress(t *testing.T) {
	f, _, _, _, _ := newFenceTest(t)
	f.spec = func() (*cellspec.ReleaseFence, map[string]string) { return nil, map[string]string{} }
	n := netbirdRollout{fence: f}
	if err := saveNetBirdTestAdmission(t.Context(), &n, 3, network.Record{ID: "not-admitted", Node: "ctl-1", Phase: "drain"}); err == nil {
		t.Fatal("new transaction admitted without its fence/address snapshot")
	}
}

func TestNetBirdDrainPreflightKeepsAdmissionAndLiveGatesAfterFenceRemoval(t *testing.T) {
	n, pin, _ := netbirdArtifactTest(t, "")
	stageTestNetbirdArtifacts(t, n.artifacts, pin)
	n.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	n.services.current.HostGrants = []cellspec.HostGrant{{Node: "leader", Controller: "controller-a"}}
	n.cfg.NATS = natscell.Config{Cell: "gru", Instance: "controller-a"}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "admitted-lb", BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465, MinServing: 3}}}
	addresses := map[string]string{"leader": "10.251.0.11", "selected": "10.251.0.12"}
	n.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) {
		return spec, map[string]string{"leader": addresses["leader"], "selected": addresses["selected"]}
	}
	record := network.Record{ID: "admitted", Node: "selected", Phase: "drain", Deadline: time.Now().Add(time.Minute), Target: network.Target{Pin: pin}}
	if err := saveNetBirdTestAdmission(t.Context(), n, 3, record); err != nil {
		t.Fatal(err)
	}
	spec = nil
	addresses["selected"] = "10.251.0.99"
	saved, resolved, err := n.preflightAddresses(t.Context(), record.Node)
	if err != nil || saved == nil || saved.LoadBalancerID != "admitted-lb" || saved.BackendSets[0].Min() != 3 ||
		resolved[record.Node] != "10.251.0.12" || resolved["leader"] != addresses["leader"] {
		t.Fatalf("resumed preflight lost admitted scope or live peers: fence=%+v addresses=%v err=%v", saved, resolved, err)
	}
	if other, _, err := n.preflightAddresses(t.Context(), "other"); err != nil || other != nil {
		t.Fatalf("another node reused the active node's admission: %+v %v", other, err)
	}
	if err := n.saveAt(t.Context(), 3, "netbird.status.leader", network.Status{Version: "0.79.0", Connected: true, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	quorumHeld := errors.New("live controller quorum held")
	checks := 0
	n.nodes = &nodeOps{cluster: func(context.Context, string) error { checks++; return quorumHeld }}
	if err := n.preflight(t.Context(), record.Node); !errors.Is(err, quorumHeld) || checks != 1 {
		t.Fatalf("removed fence stopped resumed preflight or skipped live quorum: checks=%d err=%v", checks, err)
	}
	if err := n.saveAt(t.Context(), 3, "netbird.status.leader", network.Status{Missing: true, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := n.preflight(t.Context(), record.Node); err == nil || !strings.Contains(err.Error(), "probing leader has no working mesh client") || checks != 1 {
		t.Fatalf("saved admission bypassed live leader health: checks=%d err=%v", checks, err)
	}
}
