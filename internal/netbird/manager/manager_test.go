package manager

import (
	"testing"
	"time"
)

func TestPruneDeletesReplacedRevisionsAndRestoresSlotNames(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	ancient := now.Add(-72 * time.Hour)
	servers := ids.servers
	// ctl-2: the replaced revision is offline under the slot name;
	// the new revision registered with a suffixed label.
	staleB := f.addPeer("ts-gru-2", "10.251.0.12", false, old, servers)
	liveB := f.addPeer("ts-gru-2", "10.251.0.12", true, now, servers)
	// db-1: the live revision registered under its OS hostname.
	staleM := f.addPeer("gru-1-db-1", "10.251.0.21", false, old, servers)
	liveM := f.addPeer("ip-10-251-0-21", "10.251.0.21", true, now, servers)
	// db-2 is down: keep its newest peer, delete an ancient one.
	keepM2 := f.addPeer("gru-1-db-2", "10.251.0.22", false, ancient.Add(time.Hour), servers)
	oldM2 := f.addPeer("gru-1-db-2-old", "10.251.0.22", false, ancient, servers)
	// An unattributed server peer, long offline, and a recent one.
	orphan := f.addPeer("scratch", "10.251.0.50", false, ancient, servers)
	recent := f.addPeer("scratch-2", "10.251.0.51", false, old, servers)
	// A disconnected peer outside the servers group is never touched.
	outside := f.addPeer("ts-gru-3", "10.251.0.13", false, ancient, ids.operators)
	api := f.api(t)
	d := GRU()

	plan, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, false)
	if err != nil || len(f.mutations) != 0 {
		t.Fatalf("dry run: %v %v", f.mutations, err)
	}
	if len(plan.Changes) != 6 {
		t.Fatalf("plan: %v", plan.Changes)
	}
	if _, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{staleB, staleM, oldM2, orphan} {
		if f.peer(id) != nil {
			t.Errorf("peer %s was not deleted", id)
		}
	}
	for _, id := range []string{ids.server1, liveB, liveM, keepM2, recent, outside, ids.tsOps} {
		if f.peer(id) == nil {
			t.Errorf("peer %s was deleted", id)
		}
	}
	if p := f.peer(liveB); p.Name != "ts-gru-2" || p.DNSLabel != "ts-gru-2.netbird.selfhosted" {
		t.Fatalf("ctl-2: %+v", p.apiPeer)
	}
	if p := f.peer(liveM); p.Name != "gru-1-db-1" || p.DNSLabel != "gru-1-db-1.netbird.selfhosted" || !p.SSHEnabled {
		t.Fatalf("db-1: %+v", p.apiPeer)
	}
	f.mutations = nil
	again, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, true)
	if err != nil || len(again.Changes) != 0 || len(f.mutations) != 0 {
		t.Fatalf("second prune: %v %v", again.Changes, err)
	}
}

func TestRemovePeersDeletesOnlyDisconnectedServerPeersOfTheNamedSlots(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	old := time.Now().Add(-time.Hour)
	// ctl-1's live peer (ids.server1) is connected; its replaced
	// revision is not. db-1 is down and matches only by name; db-2
	// registered under its hostname; a slot-named peer outside the servers
	// group is no server.
	staleA := f.addPeer("ts-gru-1-old", "10.251.0.11", false, old, ids.servers)
	member1 := f.addPeer("gru-1-db-1", "10.251.0.99", false, old, ids.servers)
	member2 := f.addPeer("ip-10-251-0-22", "10.251.0.22", false, old, ids.servers)
	scratch := f.addPeer("scratch", "10.251.0.50", false, old, ids.servers)
	outside := f.addPeer("gru-1-db-1", "203.0.113.9", false, old, ids.operators)
	api, d := f.api(t), GRU()

	if _, err := Remove(t.Context(), api, d, []string{"controller-z"}, false); err == nil {
		t.Fatal("accepted an unknown slot")
	}
	plan, err := Remove(t.Context(), api, d, []string{"ts-gru-1", "db-1"}, false)
	if err != nil || len(plan.Changes) != 2 || len(plan.Warnings) != 1 || len(f.mutations) != 0 {
		t.Fatalf("dry run: %v %v %v %v", plan.Changes, plan.Warnings, f.mutations, err)
	}
	if _, err := Remove(t.Context(), api, d, []string{"ts-gru-1", "db-1"}, true); err != nil {
		t.Fatal(err)
	}
	for id, kept := range map[string]bool{staleA: false, member1: false, ids.server1: true, member2: true,
		scratch: true, outside: true, ids.tsOps: true} {
		if (f.peer(id) != nil) != kept {
			t.Errorf("peer %s kept=%t, want %t", id, f.peer(id) != nil, kept)
		}
	}
	report, err := Remove(t.Context(), api, d, nil, true)
	if err != nil || len(report.Changes) != 2 || f.peer(member2) != nil || f.peer(scratch) != nil ||
		f.peer(ids.server1) == nil || f.peer(outside) == nil {
		t.Fatalf("remove all: %v %v", report.Changes, err)
	}
}
