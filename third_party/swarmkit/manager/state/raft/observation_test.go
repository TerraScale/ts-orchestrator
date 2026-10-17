package raft

import (
	"strings"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
)

func TestObservationReplayBounds(t *testing.T) {
	action, err := api.NewStoreAction(api.EventCreateConfig{Config: &api.Config{ID: "bounded-history", Spec: api.ConfigSpec{Data: make([]byte, 1024)}}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := (&api.InternalRaftRequest{Action: []api.StoreAction{action}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	entries := []raftpb.Entry{{Index: 1, Term: 1, Data: data}, {Index: 2, Term: 1, Data: data}}
	n := &Node{raftStore: raft.NewMemoryStorage(), isMember: 1}
	if err := n.raftStore.Append(entries); err != nil {
		t.Fatal(err)
	}
	if _, err := n.changesBetween(api.Version{}, api.Version{Index: 1}, 128); err == nil || !strings.Contains(err.Error(), "replay limit") {
		t.Fatalf("oversized first Raft entry escaped the fixed replay bound: %v", err)
	}
	if _, err := n.changesBetween(api.Version{}, api.Version{Index: 2}, uint64(entries[0].Size()+1)); err == nil || !strings.Contains(err.Error(), "replay limit") {
		t.Fatalf("partial bounded history accepted as complete: %v", err)
	}
	changes, err := n.ObservationChangesBetween(api.Version{}, api.Version{Index: 2})
	if err != nil || len(changes) != 2 || changes[0].Version.Index != 1 || changes[1].Version.Index != 2 {
		t.Fatalf("complete available replay lost exact indexes: %+v %v", changes, err)
	}
	if err := n.raftStore.Compact(1); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ObservationChangesBetween(api.Version{}, api.Version{Index: 2}); err == nil {
		t.Fatal("compacted history accepted as complete")
	}
}
