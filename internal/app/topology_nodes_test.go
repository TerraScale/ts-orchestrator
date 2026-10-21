package app

import (
	"reflect"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func TestTopologyNodes(t *testing.T) {
	grants := []cellspec.HostGrant{
		{Node: "ts-sjc-2", PrivateIP: "10.0.0.2", Roles: []string{"terrabase"}},
		{Node: "ts-sjc-1", PrivateIP: "10.0.0.1", Roles: []string{"terrabase", "ts-auth"}, Controller: "controller-a"},
	}
	status := nodeOpReply{
		Operations: []nodeOp{
			{Node: "ts-sjc-2", Op: "drain", State: nodeOpRunning, Step: "fence"},
			{Node: "ts-sjc-1", Op: "reboot", State: nodeOpDone},
		},
		Fences: []nodeFenceStatus{{Node: "ts-sjc-2", Holders: []string{"drain"},
			Backends: []fencedBackend{{Set: "terrabase-https", IP: "10.0.0.2", Offline: true}}}},
	}
	sets := []cellspec.FencedSet{{Name: "terrabase-https", Role: "terrabase"}, {Name: "auth-https", Role: "ts-auth"},
		{Name: "manual"}}
	members := map[string]string{"ts-sjc-1": "controller-a"}

	got := topologyNodes(grants, members, status, sets)
	want := []regionview.Node{
		{Name: "ts-sjc-1", Address: "10.0.0.1", Member: "controller-a",
			Services: []regionview.Service{{Role: "terrabase", State: "unknown", StateReason: "current manager task readiness is unavailable in node topology"}, {Role: "ts-auth", State: "unknown", StateReason: "current manager task readiness is unavailable in node topology"}},
			Backends: []regionview.Backend{{Set: "terrabase-https"}, {Set: "auth-https"}}},
		{Name: "ts-sjc-2", Address: "10.0.0.2", Services: []regionview.Service{{Role: "terrabase", State: "unknown", StateReason: "current manager task readiness is unavailable in node topology"}},
			Fence: []string{"drain"}, Operation: "drain: fence",
			Backends: []regionview.Backend{{Set: "terrabase-https", Offline: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topologyNodes =\n%+v\nwant\n%+v", got, want)
	}
	if nodes := topologyNodes(nil, nil, nodeOpReply{}, nil); len(nodes) != 0 {
		t.Fatalf("no grants listed %d nodes", len(nodes))
	}
}
