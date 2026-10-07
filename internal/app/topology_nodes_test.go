package app

import (
	"reflect"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func TestTopologyNodes(t *testing.T) {
	grants := []cellspec.HostGrant{
		{Node: "ts-sfo-2", PrivateIP: "10.0.0.2", Roles: []string{"terrabase"}},
		{Node: "ts-sfo-1", PrivateIP: "10.0.0.1", Roles: []string{"terrabase", "ts-auth"}, Controller: "controller-a"},
	}
	hosts := []host.HostStatus{
		{Registration: host.Registration{Node: "ts-sfo-1"}, Verified: true, Reports: []host.Report{
			{Role: "ts-auth", Digest: "sha256:auth", State: "running"}}},
		// An unverified host's reports are not shown.
		{Registration: host.Registration{Node: "ts-sfo-2"}, Reports: []host.Report{
			{Role: "terrabase", Digest: "sha256:base", State: "running"}}},
	}
	status := nodeOpReply{
		Operations: []nodeOp{
			{Node: "ts-sfo-2", Op: "drain", State: nodeOpRunning, Step: "fence"},
			{Node: "ts-sfo-1", Op: "reboot", State: nodeOpDone},
		},
		Fences: []nodeFenceStatus{{Node: "ts-sfo-2", Holders: []string{"drain"},
			Backends: []fencedBackend{{Set: "terrabase-https", IP: "10.0.0.2", Offline: true}}}},
	}
	sets := []cellspec.FencedSet{{Name: "terrabase-https", Role: "terrabase"}, {Name: "auth-https", Role: "ts-auth"},
		{Name: "manual"}}
	members := map[string]string{"ts-sfo-1": "controller-a"}

	got := topologyNodes(grants, members, hosts, status, sets)
	want := []regionview.Node{
		{Name: "ts-sfo-1", Address: "10.0.0.1", Member: "controller-a",
			Services: []regionview.Service{{Role: "terrabase"}, {Role: "ts-auth", Digest: "sha256:auth", State: "running"}},
			Backends: []regionview.Backend{{Set: "terrabase-https"}, {Set: "auth-https"}}},
		{Name: "ts-sfo-2", Address: "10.0.0.2", Services: []regionview.Service{{Role: "terrabase"}},
			Fence: []string{"drain"}, Operation: "drain: fence",
			Backends: []regionview.Backend{{Set: "terrabase-https", Offline: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topologyNodes =\n%+v\nwant\n%+v", got, want)
	}
	if nodes := topologyNodes(nil, nil, nil, nodeOpReply{}, nil); len(nodes) != 0 {
		t.Fatalf("no grants listed %d nodes", len(nodes))
	}
}
