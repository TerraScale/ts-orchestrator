package dashboard

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func TestRemoteTopologyUsesSummaryMembersAndHosts(t *testing.T) {
	t.Parallel()
	summary := regionview.Summary{Region: "sfo",
		Leaders: regionview.Leaders{Authority: "c1", MetaLeader: "c1"},
		Quorum:  regionview.Quorum{Missing: []string{"c3"}},
		Members: []regionview.Member{{Name: "c1", Role: "controller", Ready: true, Version: "v1"},
			{Name: "c2", Role: "controller", Ready: false, Version: "v1"}, {Name: "h0", Role: "host", Ready: true}},
		Hosts: []regionview.Host{{Name: "h1", Seats: 3, Serving: 2}}}
	spec := topologySpec{}
	nodes := map[string]topologyNode{}
	remoteTopology(&spec, func(node topologyNode) { nodes[node.ID] = node }, summary, uiState{})
	for id, kind := range map[string]string{"member:sfo:c1": "controller", "member:sfo:c2": "controller",
		"member:sfo:c3": "controller", "member:sfo:h0": "host", "member:sfo:h1": "host"} {
		if node, ok := nodes[id]; !ok || node.Kind != kind || node.Region != "sfo" {
			t.Errorf("node %s = %+v, want a %s in sfo", id, node, kind)
		}
	}
	if nodes["member:sfo:c2"].State != "bad" || nodes["member:sfo:c3"].StateLabel != "missing" {
		t.Errorf("states = %+v %+v", nodes["member:sfo:c2"], nodes["member:sfo:c3"])
	}
	if nodes["member:sfo:c1"].Details["JetStream"] != "meta leader" || nodes["member:sfo:h1"].Details["serving"] != "2" {
		t.Errorf("details = %+v %+v", nodes["member:sfo:c1"].Details, nodes["member:sfo:h1"].Details)
	}
	routes, leaves := 0, 0
	for _, link := range spec.Links {
		switch link.Kind {
		case "route":
			routes++
		case "leaf":
			leaves++
			if link.Source != "member:sfo:c1" {
				t.Errorf("leaf %+v does not start at the meta leader", link)
			}
		}
	}
	if routes != 3 || leaves != 1 {
		t.Errorf("routes=%d leaves=%d, want 3 and 1", routes, leaves)
	}
}

func TestRemoteTopologyFallsBackToVersions(t *testing.T) {
	t.Parallel()
	summary := regionview.Summary{Region: "fra",
		Versions: []regionview.Version{{Version: "v1", Members: []string{"a", "b"}}}}
	spec := topologySpec{}
	count := 0
	remoteTopology(&spec, func(node topologyNode) {
		count++
		if node.Kind != "controller" || node.State != "ok" {
			t.Errorf("node = %+v", node)
		}
	}, summary, uiState{})
	if count != 2 || len(spec.Links) != 3 {
		t.Errorf("nodes=%d links=%d, want 2 and 3", count, len(spec.Links))
	}
}
