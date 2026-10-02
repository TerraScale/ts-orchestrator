package dashboard

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
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
			// Answering is not route evidence: c1-c2 and c1-c3 touch a
			// not-ready or missing controller, nothing is drawn healthy.
			if link.State == "ok" {
				t.Errorf("route %+v is drawn healthy from readiness alone", link)
			}
		case "leaf":
			leaves++
			if link.Source != "member:sfo:c1" {
				t.Errorf("leaf %+v does not start at the meta leader", link)
			}
		}
	}
	// h0 is a seatless host member and still gets its leaf.
	if routes != 3 || leaves != 2 {
		t.Errorf("routes=%d leaves=%d, want 3 and 2", routes, leaves)
	}
	if nodes["member:sfo:h1"].State != "idle" || nodes["member:sfo:h0"].State != "ok" {
		t.Errorf("a placement-only host must be unknown, a ready host member ok: %+v %+v",
			nodes["member:sfo:h1"], nodes["member:sfo:h0"])
	}
}

// The NATS meta leader is a server name, so the summary flags the leading
// member; a hostile summary's duplicates must not produce self routes.
func TestRemoteTopologyMetaLeaderFlagAndDuplicates(t *testing.T) {
	t.Parallel()
	summary := regionview.Summary{Region: "sfo",
		Leaders: regionview.Leaders{MetaLeader: "sfo-c2"},
		Quorum:  regionview.Quorum{Missing: []string{"c1", "c3"}},
		Members: []regionview.Member{{Name: "c1", Role: "controller", Ready: true},
			{Name: "c2", Role: "controller", Ready: true, MetaLeader: true}, {Name: "c1", Role: "controller", Ready: true}},
		Hosts: []regionview.Host{{Name: "h1", Seats: 1}, {Name: "c1", Seats: 1}}}
	spec := topologySpec{}
	nodes := map[string]topologyNode{}
	remoteTopology(&spec, func(node topologyNode) {
		if _, ok := nodes[node.ID]; !ok {
			nodes[node.ID] = node
		}
	}, summary, uiState{})
	if nodes["member:sfo:c1"].Kind != "controller" || nodes["member:sfo:c1"].State != "ok" {
		t.Errorf("c1 = %+v", nodes["member:sfo:c1"])
	}
	routes := 0
	for _, link := range spec.Links {
		if link.Source == link.Target {
			t.Errorf("self link %+v", link)
		}
		if link.Kind == "leaf" && (link.Source != "member:sfo:c2" || link.Target != "member:sfo:h1") {
			t.Errorf("leaf %+v, want c2 -> h1 only", link)
		}
		if link.Kind == "route" {
			routes++
		}
	}
	if routes != 3 {
		t.Errorf("routes = %d, want 3 for c1, c2, c3", routes)
	}
}

// Seat IDs repeat across databases and partitions; every placed seat keeps
// its own node, and routes are healthy only with full-mesh route counts.
func TestLocalTopologySeatsAndRouteEvidence(t *testing.T) {
	t.Parallel()
	first, second := memberSnapshot(), memberSnapshot()
	second.Member, second.Authority.Leader, second.NATS.IsMetaLeader, second.NATS.ServerName = "ctl-2", false, false, "fra-ctl-2"
	first.NATS.ServerName, first.NATS.MetaLeader, second.NATS.MetaLeader = "fra-ctl-1", "fra-ctl-1", "fra-ctl-1"
	first.NATS.Routes, second.NATS.Routes = 1, 0
	first.NATS.MetaPeers = []observability.PeerView{{Name: "fra-ctl-2", Current: true}}
	database := first.Placement.Databases[0]
	other := database
	other.PartitionID = "p1"
	first.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{database, other}}
	current := view{Cluster: &observability.ClusterSnapshot{Cell: "fra", Members: []observability.MemberSnapshot{first, second}}}
	spec := current.topology()
	seats, ids := 0, map[string]bool{}
	for _, node := range spec.Nodes {
		if ids[node.ID] {
			t.Errorf("duplicate node %s", node.ID)
		}
		ids[node.ID] = true
		if node.Kind == "seat" {
			seats++
		}
		if node.Kind == "host" && node.State != "idle" {
			t.Errorf("placement-only host %+v must be unknown", node)
		}
	}
	if seats != 6 {
		t.Errorf("seats = %d, want 3 per partition", seats)
	}
	for _, link := range spec.Links {
		switch link.Kind {
		case "leaf":
			if link.Source != "member:fra:ctl-1" {
				t.Errorf("leaf %+v must start at the meta leader member", link)
			}
		case "route":
			if link.State != "idle" {
				t.Errorf("route %+v: ctl-2 reports no routes, so the route is unproven", link)
			}
		}
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
