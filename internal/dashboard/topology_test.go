package dashboard

import (
	"net/url"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

// topologyFixture is a healthy GRU cell seen from ctl-1: three colocated
// nodes, each running a controller, ts-auth and a TerraBase member, and one
// partition replicated over all three.
func topologyFixture(query string) view {
	values, _ := url.ParseQuery(query)
	var members []observability.MemberSnapshot
	nodes := []regionview.Node{}
	var summaryMembers []regionview.Member
	for index, name := range []string{"ctl-1", "ctl-2", "ctl-3"} {
		member := memberSnapshot()
		member.Cell, member.Member = "gru", name
		member.NATS.ServerName, member.NATS.IsMetaLeader = "gru-1-"+name, index == 0
		member.NATS.MetaPeers, member.NATS.ClusterPeers, member.NATS.Connections = nil, 3, 4+index
		member.Placement = &observability.PlacementView{Databases: []observability.DatabaseView{{DatabaseID: "00000000000DMQEY0YD7RZ04RR",
			PartitionID: "00000000003K6TBW31R91GBDRD", Members: []observability.MemberView{{SeatID: "0000000000DNKA8DBDEPN1J9XM", Stage: "serving", HostNode: "ts-gru-1"},
				{SeatID: "0000000000K6ST06WNWDFCTSJY", Stage: "serving", HostNode: "ts-gru-2"}, {SeatID: "000000000036XR713YE93E9M0S", Stage: "serving", HostNode: "ts-gru-3"}}}}}
		members = append(members, member)
		summaryMembers = append(summaryMembers, regionview.Member{Name: name, Role: "controller", Ready: true,
			Version: "v0.43.0", MetaLeader: index == 0})
		node := "ts-gru-" + itoa(index+1)
		nodes = append(nodes, regionview.Node{Name: node, Address: "10.251.0.1" + itoa(index+1), Member: name,
			Resources: &regionview.ResourceView{CPU: &regionview.Reading{ObservedAt: testNow},
				Memory: &regionview.Reading{ObservedAt: testNow}, Disk: &regionview.Reading{ObservedAt: testNow}},
			Services: []regionview.Service{{Role: "terrabase", Digest: "sha256:7da6542c9f0e1b2a3c", State: "running"},
				{Role: "ts-auth", Digest: "sha256:f8e35965", State: "running"}},
			Backends: []regionview.Backend{{Set: "terrabase"}}})
	}
	return view{Now: testNow, State: parseState(values), Ready: true, Local: &members[0],
		Cluster: &observability.ClusterSnapshot{Cell: "gru", Members: members},
		LocalSummary: &regionview.Summary{Region: "gru", Local: true, Reach: decisionlog.RegionOK,
			Health:  regionview.Health{Score: 100, Status: regionview.StatusHealthy},
			Leaders: regionview.Leaders{Authority: "ctl-1", MetaLeader: "gru-1-ctl-1"},
			Members: summaryMembers, Nodes: nodes}}
}

// withSFO adds sfo to the global view, so the topology links it below the graph.
func withSFO(current view) view {
	current.Global = []globalview.Region{{Cell: "gru"},
		{Cell: "sfo", Rollup: &globalview.Rollup{Cell: "sfo", Health: globalview.Health{Status: globalview.Healthy}}}}
	return current
}

func renderTopology(t *testing.T, current view) string {
	t.Helper()
	return fixturePage(t, current, "/topology")
}

func nodeClass(body, node string) string {
	at := strings.Index(body, `data-node="`+node+`"`)
	if at < 0 {
		return ""
	}
	start := strings.LastIndex(body[:at], `class="`)
	return body[start+len(`class="`) : at-2]
}

func TestTopologyHealthyCell(t *testing.T) {
	t.Parallel()
	body := renderTopology(t, topologyFixture("nats=1"))
	for _, node := range []string{"ts-gru-1", "ts-gru-2", "ts-gru-3"} {
		if got := nodeClass(body, node); got != "node s-ok" {
			t.Errorf("%s class = %q, want a healthy node", node, got)
		}
	}
	for _, want := range []string{"<svg", "10.251.0.11", "member ctl-1", "TerraBase member", "7da6542c9f0e", "ts-auth",
		"LB terrabase", "in rotation", "ts-orch controller", "v0.43.0", "meta leader", `data-server="gru-1-ctl-1"`,
		"edge e-route s-ok", "edge e-replication s-ok", "1 partition(s) replicate", "JetStream", `href="/members/ctl-2"`,
		`href="/regions/gru/hosts/ts-gru-1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("healthy topology lacks %q", want)
		}
	}
	if svg := body[strings.Index(body, "<svg"):]; strings.Contains(svg, "s-bad") {
		t.Error("a healthy cell draws something broken")
	}
	if again := renderTopology(t, topologyFixture("nats=1")); again != body {
		t.Error("the layout is not deterministic")
	}
	// Without nats=1 the NATS layer is hidden.
	plain := renderTopology(t, topologyFixture(""))
	if strings.Contains(plain, "data-server=") || strings.Contains(plain, "e-route") || !strings.Contains(plain, "e-replication") {
		t.Error("the services layer must hide NATS and keep replication")
	}
}

func TestTopologyDrainedNode(t *testing.T) {
	t.Parallel()
	current := topologyFixture("")
	node := &current.LocalSummary.Nodes[1]
	node.Fence, node.Operation = []string{"drain"}, "drain: fence"
	node.Backends = []regionview.Backend{{Set: "terrabase", Offline: true}}
	current.Cluster.Members[0].Placement.Databases[0].Members[1].Stage = "draining"
	body := renderTopology(t, current)
	if got := nodeClass(body, "ts-gru-2"); got != "node s-warn" {
		t.Errorf("drained node class = %q, want warn", got)
	}
	for _, want := range []string{"fenced", "drain: fence", "out of rotation", "edge e-replication s-warn", "seat not serving"} {
		if !strings.Contains(body, want) {
			t.Errorf("drained topology lacks %q", want)
		}
	}
	if got := nodeClass(body, "ts-gru-1"); got != "node s-ok" {
		t.Errorf("an undrained node turned %q", got)
	}
}

func TestTopologyNATSLinkDown(t *testing.T) {
	t.Parallel()
	current := withSFO(topologyFixture("nats=1"))
	// ctl-1 sees ctl-3 offline: every route to it breaks.
	current.Cluster.Members[0].NATS.MetaPeers = []observability.PeerView{{Name: "gru-1-ctl-3", Offline: true}}
	current.Cluster.Members[0].NATS.Streams = []observability.StreamView{{Name: "KV_desired", Replicas: 3, OfflinePeers: 1}}
	body := renderTopology(t, current)
	for _, want := range []string{"edge e-route s-bad", "KV_desired", "1 offline"} {
		if !strings.Contains(body, want) {
			t.Errorf("link-down topology lacks %q", want)
		}
	}
	// ctl-1 ↔ ctl-2 still has full-mesh evidence on both ends.
	if !strings.Contains(body, "edge e-route s-ok") {
		t.Error("an unaffected route lost its health")
	}
}

func TestTopologyLinksOtherRegions(t *testing.T) {
	t.Parallel()
	current := withSFO(topologyFixture("nats=1"))
	body := renderTopology(t, current)
	if !strings.Contains(body, "Other regions") || !strings.Contains(body, `href="/regions/sfo"`) {
		t.Error("the topology does not link the other regions")
	}
	if strings.Contains(body, "edge e-region") {
		t.Error("the topology draws a region pair it cannot evidence")
	}
}

// A region whose summary predates nodes still shows its members and seat
// hosts, and a missing controller is drawn broken.
func TestTopologyOlderSummary(t *testing.T) {
	t.Parallel()
	current := view{LocalSummary: &regionview.Summary{Region: "fra", Local: true, Members: []regionview.Member{{Name: "c1", Role: "controller", Ready: true}, {Name: "h0", Role: "host", Ready: true}}, Quorum: regionview.Quorum{Missing: []string{"c2"}}, Hosts: []regionview.Host{{Name: "h1", Seats: 2, Serving: 1}}}}
	body := renderTopology(t, current)
	for _, name := range []string{"c1", "h0", "c2", "h1"} {
		if !strings.Contains(body, `data-node="`+name+`"`) {
			t.Errorf("older summary lost node %s", name)
		}
	}
	if nodeClass(body, "c2") != "node s-bad" || !strings.Contains(body, "missing: did not answer") {
		t.Fatal("missing controller did not render as failed")
	}
}

// Without the cell-wide view (controller credentials without the
// observability grant) only this member answers; the others are drawn from
// what its JetStream metadata peers say, not as missing.
func TestTopologyWithoutCellWideView(t *testing.T) {
	t.Parallel()
	current := topologyFixture("nats=1")
	local := current.Cluster.Members[0]
	local.NATS.MetaPeers = []observability.PeerView{{Name: "gru-1-ctl-2", Current: true},
		{Name: "gru-1-ctl-3", Offline: true}}
	current.Local, current.Cluster = &local, nil
	summary := current.LocalSummary
	summary.Members = summary.Members[:1]
	for index := range summary.Nodes {
		summary.Nodes[index].Server = "gru-1-" + summary.Nodes[index].Member
	}
	body := renderTopology(t, current)
	if got := nodeClass(body, "ts-gru-2"); got != "node s-ok" || !strings.Contains(body, "JetStream peer current") {
		t.Errorf("a current peer is drawn %q", got)
	}
	if got := nodeClass(body, "ts-gru-3"); got != "node s-bad" || !strings.Contains(body, "JetStream peer offline") {
		t.Errorf("an offline peer is drawn %q", got)
	}
	if strings.Contains(body, "missing: did not answer") {
		t.Error("a controller the cell-wide view never asked is drawn missing")
	}
	if !strings.Contains(body, `data-server="gru-1-ctl-2"`) {
		t.Error("the peer's NATS server is not drawn")
	}
}
