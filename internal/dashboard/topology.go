package dashboard

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// The topology page draws every region as a column of its nodes, each with
// the services it runs, as server-rendered SVG. The layout is a pure
// function of the view (columns per region, rows per node), so a stream
// tick re-renders the same picture until the state changes. With nats=1 a
// NATS lane is added to every region: its servers, the route mesh, the
// nodes' client connections, JetStream health and the links between
// regions.
const (
	topoMargin    = 16
	topoRegionGap = 40
	topoPad       = 12
	// topoReplLane is the lane left of the nodes for replication arcs.
	topoReplLane = 44
	topoNodeW    = 340
	topoNATSLane = 230
	topoHeader   = 58
	topoNodeHead = 40
	topoRowH     = 20
	topoNodeGap  = 14
	// topoCharW is a detail character's width, to fit details to boxes.
	topoCharW = 6
)

type topoBox struct{ X, Y, W, H int }

type topoGraph struct {
	Width, Height int
	NATS          bool
	Regions       []topoRegion
	// Edges are drawn under the boxes.
	Edges []topoEdge
}

type topoRegion struct {
	topoBox
	Name, Caption, Status, Href string
	Nodes                       []topoNode
	Servers                     []topoServer
	// JetStream is the NATS lane's JetStream box; empty without NATS.
	JetStream    []topoRow
	JetStreamBox topoBox
}

type topoNode struct {
	topoBox
	Name, Sub, Status, Href string
	// Member is the controller member the node runs, if any.
	Member string
	Rows   []topoRow
}

// topoRow is one line in a box: a service, a fence, an operation or a
// load balancer backend. Y is its text baseline.
type topoRow struct {
	// DX is the detail text's offset from X and Width its room.
	X, Y, DX, Width             int
	Label, Detail, Status, Href string
}

// Short fits the detail to its room; the row's tooltip keeps all of it.
func (row topoRow) Short() string { return short(row.Detail, max(row.Width/topoCharW, 4)) }

type topoServer struct {
	X, Y                       int
	Name, Detail, Status, Href string
	Hub                        bool
}

type topoEdge struct {
	// Kind is region, route, attach, leaf or replication.
	Path, Kind, Status, Title string
	Label                     string
	LX, LY                    int
}

func (edge topoEdge) Class() string {
	return "edge e-" + edge.Kind + " " + sClass(edge.Status)
}

// statusRank orders status tokens from best to worst.
var statusRank = map[string]int{"ok": 0, "info": 0, "idle": 1, "run": 2, "warn": 3, "serious": 4, "bad": 5}

func worst(statuses ...string) string {
	out := ""
	for _, status := range statuses {
		if out == "" || statusRank[status] > statusRank[out] {
			out = status
		}
	}
	return cmp.Or(out, "idle")
}

func itos(value int) string { return strconv.Itoa(value) }

// topologyGraph lays out every summarized region, or this member's region
// alone before the region provider runs.
func (current view) topologyGraph() topoGraph {
	graph := topoGraph{NATS: current.State.param("nats") == "1"}
	summaries := current.topologySummaries()
	top := topoMargin
	pairs := len(summaries) * (len(summaries) - 1) / 2
	if graph.NATS && pairs > 0 {
		top += 34 + 14*min(pairs, 6)
	}
	x := topoMargin
	for _, summary := range summaries {
		region := current.topologyRegion(summary, x, top, graph.NATS, &graph.Edges)
		graph.Regions = append(graph.Regions, region)
		x += region.W + topoRegionGap
		graph.Height = max(graph.Height, region.Y+region.H+topoMargin)
	}
	graph.Width = max(x-topoRegionGap+topoMargin, 320)
	if graph.NATS {
		graph.Edges = append(graph.Edges, current.regionEdges(summaries, graph.Regions, top)...)
	}
	return graph
}

func (current view) topologySummaries() []regionview.Summary {
	if len(current.Regions) > 0 {
		return current.Regions
	}
	summary := regionview.Summary{Region: current.localRegion(), Local: true, Reach: decisionlog.RegionOK,
		Quorum: regionview.Quorum{Missing: current.missing()}}
	for _, member := range current.members() {
		summary.Members = append(summary.Members, regionview.Member{Name: member.Member, Role: member.Role,
			Ready: member.Ready, Version: member.BuildVersion, MetaLeader: member.NATS != nil && member.NATS.IsMetaLeader})
	}
	return []regionview.Summary{summary}
}

// topologyNodes is the region's nodes: its granted nodes plus every
// controller no node names, or, from a summary without nodes (an older
// region, a cell without host grants), one node per member and seat host.
func topologyNodes(summary regionview.Summary) []regionview.Node {
	nodes := slices.Clone(summary.Nodes)
	known := map[string]bool{}
	for _, node := range nodes {
		known[node.Name] = true
		if node.Member != "" {
			known[node.Member] = true
		}
	}
	add := func(name, member string) {
		if name != "" && !known[name] {
			known[name] = true
			nodes = append(nodes, regionview.Node{Name: name, Member: member})
		}
	}
	for _, member := range summary.Members {
		switch {
		case member.Role != "host":
			add(member.Name, member.Name)
		case len(summary.Nodes) == 0:
			add(member.Name, "")
		}
	}
	if len(summary.Members) == 0 {
		for _, version := range summary.Versions {
			for _, name := range version.Members {
				add(name, name)
			}
		}
	}
	for _, missing := range summary.Quorum.Missing {
		add(missing, missing)
	}
	if len(summary.Nodes) == 0 {
		for _, host := range summary.Hosts {
			add(host.Name, "")
		}
	}
	return nodes
}

// roleLabels names the roles a host grant places.
var roleLabels = map[string]string{"terrabase": "TerraBase member", "ts-auth": "ts-auth"}

func serviceStatus(state string) (string, string) {
	switch state {
	case "running":
		return "ok", "running"
	case "starting":
		return "run", "starting"
	case "stopped":
		return "warn", "stopped"
	case "":
		return "bad", "no current report"
	default:
		return "bad", state
	}
}

func shortDigest(digest string) string {
	_, hex, found := strings.Cut(digest, ":")
	if !found {
		hex = digest
	}
	return short(hex, 12)
}

func joinDetail(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(part string) bool { return part == "" }), " · ")
}

// topologyRegion lays out one region at x, top and appends its edges.
func (current view) topologyRegion(summary regionview.Summary, x, top int, nats bool, edges *[]topoEdge) topoRegion {
	local := summary.Local
	region := topoRegion{topoBox: topoBox{X: x, Y: top, W: 2*topoPad + topoReplLane + topoNodeW}, Name: upper(summary.Region),
		Href: current.State.link("/region", "r", summary.Region)}
	if nats {
		region.W += topoNATSLane
	}
	region.Status, region.Caption = regionStatus(summary.Health.Status), string(summary.Health.Status)
	if summary.Health.Status == "" {
		region.Status, region.Caption = boolStatus(current.Ready), "this region"
	}
	if city := regionName(summary.Region); city != "" {
		region.Caption = city + " · " + region.Caption
	}
	if !summary.Local && summary.Reach != decisionlog.RegionOK && len(current.Regions) > 0 {
		region.Status, region.Caption = reachStatus(summary.Reach), reachLabel(summary.Reach)
	}
	members := map[string]regionview.Member{}
	for _, member := range summary.Members {
		members[member.Name] = member
	}
	seats := map[string]regionview.Host{}
	for _, host := range summary.Hosts {
		seats[host.Name] = host
	}
	snapshots := map[string]*observability.MemberSnapshot{}
	if local {
		all := current.members()
		for index := range all {
			snapshots[all[index].Member] = &all[index]
		}
	}
	nodeX := x + topoPad + topoReplLane
	y := top + topoHeader
	for _, node := range topologyNodes(summary) {
		box := current.topologyNode(summary, node, members, seats, local)
		box.X, box.Y, box.W = nodeX, y, topoNodeW
		box.H = topoNodeHead + len(box.Rows)*topoRowH + 6
		for index := range box.Rows {
			box.Rows[index].X, box.Rows[index].Y = nodeX+12, y+topoNodeHead+index*topoRowH+10
			box.Rows[index].DX, box.Rows[index].Width = 132, topoNodeW-12-132-8
		}
		region.Nodes = append(region.Nodes, box)
		y += box.H + topoNodeGap
	}
	if local {
		*edges = append(*edges, current.replicationEdges(region.Nodes)...)
	}
	if nats {
		y = max(y, current.natsLane(&region, summary, members, snapshots, local, edges))
	}
	region.H = max(y-top, topoHeader+20) + topoPad - topoNodeGap
	return region
}

func (current view) topologyNode(summary regionview.Summary, node regionview.Node, members map[string]regionview.Member,
	seats map[string]regionview.Host, local bool,
) topoNode {
	href := current.State.hostLink(summary.Region, node.Name)
	box := topoNode{Name: node.Name, Member: node.Member, Href: href}
	box.Sub = node.Address
	if node.Member != "" && node.Member != node.Name {
		box.Sub = joinDetail(box.Sub, "member "+node.Member)
	}
	row := func(label, detail, status, link string) {
		box.Rows = append(box.Rows, topoRow{Label: label, Detail: detail, Status: status, Href: link})
	}
	if node.Member != "" {
		link := current.State.link("/region", "r", summary.Region)
		if local {
			link = current.State.memberLink(node.Member)
		}
		if member, ok := members[node.Member]; ok {
			leader := ""
			if member.Name == summary.Leaders.Authority {
				leader = "authority"
			}
			if member.MetaLeader {
				leader = joinDetail(leader, "meta leader")
			}
			ready := ""
			if !member.Ready {
				ready = "not ready"
			}
			row("ts-orch controller", joinDetail(short(member.Version, 14), ready, leader), boolStatus(member.Ready), link)
		} else {
			row("ts-orch controller", "missing: did not answer", "bad", link)
		}
	}
	if len(node.Services) > 0 {
		status, detail := "bad", "no current report"
		if slices.ContainsFunc(node.Services, func(service regionview.Service) bool { return service.State != "" }) {
			status, detail = "ok", "session reporting"
		}
		row("ts-orch agent", detail, status, href)
	} else if member, ok := members[node.Name]; ok && member.Role == "host" {
		row("ts-orch agent", joinDetail(short(member.Version, 14), readyText(member.Ready)), boolStatus(member.Ready), href)
	}
	host, hasSeats := seats[node.Name]
	if !hasSeats && node.Member != "" {
		host, hasSeats = seats[node.Member]
	}
	seatText := ""
	if hasSeats {
		seatText = itoa(host.Serving) + "/" + itoa(host.Seats) + " seats serving"
	}
	for _, service := range node.Services {
		status, state := serviceStatus(service.State)
		detail := joinDetail(shortDigest(service.Digest), state)
		if service.Role == "terrabase" && seatText != "" {
			detail = joinDetail(shortDigest(service.Digest), state, seatText)
			seatText = ""
		}
		row(cmp.Or(roleLabels[service.Role], service.Role), detail, status, href)
	}
	if seatText != "" {
		status := "ok"
		if host.Serving < host.Seats {
			status = "warn"
		}
		row("TerraBase member", seatText, status, href)
	}
	if len(node.Fence) > 0 {
		row("fenced", strings.Join(node.Fence, ", "), "warn", href)
	}
	if node.Operation != "" {
		row("operation", node.Operation, "run", href)
	}
	for _, backend := range node.Backends {
		status, detail := "ok", "in rotation"
		if backend.Offline {
			status, detail = "warn", "out of rotation"
		}
		row("LB "+backend.Set, detail, status, href)
	}
	statuses := make([]string, 0, len(box.Rows))
	for _, row := range box.Rows {
		statuses = append(statuses, row.Status)
	}
	box.Status = worst(statuses...)
	return box
}

func readyText(ready bool) string {
	if ready {
		return "ready"
	}
	return "not ready"
}

// nodeAt finds the node a seat's host node names: by node or member name.
func nodeAt(nodes []topoNode, name string) int {
	return slices.IndexFunc(nodes, func(node topoNode) bool {
		return strings.EqualFold(node.Name, name) || node.Member != "" && strings.EqualFold(node.Member, name)
	})
}

// replicationEdges joins every two nodes that carry seats of one TerraBase
// partition, from this region's placement. An edge is healthy when every
// shared partition's seats on both ends serve; its tooltip names the
// largest replication lag either end last reported.
func (current view) replicationEdges(nodes []topoNode) []topoEdge {
	placement := current.placement()
	if placement == nil {
		return nil
	}
	type pair struct{ partitions, unhealthy int }
	pairs := map[[2]int]*pair{}
	var order [][2]int
	for _, database := range placement.Databases {
		ends := map[int]bool{}
		healthy := true
		for _, seat := range database.Members {
			if at := nodeAt(nodes, seat.HostNode); at >= 0 && seat.HostNode != "" {
				ends[at] = true
				healthy = healthy && seat.Stage == "serving"
			}
		}
		sorted := slices.Sorted(func(yield func(int) bool) {
			for at := range ends {
				if !yield(at) {
					return
				}
			}
		})
		for left := range sorted {
			for right := left + 1; right < len(sorted); right++ {
				key := [2]int{sorted[left], sorted[right]}
				if pairs[key] == nil {
					pairs[key] = &pair{}
					order = append(order, key)
				}
				pairs[key].partitions++
				if !healthy {
					pairs[key].unhealthy++
				}
			}
		}
	}
	slices.SortFunc(order, func(a, b [2]int) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) })
	edges := make([]topoEdge, 0, len(order))
	for _, key := range order {
		from, to := nodes[key[0]], nodes[key[1]]
		y1, y2 := from.Y+20, to.Y+20
		dx := min(topoReplLane-6, 14+(y2-y1)/4)
		status, title := "ok", from.Name+" ↔ "+to.Name+": "+itoa(pairs[key].partitions)+" partition(s) replicate"
		if pairs[key].unhealthy > 0 {
			status, title = "warn", title+", "+itoa(pairs[key].unhealthy)+" with a seat not serving"
		}
		label := ""
		if lag, ok := current.replicationLag(from.Name, to.Name); ok {
			label = formatFloat(lag, 0)
			title += " · replication lag " + label + " seq"
		}
		edges = append(edges, topoEdge{Kind: "replication", Status: status, Title: title, Label: label,
			LX: from.X - dx + 2, LY: (y1+y2)/2 + 4,
			Path: "M" + itos(from.X) + " " + itos(y1) + " C" + itos(from.X-dx) + " " + itos(y1) + " " + itos(to.X-dx) + " " +
				itos(y2) + " " + itos(to.X) + " " + itos(y2)})
	}
	return edges
}

// replicationLag is the largest TerraBase replication lag either node last
// reported through host telemetry.
func (current view) replicationLag(nodes ...string) (float64, bool) {
	type latestSource interface {
		Latest(string, map[string]string) map[string]float64
	}
	if current.Journal == nil {
		return 0, false
	}
	source, ok := current.Journal.History.(latestSource)
	if !ok {
		return 0, false
	}
	lag, found := 0.0, false
	for _, node := range nodes {
		for _, value := range source.Latest(observability.HistTerraBaseLagSeq, map[string]string{"member": strings.ToLower(node)}) {
			lag, found = max(lag, value), true
		}
	}
	return lag, found
}

// natsLane places the region's NATS servers beside their controllers' nodes,
// the route mesh between them, every other node's client connection to the
// meta leader's server and JetStream health under them. It returns the
// lane's bottom.
func (current view) natsLane(region *topoRegion, summary regionview.Summary, members map[string]regionview.Member,
	snapshots map[string]*observability.MemberSnapshot, local bool, edges *[]topoEdge,
) int {
	laneX := region.X + topoPad + topoReplLane + topoNodeW
	serverX := laneX + 34
	missing := map[string]bool{}
	for _, name := range summary.Quorum.Missing {
		missing[name] = true
	}
	// NATS names peers by server name; the snapshots by member name.
	serverMember := map[string]string{}
	offline := map[string]bool{}
	answering := 0
	for _, snapshot := range snapshots {
		if snapshot.NATS != nil && snapshot.NATS.ServerName != "" {
			serverMember[snapshot.NATS.ServerName] = snapshot.Member
		}
		if snapshot.Role != "host" {
			answering++
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.NATS != nil && snapshot.Role != "host" {
			for _, peer := range snapshot.NATS.MetaPeers {
				if peer.Offline {
					offline[cmp.Or(serverMember[peer.Name], peer.Name)] = true
				}
			}
		}
	}
	hub := -1
	memberOf := map[int]string{}
	for _, node := range region.Nodes {
		name := node.Member
		if name == "" {
			continue
		}
		server := topoServer{X: serverX, Y: node.Y + 20, Name: name, Status: "idle", Detail: "not reported",
			Href: current.State.link("/nats", "r", summary.Region)}
		member, answered := members[name]
		snapshot := snapshots[name]
		switch {
		case missing[name] || !answered && snapshot == nil:
			server.Status, server.Detail = "bad", "missing"
		case snapshot != nil && snapshot.NATS != nil:
			nats := snapshot.NATS
			server.Name = cmp.Or(nats.ServerName, name)
			server.Status = boolStatus(snapshot.Ready && !offline[name])
			server.Detail = itoa(nats.Connections) + " conns · " + itoa(nats.ClusterPeers) + " peers"
			if nats.SlowConsumers > 0 {
				server.Status, server.Detail = worst(server.Status, "warn"), server.Detail+" · "+itoa(nats.SlowConsumers)+" slow"
			}
			server.Hub = nats.IsMetaLeader
		case snapshot != nil:
			server.Status = "idle"
		default:
			server.Status, server.Detail = boolStatus(member.Ready), "counts in its region"
			server.Hub = member.MetaLeader
		}
		if server.Hub {
			hub = len(region.Servers)
		}
		memberOf[len(region.Servers)] = name
		region.Servers = append(region.Servers, server)
		*edges = append(*edges, topoEdge{Kind: "attach", Status: server.Status, Title: node.Name + " runs " + server.Name,
			Path: "M" + itos(node.X+node.W) + " " + itos(server.Y) + " H" + itos(serverX-8)})
	}
	if hub < 0 && len(region.Servers) > 0 {
		hub = 0
	}
	// Routes form a full mesh. Locally a route is healthy only when both
	// ends see every answering controller, broken when an end is missing
	// or offline, and expected (idle) otherwise; another region's summary
	// says who answered, not which routes are up.
	full := func(name string) bool {
		snapshot := snapshots[name]
		return snapshot != nil && snapshot.NATS != nil && snapshot.NATS.ClusterPeers >= answering
	}
	for left := range region.Servers {
		for right := left + 1; right < len(region.Servers); right++ {
			a, b := region.Servers[left], region.Servers[right]
			nameA, nameB := memberOf[left], memberOf[right]
			status, title := "idle", "NATS route (expected)"
			switch {
			case a.Status == "bad" || b.Status == "bad" || offline[nameA] || offline[nameB]:
				status, title = "bad", "NATS route"
			case local && full(nameA) && full(nameB):
				status, title = "ok", "NATS route"
			}
			dx := min(topoNATSLane-60, 18+(b.Y-a.Y)/3)
			*edges = append(*edges, topoEdge{Kind: "route", Status: status, Title: title + ": " + a.Name + " ↔ " + b.Name,
				Path: "M" + itos(a.X+7) + " " + itos(a.Y) + " C" + itos(a.X+7+dx) + " " + itos(a.Y) + " " + itos(b.X+7+dx) + " " +
					itos(b.Y) + " " + itos(b.X+7) + " " + itos(b.Y)})
		}
	}
	// A node without a controller reaches NATS as a client of the cell's
	// servers; its agent's verified reports prove the session.
	if hub >= 0 {
		target := region.Servers[hub]
		for _, node := range region.Nodes {
			if node.Member != "" {
				continue
			}
			status, title := "idle", node.Name+" → NATS (client, expected)"
			if slices.ContainsFunc(node.Rows, func(row topoRow) bool { return row.Label == "ts-orch agent" && row.Status == "ok" }) {
				status, title = "ok", node.Name+" → NATS (agent session reporting)"
			}
			y := node.Y + 20
			*edges = append(*edges, topoEdge{Kind: "leaf", Status: status, Title: title,
				Path: "M" + itos(node.X+node.W) + " " + itos(y) + " C" + itos(node.X+node.W+24) + " " + itos(y) + " " +
					itos(target.X-30) + " " + itos(target.Y) + " " + itos(target.X-8) + " " + itos(target.Y)})
		}
	}
	bottom := region.Y + topoHeader
	if len(region.Nodes) > 0 {
		last := region.Nodes[len(region.Nodes)-1]
		bottom = last.Y + last.H + topoNodeGap
	}
	region.JetStream = current.jetStreamRows(summary, local)
	box := topoBox{X: laneX + 8, Y: bottom, W: topoNATSLane - 16, H: 26 + len(region.JetStream)*topoRowH}
	for index := range region.JetStream {
		region.JetStream[index].X, region.JetStream[index].Y = box.X+10, box.Y+38+index*topoRowH
		region.JetStream[index].DX, region.JetStream[index].Width = 90, box.W-10-90-8
	}
	region.JetStreamBox = box
	return box.Y + box.H + topoNodeGap
}

// maxJetStreamRows bounds the streams the JetStream box names.
const maxJetStreamRows = 5

// jetStreamRows is this region's JetStream health from the meta leader's
// stream list: totals, the store, and every stream with an offline replica
// or replica lag. Another region's summary carries only its store.
func (current view) jetStreamRows(summary regionview.Summary, local bool) []topoRow {
	href := current.State.link("/nats", "r", summary.Region)
	if !local {
		capacity := summary.Capacity
		if capacity.StoreLimitBytes <= 0 {
			return []topoRow{{Label: "streams", Detail: "on its region's NATS page", Status: "idle", Href: href}}
		}
		return []topoRow{{Label: "store", Detail: percent(storeRatio(capacity)) + " of " +
			formatBytes(capacity.StoreLimitBytes), Status: ratioStatus(storeRatio(capacity)), Href: href}}
	}
	reporter := current.natsReporter()
	if reporter == nil || reporter.NATS == nil {
		return []topoRow{{Label: "streams", Detail: "not reported", Status: "idle", Href: href}}
	}
	nats := reporter.NATS
	streams, buckets := 0, 0
	var unhealthy []topoRow
	for _, stream := range nats.Streams {
		if strings.HasPrefix(stream.Name, "KV_") {
			buckets++
		} else {
			streams++
		}
		switch {
		case stream.OfflinePeers > 0:
			unhealthy = append(unhealthy, topoRow{Label: short(stream.Name, 14), Detail: itoa(stream.OfflinePeers) + " offline",
				Status: "bad", Href: href})
		case stream.MaxReplicaLag > 0:
			unhealthy = append(unhealthy, topoRow{Label: short(stream.Name, 14), Detail: "lag " + itoa(stream.MaxReplicaLag),
				Status: "warn", Href: href})
		}
	}
	statuses := []string{"ok"}
	for _, row := range unhealthy {
		statuses = append(statuses, row.Status)
	}
	count := itoa(streams) + " streams · " + itoa(buckets) + " KV"
	if nats.Truncated {
		count += "+"
	}
	rows := []topoRow{{Label: "health", Detail: count, Status: worst(statuses...), Href: href}}
	if nats.StoreLimitBytes > 0 {
		used := ratio(float64(nats.StoreUsedBytes), float64(nats.StoreLimitBytes))
		rows = append(rows, topoRow{Label: "store", Detail: percent(used) + " of " + formatBytes(nats.StoreLimitBytes),
			Status: ratioStatus(used), Href: href})
	}
	return append(rows, unhealthy[:min(len(unhealthy), maxJetStreamRows)]...)
}

// regionEdges are the inter-region NATS links, arcs over the regions'
// NATS lanes. Only links that touch this region carry evidence (whether
// the other region answers over its link); a missing link is drawn broken,
// a link between two other regions stays unknown.
func (current view) regionEdges(summaries []regionview.Summary, regions []topoRegion, top int) []topoEdge {
	local := current.localRegion()
	var edges []topoEdge
	index := 0
	for left := range summaries {
		for right := left + 1; right < len(summaries); right++ {
			from, to := summaries[left], summaries[right]
			status, label := "idle", "unknown"
			other := ""
			switch {
			case from.Region == local:
				other = to.Reach
			case to.Region == local:
				other = from.Reach
			}
			switch other {
			case "":
			case decisionlog.RegionOK:
				status, label = "ok", "linked"
			case decisionlog.RegionNotLinked:
				status, label = "bad", "missing (no leaf link)"
			default:
				status, label = "bad", reachLabel(other)
			}
			x1 := regions[left].X + regions[left].W - topoPad - topoNATSLane/2
			x2 := regions[right].X + regions[right].W - topoPad - topoNATSLane/2
			height := 22 + 14*min(index, 5)
			index++
			title := upper(from.Region) + " ↔ " + upper(to.Region) + ": " + label
			edges = append(edges, topoEdge{Kind: "region", Status: status, Title: title, Label: title,
				LX: (x1 + x2) / 2, LY: top - height + 4,
				Path: "M" + itos(x1) + " " + itos(top) + " C" + itos(x1) + " " + itos(top-height-8) + " " + itos(x2) + " " +
					itos(top-height-8) + " " + itos(x2) + " " + itos(top)})
		}
	}
	return edges
}
