package dashboard

import (
	"encoding/json"
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// topologyNode is one <ts-topology> node; clicking it opens a drill-down
// panel with Details and a link to Href.
type topologyNode struct {
	ID string `json:"id"`
	// Region groups the node under its region for collapse and layout.
	Region     string            `json:"region"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	State      string            `json:"state"`
	StateLabel string            `json:"stateLabel"`
	Href       string            `json:"href,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type topologyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// Kind is region, member, route, leaf or seat.
	Kind  string `json:"kind"`
	State string `json:"state,omitempty"`
	Label string `json:"label,omitempty"`
}

type topologySpec struct {
	Nodes []topologyNode `json:"nodes"`
	Links []topologyLink `json:"links"`
}

// maxTopologySeats keeps the force layout responsive in large cells.
const maxTopologySeats = 400

// topology builds regions -> controllers -> hosts -> TerraBase seats, the
// NATS routes between controllers, host leaf connections and the links
// between regions. Other regions show the members their summary names.
func (current view) topology() topologySpec {
	spec := topologySpec{}
	nodes := map[string]bool{}
	addNode := func(node topologyNode) {
		if !nodes[node.ID] {
			nodes[node.ID] = true
			spec.Nodes = append(spec.Nodes, node)
		}
	}
	local := current.localRegion()
	regions := current.Regions
	if len(regions) == 0 {
		addNode(topologyNode{ID: "region:" + local, Region: local, Name: upper(local), Kind: "region", State: boolStatus(current.Ready),
			StateLabel: "this region", Href: current.State.link("/region")})
	}
	for _, summary := range regions {
		status := regionStatus(summary.Health.Status)
		addNode(topologyNode{ID: "region:" + summary.Region, Region: summary.Region, Name: upper(summary.Region), Kind: "region", State: status,
			StateLabel: string(summary.Health.Status), Href: current.State.link("/region", "r", summary.Region),
			Details: map[string]string{"health score": itoa(summary.Health.Score), "reach": reachLabel(summary.Reach),
				"quorum":    itoa(summary.Quorum.Answering) + "/" + itoa(summary.Quorum.Expected),
				"authority": orDash(summary.Leaders.Authority), "meta leader": orDash(summary.Leaders.MetaLeader),
				"TerraBase": itoa(summary.TerraBase.Databases) + " databases", "versions": versionsText(summary)}})
		if !summary.Local {
			remoteTopology(&spec, addNode, summary, current.State)
		}
	}
	current.localTopology(&spec, addNode)
	current.regionLinks(&spec)
	return spec
}

// remoteTopology adds another region's controllers and seat hosts from its
// summary. Summaries from older regions carry only the build versions'
// members, which are shown as controllers. A summary says who answered,
// not which routes are up, so routes between ready controllers are drawn
// as expected (idle) and only routes to a not-ready or missing controller
// as broken.
func remoteTopology(spec *topologySpec, addNode func(topologyNode), summary regionview.Summary, state uiState) {
	region := summary.Region
	regionID := "region:" + region
	href := state.link("/region", "r", region)
	id := func(name string) string { return "member:" + region + ":" + name }
	members := summary.Members
	if len(members) == 0 {
		for _, version := range summary.Versions {
			for _, name := range version.Members {
				members = append(members, regionview.Member{Name: name, Role: "controller", Ready: true, Version: version.Version})
			}
		}
	}
	var controllers, hosts []string
	seen := map[string]bool{}
	ready := map[string]bool{}
	hostReady := map[string]bool{}
	hub := regionID
	for _, member := range members {
		if member.Name == "" || seen[member.Name] {
			continue
		}
		seen[member.Name] = true
		kind, label := "controller", "answering"
		if member.Role == "host" {
			kind = "host"
		}
		if !member.Ready {
			label = "not ready"
		}
		details := map[string]string{"region": upper(region), "role": orDash(member.Role), "build": orDash(member.Version)}
		if member.Name == summary.Leaders.Authority {
			details["authority"] = "leader, epoch " + itoa(summary.Leaders.Epoch)
		}
		if member.MetaLeader || member.Name == summary.Leaders.MetaLeader {
			details["JetStream"] = "meta leader"
			if kind == "controller" {
				hub = id(member.Name)
			}
		}
		addNode(topologyNode{ID: id(member.Name), Region: region, Name: member.Name, Kind: kind, State: boolStatus(member.Ready),
			StateLabel: label, Href: href, Details: details})
		if kind == "host" {
			hostReady[member.Name] = member.Ready
			hosts = append(hosts, member.Name)
			continue
		}
		controllers = append(controllers, member.Name)
		ready[member.Name] = member.Ready
		spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id(member.Name), Kind: "member"})
	}
	for _, missing := range summary.Quorum.Missing {
		if missing == "" || seen[missing] {
			continue
		}
		seen[missing] = true
		addNode(topologyNode{ID: id(missing), Region: region, Name: missing, Kind: "controller", State: "bad", StateLabel: "missing",
			Href: href, Details: map[string]string{"region": upper(region), "why": "did not answer its region's snapshot request"}})
		controllers = append(controllers, missing)
		spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id(missing), Kind: "member", State: "bad"})
	}
	slices.Sort(controllers)
	for left := range controllers {
		for right := left + 1; right < len(controllers); right++ {
			state := "idle"
			if !ready[controllers[left]] || !ready[controllers[right]] {
				state = "bad"
			}
			spec.Links = append(spec.Links, topologyLink{Source: id(controllers[left]), Target: id(controllers[right]),
				Kind: "route", State: state, Label: "NATS route (expected)"})
		}
	}
	for _, host := range summary.Hosts {
		if host.Name == "" {
			continue
		}
		if !seen[host.Name] {
			seen[host.Name] = true
			hosts = append(hosts, host.Name)
		} else if _, isHost := hostReady[host.Name]; !isHost {
			continue // a controller of the same name already holds this node
		}
		// Placement says where seats are, not that the host is alive.
		hostState := "idle"
		if ready, ok := hostReady[host.Name]; ok {
			hostState = boolStatus(ready)
		}
		addNode(topologyNode{ID: id(host.Name), Region: region, Name: host.Name, Kind: "host", State: hostState,
			StateLabel: "carries seats", Href: href,
			Details: map[string]string{"region": upper(region), "seats": itoa(host.Seats), "serving": itoa(host.Serving)}})
	}
	for _, host := range hosts {
		spec.Links = append(spec.Links, topologyLink{Source: hub, Target: id(host), Kind: "leaf", Label: "NATS leaf / client"})
	}
}

// topologySeat is one placed TerraBase seat. Seat IDs repeat across
// databases and partitions, so the node ID carries both.
type topologySeat struct {
	database, partition string
	observability.MemberView
}

func (current view) localTopology(spec *topologySpec, addNode func(topologyNode)) {
	local := current.localRegion()
	regionID := "region:" + local
	members := current.members()
	memberID := func(name string) string { return "member:" + local + ":" + name }
	// NATS names peers and the meta leader by server name; members are
	// keyed by member name.
	serverMember := map[string]string{}
	answering := 0
	for _, member := range members {
		if member.NATS != nil && member.NATS.ServerName != "" {
			serverMember[member.NATS.ServerName] = member.Member
		}
		if member.Role != "host" {
			answering++
		}
	}
	memberOf := func(server string) string {
		if name, ok := serverMember[server]; ok {
			return name
		}
		return server
	}
	offline := map[string]bool{}
	routes := map[string]int{}
	snapshot := map[string]*observability.MemberSnapshot{}
	hub := regionID
	for index, member := range members {
		snapshot[member.Member] = &members[index]
		if member.NATS == nil || member.Role == "host" {
			continue
		}
		// Distinct route peers including this server, not route
		// connections: route pooling opens several connections per peer.
		routes[member.Member] = member.NATS.ClusterPeers
		for _, peer := range member.NATS.MetaPeers {
			if peer.Offline {
				offline[memberOf(peer.Name)] = true
			}
		}
		if member.NATS.IsMetaLeader {
			hub = memberID(member.Member)
		}
	}
	if leader := current.metaLeader(); hub == regionID && leader != "" {
		if member := snapshot[memberOf(leader)]; member != nil && member.Role != "host" {
			hub = memberID(member.Member)
		}
	}
	var controllers []string
	for _, member := range members {
		id := memberID(member.Member)
		kind := "controller"
		if member.Role == "host" {
			kind = "host"
		}
		state, label := boolStatus(member.Ready), "ready"
		if !member.Ready {
			label = "not ready"
		}
		details := map[string]string{"role": member.Role, "build": orDash(member.BuildVersion)}
		if member.Authority != nil && member.Authority.Leader {
			details["authority"] = "leader, epoch " + itoa(member.Authority.Epoch)
		}
		if member.NATS != nil {
			details["routes"] = itoa(member.NATS.Routes)
			details["connections"] = itoa(member.NATS.Connections)
			if member.NATS.IsMetaLeader {
				details["JetStream"] = "meta leader"
			}
		}
		if member.System != nil {
			details["memory used"] = percent(memoryUsed(member.System))
			details["load 1m"] = formatFloat(member.System.Load1, 2)
		}
		addNode(topologyNode{ID: id, Region: local, Name: member.Member, Kind: kind, State: state, StateLabel: label,
			Href: current.State.memberLink(member.Member), Details: details})
		if kind == "controller" {
			controllers = append(controllers, member.Member)
			spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id, Kind: "member"})
		}
	}
	missing := current.missing()
	for _, name := range missing {
		if snapshot[name] != nil || slices.Contains(controllers, name) {
			continue
		}
		id := memberID(name)
		addNode(topologyNode{ID: id, Region: local, Name: name, Kind: "controller", State: "bad", StateLabel: "missing",
			Details: map[string]string{"why": "did not answer the cell-wide snapshot request"}})
		controllers = append(controllers, name)
		spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id, Kind: "member", State: "bad"})
	}
	// NATS routes form a full mesh between the region's controllers. The
	// snapshot carries distinct peer counts (this server included), not
	// route peers: a route is healthy only when both ends see every
	// answering controller, broken when an end is missing or offline, and
	// expected (idle) otherwise.
	slices.Sort(controllers)
	full := func(name string) bool {
		count, ok := routes[name]
		return ok && count >= answering
	}
	for left := range controllers {
		for right := left + 1; right < len(controllers); right++ {
			a, b := controllers[left], controllers[right]
			state, label := "idle", "NATS route (expected)"
			switch {
			case offline[a] || offline[b] || slices.Contains(missing, a) || slices.Contains(missing, b):
				state, label = "bad", "NATS route"
			case full(a) && full(b):
				state, label = "ok", "NATS route"
			}
			spec.Links = append(spec.Links, topologyLink{Source: memberID(a), Target: memberID(b), Kind: "route", State: state,
				Label: label})
		}
	}
	placement := current.placement()
	hosts := map[string][]topologySeat{}
	if placement != nil {
		for _, database := range placement.Databases {
			for _, member := range database.Members {
				if member.HostNode != "" {
					hosts[member.HostNode] = append(hosts[member.HostNode],
						topologySeat{database: database.DatabaseID, partition: database.PartitionID, MemberView: member})
				}
			}
		}
	}
	for _, member := range members {
		if member.Role == "host" {
			if _, ok := hosts[member.Member]; !ok {
				hosts[member.Member] = nil
			}
		}
	}
	seats := 0
	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		id := memberID(host)
		serving := 0
		for _, seat := range hosts[host] {
			if seat.Stage == "serving" {
				serving++
			}
		}
		// Placement says where seats are, not that the host is alive; only
		// a member's own snapshot shows its readiness.
		state := "idle"
		if member := snapshot[host]; member != nil {
			state = boolStatus(member.Ready)
		}
		addNode(topologyNode{ID: id, Region: local, Name: host, Kind: "host", State: state, StateLabel: "carries seats",
			Href:    current.State.hostLink(local, host),
			Details: map[string]string{"seats": itoa(len(hosts[host])), "serving": itoa(serving)}})
		if id != hub {
			spec.Links = append(spec.Links, topologyLink{Source: hub, Target: id, Kind: "leaf", Label: "NATS leaf / client"})
		}
		for _, seat := range hosts[host] {
			if seats >= maxTopologySeats {
				break
			}
			seats++
			seatID := "seat:" + local + ":" + seat.database + "/" + seat.partition + "/" + seat.SeatID
			addNode(topologyNode{ID: seatID, Region: local, Name: seat.SeatID, Kind: "seat", State: stageStatus(seat.Stage),
				StateLabel: seat.Stage, Href: current.State.partitionLink(seat.database, seat.partition),
				Details: map[string]string{"host": host, "database": orDash(seat.database), "partition": orDash(seat.partition),
					"failure domain": orDash(seat.FailureDomain), "update phase": orDash(seat.UpdatePhase),
					"updated": formatTime(seat.UpdatedAt)}})
			spec.Links = append(spec.Links, topologyLink{Source: id, Target: seatID, Kind: "seat"})
		}
	}
}

func (current view) regionLinks(spec *topologySpec) {
	local := current.localRegion()
	reach := map[string]string{}
	for _, summary := range current.Regions {
		reach[summary.Region] = summary.Reach
	}
	for left := range current.Regions {
		for right := left + 1; right < len(current.Regions); right++ {
			from, to := current.Regions[left].Region, current.Regions[right].Region
			state := "idle"
			switch {
			case from == local:
				state = reachStatus(reach[to])
			case to == local:
				state = reachStatus(reach[from])
			}
			// Both regions answering this one says nothing about the link
			// between them, so a remote-to-remote edge stays unknown.
			spec.Links = append(spec.Links, topologyLink{Source: "region:" + from, Target: "region:" + to, Kind: "region",
				State: state, Label: upper(from) + " ↔ " + upper(to)})
		}
	}
}

func (current view) topologyJSON() string {
	data, _ := json.Marshal(current.topology())
	return string(data)
}
