package dashboard

import (
	"encoding/json"
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// topologyNode is one <ts-topology> node; clicking it opens a drill-down
// panel with Details and a link to Href.
type topologyNode struct {
	ID         string            `json:"id"`
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
		addNode(topologyNode{ID: "region:" + local, Name: upper(local), Kind: "region", State: boolStatus(current.Ready),
			StateLabel: "this region", Href: current.State.link("/region")})
	}
	for _, summary := range regions {
		status := regionStatus(summary.Health.Status)
		addNode(topologyNode{ID: "region:" + summary.Region, Name: upper(summary.Region), Kind: "region", State: status,
			StateLabel: string(summary.Health.Status), Href: current.State.link("/region", "r", summary.Region),
			Details: map[string]string{"health score": itoa(summary.Health.Score), "reach": reachLabel(summary.Reach),
				"quorum": itoa(summary.Quorum.Answering) + "/" + itoa(summary.Quorum.Expected),
				"authority": orDash(summary.Leaders.Authority), "meta leader": orDash(summary.Leaders.MetaLeader),
				"TerraBase": itoa(summary.TerraBase.Databases) + " databases", "versions": versionsText(summary)}})
		if summary.Local {
			continue
		}
		for _, version := range summary.Versions {
			for _, member := range version.Members {
				id := "member:" + summary.Region + ":" + member
				addNode(topologyNode{ID: id, Name: member, Kind: "controller", State: "ok", StateLabel: "answering",
					Href:    current.State.link("/region", "r", summary.Region),
					Details: map[string]string{"region": upper(summary.Region), "version": version.Version}})
				spec.Links = append(spec.Links, topologyLink{Source: "region:" + summary.Region, Target: id, Kind: "member"})
			}
		}
		for _, missing := range summary.Quorum.Missing {
			id := "member:" + summary.Region + ":" + missing
			addNode(topologyNode{ID: id, Name: missing, Kind: "controller", State: "bad", StateLabel: "missing",
				Details: map[string]string{"region": upper(summary.Region)}})
			spec.Links = append(spec.Links, topologyLink{Source: "region:" + summary.Region, Target: id, Kind: "member", State: "bad"})
		}
	}
	current.localTopology(&spec, addNode)
	current.regionLinks(&spec)
	return spec
}

func (current view) localTopology(spec *topologySpec, addNode func(topologyNode)) {
	local := current.localRegion()
	regionID := "region:" + local
	members := current.members()
	var controllers []string
	offline := map[string]bool{}
	for _, member := range members {
		if member.NATS != nil {
			for _, peer := range member.NATS.MetaPeers {
				if peer.Offline {
					offline[peer.Name] = true
				}
			}
		}
	}
	for _, member := range members {
		id := "member:" + local + ":" + member.Member
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
		addNode(topologyNode{ID: id, Name: member.Member, Kind: kind, State: state, StateLabel: label,
			Href: current.State.link("/members", "host", member.Member), Details: details})
		if kind == "controller" {
			controllers = append(controllers, member.Member)
			spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id, Kind: "member"})
		}
	}
	for _, missing := range current.missing() {
		id := "member:" + local + ":" + missing
		addNode(topologyNode{ID: id, Name: missing, Kind: "controller", State: "bad", StateLabel: "missing",
			Details: map[string]string{"why": "did not answer the cell-wide snapshot request"}})
		controllers = append(controllers, missing)
		spec.Links = append(spec.Links, topologyLink{Source: regionID, Target: id, Kind: "member", State: "bad"})
	}
	// NATS routes form a full mesh between the region's controllers.
	slices.Sort(controllers)
	for left := range controllers {
		for right := left + 1; right < len(controllers); right++ {
			state := "ok"
			if offline[controllers[left]] || offline[controllers[right]] || slices.Contains(current.missing(), controllers[left]) ||
				slices.Contains(current.missing(), controllers[right]) {
				state = "bad"
			}
			spec.Links = append(spec.Links, topologyLink{Source: "member:" + local + ":" + controllers[left],
				Target: "member:" + local + ":" + controllers[right], Kind: "route", State: state, Label: "NATS route"})
		}
	}
	leader := current.metaLeader()
	hub := regionID
	if leader != "" && slices.Contains(controllers, leader) {
		hub = "member:" + local + ":" + leader
	}
	placement := current.placement()
	hosts := map[string][]observability.MemberView{}
	if placement != nil {
		for _, database := range placement.Databases {
			for _, member := range database.Members {
				if member.HostNode != "" {
					hosts[member.HostNode] = append(hosts[member.HostNode], member)
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
		id := "member:" + local + ":" + host
		serving := 0
		for _, seat := range hosts[host] {
			if seat.Stage == "serving" {
				serving++
			}
		}
		addNode(topologyNode{ID: id, Name: host, Kind: "host", State: "ok", StateLabel: "carries seats",
			Href:    current.State.link("/members", "host", host),
			Details: map[string]string{"seats": itoa(len(hosts[host])), "serving": itoa(serving)}})
		spec.Links = append(spec.Links, topologyLink{Source: hub, Target: id, Kind: "leaf", Label: "NATS leaf / client"})
		for _, seat := range hosts[host] {
			if seats >= maxTopologySeats {
				break
			}
			seats++
			seatID := "seat:" + local + ":" + seat.SeatID
			addNode(topologyNode{ID: seatID, Name: seat.SeatID, Kind: "seat", State: stageStatus(seat.Stage),
				StateLabel: seat.Stage, Href: current.State.link("/terrabase", "host", host),
				Details: map[string]string{"host": host, "failure domain": orDash(seat.FailureDomain),
					"update phase": orDash(seat.UpdatePhase), "updated": formatTime(seat.UpdatedAt)}})
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
			case reach[from] == decisionlog.RegionOK && reach[to] == decisionlog.RegionOK:
				state = "ok"
			}
			spec.Links = append(spec.Links, topologyLink{Source: "region:" + from, Target: "region:" + to, Kind: "region",
				State: state, Label: upper(from) + " ↔ " + upper(to)})
		}
	}
}

func (current view) topologyJSON() string {
	data, _ := json.Marshal(current.topology())
	return string(data)
}
