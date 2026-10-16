package dashboard

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

// find returns the first item that matches.
func find[T any](items []T, match func(T) bool) (T, bool) {
	if index := slices.IndexFunc(items, match); index >= 0 {
		return items[index], true
	}
	var zero T
	return zero, false
}

func regionNamed(regions []globalview.Region, cell string) (globalview.Region, bool) {
	return find(regions, func(region globalview.Region) bool { return region.Cell == cell })
}

// A region without a rollup has no nodes, volumes or autoscale state.

func nodeNamed(region globalview.Region, name string) (globalview.Node, bool) {
	if region.Rollup == nil {
		return globalview.Node{}, false
	}
	return find(region.Rollup.Nodes, func(node globalview.Node) bool { return node.Name == name })
}

func volumeNamed(region globalview.Region, id string) (globalview.Volume, bool) {
	if region.Rollup == nil || region.Rollup.VolumesUnavailable {
		return globalview.Volume{}, false
	}
	return find(region.Rollup.Volumes, func(volume globalview.Volume) bool { return volume.ID == id })
}

func scalingNamed(region globalview.Region, role string) (globalview.Scaling, bool) {
	if region.Rollup == nil {
		return globalview.Scaling{}, false
	}
	return find(region.Rollup.Autoscale.Services, func(scaling globalview.Scaling) bool { return scaling.Service == role })
}

func serviceNamed(node globalview.Node, role string) (globalview.Service, bool) {
	return find(node.Services, func(service globalview.Service) bool { return service.Role == role })
}

// Missing observations cannot establish that a resource is absent.
func resourceMissing(region globalview.Region, kind, name string) string {
	subject := kind + " " + name
	if kind == "Volume" && region.Rollup != nil && region.Rollup.VolumesUnavailable {
		return subject + " is unknown: the regional volume observation is unavailable."
	}
	switch region.ResourceState(false) {
	case "stale":
		return subject + " is unknown: the regional observation is stale."
	case "truncated":
		return subject + " is unknown: the regional observation is truncated."
	case "missing":
		return subject + " is unknown: no regional observation is available."
	default:
		return subject + " is absent from the current complete regional observation."
	}
}

// nodeStatus maps a node's health to a status token.
func nodeStatus(health string) string {
	switch health {
	case globalview.NodeOK:
		return "ok"
	case globalview.NodeWarn:
		return "warn"
	case globalview.NodeDown:
		return "bad"
	default:
		return "idle"
	}
}

// nodeEntry is one node with the region that reports it.
type nodeEntry struct {
	Region string
	Stale  bool
	Node   globalview.Node
}

// nodeEntries lists the nodes of every region with a rollup, or of region
// alone, in sort order.
func nodeEntries(regions []globalview.Region, region, sortKey string) []nodeEntry {
	var out []nodeEntry
	for _, listed := range regions {
		if listed.Rollup == nil || region != "" && listed.Cell != region {
			continue
		}
		for _, node := range listed.Rollup.Nodes {
			out = append(out, nodeEntry{Region: listed.Cell, Stale: listed.Stale, Node: node})
		}
	}
	slices.SortStableFunc(out, func(left, right nodeEntry) int {
		return cmp.Or(cmp.Compare(nodeMetric(right.Node, sortKey), nodeMetric(left.Node, sortKey)),
			cmp.Compare(left.Region, right.Region), cmp.Compare(left.Node.Name, right.Node.Name))
	})
	return out
}

// nodeMetric is the value a sort key orders a node by.
func nodeMetric(node globalview.Node, sortKey string) float64 {
	switch sortKey {
	case "cpu":
		return valueOr(node.CPU, -1)
	case "memory":
		return ratio(float64(node.MemoryUsedBytes), float64(node.MemoryBytes))
	case "disk":
		return ratio(float64(node.DiskUsedBytes), float64(node.DiskBytes))
	case "network":
		return valueOr(node.NetworkRxBps, 0) + valueOr(node.NetworkTxBps, 0)
	default:
		return 0
	}
}

// valueOr reads an optional reading, or fallback when it was not measured.
func valueOr(value *float64, fallback float64) float64 {
	if value == nil {
		return fallback
	}
	return *value
}

// nodeCells is one node of a node table, already formatted.
type nodeCells struct {
	Region, Name, Status, Health string
	CPU, Memory, Disk, Network   string
	Load, Services, Reported     string
}

func nodeCellsOf(entry nodeEntry, now time.Time) nodeCells {
	node := entry.Node
	cells := nodeCells{Region: entry.Region, Name: node.Name, Status: nodeStatus(node.Health), Health: node.Health,
		CPU: "—", Memory: pctOf(float64(node.MemoryUsedBytes), float64(node.MemoryBytes)),
		Disk:     pctOf(float64(node.DiskUsedBytes), float64(node.DiskBytes)),
		Network:  rateOr(node.NetworkRxBps) + " / " + rateOr(node.NetworkTxBps),
		Load:     "—",
		Services: itoa(len(node.Services)), Reported: age(now, node.ReportedAt)}
	if node.CPU != nil {
		cells.CPU = percent(*node.CPU)
	}
	if node.Load1 != nil {
		cells.Load = formatFloat(*node.Load1, 2)
	}
	if entry.Stale {
		cells.Status, cells.Health = "idle", "stale"
	}
	return cells
}

// regionNodeCells formats one node of region.
func regionNodeCells(region globalview.Region, node globalview.Node, now time.Time) nodeCells {
	return nodeCellsOf(nodeEntry{Region: region.Cell, Stale: region.Stale, Node: node}, now)
}

// regionNodes lists one region's nodes by name.
func regionNodes(region globalview.Region) []nodeEntry {
	return nodeEntries([]globalview.Region{region}, "", "name")
}

func rateOr(value *float64) string {
	if value == nil {
		return "—"
	}
	return rate(*value)
}

// optionalText renders a measurement with its unit, or a dash when it was not measured.
func optionalText(value *float64, unit string) string {
	if value == nil {
		return "—"
	}
	return tenths(*value) + " " + unit
}

// volumeEntry is one volume with the region that reports it.
type volumeEntry struct {
	Region string
	Volume globalview.Volume
}

// volumeEntries lists the volumes of every region, or of region alone, by
// region, node and ID.
func volumeEntries(regions []globalview.Region, region string) []volumeEntry {
	var out []volumeEntry
	for _, listed := range regions {
		if listed.Rollup == nil || region != "" && listed.Cell != region {
			continue
		}
		for _, volume := range listed.Rollup.Volumes {
			out = append(out, volumeEntry{Region: listed.Cell, Volume: volume})
		}
	}
	slices.SortStableFunc(out, func(left, right volumeEntry) int {
		return cmp.Or(cmp.Compare(left.Region, right.Region), cmp.Compare(left.Volume.Node, right.Volume.Node),
			cmp.Compare(left.Volume.ID, right.Volume.ID))
	})
	return out
}

// regionVolumes lists one region's volumes.
func regionVolumes(region globalview.Region) []volumeEntry {
	return volumeEntries([]globalview.Region{region}, "")
}

// nodeVolumes lists the volumes that node holds.
func nodeVolumes(region globalview.Region, node string) []volumeEntry {
	return slices.DeleteFunc(regionVolumes(region), func(entry volumeEntry) bool {
		return entry.Volume.Node != node
	})
}

// roleHolder is a node of a region that runs a role, with the role's state there.
type roleHolder struct {
	Node, State string
}

// roleHolders lists the nodes of region other than except that run role.
func roleHolders(region globalview.Region, role, except string) []roleHolder {
	if region.Rollup == nil {
		return nil
	}
	var out []roleHolder
	for _, node := range region.Rollup.Nodes {
		if service, ok := serviceNamed(node, role); ok && node.Name != except {
			out = append(out, roleHolder{Node: node.Name, State: service.State})
		}
	}
	return out
}

// regionTiles are the region page's stat tiles, from its rollup.
func regionTiles(rollup *globalview.Rollup) []kpi {
	sum := rollup.Totals
	nodes, controllers := "ok", "ok"
	switch {
	case sum.Nodes == 0:
		nodes = "idle"
	case sum.Ready < sum.Nodes:
		nodes = "warn"
	}
	if rollup.Controllers.Ready < rollup.Controllers.Expected {
		controllers = "warn"
	}
	costValue, costSub := "not reported", ""
	if cost := rollup.Cost; cost != nil {
		costValue = strings.TrimSpace(formatFloat(cost.PerHour, 2) + " " + cost.Currency)
		costSub = "month forecast " + formatFloat(cost.MonthForecast, 2)
	}
	cpu := ratio(sum.CPUUsedCores, float64(sum.CPUCores))
	memory := ratio(float64(sum.MemoryUsedBytes), float64(sum.MemoryBytes))
	disk := ratio(float64(sum.DiskUsedBytes), float64(sum.DiskBytes))
	return []kpi{
		{Label: "Nodes ready", Value: itoa(sum.Ready) + " / " + itoa(sum.Nodes), Status: nodes, Href: "#nodes"},
		{Label: "Controllers ready", Value: itoa(rollup.Controllers.Ready) + " / " + itoa(rollup.Controllers.Expected),
			Status: controllers, Href: "#routes"},
		{Label: "CPU used", Value: formatFloat(sum.CPUUsedCores, 1) + " / " + itoa(sum.CPUCores) + " cores",
			Sub: pctOf(sum.CPUUsedCores, float64(sum.CPUCores)) + " used", Status: ratioStatus(cpu), Href: "#nodes"},
		{Label: "Memory used", Value: formatBytes(sum.MemoryUsedBytes) + " / " + formatBytes(sum.MemoryBytes),
			Sub: pctOf(float64(sum.MemoryUsedBytes), float64(sum.MemoryBytes)) + " used", Status: ratioStatus(memory), Href: "#nodes"},
		{Label: "Disk used", Value: formatBytes(sum.DiskUsedBytes) + " / " + formatBytes(sum.DiskBytes),
			Sub: pctOf(float64(sum.DiskUsedBytes), float64(sum.DiskBytes)) + " used", Status: ratioStatus(disk), Href: "#nodes"},
		{Label: "Network", Value: rate(sum.NetworkRxBps) + " rx", Sub: rate(sum.NetworkTxBps) + " tx", Status: "info", Href: "#nodes"},
		{Label: "Load (1m)", Value: formatFloat(sum.Load1, 2), Status: "info", Href: "#nodes"},
		{Label: "Replication lag", Value: optionalText(rollup.Replication.LagSeconds, "s"), Status: "info", Href: "#links"},
		{Label: "Cost per hour", Value: costValue, Sub: costSub, Status: "info", Href: "#health"},
	}
}

// routeCell is one controller route: its round trip and lag, with its error as the title.
func routeCell(route globalview.Route) cell {
	text := "lag " + itoa(route.Lag)
	if route.RTTMillis != nil {
		text = tenths(*route.RTTMillis) + " ms, " + text
	}
	status := "ok"
	if route.Error != "" {
		status = "bad"
	}
	return cell{Text: text, Status: status, Title: route.Error}
}

// regionDatabases lists one region's databases by replication bandwidth. A
// stale region keeps its last-known rows.
func regionDatabases(region globalview.Region) []regionDatabase {
	if region.Rollup == nil {
		return nil
	}
	out := make([]regionDatabase, 0, len(region.Rollup.Databases))
	for _, database := range region.Rollup.Databases {
		out = append(out, regionDatabase{Region: region.Cell, Database: database})
	}
	slices.SortStableFunc(out, func(left, right regionDatabase) int {
		return cmp.Compare(right.ReplicationBytesPerSecond, left.ReplicationBytesPerSecond)
	})
	return out
}

// regionErrors lists one region's errors, newest first.
func regionErrors(region globalview.Region) []regionError {
	if region.Rollup == nil {
		return nil
	}
	out := make([]regionError, 0, len(region.Rollup.Errors))
	for _, failure := range region.Rollup.Errors {
		out = append(out, regionError{Region: region.Cell, Error: failure})
	}
	slices.SortStableFunc(out, func(left, right regionError) int {
		return right.At.Compare(left.At)
	})
	return out
}

// nodeTable lists nodes. Each row links to its region and node.
func nodeTable(current view, entries []nodeEntry) table {
	nodes := table{Caption: "Nodes", Empty: "No nodes to show.",
		Headers: []string{"Region", "Node", "Health", "CPU", "Memory", "Disk", "Network rx / tx", "Load", "Services", "Report age"}}
	for _, entry := range entries {
		row := nodeCellsOf(entry, current.Now)
		nodes.Rows = append(nodes.Rows, []cell{{Text: upper(row.Region), Href: current.State.regionLink(row.Region)},
			{Text: row.Name, Href: current.State.nodeLink(row.Region, row.Name)}, {Text: row.Health, Status: row.Status},
			textCell(row.CPU), textCell(row.Memory), textCell(row.Disk), textCell(row.Network), textCell(row.Load),
			textCell(row.Services), textCell(row.Reported)})
	}
	return nodes
}

// volumeTable lists volumes. Each row links to its region, node and volume.
func volumeTable(current view, entries []volumeEntry) table {
	volumes := table{Caption: "Volumes", Empty: "No volumes to show.",
		Headers: []string{"Volume", "Region", "Node", "State", "Detail", "In state for"}}
	for _, entry := range entries {
		node := textCell(orDash(entry.Volume.Node))
		if entry.Volume.Node != "" {
			node = cell{Text: entry.Volume.Node, Href: current.State.nodeLink(entry.Region, entry.Volume.Node)}
		}
		volumes.Rows = append(volumes.Rows, []cell{
			{Text: entry.Volume.ID, Href: current.State.regionVolumeLink(entry.Region, entry.Volume.ID)},
			{Text: upper(entry.Region), Href: current.State.regionLink(entry.Region)},
			node, textCell(entry.Volume.State), textCell(orDash(entry.Volume.Detail)),
			textCell(age(current.Now, entry.Volume.Since))})
	}
	return volumes
}

// regionVolumeTable is volumeTable for one region; a failed volume read is
// not shown as an empty list.
func regionVolumeTable(current view, region globalview.Region, entries []volumeEntry) table {
	volumes := volumeTable(current, entries)
	if region.Rollup != nil && region.Rollup.VolumesUnavailable {
		volumes.Empty = "This region could not read its volume list."
	}
	return volumes
}

// unreadVolumeRegions lists the regions whose last rollup could not read
// their volumes, for the global volume list.
func unreadVolumeRegions(regions []globalview.Region) []string {
	var out []string
	for _, region := range regions {
		if region.Rollup != nil && region.Rollup.VolumesUnavailable {
			out = append(out, upper(region.Cell))
		}
	}
	return out
}

// filesystemTable lists a node's filesystems with their use.
func filesystemTable(filesystems []globalview.Filesystem) table {
	disks := table{Caption: "Filesystems", Empty: "No filesystem reported.", Headers: []string{"Role", "Used / size", "Used"}}
	for _, fs := range filesystems {
		disks.Rows = append(disks.Rows, []cell{textCell(fs.Role),
			textCell(formatBytes(fs.UsedBytes) + " / " + formatBytes(fs.SizeBytes)),
			textCell(pctOf(float64(fs.UsedBytes), float64(fs.SizeBytes)))})
	}
	return disks
}

// serviceTable lists the services on a node. Each row links to the service.
func serviceTable(current view, region, node string, services []globalview.Service) table {
	roles := table{Caption: "Services on this node", Empty: "No service reported on this node.",
		Headers: []string{"Role", "State", "Digest"}}
	for _, service := range services {
		roles.Rows = append(roles.Rows, []cell{{Text: service.Role, Href: current.State.serviceLink(region, node, service.Role)},
			textCell(orDash(service.State)), textCell(short(orDash(service.Digest), 12))})
	}
	return roles
}

// peerTable lists the other nodes of a region that run role, each linked to its service.
func peerTable(current view, region, role string, peers []roleHolder) table {
	holders := table{Caption: "Other nodes running this role", Empty: "No other node in this region runs it.",
		Headers: []string{"Node", "State"}}
	for _, peer := range peers {
		holders.Rows = append(holders.Rows, []cell{{Text: peer.Node, Href: current.State.serviceLink(region, peer.Node, role)},
			textCell(orDash(peer.State))})
	}
	return holders
}

// regionLinkTable lists a region's links to other regions.
func regionLinkTable(current view, links []globalview.Link) table {
	linked := table{Caption: "Links to other regions", Empty: "No links to other regions reported yet.",
		Headers: []string{"Region", "Reach", "Round trip", "Replication lag", "Error", "Observed"}}
	for _, link := range links {
		linked.Rows = append(linked.Rows, []cell{{Text: upper(link.Region), Href: current.State.regionLink(link.Region)},
			{Text: reachLabel(link.Reach), Status: reachStatus(link.Reach)},
			textCell(optionalText(link.RTTMillis, "ms")), textCell(optionalText(link.LagSeconds, "s")),
			textCell(orDash(link.Error)), textCell(age(current.Now, link.ObservedAt))})
	}
	return linked
}

// routeTable has one row per controller, from it to every controller in
// order. A controller's own cell is "—"; a pair with no route is "·".
func routeTable(routes []globalview.Route) table {
	routing := table{Caption: "Controller routes", Empty: "No controller routes reported yet.", Headers: []string{`From \ To`}}
	var columns []string
	for _, route := range routes {
		columns = append(columns, route.From, route.To)
	}
	slices.Sort(columns)
	columns = slices.Compact(columns)
	routing.Headers = append(routing.Headers, columns...)
	byPair := make(map[[2]string]globalview.Route, len(routes))
	for _, route := range routes {
		byPair[[2]string{route.From, route.To}] = route
	}
	for _, from := range columns {
		row := []cell{textCell(from)}
		for _, to := range columns {
			route, ok := byPair[[2]string{from, to}]
			switch {
			case from == to:
				row = append(row, cell{Text: "—", Status: "idle"})
			case !ok:
				row = append(row, cell{Text: "·", Status: "idle"})
			default:
				row = append(row, routeCell(route))
			}
		}
		routing.Rows = append(routing.Rows, row)
	}
	return routing
}

// scalingTable lists the autoscaled services of a region.
func scalingTable(services []globalview.Scaling) table {
	scaled := table{Caption: "Autoscaled services", Empty: "No service is autoscaled.",
		Headers: []string{"Service", "Replicas", "Goal", "Reason"}}
	for _, scaling := range services {
		scaled.Rows = append(scaled.Rows, []cell{textCell(scaling.Service), textCell(itoa(scaling.Replicas)),
			textCell(itoa(scaling.Goal)), textCell(orDash(scaling.Reason))})
	}
	return scaled
}

// scaleTable lists a region's node scaling status, field by field. Spend rows
// are left out while the region reports no cost.
func scaleTable(current view, scale *nodescale.Status) table {
	scaling := table{Caption: "Node scaling", Empty: "This region runs no node scaler yet.",
		Headers: []string{"Field", "Value"}}
	if scale == nil {
		return scaling
	}
	allowance := itoa(scale.Allowance)
	if !scale.AllowanceFresh {
		allowance += " (stale)"
	}
	inFlight := "no"
	if scale.InFlight != nil {
		inFlight = "yes"
	}
	pressure := percent(scale.Pressure)
	if scale.Signal != "" {
		pressure += " · " + string(scale.Signal)
	}
	rows := [][]cell{
		{textCell("Action"), {Text: string(scale.Action), Status: scaleStatus(*scale)}},
		{textCell("Nodes now"), textCell(itoa(scale.Nodes) + " (" + itoa(scale.QuorumNodes) + " quorum, " + itoa(scale.PoolNodes) + " pool)")},
		{textCell("Want"), textCell(itoa(scale.Want))},
		{textCell("Allowance"), textCell(allowance)},
		{textCell("Pressure"), textCell(pressure)},
		{textCell("Reason"), textCell(orDash(scale.Reason))},
		{textCell("In flight"), textCell(inFlight)},
		{textCell("Last change"), textCell(age(current.Now, scale.LastChange))},
	}
	if scale.NodeMonthlyCents != 0 {
		rows = append(rows, []cell{textCell("Node cost / month"), textCell(strings.TrimSpace(majorUnits(scale.NodeMonthlyCents) + " " + scale.Currency))})
	}
	if scale.ProjectedCents != 0 {
		rows = append(rows, []cell{textCell("Projected"), textCell(strings.TrimSpace(majorUnits(scale.ProjectedCents) + " " + scale.Currency))})
	}
	scaling.Rows = rows
	return scaling
}

// drillLink links a drill-down page. Its path names the region, so the top
// bar's region is not carried.
func (state uiState) drillLink(path string) string { return state.link(path, "r", "") }

func (state uiState) regionLink(cell string) string {
	return state.drillLink(detailPath("/regions/{r}", map[string]string{"r": cell}))
}

func (state uiState) nodeLink(cell, node string) string {
	return state.drillLink(detailPath("/regions/{r}/nodes/{n}", map[string]string{"r": cell, "n": node}))
}

func (state uiState) serviceLink(cell, node, role string) string {
	return state.drillLink(detailPath("/regions/{r}/nodes/{n}/services/{s}",
		map[string]string{"r": cell, "n": node, "s": role}))
}

func (state uiState) regionVolumeLink(cell, id string) string {
	return state.drillLink(detailPath("/regions/{r}/volumes/{v}", map[string]string{"r": cell, "v": id}))
}
