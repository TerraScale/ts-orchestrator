package dashboard

import (
	"cmp"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// overviewTop bounds the merged database and error lists.
const overviewTop = 10

// overviewPeers bounds the peer regions a database row lists in its cell.
const overviewPeers = 3

// freshRegion reports a rollup inside its freshness window. Totals and merged
// lists sum only fresh regions; stale ones show last-known values in the table.
func freshRegion(region globalview.Region) bool { return region.Rollup != nil && !region.Stale }

// globalTotals is what the fresh regions add up to.
type globalTotals struct {
	Regions, Fresh, Stale, NoData int
	Nodes, Ready                  int
	CPUCores                      int
	CPUUsed                       float64
	MemoryBytes, MemoryUsed       uint64
	DiskBytes, DiskUsed           uint64
	RxBps, TxBps                  float64
	Costed                        int
	Currency                      string
	PerHour, MonthForecast        float64
}

func totalsOf(regions []globalview.Region) globalTotals {
	totals := globalTotals{Regions: len(regions)}
	for _, region := range regions {
		switch {
		case region.Rollup == nil:
			totals.NoData++
			continue
		case region.Stale:
			totals.Stale++
			continue
		}
		totals.Fresh++
		sum := region.Rollup.Totals
		totals.Nodes += sum.Nodes
		totals.Ready += sum.Ready
		totals.CPUCores += sum.CPUCores
		totals.CPUUsed += sum.CPUUsedCores
		totals.MemoryBytes += sum.MemoryBytes
		totals.MemoryUsed += sum.MemoryUsedBytes
		totals.DiskBytes += sum.DiskBytes
		totals.DiskUsed += sum.DiskUsedBytes
		totals.RxBps += sum.NetworkRxBps
		totals.TxBps += sum.NetworkTxBps
		if cost := region.Rollup.Cost; cost != nil {
			totals.Costed++
			totals.Currency = cmp.Or(totals.Currency, cost.Currency)
			totals.PerHour += cost.PerHour
			totals.MonthForecast += cost.MonthForecast
		}
	}
	return totals
}

// overviewTiles are the overview's stat tiles over every region.
func overviewTiles(regions []globalview.Region) []kpi {
	totals := totalsOf(regions)
	status := "ok"
	switch {
	case totals.Fresh == 0:
		status = "bad"
	case totals.Fresh < totals.Regions:
		status = "warn"
	}
	nodes := "ok"
	switch {
	case totals.Nodes == 0:
		nodes = "idle"
	case totals.Ready < totals.Nodes:
		nodes = "warn"
	}
	return []kpi{
		{Label: "Regions", Value: itoa(totals.Regions), Sub: itoa(totals.Stale) + " stale · " + itoa(totals.NoData) + " no data",
			Status: status, Href: "#regions"},
		{Label: "Nodes ready", Value: itoa(totals.Ready) + " / " + itoa(totals.Nodes), Sub: "fresh regions",
			Status: nodes, Href: "#regions"},
		{Label: "CPU used", Value: formatFloat(totals.CPUUsed, 1) + " / " + itoa(totals.CPUCores) + " cores",
			Sub:    pctOf(totals.CPUUsed, float64(totals.CPUCores)) + " used",
			Status: ratioStatus(ratio(totals.CPUUsed, float64(totals.CPUCores))), Href: "#regions"},
		{Label: "Memory used", Value: formatBytes(totals.MemoryUsed) + " / " + formatBytes(totals.MemoryBytes),
			Sub:    pctOf(float64(totals.MemoryUsed), float64(totals.MemoryBytes)) + " used",
			Status: ratioStatus(ratio(float64(totals.MemoryUsed), float64(totals.MemoryBytes))), Href: "#regions"},
		{Label: "Disk used", Value: formatBytes(totals.DiskUsed) + " / " + formatBytes(totals.DiskBytes),
			Sub:    pctOf(float64(totals.DiskUsed), float64(totals.DiskBytes)) + " used",
			Status: ratioStatus(ratio(float64(totals.DiskUsed), float64(totals.DiskBytes))), Href: "#regions"},
		{Label: "Network", Value: rate(totals.RxBps) + " rx", Sub: rate(totals.TxBps) + " tx", Status: "info", Href: "#regions"},
		{Label: "Cost per hour", Value: costValue(totals.PerHour, totals), Sub: costSub(totals), Status: "info", Href: "#regions"},
		{Label: "Month forecast", Value: costValue(totals.MonthForecast, totals), Sub: costSub(totals), Status: "info", Href: "#regions"},
	}
}

func costValue(amount float64, totals globalTotals) string {
	if totals.Costed == 0 {
		return "not reported"
	}
	return strings.TrimSpace(formatFloat(amount, 2) + " " + totals.Currency)
}

func costSub(totals globalTotals) string {
	return itoa(totals.Costed) + " of " + itoa(totals.Fresh) + " fresh regions report cost"
}

func pctOf(used, total float64) string {
	if total <= 0 {
		return "—"
	}
	return percent(ratio(used, total))
}

func rate(bytes float64) string { return formatBytes(int64(bytes)) + "/s" }

// tenths renders a number with at most one decimal.
func tenths(value float64) string {
	return strconv.FormatFloat(math.Round(value*10)/10, 'f', -1, 64)
}

// regionCells is one row of the overview's region table, already formatted.
type regionCells struct {
	Health, HealthLabel, Reasons string
	Stale                        string
	Nodes, Controllers           string
	CPU, Memory, Disk            string
	Network, Load, Lag, Cost     string
	Scaling, ScalingStatus       string
	ScalingTitle                 string
}

// regionCellsOf formats one region for the table. A region without a rollup
// shows dashes; a stale one keeps its last-known values with a stale badge.
func regionCellsOf(region globalview.Region, now time.Time) regionCells {
	cells := regionCells{Health: "idle", HealthLabel: "no data", Nodes: "—", Controllers: "—", CPU: "—",
		Memory: "—", Disk: "—", Network: "—", Load: "—", Lag: "—", Cost: "—", Scaling: "—"}
	rollup := region.Rollup
	if rollup == nil {
		return cells
	}
	cells.Health, cells.HealthLabel = "idle", rollup.Health.Status
	cells.Reasons = strings.Join(rollup.Health.Reasons, "; ")
	if !region.Stale {
		cells.Health = regionStatus(regionview.Status(rollup.Health.Status))
	} else {
		cells.HealthLabel = "unknown"
		cells.Stale = "stale · last seen " + formatDuration(now.Sub(rollup.ObservedAt).Round(time.Second)) + " ago"
	}
	sum := rollup.Totals
	cells.Nodes = itoa(sum.Ready) + " / " + itoa(sum.Nodes)
	cells.Controllers = itoa(rollup.Controllers.Ready) + " / " + itoa(rollup.Controllers.Expected)
	cells.CPU = pctOf(sum.CPUUsedCores, float64(sum.CPUCores))
	cells.Memory = pctOf(float64(sum.MemoryUsedBytes), float64(sum.MemoryBytes))
	cells.Disk = pctOf(float64(sum.DiskUsedBytes), float64(sum.DiskBytes))
	cells.Network = rate(sum.NetworkRxBps) + " / " + rate(sum.NetworkTxBps)
	cells.Load = formatFloat(sum.Load1, 2)
	if rollup.Replication.LagSeconds != nil {
		cells.Lag = tenths(*rollup.Replication.LagSeconds) + " s"
	}
	if cost := rollup.Cost; cost != nil {
		cells.Cost = strings.TrimSpace(formatFloat(cost.PerHour, 2) + " " + cost.Currency)
	}
	atGoal, services := scalingAtGoal(rollup.Autoscale)
	goal := ""
	if services > 0 {
		goal = itoa(atGoal) + " / " + itoa(services) + " at goal"
	}
	if scale := rollup.Scale; scale != nil {
		cells.Scaling, cells.ScalingStatus, cells.ScalingTitle = scaleCell(*scale, goal)
	} else if goal != "" {
		cells.Scaling = goal
	}
	return cells
}

// scaleCell formats the node scaler's action as nodes now and nodes wanted.
// Its title is the reason, plus whether a change is in flight and the services
// at goal.
func scaleCell(scale nodescale.Status, goal string) (text, status, title string) {
	switch scale.Action {
	case nodescale.Up:
		text = itoa(scale.Nodes) + " → " + itoa(scale.Want) + " ↑"
	case nodescale.Down:
		text = itoa(scale.Nodes) + " → " + itoa(scale.Want) + " ↓"
	default:
		text = itoa(scale.Nodes) + " nodes"
	}
	title = scale.Reason
	if scale.InFlight != nil {
		title += " · in flight"
	}
	if goal != "" {
		title += " · " + goal
	}
	return text, scaleStatus(scale), title
}

// scaleStatus colors the node scaler: a region capped by its allowance warns
// whatever it is doing, a change runs, and any other hold is ok.
func scaleStatus(scale nodescale.Status) string {
	switch {
	case scale.Saturated:
		return "warn"
	case scale.Action == nodescale.Up || scale.Action == nodescale.Down:
		return "run"
	default:
		return "ok"
	}
}

// regionTable is the overview's region table. The region name links to its
// page; a stale region keeps its last-known values behind a stale badge.
func regionTable(current view) table {
	regions := table{Caption: "Regions", Empty: "No region has reported to the global view yet.",
		Headers: []string{"Region", "Health", "Nodes ready", "Controllers", "CPU", "Memory", "Disk", "Network rx / tx", "Load", "Replication lag", "Cost / h", "Scaling"}}
	for _, region := range current.Global {
		cells := regionCellsOf(region, current.Now)
		health := cell{Text: cells.HealthLabel, Status: cells.Health, Title: cells.Reasons}
		if cells.Stale != "" {
			health.Extra = statusPill("idle", cells.Stale)
		}
		regions.Rows = append(regions.Rows, []cell{{Text: upper(region.Cell), Href: "/regions/" + region.Cell}, health,
			textCell(cells.Nodes), textCell(cells.Controllers), textCell(cells.CPU), textCell(cells.Memory),
			textCell(cells.Disk), textCell(cells.Network), textCell(cells.Load), textCell(cells.Lag),
			textCell(cells.Cost), {Text: cells.Scaling, Status: cells.ScalingStatus, Title: cells.ScalingTitle}})
	}
	return regions
}

// scalingAtGoal counts the autoscaled services already at their goal.
func scalingAtGoal(autoscale globalview.Autoscale) (atGoal, services int) {
	for _, scaling := range autoscale.Services {
		services++
		if scaling.Replicas == scaling.Goal {
			atGoal++
		}
	}
	return atGoal, services
}

// linkMatrix has one row per region, from it to every region in order. A
// region's own cell is "—"; a link it has no entry for is "·".
func linkMatrix(regions []globalview.Region) table {
	matrix := table{Caption: "Links between regions", Headers: []string{`From \ To`}, Empty: "No region has reported links yet."}
	for _, region := range regions {
		matrix.Headers = append(matrix.Headers, upper(region.Cell))
	}
	for _, from := range regions {
		row := []cell{textCell(upper(from.Cell))}
		for _, to := range regions {
			if from.Cell == to.Cell {
				row = append(row, cell{Text: "—", Status: "idle"})
				continue
			}
			link, ok := linkTo(from, to.Cell)
			if !ok {
				row = append(row, cell{Text: "·", Status: "idle"})
				continue
			}
			title := linkText(link)
			if link.Error != "" {
				title += " · " + link.Error
			}
			row = append(row, cell{Text: linkRTT(link), Status: reachStatus(link.Reach), Title: title})
		}
		matrix.Rows = append(matrix.Rows, row)
	}
	return matrix
}

// linkTo is the region's link entry for cell, if its rollup holds one.
func linkTo(region globalview.Region, cell string) (globalview.Link, bool) {
	if region.Rollup == nil {
		return globalview.Link{}, false
	}
	for _, link := range region.Rollup.Links {
		if link.Region == cell {
			return link, true
		}
	}
	return globalview.Link{}, false
}

// linkRTT is a link's round trip in whole milliseconds, or its reach when it
// has none.
func linkRTT(link globalview.Link) string {
	if link.RTTMillis == nil {
		return reachLabel(link.Reach)
	}
	return strconv.Itoa(int(math.Round(*link.RTTMillis)))
}

// linkText is a link's round trip and replication lag, or its reach.
func linkText(link globalview.Link) string {
	var parts []string
	if link.RTTMillis != nil {
		parts = append(parts, tenths(*link.RTTMillis)+" ms")
	}
	if link.LagSeconds != nil {
		parts = append(parts, "lag "+tenths(*link.LagSeconds)+" s")
	}
	if len(parts) == 0 {
		return reachLabel(link.Reach)
	}
	return strings.Join(parts, ", ")
}

// linkDetail is what the map labels a link with: its error when it has one.
func linkDetail(link globalview.Link) string {
	if link.Error != "" {
		return link.Error
	}
	return linkText(link)
}

// reachRank orders reach states so the worst one is largest.
func reachRank(reach string) int {
	switch reachStatus(reach) {
	case "bad":
		return 2
	case "idle":
		return 1
	default:
		return 0
	}
}

// worstLink picks the link between two regions. When both regions report
// one, the worse direction wins; it names the direction it came from.
func worstLink(left, right globalview.Region) (link globalview.Link, from, to string, ok bool) {
	forward, hasForward := linkTo(left, right.Cell)
	backward, hasBackward := linkTo(right, left.Cell)
	switch {
	case hasForward && hasBackward && reachRank(backward.Reach) > reachRank(forward.Reach):
		return backward, right.Cell, left.Cell, true
	case hasForward:
		return forward, left.Cell, right.Cell, true
	case hasBackward:
		return backward, right.Cell, left.Cell, true
	}
	return globalview.Link{}, "", "", false
}

// globalMapJSON places every region the geo catalog knows on the world map,
// with the links between them.
func globalMapJSON(current view) string {
	placed := slices.DeleteFunc(slices.Clone(current.Global), func(region globalview.Region) bool {
		_, ok := regionGeo(region.Cell)
		return !ok
	})
	spec := mapSpec{}
	for _, region := range placed {
		geo, _ := regionGeo(region.Cell)
		cells := regionCellsOf(region, current.Now)
		score := 0
		if sum := region.Rollup; sum != nil && sum.Totals.Nodes > 0 {
			score = sum.Totals.Ready * 100 / sum.Totals.Nodes
		}
		spec.Regions = append(spec.Regions, mapRegion{ID: region.Cell, Name: upper(region.Cell), Lon: geo.Lon,
			Lat: geo.Lat, Status: cells.Health, Score: score, Detail: geo.Name + " · " + cells.Nodes + " nodes ready",
			Current: region.Cell == current.localRegion(), Href: "/regions/" + region.Cell})
	}
	for left := range placed {
		for right := left + 1; right < len(placed); right++ {
			link, from, to, ok := worstLink(placed[left], placed[right])
			if !ok {
				continue
			}
			spec.Links = append(spec.Links, mapLink{From: from, To: to, State: reachStatus(link.Reach),
				Label: upper(from) + " → " + upper(to) + " " + linkDetail(link)})
		}
	}
	data, _ := json.Marshal(spec)
	return string(data)
}

// regionDatabase is one database with the region that reports it.
type regionDatabase struct {
	Region string
	globalview.Database
}

// topDatabases lists the fresh regions' databases by replication bandwidth.
func topDatabases(regions []globalview.Region) []regionDatabase {
	var out []regionDatabase
	for _, region := range regions {
		if !freshRegion(region) {
			continue
		}
		for _, database := range region.Rollup.Databases {
			out = append(out, regionDatabase{Region: region.Cell, Database: database})
		}
	}
	slices.SortStableFunc(out, func(left, right regionDatabase) int {
		return cmp.Compare(right.ReplicationBytesPerSecond, left.ReplicationBytesPerSecond)
	})
	return out[:min(overviewTop, len(out))]
}

// databaseTable renders the top databases by replication bandwidth. Catalog
// IDs are shortened in the cell; the full ID is its tooltip.
func databaseTable(rows []regionDatabase) table {
	databases := table{Caption: "Top databases by replication bandwidth", Empty: "No region reports database replication yet.",
		Headers: []string{"Region", "Database", "Project", "Replication out", "Replication in", "Top peers (out / in)", "Storage", "Ops/s (reads / writes)", "Lag"}}
	for _, row := range rows {
		databases.Rows = append(databases.Rows, []cell{textCell(upper(row.Region)),
			{Text: orDash(shortID(row.ID)), Title: row.ID}, {Text: orDash(shortID(row.Project)), Title: row.Project},
			textCell(rate(row.SentBytesPerSecond)), textCell(rate(row.ReceivedBytesPerSecond)), peersCell(row.Peers),
			textCell(storageText(row.StorageBytes)), textCell(tenths(row.ReadsPerSecond) + " / " + tenths(row.WritesPerSecond)),
			textCell(tenths(row.LagSeconds) + " s")})
	}
	return databases
}

// peersCell lists the busiest peers of a database. The tooltip lists them all.
func peersCell(peers []globalview.DatabasePeer) cell {
	var all []string
	for _, peer := range peers {
		all = append(all, upper(peer.Region)+" "+rate(peer.SentBytesPerSecond)+" / "+rate(peer.ReceivedBytesPerSecond))
	}
	return cell{Text: orDash(strings.Join(all[:min(len(all), overviewPeers)], ", ")), Title: strings.Join(all, "\n")}
}

// storageText renders a replica size; zero is unknown.
func storageText(bytes int64) string {
	if bytes == 0 {
		return "—"
	}
	return formatBytes(bytes)
}

// shortID is the first twelve characters of a catalog ID.
func shortID(id string) string {
	return id[:min(12, len(id))]
}

// regionError is one error with the region that reports it.
type regionError struct {
	Region string
	globalview.Error
}

// recentErrors lists the fresh regions' errors, newest first.
func recentErrors(regions []globalview.Region) []regionError {
	var out []regionError
	for _, region := range regions {
		if !freshRegion(region) {
			continue
		}
		for _, failure := range region.Rollup.Errors {
			out = append(out, regionError{Region: region.Cell, Error: failure})
		}
	}
	slices.SortStableFunc(out, func(left, right regionError) int {
		return right.At.Compare(left.At)
	})
	return out[:min(overviewTop, len(out))]
}

// errorTable renders the recent errors, newest first.
func errorTable(rows []regionError) table {
	errors := table{Caption: "Recent errors, newest first", Empty: "No recent errors.",
		Headers: []string{"Time", "Region", "Level", "Service", "Component", "Message", "Count", "Nodes"}}
	for _, row := range rows {
		errors.Rows = append(errors.Rows, []cell{{Extra: ago(row.At)}, textCell(upper(row.Region)),
			{Text: row.Level, Status: levelStatus(row.Level)}, textCell(orDash(row.Service)),
			textCell(orDash(row.Component)), textCell(row.Message), textCell(itoa(row.Count)),
			textCell(orDash(strings.Join(row.Nodes, ", ")))})
	}
	return errors
}

// levelStatus maps a log level to its status pill.
func levelStatus(level string) string {
	switch level {
	case "ERROR":
		return "bad"
	case "WARN":
		return "warn"
	}
	return ""
}
