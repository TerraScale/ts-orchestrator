package dashboard

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// hostFilter narrows member series to the host drill-down, if any.
func (current view) hostFilter() map[string]string {
	if host := current.State.param("host"); host != "" {
		return map[string]string{"member": host}
	}
	return nil
}

func (current view) memberChart(metric, unit string, rate bool, empty string) chartSpec {
	return current.lineChart("line", unit, current.historyRange(metric, current.hostFilter(), "member", rate), empty)
}

// filesystemChart charts used ratio per member and filesystem role.
func (current view) filesystemChart() chartSpec {
	series := current.historyRange(observability.HistFSRatio, current.hostFilter(), "member", false)
	labelled := current.Journal != nil && current.Journal.History != nil
	if labelled {
		result := current.Journal.History.Range(observability.HistoryQuery{Metric: observability.HistFSRatio,
			Labels: current.hostFilter(), Start: current.Now.Add(-current.State.Range.Duration), End: current.Now})
		series = series[:0]
		for _, found := range result.Series {
			points := make([][2]float64, 0, len(found.Points))
			for _, point := range found.Points {
				points = append(points, [2]float64{float64(point.Time.UnixMilli()), round(point.Value)})
			}
			series = append(series, chartSeries{Name: found.Labels["member"] + " " + found.Labels["role"], Points: points})
		}
	}
	spec := current.lineChart("line", "percent", series, "No filesystem history yet.")
	spec.Min, spec.Max = float(0), float(1)
	spec.Thresholds = []chartThreshold{{Value: 0.9, Label: "90%", Status: "bad"}}
	return spec
}

func (current view) cpuHeatmap() chartSpec {
	spec := current.heatmap("percent", current.historyRange(observability.HistCPUUtilization, nil, "member", false),
		"No CPU history yet.")
	spec.Min, spec.Max = float(0), float(1)
	return spec
}

// capacityChart stacks used and free memory and disk per member.
func (current view) capacityChart(disk bool) chartSpec {
	spec := chartSpec{Kind: "hbar", Unit: "bytes"}
	used := barSeries{Name: "used", Status: "info"}
	free := barSeries{Name: "free", Status: "idle"}
	for _, member := range current.members() {
		if member.System == nil {
			continue
		}
		var total, available uint64
		if disk {
			for _, filesystem := range member.System.Filesystems {
				total += filesystem.SizeBytes
				available += min(filesystem.AvailBytes, filesystem.SizeBytes)
			}
		} else {
			total, available = member.System.MemTotalBytes, min(member.System.MemAvailBytes, member.System.MemTotalBytes)
		}
		if total == 0 {
			continue
		}
		spec.Categories = append(spec.Categories, member.Member)
		used.Values = append(used.Values, float64(total-available))
		free.Values = append(free.Values, float64(available))
	}
	spec.Bars = []barSeries{used, free}
	if len(spec.Categories) == 0 {
		spec.Empty = "No member reported its system view."
	}
	return spec
}

// natsRateChart sums a counter's per-second rate over members.
func (current view) natsRateChart(inMetric, outMetric, unit string) chartSpec {
	var series []chartSeries
	if in := sumSeries("in", current.historyRange(inMetric, nil, "member", true)); in != nil {
		series = append(series, in...)
	}
	if out := sumSeries("out", current.historyRange(outMetric, nil, "member", true)); out != nil {
		series = append(series, out...)
	}
	return current.lineChart("area", unit, series, "No NATS traffic history yet.")
}

// stageChart stacks TerraBase seats by stage over time.
func (current view) stageChart() chartSpec {
	series := current.historyRange(observability.HistStageMembers, nil, "stage", false)
	for index := range series {
		series[index].Status = stageStatus(series[index].Name)
	}
	return current.lineChart("stacked", "count", series, "No seat stage history yet.")
}

func (current view) seatsChart() chartSpec {
	desired := current.historyRange(observability.HistSeatsDesired, nil, "", false)
	serving := current.historyRange(observability.HistSeatsServing, nil, "", false)
	var series []chartSeries
	if len(desired) > 0 {
		desired[0].Name, desired[0].Dashed, desired[0].Status = "desired", true, "idle"
		series = append(series, desired[0])
	}
	if len(serving) > 0 {
		serving[0].Name, serving[0].Status = "serving", "ok"
		series = append(series, serving[0])
	}
	spec := current.lineChart("line", "count", series, "No seat history yet.")
	spec.Min = float(0)
	return spec
}

// forecast is one filesystem's growth projection.
type forecast struct {
	Name   string
	Used   float64
	Full   time.Duration
	Known  bool
	Status string
}

// storageForecasts projects time to full per member filesystem from the
// trend over the selected range (at least an hour of points).
func (current view) storageForecasts() ([]forecast, chartSpec) {
	if current.Journal == nil || current.Journal.History == nil {
		return nil, chartSpec{Kind: "line", Empty: "No storage history yet."}
	}
	window := max(current.State.Range.Duration, 24*time.Hour)
	result := current.Journal.History.Range(observability.HistoryQuery{Metric: observability.HistFSRatio,
		Start: current.Now.Add(-window), End: current.Now})
	var forecasts []forecast
	var series []chartSeries
	for _, found := range result.Series {
		points := make([][2]float64, 0, len(found.Points))
		for _, point := range found.Points {
			points = append(points, [2]float64{float64(point.Time.UnixMilli()), round(point.Value)})
		}
		if len(points) == 0 {
			continue
		}
		name := found.Labels["member"] + " " + found.Labels["role"]
		entry := forecast{Name: name, Used: points[len(points)-1][1], Status: "ok"}
		entry.Full, entry.Known = timeToFull(points)
		switch {
		case entry.Known && entry.Full < 72*time.Hour:
			entry.Status = "bad"
		case entry.Known && entry.Full < 14*24*time.Hour:
			entry.Status = "warn"
		}
		forecasts = append(forecasts, entry)
		one := chartSeries{Name: name, Points: points}
		if entry.Status != "ok" {
			one.Status = entry.Status
			series = append(series, one)
			if slope, last, ok := linearForecast(points); ok && slope > 0 {
				end := points[len(points)-1][0]
				horizon := min(entry.Full.Seconds(), 72*3600)
				series = append(series, chartSeries{Name: name + " forecast", Status: entry.Status, Dashed: true,
					Points: [][2]float64{{end, round(last)}, {end + horizon*1000, round(min(last+slope*horizon, 1))}}})
			}
		}
	}
	slices.SortFunc(forecasts, func(left, right forecast) int {
		if left.Known != right.Known {
			if left.Known {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(left.Full, right.Full), cmp.Compare(left.Name, right.Name))
	})
	spec := chartSpec{Kind: "line", Unit: "percent", Series: series, Min: float(0), Max: float(1),
		Start:      current.Now.Add(-window).UnixMilli(),
		Thresholds: []chartThreshold{{Value: 1, Label: "full", Status: "bad"}}}
	if len(series) == 0 {
		spec.Empty = "Every filesystem has more than 14 days of headroom at its current growth."
	}
	return forecasts, spec
}

func forecastText(entry forecast) string {
	switch {
	case !entry.Known:
		return "not growing"
	case entry.Full == 0:
		return "full"
	default:
		return formatDuration(entry.Full)
	}
}

// filesystemTree sizes every member filesystem for the capacity treemap.
func (current view) filesystemTree() chartSpec {
	spec := chartSpec{Kind: "treemap", Unit: "bytes"}
	for _, member := range current.members() {
		if member.System == nil {
			continue
		}
		node := treeNode{Name: member.Member, Href: current.State.link("/members", "host", member.Member)}
		for _, filesystem := range member.System.Filesystems {
			used := filesystemUsed(filesystem)
			node.Children = append(node.Children, treeNode{Name: filesystem.Role, Value: float64(filesystem.SizeBytes),
				Status: ratioStatus(used)})
			node.Value += float64(filesystem.SizeBytes)
		}
		if len(node.Children) > 0 {
			spec.Tree = append(spec.Tree, node)
		}
	}
	if len(spec.Tree) == 0 {
		spec.Empty = "No filesystem was observed."
	}
	return spec
}

func volumeStatus(volume insights.Volume, now time.Time) string {
	switch volume.State {
	case "attached":
		return "ok"
	case "available":
		return "idle"
	case "attaching", "detaching":
		if now.Sub(volume.StateSince) > 15*time.Minute {
			return "bad"
		}
		return "run"
	default:
		return "warn"
	}
}

// volumeCounts tallies volumes by state.
func (current view) volumeCounts() string {
	states := map[string]int{}
	for _, volume := range current.Volumes {
		states[volume.State]++
	}
	return counts(states)
}

// ociOperationChart charts per-operation rates of a counter.
func (current view) ociOperationChart(metric, unit, empty string) chartSpec {
	series := current.historyRange(metric, nil, "operation", true)
	for index := range series {
		series[index].Name = shortOperation(series[index].Name)
	}
	return current.lineChart("line", unit, series, empty)
}

// ociLatencyChart divides seconds by calls per operation: the mean latency.
func (current view) ociLatencyChart() chartSpec {
	seconds := current.historyRange(observability.HistOCISeconds, nil, "operation", true)
	calls := current.historyRange(observability.HistOCICalls, nil, "operation", true)
	byName := map[string]chartSeries{}
	for _, one := range calls {
		byName[one.Name] = one
	}
	var series []chartSeries
	for _, one := range seconds {
		if mean := divideSeries(shortOperation(one.Name), []chartSeries{one}, []chartSeries{byName[one.Name]}); mean != nil {
			series = append(series, mean...)
		}
	}
	return current.lineChart("line", "seconds", series, "No OCI latency history yet.")
}

func shortOperation(operation string) string {
	if service, rest, ok := strings.Cut(operation, " "); ok && len(rest) > 0 {
		return service + " " + rest
	}
	return operation
}

func driftStatus(drift string) string {
	switch drift {
	case "in_sync":
		return "ok"
	case "drifted":
		return "warn"
	case "missing":
		return "bad"
	default:
		return "idle"
	}
}

// inventoryCounts tallies inventory items by kind.
func (current view) inventoryCounts() []string {
	counts := map[string]int{}
	for _, item := range current.Inventory {
		counts[item.Kind]++
	}
	var out []string
	for _, kind := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, kind+" "+itoa(counts[kind]))
	}
	return out
}

// rolloutPhases are the phase diagram's steps.
var rolloutPhases = []string{"canary", "soak", "batch-1", "batch-2", "batch-3", "complete"}

func phaseStatus(rollout insights.Rollout, phase string, now time.Time) string {
	current := slices.Index(rolloutPhases, rollout.Phase)
	index := slices.Index(rolloutPhases, phase)
	switch {
	case rollout.Phase == "rolled_back":
		return "serious"
	case rollout.Done || rollout.Phase == "complete":
		return "ok"
	case rollout.Phase == "held" && index == 0:
		return "warn"
	case current < 0:
		return "idle"
	case index < current:
		return "ok"
	case index == current:
		if !rollout.PhaseDeadline.IsZero() && now.After(rollout.PhaseDeadline) {
			return "warn"
		}
		return "run"
	default:
		return "idle"
	}
}

func rolloutStatus(rollout insights.Rollout, now time.Time) string {
	switch {
	case rollout.Phase == "rolled_back":
		return "serious"
	case rollout.Done || rollout.Phase == "complete":
		return "ok"
	case rollout.Phase == "held":
		return "warn"
	case !rollout.PhaseDeadline.IsZero() && now.After(rollout.PhaseDeadline):
		return "warn"
	default:
		return "run"
	}
}

// seatsByDatabase returns each database's seats for the seat grid.
func seatTitle(member observability.MemberView) string {
	return member.SeatID + ": " + member.Stage + " on " + orDash(member.HostNode) + " (" + orDash(member.FailureDomain) + ")"
}

var stageLegend = []string{"serving", "awaiting-healthy", "cordoned", "drained", "terminated"}
