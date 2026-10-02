package dashboard

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// kpi is one stat tile with an optional sparkline.
type kpi struct {
	Label  string
	Value  string
	Sub    string
	Status string
	Spark  string
	Href   string
}

// globalKPIs are the landing page's tiles. Cross-region totals come from the
// region summaries; sparklines from this region's metric history.
func (current view) globalKPIs() []kpi {
	var tiles []kpi
	regions := current.Regions
	healthy, observed := 0, 0
	answering, expected := 0, 0
	databases, serving, desired, rollouts := 0, 0, 0, 0
	var diskUsed, diskTotal uint64
	for _, summary := range regions {
		if summary.Reach == decisionlog.RegionOK {
			observed++
		}
		if summary.Health.Status == regionview.StatusHealthy {
			healthy++
		}
		answering += summary.Quorum.Answering
		expected += summary.Quorum.Expected
		databases += summary.TerraBase.Databases
		serving += summary.TerraBase.ServingSeats
		desired += summary.TerraBase.DesiredSeats
		rollouts += len(summary.Rollouts)
		diskUsed += summary.Capacity.DiskUsedBytes
		diskTotal += summary.Capacity.DiskBytes
	}
	if len(regions) > 0 {
		status := "ok"
		if healthy < len(regions) {
			status = "warn"
		}
		if observed < len(regions) {
			status = "bad"
		}
		tiles = append(tiles, kpi{Label: "Regions healthy", Value: itoa(healthy) + " / " + itoa(len(regions)),
			Sub: itoa(observed) + " observed", Status: status, Href: current.State.link("/")})
	}
	members := current.historyRange(observability.HistMembersAnswering, nil, "", false)
	if expected > 0 {
		status := "ok"
		if answering < expected {
			status = "warn"
		}
		tiles = append(tiles, kpi{Label: "Controllers up", Value: itoa(answering) + " / " + itoa(expected),
			Sub: "across all regions", Status: status, Spark: sparkValues(members),
			Href: current.State.link("/topology")})
	} else if len(current.members()) > 0 {
		tiles = append(tiles, kpi{Label: "Members up", Value: itoa(len(current.members())),
			Sub: itoa(len(current.missing())) + " missing", Status: boolStatus(len(current.missing()) == 0),
			Spark: sparkValues(members), Href: current.State.link("/members")})
	}
	if leader := current.metaLeader(); leader != "" {
		sub := "JetStream meta leader"
		if lease := current.authority(); lease != nil {
			sub = "authority " + orDash(lease.OwnerID) + " · epoch " + itoa(lease.Epoch)
		}
		tiles = append(tiles, kpi{Label: "Meta leader · " + upper(current.localRegion()), Value: leader, Sub: sub,
			Status: "ok", Href: current.State.link("/nats")})
	}
	if reporter := current.natsReporter(); reporter != nil {
		degraded := 0
		for _, stream := range reporter.NATS.Streams {
			if stream.OfflinePeers > 0 {
				degraded++
			}
		}
		status := "ok"
		if degraded > 0 {
			status = "warn"
		}
		tiles = append(tiles, kpi{Label: "JetStream · " + upper(current.localRegion()),
			Value: itoa(len(reporter.NATS.Streams)-degraded) + " / " + itoa(len(reporter.NATS.Streams)) + " healthy",
			Sub:   percent(storeUsed(reporter.NATS)) + " store used", Status: status,
			Spark: sparkValues(sumSeries("store", current.historyRange(observability.HistJSStoreUsed, nil, "member", false))),
			Href:  current.State.link("/nats")})
	}
	if len(regions) > 0 || current.placement() != nil {
		if len(regions) == 0 {
			placement := current.placement()
			databases = len(placement.Databases)
			for _, database := range placement.Databases {
				serving += database.Serving
				desired += database.DesiredSeats
			}
		}
		tiles = append(tiles, kpi{Label: "TerraBase instances", Value: itoa(databases),
			Sub: itoa(serving) + " / " + itoa(desired) + " seats serving", Status: boolStatus(serving >= desired),
			Spark: sparkValues(current.historyRange(observability.HistSeatsServing, nil, "", false)),
			Href:  current.State.link("/terrabase")})
		tiles = append(tiles, kpi{Label: "Open rollouts", Value: itoa(rollouts), Sub: "managed updates in flight",
			Status: "info", Spark: sparkValues(current.historyRange(observability.HistRolloutProgress, nil, "", false)),
			Href: current.State.link("/rollouts")})
	}
	calls := sumSeries("calls", current.historyRange(observability.HistOCICalls, nil, "operation", true))
	errors := sumSeries("errors", current.historyRange(observability.HistOCIErrors, nil, "operation", true))
	if rate := divideSeries("error rate", errors, calls); rate != nil {
		value, _ := lastValue(rate)
		tiles = append(tiles, kpi{Label: "OCI error rate · " + upper(current.localRegion()), Value: percent(value),
			Sub: "of API calls", Status: ratioStatus(min(value*10, 1)), Spark: sparkValues(rate),
			Href: current.State.link("/oci")})
	}
	if diskTotal > 0 {
		used := float64(diskUsed) / float64(diskTotal)
		tiles = append(tiles, kpi{Label: "Storage used", Value: percent(used),
			Sub: formatBytes(diskUsed) + " of " + formatBytes(diskTotal), Status: ratioStatus(used),
			Spark: sparkValues(sumSeries("disk", current.historyRange(observability.HistFSUsed, nil, "member", false))),
			Href:  current.State.link("/storage")})
	}
	counts := current.globalCounts()
	tiles = append(tiles, kpi{Label: "Needs attention", Value: itoa(counts.Total()),
		Sub: itoa(counts.Critical) + " critical · " + itoa(counts.Warning) + " warning", Status: countsStatus(counts),
		Href: current.State.link("/insights")})
	return tiles
}

// globalInsights merges this region's full evaluation with the top
// insights other regions report in their summaries, worst first.
func (current view) globalInsights() []insights.Insight {
	var merged []insights.Insight
	seen := map[string]bool{}
	add := func(insight insights.Insight) {
		key := insight.Region + "|" + insight.Key
		if !seen[key] {
			seen[key] = true
			merged = append(merged, insight)
		}
	}
	if current.Evaluation != nil {
		for _, insight := range current.Evaluation.Insights {
			add(insight)
		}
	}
	for _, summary := range current.Regions {
		if summary.Local && current.Evaluation != nil {
			continue
		}
		for _, insight := range summary.Insights {
			if insight.Region == "" {
				insight.Region = summary.Region
			}
			add(insight)
		}
	}
	insights.Rank(merged)
	return merged
}

func (current view) globalCounts() insights.Counts {
	counts := insights.Count(current.globalInsights())
	// Remote summaries carry only their top insights; their counts are
	// complete.
	for _, summary := range current.Regions {
		if summary.Local && current.Evaluation != nil {
			continue
		}
		if summary.Counts.Total() > len(summary.Insights) {
			listed := insights.Count(summary.Insights)
			counts.Critical += summary.Counts.Critical - listed.Critical
			counts.Warning += summary.Counts.Warning - listed.Warning
			counts.Info += summary.Counts.Info - listed.Info
		}
	}
	return counts
}

// filteredInsights applies the insights page's severity and region filters.
func (current view) filteredInsights() []insights.Insight {
	severities := current.State.list("severity")
	regions := current.State.list("region")
	var out []insights.Insight
	for _, insight := range current.globalInsights() {
		if len(severities) > 0 && !slices.Contains(severities, string(insight.Severity)) {
			continue
		}
		if len(regions) > 0 && !slices.Contains(regions, insight.Region) {
			continue
		}
		out = append(out, insight)
	}
	return out
}

func (current view) regionInsights(region string) []insights.Insight {
	var out []insights.Insight
	for _, insight := range current.globalInsights() {
		if insight.Region == region {
			out = append(out, insight)
		}
	}
	return out
}

// selectedSummary is the selected region's summary, if summarized.
func (current view) selectedSummary() *regionview.Summary {
	for index := range current.Regions {
		if current.Regions[index].Region == current.region() {
			return &current.Regions[index]
		}
	}
	return nil
}

// mapSpec is the <ts-map> data.
type mapSpec struct {
	Regions []mapRegion `json:"regions"`
	Links   []mapLink   `json:"links"`
}

type mapRegion struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Lon     float64 `json:"lon"`
	Lat     float64 `json:"lat"`
	Status  string  `json:"status"`
	Score   int     `json:"score"`
	Href    string  `json:"href"`
	Detail  string  `json:"detail"`
	Current bool    `json:"current,omitempty"`
}

type mapLink struct {
	From  string `json:"from"`
	To    string `json:"to"`
	State string `json:"state"`
	Label string `json:"label"`
}

func (current view) mapJSON() string {
	spec := mapSpec{}
	reach := map[string]string{}
	local := ""
	for _, summary := range current.Regions {
		geo, ok := regionGeo(summary.Region)
		if !ok {
			continue
		}
		if summary.Local {
			local = summary.Region
		}
		reach[summary.Region] = summary.Reach
		status := regionStatus(summary.Health.Status)
		detail := fmt.Sprintf("%s · quorum %d/%d · %d TerraBase · %s", geo.Name, summary.Quorum.Answering,
			summary.Quorum.Expected, summary.TerraBase.Databases, reachLabel(summary.Reach))
		spec.Regions = append(spec.Regions, mapRegion{ID: summary.Region, Name: upper(summary.Region), Lon: geo.Lon,
			Lat: geo.Lat, Status: status, Score: summary.Health.Score, Detail: detail, Current: summary.Local,
			Href: current.State.link("/region", "r", summary.Region)})
	}
	for left := range spec.Regions {
		for right := left + 1; right < len(spec.Regions); right++ {
			from, to := spec.Regions[left].ID, spec.Regions[right].ID
			state := "idle"
			label := upper(from) + " ↔ " + upper(to)
			switch {
			case from == local:
				state = reachStatus(reach[to])
				label += ": " + reachLabel(reach[to])
			case to == local:
				state = reachStatus(reach[from])
				label += ": " + reachLabel(reach[from])
			case reach[from] == decisionlog.RegionOK && reach[to] == decisionlog.RegionOK:
				state = "ok"
				label += ": both answer"
			default:
				label += ": not observed from here"
			}
			spec.Links = append(spec.Links, mapLink{From: from, To: to, State: state, Label: label})
		}
	}
	data, _ := json.Marshal(spec)
	return string(data)
}

// decisionTimeline turns decisions into timeline marks, one lane per region
// (or per actor when one region is shown).
func (current view) decisionTimeline(decisions []decisionlog.Decision, byActor bool) chartSpec {
	spec := chartSpec{Kind: "timeline", Start: current.Now.Add(-current.State.Range.Duration).UnixMilli(),
		End: current.Now.UnixMilli()}
	lanes := map[string]bool{}
	for _, decision := range decisions {
		lane := upper(decision.Region)
		if byActor {
			lane = decision.Actor.Slice
		}
		lanes[lane] = true
		spec.Items = append(spec.Items, timelineItem{Time: decision.Time.UnixMilli(), Lane: lane,
			Label: decision.Summary, Status: decisionStatus(decision.Status),
			Detail: kindLabel(decision.Kind) + " · " + decision.Actor.Slice + " · " + statusLabel(decision.Status),
			Href:   current.State.link("/decisions", "id", decision.ID)})
		if decision.Time.UnixMilli() < spec.Start {
			spec.Start = decision.Time.UnixMilli()
		}
	}
	spec.Lanes = slices.Sorted(func(yield func(string) bool) {
		for lane := range lanes {
			if !yield(lane) {
				return
			}
		}
	})
	if len(spec.Items) == 0 {
		spec.Empty = "No decisions were recorded in this time range."
	}
	return spec
}

// ringDash renders a health score as an SVG stroke-dasharray.
func ringDash(score int) string {
	circumference := 2 * math.Pi * 26
	filled := circumference * float64(max(0, min(score, 100))) / 100
	return strconv.FormatFloat(filled, 'f', 1, 64) + " " + strconv.FormatFloat(circumference, 'f', 1, 64)
}

func versionsText(summary regionview.Summary) string {
	parts := make([]string, 0, len(summary.Versions))
	for _, version := range summary.Versions {
		parts = append(parts, short(version.Version, 14)+" ×"+itoa(len(version.Members)))
	}
	return orDash(strings.Join(parts, ", "))
}

func capacityRatio(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return ratio(float64(used), float64(total))
}

func storeRatio(capacity regionview.Capacity) float64 {
	if capacity.StoreLimitBytes <= 0 {
		return 0
	}
	return ratio(float64(capacity.StoreUsedBytes), float64(capacity.StoreLimitBytes))
}
