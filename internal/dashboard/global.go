package dashboard

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

// Shared page helpers (KPI tiles, map types, insight and region helpers).

// kpi is one stat tile with an optional sparkline.
type kpi struct {
	Label  string
	Value  string
	Sub    string
	Status string
	Spark  string
	Href   string
}

// globalInsights is this region's open insights, worst first. Rollups carry
// health reasons, not insights, so other regions contribute none.
func (current view) globalInsights() []insights.Insight {
	if current.Evaluation == nil {
		return nil
	}
	merged := slices.Clone(current.Evaluation.Insights)
	insights.Rank(merged)
	return merged
}

func (current view) globalCounts() insights.Counts {
	return insights.Count(current.globalInsights())
}

// filteredInsights applies the insights page's severity and region filters.
func (current view) filteredInsights() []insights.Insight {
	severities := current.State.list("severity")
	regions := current.State.regionFilter()
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
		switch current.decisionCoverage() {
		case coverageMissing:
			spec.Empty = "No decision journal is attached on this member."
		case coverageFailed:
			spec.Empty = "The decision timeline is unavailable right now: the journal query failed."
		case coveragePartial:
			spec.Empty = "No decisions found, but part of the history could not be searched."
		default:
			spec.Empty = "No decisions were recorded since " + formatTime(time.UnixMilli(spec.Start)) + "."
		}
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
