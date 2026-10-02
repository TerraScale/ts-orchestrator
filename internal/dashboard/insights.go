package dashboard

import (
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
)

// insightChart charts the insight's most telling evidence: the first
// charted evidence with a threshold, else the first charted one.
func (current view) insightChart(insight insights.Insight) (chartSpec, bool) {
	var fallback *chartSpec
	for _, evidence := range insight.Evidence {
		spec, ok := current.evidenceChart(insight, evidence)
		if !ok {
			continue
		}
		if evidence.Threshold != nil {
			return spec, true
		}
		if fallback == nil {
			fallback = &spec
		}
	}
	if fallback == nil {
		return chartSpec{}, false
	}
	return *fallback, true
}

// evidenceChart charts an evidence metric over the view's range with its
// threshold, when the metric is in the history store.
func (current view) evidenceChart(insight insights.Insight, evidence insights.Evidence) (chartSpec, bool) {
	if evidence.Metric == "" || insight.Region != current.localRegion() {
		return chartSpec{}, false
	}
	nameBy := "member"
	for name := range evidence.Labels {
		nameBy = name
		break
	}
	series := current.historyRange(evidence.Metric, evidence.Labels, nameBy, false)
	if len(series) == 0 {
		return chartSpec{}, false
	}
	unit := "count"
	switch evidence.Unit {
	case "ratio", "percent":
		unit = "percent"
	case "bytes":
		unit = "bytes"
	case "seconds", "s":
		unit = "seconds"
	}
	spec := current.lineChart("area", unit, series, "")
	spec.Series = spec.Series[:min(len(spec.Series), 4)]
	for index := range spec.Series {
		spec.Series[index].Status = severityStatus(insight.Severity)
	}
	if evidence.Threshold != nil {
		spec.Thresholds = []chartThreshold{{Value: *evidence.Threshold, Label: "threshold " + evidenceThreshold(evidence),
			Status: severityStatus(insight.Severity)}}
	}
	return spec, true
}

func evidenceValue(evidence insights.Evidence) string {
	if evidence.Text != "" {
		return evidence.Text
	}
	return formatUnit(evidence.Value, evidence.Unit)
}

func evidenceThreshold(evidence insights.Evidence) string {
	if evidence.Threshold == nil {
		return ""
	}
	return evidence.Comparison + " " + formatUnit(*evidence.Threshold, evidence.Unit)
}

// formatUnit renders a value in an evidence or signal unit.
func formatUnit(value float64, unit string) string {
	switch unit {
	case "ratio":
		return percent(value)
	case "percent", "%":
		return formatFloat(value, 1) + "%"
	case "bytes":
		return formatBytes(int64(value))
	case "seconds", "s":
		return formatSeconds(value)
	case "bytes/h", "bytes/s":
		return formatBytes(int64(value)) + unit[len("bytes"):]
	case "":
		return formatFloat(value, decimalsFor(value))
	default:
		return formatFloat(value, decimalsFor(value)) + " " + unit
	}
}

func decimalsFor(value float64) int {
	if value == float64(int64(value)) {
		return 0
	}
	if value < 10 && value > -10 {
		return 2
	}
	return 1
}

// insightChanges lists the engine's recent transitions in the view's range,
// newest first.
func (current view) insightChanges() []insights.Change {
	if current.Journal == nil || current.Journal.Insights == nil {
		return nil
	}
	changes := current.Journal.Insights.Changes(current.Now.Add(-current.State.Range.Duration))
	slices.Reverse(changes)
	return changes[:min(len(changes), 30)]
}

func changeStatus(change insights.Change) string {
	if change.Type == insights.ChangeResolved {
		return "ok"
	}
	return severityStatus(change.Insight.Severity)
}

// insightRegions lists the regions that have insights, for the filter.
func (current view) insightRegions() []string {
	seen := map[string]bool{}
	var regions []string
	for _, summary := range current.Regions {
		if !seen[summary.Region] {
			seen[summary.Region] = true
			regions = append(regions, summary.Region)
		}
	}
	for _, insight := range current.globalInsights() {
		if !seen[insight.Region] {
			seen[insight.Region] = true
			regions = append(regions, insight.Region)
		}
	}
	return regions
}

// foreign returns region when it is not this member's, so a link into that
// region's entity selects it.
func (current view) foreign(region string) string {
	if region == current.localRegion() {
		return ""
	}
	return region
}

var severityNames = []string{string(insights.SeverityCritical), string(insights.SeverityWarning),
	string(insights.SeverityInfo)}
