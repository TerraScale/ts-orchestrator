package dashboard

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const metricHistoryPointLimit = 1200

func validMetricName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for index, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character == '_' || character == ':' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

// loadMetrics keeps registry scrapes and history queries out of template rendering.
func (current *view) loadMetrics(ctx context.Context) {
	if current.Page.slug != "metric-catalog" || current.Journal == nil || current.Journal.Metrics == nil {
		return
	}
	catalog, err := current.Journal.Metrics.Catalog(ctx)
	if err != nil {
		current.Unavailable = append(current.Unavailable, "metric catalog")
		return
	}
	current.MetricCatalog = &catalog
	if metric := current.selectedMetric(); metric != nil {
		history, err := current.Journal.Metrics.History(ctx, observability.HistoryQuery{
			Metric: metric.Name, Start: current.Now.Add(-current.State.Range.Duration), End: current.Now,
			MaxSeries: 32,
		})
		if err != nil {
			current.Unavailable = append(current.Unavailable, "metric history")
			return
		}
		// Keep the newest observations without downsampling across gaps.
		limit := metricHistoryPointLimit / max(len(history.Series), 1)
		for index := range history.Series {
			points := history.Series[index].Points
			if len(points) > limit {
				history.Series[index].Points = points[len(points)-limit:]
				current.MetricHistoryLimited = true
			}
		}
		current.MetricHistory = &history
	}
}

func (current view) selectedMetric() *observability.CatalogMetric {
	if current.MetricCatalog == nil {
		return nil
	}
	for index := range current.MetricCatalog.Metrics {
		if current.MetricCatalog.Metrics[index].Name == current.State.param("metric") {
			return &current.MetricCatalog.Metrics[index]
		}
	}
	return nil
}

func (current view) metricCatalogTable() table {
	listing := table{Caption: "Searchable local metric catalog",
		Headers: []string{"Metric", "Description", "Type / unit", "Source", "State", "History"},
		Empty:   "No metric families match this search."}
	if current.MetricCatalog == nil {
		return listing
	}
	needle := strings.ToLower(current.State.param("q"))
	for _, metric := range current.MetricCatalog.Metrics {
		text := strings.Join([]string{metric.Name, metric.Description, metric.Unit, metric.Type, metric.Source,
			strings.Join(metric.Labels, " "), metric.State, metric.HistoryState}, " ")
		if !strings.Contains(strings.ToLower(text), needle) {
			continue
		}
		listing.Rows = append(listing.Rows, []cell{
			{Text: metric.Name, Href: current.State.keep("/metric-catalog", "metric", metric.Name)},
			textCell(metricMetadata(metric.Description)),
			textCell(metricMetadata(metric.Type) + " / " + metricMetadata(metric.Unit)),
			textCell(metricMetadata(metric.Source)), textCell(metricMetadata(metric.State)),
			textCell(metricMetadata(metric.HistoryState)),
		})
	}
	return listing
}

func metricMetadata(value string) string { return cmp.Or(value, "unsupported") }

func metricDimensions(labels []string) string {
	if len(labels) == 0 {
		return "none reported"
	}
	return strings.Join(labels, ", ")
}

func metricObserved(at time.Time) string {
	if at.IsZero() {
		return "unsupported: collection timestamp unavailable"
	}
	return at.UTC().Format(time.RFC3339Nano)
}

func metricRetention(metric observability.CatalogMetric) string {
	if metric.HistoryRetentionSeconds <= 0 {
		return "unsupported: retention unavailable"
	}
	return (time.Duration(metric.HistoryRetentionSeconds) * time.Second).String()
}

func metricSamplesTable(metric observability.CatalogMetric) table {
	listing := table{Caption: metric.Name + " current samples", Headers: []string{"Sample", "Value", "Label dimensions"},
		Empty: "Missing: no current sample reported. Missing values are not zero."}
	for _, sample := range metric.Samples {
		listing.Rows = append(listing.Rows, []cell{textCell(sample.Name), textCell(sample.Value),
			textCell(metricDimensions(sample.Labels))})
	}
	return listing
}

func metricSeriesName(series observability.HistorySeries) string {
	parts := []string{series.Metric}
	for _, name := range slices.Sorted(maps.Keys(series.Labels)) {
		parts = append(parts, name+"="+series.Labels[name])
	}
	return strings.Join(parts, " ")
}

func (current view) metricInterval() time.Duration {
	if current.MetricHistory != nil && current.MetricHistory.IntervalSeconds > 0 {
		return time.Duration(current.MetricHistory.IntervalSeconds * float64(time.Second))
	}
	return observability.DefaultHistoryInterval
}

func metricStep(tier string, interval time.Duration) time.Duration {
	switch tier {
	case observability.Tier1m:
		return time.Minute
	case observability.Tier5m:
		return 5 * time.Minute
	case observability.Tier1h:
		return time.Hour
	default:
		return interval
	}
}

// metricGap detects missing intervals and partially observed rollup buckets.
func metricGap(series observability.HistorySeries, index int, interval time.Duration) bool {
	point := series.Points[index]
	step := metricStep(series.Tier, interval)
	if index > 0 && point.Time.Sub(series.Points[index-1].Time) > 2*step {
		return true
	}
	return metricPartial(series, index, interval)
}

func metricPartial(series observability.HistorySeries, index int, interval time.Duration) bool {
	point := series.Points[index]
	if series.Tier != observability.TierRaw && point.Samples > 0 {
		return time.Duration(point.Samples)*interval < metricStep(series.Tier, interval)
	}
	return false
}

// metricHistoryChart splits lines at gaps instead of connecting missing observations.
func (current view) metricHistoryChart(metric observability.CatalogMetric) chartSpec {
	spec := current.lineChart("line", metric.Unit, nil, "Missing: no retained samples in this time range.")
	if current.MetricHistory == nil {
		return spec
	}
	for _, series := range current.MetricHistory.Series {
		segment := chartSeries{Name: metricSeriesName(series)}
		flush := func() {
			if len(segment.Points) > 0 {
				spec.Series = append(spec.Series, segment)
				segment.Points = nil
			}
		}
		for index, point := range series.Points {
			if math.IsNaN(point.Value) || math.IsInf(point.Value, 0) {
				flush()
				continue
			}
			if metricGap(series, index, current.metricInterval()) || index > 0 && metricPartial(series, index-1, current.metricInterval()) {
				flush()
			}
			segment.Points = append(segment.Points, [2]float64{float64(point.Time.UnixMilli()), point.Value})
		}
		flush()
	}
	if len(spec.Series) > 0 {
		spec.Empty = ""
	}
	return spec
}

// metricHistoryTable is a bounded text alternative to all charted observations.
func (current view) metricHistoryTable() table {
	listing := table{Caption: "Retained metric observations", Headers: []string{"Series", "Timestamp (UTC)", "Value", "Resolution", "Coverage", "Events"},
		Empty: "No retained samples in this time range."}
	if current.MetricHistory == nil {
		return listing
	}
	for _, series := range current.MetricHistory.Series {
		for index, point := range series.Points {
			coverage := "observed"
			if metricGap(series, index, current.metricInterval()) {
				coverage = "gap / partial observation"
			}
			listing.Rows = append(listing.Rows, []cell{textCell(metricSeriesName(series)),
				textCell(metricObserved(point.Time)), textCell(strconv.FormatFloat(point.Value, 'g', -1, 64)),
				textCell(series.Tier), textCell(coverage),
				{Text: "Events at this time", Href: current.State.link("/events", "at", point.Time.UTC().Format(time.RFC3339))},
			})
		}
	}
	return listing
}

func (current view) metricHistoryWarnings() []string {
	if current.MetricHistory == nil {
		return nil
	}
	history := current.MetricHistory
	var warnings []string
	if history.Reason != "" {
		warnings = append(warnings, history.Reason)
	}
	if history.Truncated {
		warnings = append(warnings, "Truncated: more series exist than this query can show.")
	}
	if current.MetricHistoryLimited {
		warnings = append(warnings, "Truncated display: only the newest observations are shown within the 1,200-point page budget. Older retained observations remain queryable through the history API.")
	}
	if history.Incomplete {
		warnings = append(warnings, "Regional metric history is incomplete: some retained measurements are unavailable.")
	}
	if history.Pending {
		warnings = append(warnings, "Regional metric history is loading.")
	}
	gaps := 0
	stale := false
	for _, series := range history.Series {
		stale = stale || series.Stale
		for index := range series.Points {
			if metricGap(series, index, current.metricInterval()) {
				gaps++
			}
		}
	}
	if gaps > 0 {
		warnings = append(warnings, fmt.Sprintf("Gaps / partial observations: %d. Chart lines break at these observations; missing values are not zero.", gaps))
	}
	if stale && history.State != "stale" {
		warnings = append(warnings, "Stale: the latest retained samples predate the requested range end.")
	}
	return warnings
}
