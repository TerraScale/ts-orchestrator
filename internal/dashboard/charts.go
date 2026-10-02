package dashboard

import (
	"cmp"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// chartSpec is the compact JSON a <ts-chart> element turns into an ECharts
// option. The server decides what to draw; the element only renders, so a
// Datastar patch that changes the data-spec attribute redraws the chart.
type chartSpec struct {
	// Kind is line, area, stacked, bar, hbar, heatmap, gauge, treemap or
	// timeline.
	Kind string `json:"kind"`
	// Unit formats axis labels and tooltips: percent (0..1), bytes,
	// bytes_rate, rate, seconds, count or score.
	Unit   string        `json:"unit,omitempty"`
	Series []chartSeries `json:"series,omitempty"`
	// Categories are bar categories or heatmap rows.
	Categories []string `json:"categories,omitempty"`
	// Heat cells are [time ms, row index, value].
	Heat [][3]float64 `json:"heat,omitempty"`
	// Bars are values per category per series for bar charts.
	Bars []barSeries `json:"bars,omitempty"`
	// Min and Max pin the value axis.
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
	// Thresholds draw horizontal lines.
	Thresholds []chartThreshold `json:"thresholds,omitempty"`
	// Tree is a treemap's nodes.
	Tree []treeNode `json:"tree,omitempty"`
	// Items are timeline marks; Lanes are their rows.
	Items []timelineItem `json:"items,omitempty"`
	Lanes []string       `json:"lanes,omitempty"`
	// Value and Label are a gauge's reading.
	Value float64 `json:"value,omitempty"`
	Label string  `json:"label,omitempty"`
	// Start and End bound the time axis in ms.
	Start int64 `json:"start,omitempty"`
	End   int64 `json:"end,omitempty"`
	// Click is a link prefix; a clicked time point appends its RFC 3339
	// time, a clicked timeline item opens its own href.
	Click string `json:"click,omitempty"`
	// Empty is shown instead of a chart when there is nothing to draw.
	Empty string `json:"empty,omitempty"`
}

type chartSeries struct {
	Name string `json:"name"`
	// Points are [time ms, value].
	Points [][2]float64 `json:"points"`
	// Status colors the series with a status token (ok, warn, bad, info).
	Status string `json:"status,omitempty"`
	// Dashed draws a forecast or reference line.
	Dashed bool `json:"dashed,omitempty"`
}

type barSeries struct {
	Name   string    `json:"name"`
	Values []float64 `json:"values"`
	Status string    `json:"status,omitempty"`
}

type chartThreshold struct {
	Value  float64 `json:"value"`
	Label  string  `json:"label"`
	Status string  `json:"status,omitempty"`
}

type treeNode struct {
	Name     string     `json:"name"`
	Value    float64    `json:"value"`
	Status   string     `json:"status,omitempty"`
	Href     string     `json:"href,omitempty"`
	Children []treeNode `json:"children,omitempty"`
}

type timelineItem struct {
	Time   int64  `json:"t"`
	Lane   string `json:"lane"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Status string `json:"status,omitempty"`
	Href   string `json:"href,omitempty"`
}

// JSON renders the spec for a data-spec attribute.
func (spec chartSpec) JSON() string {
	data, err := json.Marshal(spec)
	if err != nil {
		return `{"kind":"line","empty":"chart unavailable"}`
	}
	return string(data)
}

func float(value float64) *float64 { return &value }

// historyRange reads every series of metric matching labels over the view's
// range and names each series by the label nameBy. A missing store or no
// data returns nil.
func (current view) historyRange(metric string, labels map[string]string, nameBy string, rate bool) []chartSeries {
	if current.Journal == nil || current.Journal.History == nil {
		return nil
	}
	result := current.Journal.History.Range(observability.HistoryQuery{Metric: metric, Labels: labels,
		Start: current.Now.Add(-current.State.Range.Duration), End: current.Now, Rate: rate, MaxSeries: 64})
	series := make([]chartSeries, 0, len(result.Series))
	for _, found := range result.Series {
		if len(found.Points) == 0 {
			continue
		}
		name := found.Labels[nameBy]
		if name == "" {
			name = metric
		}
		points := make([][2]float64, 0, len(found.Points))
		for _, point := range found.Points {
			if math.IsNaN(point.Value) || math.IsInf(point.Value, 0) {
				continue
			}
			points = append(points, [2]float64{float64(point.Time.UnixMilli()), round(point.Value)})
		}
		series = append(series, chartSeries{Name: name, Points: points})
	}
	slices.SortFunc(series, func(left, right chartSeries) int { return cmp.Compare(left.Name, right.Name) })
	return series
}

// sumSeries adds series point by point on their shared timestamps.
func sumSeries(name string, series []chartSeries) []chartSeries {
	if len(series) == 0 {
		return nil
	}
	totals := map[float64]float64{}
	for _, one := range series {
		for _, point := range one.Points {
			totals[point[0]] += point[1]
		}
	}
	points := make([][2]float64, 0, len(totals))
	for _, at := range slices.Sorted(maps.Keys(totals)) {
		points = append(points, [2]float64{at, round(totals[at])})
	}
	return []chartSeries{{Name: name, Points: points}}
}

// divideSeries divides numerator by denominator on shared timestamps.
func divideSeries(name string, numerator, denominator []chartSeries) []chartSeries {
	if len(numerator) == 0 || len(denominator) == 0 {
		return nil
	}
	below := map[float64]float64{}
	for _, point := range denominator[0].Points {
		below[point[0]] = point[1]
	}
	var points [][2]float64
	for _, point := range numerator[0].Points {
		if divisor := below[point[0]]; divisor > 0 {
			points = append(points, [2]float64{point[0], round(point[1] / divisor)})
		}
	}
	if len(points) == 0 {
		return nil
	}
	return []chartSeries{{Name: name, Points: points}}
}

// sparkValues returns the values of the first series for a sparkline.
func sparkValues(series []chartSeries) string {
	if len(series) == 0 {
		return ""
	}
	points := series[0].Points
	// A sparkline needs no more than about 60 points.
	step := max(1, len(points)/60)
	parts := make([]string, 0, len(points)/step+1)
	for index := 0; index < len(points); index += step {
		parts = append(parts, formatFloat(points[index][1], 4))
	}
	return strings.Join(parts, ",")
}

// lastValue returns the newest value of the first series.
func lastValue(series []chartSeries) (float64, bool) {
	if len(series) == 0 || len(series[0].Points) == 0 {
		return 0, false
	}
	points := series[0].Points
	return points[len(points)-1][1], true
}

// lineChart builds a time-series chart over the view's range.
func (current view) lineChart(kind, unit string, series []chartSeries, empty string) chartSpec {
	spec := chartSpec{Kind: kind, Unit: unit, Series: series, Start: current.Now.Add(-current.State.Range.Duration).UnixMilli(),
		End: current.Now.UnixMilli(), Click: current.State.link("/events") + eventsAtSeparator(current.State.link("/events"))}
	if len(series) == 0 {
		spec.Empty = empty
	}
	return spec
}

func eventsAtSeparator(link string) string {
	if strings.Contains(link, "?") {
		return "&at="
	}
	return "?at="
}

// heatmap builds a rows x time heatmap from per-row series.
func (current view) heatmap(unit string, series []chartSeries, empty string) chartSpec {
	spec := chartSpec{Kind: "heatmap", Unit: unit, Start: current.Now.Add(-current.State.Range.Duration).UnixMilli(),
		End: current.Now.UnixMilli()}
	for row, one := range series {
		spec.Categories = append(spec.Categories, one.Name)
		step := max(1, len(one.Points)/120)
		for index := 0; index < len(one.Points); index += step {
			spec.Heat = append(spec.Heat, [3]float64{one.Points[index][0], float64(row), one.Points[index][1]})
		}
	}
	if len(spec.Heat) == 0 {
		spec.Empty = empty
	}
	return spec
}

// linearForecast fits value = a + b*t over the points by least squares and
// returns the slope per second and the intercept at the last point.
func linearForecast(points [][2]float64) (slope, last float64, ok bool) {
	if len(points) < 3 {
		return 0, 0, false
	}
	var sumT, sumV, sumTT, sumTV float64
	origin := points[0][0]
	for _, point := range points {
		t := (point[0] - origin) / 1000
		sumT += t
		sumV += point[1]
		sumTT += t * t
		sumTV += t * point[1]
	}
	count := float64(len(points))
	denominator := count*sumTT - sumT*sumT
	if denominator == 0 {
		return 0, 0, false
	}
	slope = (count*sumTV - sumT*sumV) / denominator
	intercept := (sumV - slope*sumT) / count
	lastT := (points[len(points)-1][0] - origin) / 1000
	return slope, intercept + slope*lastT, true
}

// timeToFull projects when a used ratio reaches 1 from its trend.
func timeToFull(points [][2]float64) (time.Duration, bool) {
	slope, last, ok := linearForecast(points)
	if !ok || slope <= 0 || last >= 1 {
		return 0, ok && last >= 1
	}
	seconds := (1 - last) / slope
	if seconds > 365*24*3600 {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

func round(value float64) float64 {
	if value == 0 || math.Abs(value) >= 1e6 {
		return math.Round(value)
	}
	scale := math.Pow(10, 4-math.Ceil(math.Log10(math.Abs(value))))
	if scale > 1e9 {
		scale = 1e9
	}
	return math.Round(value*scale) / scale
}
