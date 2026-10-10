package ocicost

import (
	"slices"
	"time"
)

// maxViewLines bounds each list a view carries, so 20 regions' views stay
// small in one dashboard fan-out.
const maxViewLines = 16

// View is one region's cost as its summary carries it.
type View struct {
	Cell      string `json:"cell"`
	OCIRegion string `json:"oci_region,omitempty"`
	// Missing says why the region has no report yet; Forecast and the
	// lines are then empty.
	Missing    string   `json:"missing,omitempty"`
	Forecast   Forecast `json:"forecast"`
	Services   []Line   `json:"services,omitempty"`
	Components []Line   `json:"components,omitempty"`
	// UntaggedCents is this month's cost without a component tag.
	UntaggedCents uint64 `json:"untagged_cents"`
}

// Summarize is the view of report at now: its forecast with the region's
// autoscaled hosts.
func Summarize(report Report, now time.Time, hosts []Host) View {
	forecast := Project(report, now, hosts)
	var tagged uint64
	for _, line := range report.Components {
		tagged += line.Cents
	}
	return View{Cell: report.Cell, OCIRegion: report.OCIRegion, Forecast: forecast,
		Services:      fold(report.Services),
		Components:    fold(report.Components),
		UntaggedCents: subtractFloor(forecast.MonthToDateCents, tagged)}
}

// fold keeps the costliest lines and merges the rest into one Other line.
func fold(lines []Line) []Line {
	if len(lines) <= maxViewLines {
		return slices.Clone(lines)
	}
	out := slices.Clone(lines[:maxViewLines-1])
	other := Line{Name: "Other"}
	for _, line := range lines[maxViewLines-1:] {
		other.Cents += line.Cents
	}
	return append(out, other)
}

func subtractFloor(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
