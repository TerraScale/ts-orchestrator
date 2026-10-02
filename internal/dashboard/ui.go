package dashboard

import (
	"encoding/json"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// The status color system. Every state maps to one token: ok, warn,
// serious, bad, info, run (in progress) or idle (unknown, pending, off).
// Templates render s-<token> classes; the chart elements read the same
// tokens, so a state has one color everywhere.

func regionStatus(status regionview.Status) string {
	switch status {
	case regionview.StatusHealthy:
		return "ok"
	case regionview.StatusDegraded:
		return "warn"
	case regionview.StatusCritical:
		return "bad"
	default:
		return "idle"
	}
}

func reachStatus(reach string) string {
	switch reach {
	case decisionlog.RegionOK:
		return "ok"
	case decisionlog.RegionUnreachable, decisionlog.RegionError:
		return "bad"
	default:
		return "idle"
	}
}

func reachLabel(reach string) string {
	switch reach {
	case decisionlog.RegionOK:
		return "linked"
	case decisionlog.RegionNotLinked:
		return "not linked yet"
	case decisionlog.RegionUnreachable:
		return "unreachable"
	case decisionlog.RegionError:
		return "error"
	default:
		return orDash(reach)
	}
}

func severityStatus(severity insights.Severity) string {
	switch severity {
	case insights.SeverityCritical:
		return "bad"
	case insights.SeverityWarning:
		return "warn"
	default:
		return "info"
	}
}

func decisionStatus(status decisionlog.Status) string {
	switch status {
	case decisionlog.StatusSucceeded:
		return "ok"
	case decisionlog.StatusInProgress:
		return "run"
	case decisionlog.StatusFailed:
		return "bad"
	case decisionlog.StatusRolledBack:
		return "serious"
	default:
		return "idle"
	}
}

func statusLabel(status decisionlog.Status) string {
	return strings.ReplaceAll(string(status), "_", " ")
}

// stageStatus colors a TerraBase seat stage.
func stageStatus(stage string) string {
	switch {
	case stage == "serving":
		return "ok"
	case strings.HasPrefix(stage, "awaiting-") || strings.HasPrefix(stage, "prepared-"):
		return "run"
	case stage == "cordoned" || stage == "draining" || stage == "remove-candidate":
		return "warn"
	case stage == "drained" || stage == "storage-handled":
		return "serious"
	default:
		return "idle"
	}
}

func boolStatus(value bool) string {
	if value {
		return "ok"
	}
	return "bad"
}

func ratioStatus(value float64) string { return ratioClass(value) }

func countsStatus(counts insights.Counts) string {
	switch {
	case counts.Critical > 0:
		return "bad"
	case counts.Warning > 0:
		return "warn"
	case counts.Info > 0:
		return "info"
	default:
		return "ok"
	}
}

func sClass(token string) string { return "s-" + token }

func kindLabel(kind decisionlog.Kind) string {
	return strings.ReplaceAll(string(kind), "_", " ")
}

func upper(value string) string { return strings.ToUpper(value) }

func rfc3339(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// attention returns the open insight counts for the badge.
func (current view) attention() insights.Counts {
	if current.Evaluation == nil {
		return insights.Counts{}
	}
	return current.Evaluation.Counts
}

func (current view) attentionTitle() string {
	counts := current.attention()
	if counts.Total() == 0 {
		return "Nothing needs attention"
	}
	return itoa(counts.Critical) + " critical, " + itoa(counts.Warning) + " warning, " + itoa(counts.Info) + " info"
}

// switcherRegion is one entry of the region switcher.
type switcherRegion struct {
	ID     string
	Status string
	Local  bool
}

// switcher lists the regions for the top bar: every summarized region, or
// this member's alone.
func (current view) switcher() []switcherRegion {
	if len(current.Regions) == 0 {
		return []switcherRegion{{ID: current.localRegion(), Status: boolStatus(current.Ready), Local: true}}
	}
	out := make([]switcherRegion, 0, len(current.Regions))
	for _, summary := range current.Regions {
		status := regionStatus(summary.Health.Status)
		if summary.Reach != decisionlog.RegionOK && !summary.Local {
			status = reachStatus(summary.Reach)
		}
		out = append(out, switcherRegion{ID: summary.Region, Status: status, Local: summary.Local})
	}
	return out
}

// switchLink keeps the current page when it can show the region, and goes
// to the region overview from the global page.
func (current view) switchLink(region string) string {
	target := current.Page.href()
	if current.Page.slug == "" {
		target = "/region"
	}
	return current.State.link(target, "r", region)
}

func (current view) selectedRegion(region string) bool {
	return current.Page.slug != "" && current.region() == region
}

// paletteItem is one command palette entry.
type paletteItem struct {
	Label  string `json:"label"`
	Group  string `json:"group"`
	Href   string `json:"href,omitempty"`
	Action string `json:"action,omitempty"`
}

func (current view) paletteJSON() string {
	var items []paletteItem
	for _, entry := range pages {
		items = append(items, paletteItem{Label: entry.title, Group: "Page", Href: current.State.link(entry.href())})
	}
	for _, region := range current.switcher() {
		items = append(items, paletteItem{Label: "Region " + upper(region.ID), Group: "Region",
			Href: current.State.link("/region", "r", region.ID)})
	}
	for _, choice := range timeRanges {
		items = append(items, paletteItem{Label: "Time range " + choice.Key, Group: "Range",
			Href: current.State.keep(current.Page.href(), "range", choice.Key)})
	}
	live := "Pause live updates"
	liveValue := "0"
	if !current.State.Live {
		live, liveValue = "Resume live updates", "1"
	}
	items = append(items,
		paletteItem{Label: live, Group: "Action", Href: current.State.keep(current.Page.href(), "live", liveValue)},
		paletteItem{Label: "Toggle dark / light theme", Group: "Action", Action: "theme"},
		paletteItem{Label: "Toggle browser notifications for new insights", Group: "Action", Action: "notify"},
		paletteItem{Label: "Decisions: rollbacks", Group: "Search", Href: current.State.link("/decisions", "kind", "rollback")},
		paletteItem{Label: "Decisions: holds", Group: "Search", Href: current.State.link("/decisions", "kind", "held")},
		paletteItem{Label: "Events: warnings and errors", Group: "Search", Href: current.State.link("/events", "level", "warn")},
	)
	if current.Evaluation != nil {
		for _, insight := range current.Evaluation.Insights {
			items = append(items, paletteItem{Label: insight.Title, Group: "Insight " + string(insight.Severity),
				Href: current.State.link("/insights", "id", insight.Key)})
		}
	}
	data, _ := json.Marshal(items)
	return string(data)
}

// regionGeo places the product regions on the world map. A region that is
// not listed is drawn without a position.
var regionGeo = map[string]struct {
	Name     string
	Lon, Lat float64
}{
	"gru": {Name: "São Paulo", Lon: -46.47, Lat: -23.43},
	"sfo": {Name: "San Jose", Lon: -121.89, Lat: 37.34},
	"fra": {Name: "Frankfurt", Lon: 8.68, Lat: 50.11},
}

// chartLabel is a chart's accessible name: its series, or its empty state.
func chartLabel(spec chartSpec) string {
	if spec.Empty != "" {
		return spec.Empty
	}
	names := make([]string, 0, len(spec.Series)+len(spec.Bars))
	for _, series := range spec.Series {
		names = append(names, series.Name)
	}
	for _, bars := range spec.Bars {
		names = append(names, bars.Name)
	}
	if len(names) == 0 {
		return spec.Kind + " chart"
	}
	return spec.Kind + " chart of " + joinWords(names)
}

// joinWords renders "a", "a and b" or "a, b and c".
func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	default:
		return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
	}
}

func regionName(region string) string {
	if geo, ok := regionGeo[region]; ok {
		return geo.Name
	}
	return ""
}
