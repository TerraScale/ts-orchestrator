package dashboard

import (
	"encoding/json"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
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

// attention returns the open insight counts across every region for the
// badge.
func (current view) attention() insights.Counts {
	if current.Evaluation == nil && len(current.Global) == 0 {
		return insights.Counts{}
	}
	return current.globalCounts()
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

// switcher lists every region of the global view, or this member's alone
// before the view has a region.
func (current view) switcher() []switcherRegion {
	if len(current.Global) == 0 {
		return []switcherRegion{{ID: current.localRegion(), Status: boolStatus(current.Ready), Local: true}}
	}
	out := make([]switcherRegion, 0, len(current.Global))
	for _, region := range current.Global {
		out = append(out, switcherRegion{ID: region.Cell, Status: regionCellsOf(region, current.Now).Health,
			Local: region.Cell == current.localRegion()})
	}
	return out
}

// scope is what the region switcher's selection means on a page.
type scope int

const (
	// scopeRegional pages show the selected region (r).
	scopeRegional scope = iota
	// scopeFiltered pages list every region and narrow by their own region
	// filter, which defaults to the selected region.
	scopeFiltered
	// scopeGlobal pages always show every region.
	scopeGlobal
	// scopeLocal pages show this member's live state only.
	scopeLocal
	// scopeEntity pages show one entity of the region their path names;
	// the switcher goes to another region's overview.
	scopeEntity
)

func (page page) scope() scope {
	switch page.slug {
	case "region", "nats", "terrabase", "storage":
		return scopeRegional
	case "insights", "decisions":
		return scopeFiltered
	case "", "releases", "ci", "topology":
		return scopeGlobal
	case "host":
		return scopeEntity
	default:
		return scopeLocal
	}
}

// switchLink goes to the region's global view, which every page can reach.
func (current view) switchLink(region string) string { return current.regionLink(region) }

// regionLink is a region's global view. The selection is the path's, so the
// query's r is dropped.
func (current view) regionLink(region string) string {
	return current.State.link("/regions/"+region, "r", "")
}

// globalScope reports that the page currently shows every region.
func (current view) globalScope() bool {
	switch current.Page.scope() {
	case scopeGlobal:
		return true
	case scopeFiltered:
		return len(current.State.regionFilter()) == 0
	}
	return false
}

// allRegionsLink stays on a page that can show every region and otherwise
// goes to the global landing page.
func (current view) allRegionsLink() string {
	switch current.Page.scope() {
	case scopeFiltered:
		return current.State.keep(current.here(), "r", "", "region", "")
	case scopeGlobal:
		return current.State.keep(current.here(), "r", "")
	}
	return current.State.link("/", "r", "")
}

// selectedRegion marks the region the page's data comes from.
func (current view) selectedRegion(region string) bool {
	if named := current.Path["r"]; named != "" {
		return region == named
	}
	switch current.Page.scope() {
	case scopeGlobal:
		return false
	case scopeFiltered:
		return current.State.filtersRegion(region)
	case scopeLocal:
		return region == current.localRegion()
	}
	return current.region() == region
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
			Href: current.regionLink(region.ID)})
	}
	for _, choice := range timeRanges {
		items = append(items, paletteItem{Label: "Time range " + choice.Key, Group: "Range",
			Href: current.State.keep(current.here(), "range", choice.Key)})
	}
	live := "Pause live updates"
	liveValue := "0"
	if !current.State.Live {
		live, liveValue = "Resume live updates", "1"
	}
	items = append(items,
		paletteItem{Label: live, Group: "Action", Href: current.State.keep(current.here(), "live", liveValue)},
		paletteItem{Label: "Toggle dark / light theme", Group: "Action", Action: "theme"},
		paletteItem{Label: "Toggle browser notifications for new insights", Group: "Action", Action: "notify"},
		paletteItem{Label: "Decisions: rollbacks", Group: "Search", Href: current.State.link("/decisions", "kind", "rollback")},
		paletteItem{Label: "Decisions: holds", Group: "Search", Href: current.State.link("/decisions", "kind", "held")},
		paletteItem{Label: "Events: warnings and errors", Group: "Search", Href: current.State.link("/events", "level", "warn")},
	)
	if current.Evaluation != nil {
		for _, insight := range current.Evaluation.Insights {
			items = append(items, paletteItem{Label: insight.Title, Group: "Insight " + string(insight.Severity),
				Href: current.insightLink(insight)})
		}
	}
	data, _ := json.Marshal(items)
	return string(data)
}

// regionPlace is a region's map label and position.
type regionPlace struct {
	Name     string
	Lon, Lat float64
}

// regionGeo places a product region on the world map from the region
// catalog. A region that is not catalogued is drawn without a position.
func regionGeo(region string) (regionPlace, bool) {
	entry, ok := catalog.LookupName(region)
	return regionPlace{Name: entry.City, Lon: entry.Longitude, Lat: entry.Latitude}, ok
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
	if geo, ok := regionGeo(region); ok {
		return geo.Name
	}
	return ""
}
