package dashboard

import (
	"cmp"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// page is one dashboard route. Its body renders the element with id
// "content", which the page's stream re-renders and Datastar morphs in place.
type page struct {
	slug  string
	title string
	// group is the sidebar section the page is listed under.
	group string
	// events is how many recent events the page lists; zero lists none.
	events int
	// needs names the journal providers the page reads.
	needs needs
	// decisions returns the decision query the page lists, or nil.
	decisions func(current view) *decisionlog.Query
	body      func(view) templ.Component
	// pattern is a detail page's route with its path parameters, for
	// example /members/{id}. Detail pages are not in the sidebar; parent
	// is the slug of the sidebar page they belong to.
	pattern string
	parent  string
	// chain names the decision whose chain a detail page opens when its
	// link names none with id=, or "".
	chain func(current view) string
}

type needs uint16

const (
	// needLocal loads this region's summary. It never calls another region.
	needLocal needs = 1 << iota
	needInsights
	needSummaries
	needVersions
	needRollouts
	needRollout
	needVolumes
	needQualification
	needInventory
	// needChain loads the decision chain named by the id parameter.
	needChain
	// needGlobal copies the in-memory global view. It never calls a region.
	needGlobal
	// needBudget reads TS-804's global capacity document from the mirror.
	needBudget
)

func (page page) path() string {
	if page.pattern != "" {
		return page.pattern
	}
	if page.slug == "" {
		return "/{$}"
	}
	return "/" + page.slug
}

func (page page) href() string { return "/" + page.slug }

// navSlug is the sidebar entry the page highlights.
func (page page) navSlug() string { return cmp.Or(page.parent, page.slug) }

func (page page) streamPath() string {
	if page.pattern != "" {
		return page.pattern + "/stream"
	}
	if page.slug == "" {
		return "/global/stream"
	}
	return "/" + page.slug + "/stream"
}

// pages is the sidebar, in order. The global multi-region view is the
// landing page.
var pages = []page{
	{slug: "", title: "Global", group: "Overview", needs: needGlobal | needInsights, body: overviewBody},
	{slug: "region", title: "Region", group: "Overview", events: 10, needs: needLocal | needInsights,
		decisions: regionDecisions, body: regionBody},
	{slug: "nodes", title: "Nodes", group: "Overview", needs: needGlobal, body: globalNodesBody},
	{slug: "volumes", title: "Volumes", group: "Overview", needs: needGlobal, body: globalVolumesBody},
	{slug: "insights", title: "Needs attention", group: "Overview",
		needs: needLocal | needInsights | needSummaries, body: insightsBody},
	{slug: "decisions", title: "Decisions", group: "Overview", needs: needLocal | needChain,
		decisions: journalDecisions, body: decisionsBody},
	{slug: "releases", title: "Releases", group: "Delivery", needs: needLocal | needVersions | needChain,
		decisions: releaseDecisions, body: releasesBody},
	{slug: "rollouts", title: "Rollouts", group: "Delivery", needs: needRollouts, decisions: rolloutDecisions,
		body: rolloutsBody},
	{slug: "ci", title: "Qualification", group: "Delivery", needs: needQualification,
		decisions: qualificationDecisions, body: ciBody},
	{slug: "topology", title: "Topology", group: "Infrastructure", needs: needLocal, body: topologyBody},
	{slug: "members", title: "Hosts", group: "Infrastructure", needs: needLocal, body: membersBody},
	{slug: "nats", title: "NATS", group: "Infrastructure", decisions: natsDecisions, body: natsBody},
	{slug: "terrabase", title: "TerraBase", group: "Infrastructure", needs: needLocal, decisions: terrabaseDecisions,
		body: terrabaseBody},
	{slug: "storage", title: "Storage", group: "Infrastructure", needs: needVolumes | needLocal, decisions: storageDecisions,
		body: storageBody},
	{slug: "oci", title: "OCI", group: "Infrastructure", needs: needInventory, body: ociBody},
	{slug: "cost", title: "OCI cost", group: "Infrastructure", needs: needLocal | needGlobal | needBudget, body: costBody},
	{slug: "events", title: "Events", group: "Logs", events: recentEvents, body: eventsBody},
}

// navGroups lists the sidebar sections in order.
var navGroups = []string{"Overview", "Delivery", "Infrastructure", "Logs"}

func pagesIn(group string) []page {
	var out []page
	for _, entry := range pages {
		if entry.group == group {
			out = append(out, entry)
		}
	}
	return out
}

// view is everything one render of a page reads. Optional parts are nil when
// their provider is missing or failed; Notes explain why.
type view struct {
	Page    page
	Now     time.Time
	SignOut bool
	Ready   bool
	Checks  []observability.CheckResult
	Local   *observability.MemberSnapshot
	Cluster *observability.ClusterSnapshot
	Events  []observability.Event
	Filter  eventFilter
	State   uiState
	// Path holds a detail page's validated path parameters.
	Path  map[string]string
	Notes []string

	// Journal is nil until a controller attaches its providers.
	Journal *Journal
	// LocalSummary is this region's summary, loaded only by pages that show it.
	LocalSummary *regionview.Summary
	// Global is every region of the global view, local first (TS-805).
	Global     []globalview.Region
	Evaluation *insights.Evaluation
	Summaries  []insights.Summary
	Decisions  *decisionlog.Result
	Chain      *decisionlog.Chain
	Versions   []UnitVersion
	// VersionsDerived reports that Versions came from region summaries.
	VersionsDerived bool
	Rollout         *insights.Rollout
	Rollouts        []insights.Rollout
	Volumes         []insights.Volume
	Qualifications  []Qualification
	Inventory       []InventoryItem
	// Capacity is TS-804's global capacity document; nil when unread or never written.
	Capacity *budget.Capacity
	// Unavailable names providers that are attached but failed.
	Unavailable []string
}

// members returns every answering member, or this member alone without
// cell-wide aggregation.
func (current view) members() []observability.MemberSnapshot {
	if current.Cluster != nil && len(current.Cluster.Members) > 0 {
		return current.Cluster.Members
	}
	if current.Local != nil {
		return []observability.MemberSnapshot{*current.Local}
	}
	return nil
}

func (current view) missing() []string {
	if current.Cluster == nil {
		return nil
	}
	return current.Cluster.Missing
}

func (current view) cell() string {
	switch {
	case current.Local != nil:
		return current.Local.Cell
	case current.Cluster != nil:
		return current.Cluster.Cell
	default:
		return "unknown"
	}
}

func (current view) memberName() string {
	if current.Local == nil {
		return "starting"
	}
	return current.Local.Member
}

// placement prefers this member's view of the placement store and falls back
// to any member that reported one: hosts and unmanaged cells have none.
func (current view) placement() *observability.PlacementView {
	if current.Local != nil && current.Local.Placement != nil {
		return current.Local.Placement
	}
	for _, member := range current.members() {
		if member.Placement != nil {
			return member.Placement
		}
	}
	return nil
}

// authority returns the lease as seen by this member, or by any member.
func (current view) authority() *observability.AuthorityView {
	if current.Local != nil && current.Local.Authority != nil {
		return current.Local.Authority
	}
	for _, member := range current.members() {
		if member.Authority != nil {
			return member.Authority
		}
	}
	return nil
}

func (current view) metaLeader() string {
	for _, member := range current.members() {
		if member.NATS != nil && member.NATS.MetaLeader != "" {
			return member.NATS.MetaLeader
		}
	}
	return ""
}

// natsReporter is the member whose JetStream lists the NATS page shows.
func (current view) natsReporter() *observability.MemberSnapshot {
	members := current.members()
	for index := range members {
		if members[index].NATS != nil && members[index].NATS.IsMetaLeader {
			return &members[index]
		}
	}
	for index := range members {
		if members[index].NATS != nil {
			return &members[index]
		}
	}
	return nil
}

func (current view) sectionErrors() []string {
	var errors []string
	for _, member := range current.members() {
		for _, section := range slices.Sorted(maps.Keys(member.Errors)) {
			errors = append(errors, member.Member+": "+section+" "+member.Errors[section])
		}
	}
	return errors
}

func (current view) streamAction() string {
	target := current.Page.streamPath()
	if current.Page.pattern != "" {
		target = current.here() + "/stream"
	}
	if query := current.State.query(); query != "" {
		target += "?" + query
	}
	return "@get('" + target + "')"
}

// hostRow is one host node that carries TerraBase seats.
type hostRow struct {
	Node    string
	Domains []string
	Seats   int
	Serving int
}

func (current view) hosts() []hostRow {
	placement := current.placement()
	if placement == nil {
		return nil
	}
	rows := map[string]*hostRow{}
	for _, database := range placement.Databases {
		if database.Terminal {
			continue
		}
		for _, member := range database.Members {
			if member.HostNode == "" {
				continue
			}
			row := rows[member.HostNode]
			if row == nil {
				row = &hostRow{Node: member.HostNode}
				rows[member.HostNode] = row
			}
			row.Seats++
			if member.Stage == "serving" {
				row.Serving++
			}
			if member.FailureDomain != "" && !slices.Contains(row.Domains, member.FailureDomain) {
				row.Domains = append(row.Domains, member.FailureDomain)
			}
		}
	}
	result := make([]hostRow, 0, len(rows))
	for _, node := range slices.Sorted(maps.Keys(rows)) {
		slices.Sort(rows[node].Domains)
		result = append(result, *rows[node])
	}
	return result
}

func (current view) rollouts() []observability.DatabaseView {
	placement := current.placement()
	if placement == nil {
		return nil
	}
	var rollouts []observability.DatabaseView
	for _, database := range placement.Databases {
		if !database.Terminal && database.Rollout != nil {
			rollouts = append(rollouts, database)
		}
	}
	return rollouts
}

func (current view) eventComponents() []string {
	if current.Page.slug != "events" {
		return nil
	}
	seen := map[string]bool{}
	for _, event := range current.Events {
		if event.Component != "" {
			seen[event.Component] = true
		}
	}
	if current.Filter.Component != "" {
		seen[current.Filter.Component] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

// eventFilter selects events by minimum level, component, a search text and
// a time window around a point a chart click jumped to. It comes from the
// query string, so a filtered page is a plain link and works without JS.
type eventFilter struct {
	Level     string
	Component string
	Search    string
	// At centres the list on a moment: only events within eventWindow of
	// it match.
	At time.Time
}

// eventWindow is how far around a clicked chart point the events page looks.
const eventWindow = 5 * time.Minute

var levelNames = []string{"debug", "info", "warn", "error"}

func parseEventFilter(query url.Values) eventFilter {
	filter := eventFilter{}
	if level := strings.ToLower(query.Get("level")); slices.Contains(levelNames, level) {
		filter.Level = level
	}
	if component := query.Get("component"); validComponent(component) {
		filter.Component = component
	}
	if search := strings.TrimSpace(query.Get("q")); search != "" && validSearch(search) {
		filter.Search = strings.ToLower(search)
	}
	if at, err := time.Parse(time.RFC3339, query.Get("at")); err == nil {
		filter.At = at.UTC()
	}
	return filter
}

func eventContains(event observability.Event, lowerNeedle string) bool {
	if strings.Contains(strings.ToLower(event.Message), lowerNeedle) ||
		strings.Contains(strings.ToLower(event.Component), lowerNeedle) {
		return true
	}
	for key, value := range event.Attrs {
		if strings.Contains(strings.ToLower(key+"="+value), lowerNeedle) {
			return true
		}
	}
	return false
}

func validComponent(component string) bool {
	if component == "" || len(component) > 64 {
		return false
	}
	for _, char := range component {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("._-", char)) {
			return false
		}
	}
	return true
}

func (filter eventFilter) matches(event observability.Event) bool {
	if filter.Component != "" && event.Component != filter.Component {
		return false
	}
	if !filter.At.IsZero() && (event.Time.Before(filter.At.Add(-eventWindow)) ||
		event.Time.After(filter.At.Add(eventWindow))) {
		return false
	}
	if filter.Search != "" && !eventContains(event, filter.Search) {
		return false
	}
	if filter.Level == "" {
		return true
	}
	var minimum, level slog.Level
	_ = minimum.UnmarshalText([]byte(filter.Level))
	if err := level.UnmarshalText([]byte(event.Level)); err != nil {
		return true
	}
	return level >= minimum
}

// apply returns at most limit matching events, newest first.
func (filter eventFilter) apply(events []observability.Event, limit int) []observability.Event {
	result := make([]observability.Event, 0, min(limit, len(events)))
	for index := len(events) - 1; index >= 0 && len(result) < limit; index-- {
		if filter.matches(events[index]) {
			result = append(result, events[index])
		}
	}
	return result
}

// Formatting helpers used by the templates.

func itoa[T ~int | ~int64 | ~uint64 | ~uint32](value T) string { return fmt.Sprint(value) }

func formatBytes[T ~int64 | ~uint64](value T) string {
	if value < 0 {
		return "n/a"
	}
	amount := float64(value)
	for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if amount < 1024 || unit == "TiB" {
			if unit == "B" {
				return strconv.FormatFloat(amount, 'f', 0, 64) + " B"
			}
			return strconv.FormatFloat(amount, 'f', 1, 64) + " " + unit
		}
		amount /= 1024
	}
	return ""
}

// ratio returns used/total in [0, 1], or zero for an unknown total.
func ratio(used, total float64) float64 {
	if total <= 0 || used <= 0 {
		return 0
	}
	return min(used/total, 1)
}

func percent(value float64) string { return strconv.FormatFloat(value*100, 'f', 1, 64) + "%" }

// progressValue renders a ratio for <progress max="1000">.
func progressValue(value float64) string { return strconv.Itoa(int(value * 1000)) }

func ratioClass(value float64) string {
	switch {
	case value >= 0.9:
		return "bad"
	case value >= 0.75:
		return "warn"
	default:
		return "ok"
	}
}

func formatFloat(value float64, decimals int) string {
	return strconv.FormatFloat(value, 'f', decimals, 64)
}

func formatSeconds(seconds float64) string {
	return formatDuration(time.Duration(seconds * float64(time.Second)))
}

func formatDuration(duration time.Duration) string {
	switch {
	case duration < 0:
		return "-"
	case duration < time.Second:
		return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
	case duration < time.Minute:
		return strconv.FormatFloat(duration.Seconds(), 'f', 1, 64) + "s"
	case duration < time.Hour:
		return strconv.Itoa(int(duration.Minutes())) + "m"
	case duration < 48*time.Hour:
		return strconv.Itoa(int(duration.Hours())) + "h" + strconv.Itoa(int(duration.Minutes())%60) + "m"
	default:
		return strconv.Itoa(int(duration.Hours()/24)) + "d"
	}
}

func age(now, then time.Time) string {
	if then.IsZero() {
		return "-"
	}
	return formatDuration(now.Sub(then).Truncate(time.Second))
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format("2006-01-02 15:04:05Z")
}

func short(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length] + "…"
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func okClass(value bool) string {
	if value {
		return "ok"
	}
	return "bad"
}

func levelClass(level string) string {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		return ""
	}
	switch {
	case parsed >= slog.LevelError:
		return "bad"
	case parsed >= slog.LevelWarn:
		return "warn"
	default:
		return "muted"
	}
}

// counts renders a stage or phase histogram as "a 1, b 2" in key order.
func counts(values map[string]int) string {
	if len(values) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(values))
	for _, key := range slices.Sorted(maps.Keys(values)) {
		parts = append(parts, key+" "+strconv.Itoa(values[key]))
	}
	return strings.Join(parts, ", ")
}

func eventAttrs(attrs map[string]string) string {
	parts := make([]string, 0, len(attrs))
	for _, key := range slices.Sorted(maps.Keys(attrs)) {
		parts = append(parts, key+"="+attrs[key])
	}
	return strings.Join(parts, " ")
}

func memoryUsed(system *observability.SystemView) float64 {
	if system == nil || system.MemTotalBytes == 0 {
		return 0
	}
	return ratio(float64(system.MemTotalBytes-min(system.MemAvailBytes, system.MemTotalBytes)),
		float64(system.MemTotalBytes))
}

func filesystemUsed(filesystem observability.FilesystemView) float64 {
	return ratio(float64(filesystem.SizeBytes-min(filesystem.AvailBytes, filesystem.SizeBytes)),
		float64(filesystem.SizeBytes))
}

func storeUsed(nats *observability.NATSView) float64 {
	if nats == nil || nats.StoreLimitBytes <= 0 {
		return 0
	}
	return ratio(float64(nats.StoreUsedBytes), float64(nats.StoreLimitBytes))
}

func memoryPressure(system *observability.SystemView) string {
	if system == nil {
		return "-"
	}
	pressure, ok := system.Pressure["memory"]
	if !ok {
		return "-"
	}
	return formatFloat(pressure.SomeAvg10, 2)
}

func statusCode(code int) string {
	if code == 0 {
		return "-"
	}
	return strconv.Itoa(code)
}

func apiMean(operation observability.OCIOperationView) string {
	if operation.Calls == 0 {
		return "-"
	}
	return formatSeconds(operation.TotalSeconds / float64(operation.Calls))
}
