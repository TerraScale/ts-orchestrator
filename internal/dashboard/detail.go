package dashboard

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// detailPages are the per-entity pages. They are not in the sidebar: the
// list pages, the topology, insights and decisions link to them, and each
// highlights its parent page. Every one shows the entity's live state, its
// charts, the decisions about it with the latest decision chain, and the
// open insights that name it.
var detailPages = []page{
	{slug: "member", parent: "members", pattern: "/members/{id}", title: "Member", group: "Infrastructure",
		needs: needLocal | needInsights | needChain, decisions: memberDetailDecisions, chain: newestDecision,
		body: memberDetailBody},
	{slug: "partition", parent: "terrabase", pattern: "/terrabase/{db}/{partition}", title: "TerraBase partition",
		group: "Infrastructure", needs: needLocal | needInsights | needChain, decisions: partitionDetailDecisions,
		chain: newestDecision, body: partitionDetailBody},
	{slug: "rollout", parent: "rollouts", pattern: "/rollouts/{id}", title: "Rollout", group: "Delivery",
		needs: needLocal | needInsights | needRollout | needChain, decisions: rolloutDetailDecisions,
		chain: newestDecision, body: rolloutDetailBody},
	{slug: "volume", parent: "storage", pattern: "/volumes/{id}", title: "Volume", group: "Infrastructure",
		needs: needLocal | needInsights | needVolumes | needChain, decisions: volumeDetailDecisions,
		chain: newestDecision, body: volumeDetailBody},
	{slug: "host", parent: "members", pattern: "/regions/{r}/hosts/{h}", title: "Host", group: "Infrastructure",
		needs: needLocal | needInsights | needVolumes | needChain, decisions: hostDetailDecisions,
		chain: newestDecision, body: hostDetailBody},
	{slug: "global-region", pattern: "/regions/{r}", title: "Region", group: "Overview", needs: needGlobal,
		body: globalRegionBody},
	{slug: "global-node", parent: "nodes", pattern: "/regions/{r}/nodes/{n}", title: "Node", group: "Overview",
		needs: needGlobal, body: globalNodeBody},
	{slug: "global-volume", parent: "volumes", pattern: "/regions/{r}/volumes/{v}", title: "Volume", group: "Overview",
		needs: needGlobal, body: globalVolumeBody},
	{slug: "global-service", parent: "nodes", pattern: "/regions/{r}/nodes/{n}/services/{s}", title: "Service",
		group: "Overview", needs: needGlobal, body: globalServiceBody},
	{slug: "managed-service", pattern: "/regions/{r}/services/{s}", title: "Managed service",
		group: "Overview", needs: needGlobal, body: managedServiceBody},
}

// detailHistory is how far back a detail page looks for decisions, at
// least: an entity's last change is often older than the selected range.
const (
	detailHistory  = 24 * time.Hour
	rolloutHistory = 7 * 24 * time.Hour
)

var pathParameter = regexp.MustCompile(`\{([a-z]+)\}`)

// pathNames lists a detail page's path parameters in order.
func (page page) pathNames() []string {
	var names []string
	for _, match := range pathParameter.FindAllStringSubmatch(page.pattern, -1) {
		names = append(names, match[1])
	}
	return names
}

// pathValues reads and validates a detail page's path parameters. A value
// that is not a plain token (or a region name for r) is not found, so no
// request text reaches a provider query unvalidated.
func (page page) pathValues(request *http.Request) (map[string]string, bool) {
	names := page.pathNames()
	if len(names) == 0 {
		return nil, true
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		value := request.PathValue(name)
		if name == "r" {
			value = strings.ToLower(value)
			if !validRegion(value) {
				return nil, false
			}
		} else if value == "" || !validToken(value) {
			return nil, false
		}
		values[name] = value
	}
	return values, true
}

// here is the path of the page being shown, with a detail page's
// parameters filled in.
func (current view) here() string {
	if current.Page.pattern == "" {
		return current.Page.href()
	}
	return detailPath(current.Page.pattern, current.Path)
}

func detailPath(pattern string, values map[string]string) string {
	return pathParameter.ReplaceAllStringFunc(pattern, func(match string) string {
		return url.PathEscape(values[strings.Trim(match, "{}")])
	})
}

// Links to the detail pages, carrying the shared state.

func (state uiState) memberLink(member string) string {
	return state.link(detailPath("/members/{id}", map[string]string{"id": member}))
}

func (state uiState) partitionLink(database, partition string) string {
	return state.link(detailPath("/terrabase/{db}/{partition}", map[string]string{"db": database, "partition": partition}))
}

func (state uiState) rolloutLink(id string) string {
	return state.link(detailPath("/rollouts/{id}", map[string]string{"id": id}))
}

func (state uiState) volumeLink(id string) string {
	return state.link(detailPath("/volumes/{id}", map[string]string{"id": id}))
}

// hostLink opens a host of a region; the region is in the path, so the
// selected region is not carried.
func (state uiState) hostLink(region, host string) string {
	return state.link(detailPath("/regions/{r}/hosts/{h}", map[string]string{"r": region, "h": host}), "r", "")
}

// Decision queries of the detail pages. Subject filters match a substring
// of the subject ID, its name or the summary.

func memberDetailDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.localRegion()}, Subject: current.Path["id"],
		Since: current.since(detailHistory), Limit: 200}
}

// partitionKinds are the decisions a TerraBase partition page reads.
var partitionKinds = []decisionlog.Kind{decisionlog.KindScaleUp, decisionlog.KindScaleDown,
	decisionlog.KindStageChanged, decisionlog.KindMemberReplaced, decisionlog.KindHostLaunched,
	decisionlog.KindHostReclaimed, decisionlog.KindHeld, decisionlog.KindHoldCleared,
	decisionlog.KindReleaseAdmitted, decisionlog.KindUpgradeStarted, decisionlog.KindCanaryPromoted,
	decisionlog.KindRollback, decisionlog.KindVolumeResized, decisionlog.KindVolumeReattached,
	decisionlog.KindBackupTaken}

// partitionDetailDecisions reads every placement decision of the region
// and narrows them to the partition in partitionDecision: placement holds
// name a seat by its bare member ID, which no subject filter can match.
func partitionDetailDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.localRegion()}, Kinds: partitionKinds,
		Since: current.since(detailHistory), Limit: decisionlog.MaxQueryLimit}
}

func rolloutDetailDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Subject: current.Path["id"], Since: current.since(rolloutHistory), Limit: 300}
}

func volumeDetailDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.localRegion()}, Subject: current.Path["id"],
		Since: current.since(rolloutHistory), Limit: 200}
}

// hostDetailDecisions reads the region's recent decisions and narrows them
// to the host in entityDecisions: placement journals a seat's changes with
// the seat as subject and its host only in the host_node attribute, which
// no subject filter can match.
func hostDetailDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.Path["r"]},
		Since: current.since(detailHistory), Limit: decisionlog.MaxQueryLimit}
}

// newestDecision opens the chain of the entity's newest decision.
func newestDecision(current view) string {
	if decisions := current.entityDecisions(); len(decisions) > 0 {
		return decisions[0].ID
	}
	return ""
}

// entityDecisions are the loaded decisions about the page's entity, newest
// first.
func (current view) entityDecisions() []decisionlog.Decision {
	var about func(decisionlog.Decision) bool
	switch current.Page.slug {
	case "partition":
		about = current.partitionDecision
	case "host":
		host := current.Path["h"]
		about = func(decision decisionlog.Decision) bool {
			return decision.Attrs["host_node"] == host || namesID(decision, host)
		}
	case "member", "rollout", "volume":
		id := current.Path["id"]
		about = func(decision decisionlog.Decision) bool { return namesID(decision, id) }
	default:
		return current.decisions()
	}
	var out []decisionlog.Decision
	for _, decision := range current.decisions() {
		if about(decision) {
			out = append(out, decision)
		}
	}
	return out
}

// namesID reports that a decision names id as a whole identifier in its
// subject ID, subject name or summary. The journal's subject search matches
// any substring, so a page for gru-c1 would otherwise list gru-c10's
// decisions too.
func namesID(decision decisionlog.Decision, id string) bool {
	return mentionsID(decision.Subject.ID, id) || mentionsID(decision.Subject.Name, id) ||
		mentionsID(decision.Summary, id)
}

// mentionsID reports that text contains id, case-insensitively, not as a
// part of a longer identifier: the characters around it are not letters,
// digits, '-' or '_'.
func mentionsID(text, id string) bool {
	if id == "" {
		return false
	}
	text, id = strings.ToLower(text), strings.ToLower(id)
	for offset := 0; offset+len(id) <= len(text); {
		index := strings.Index(text[offset:], id)
		if index < 0 {
			return false
		}
		start, end := offset+index, offset+index+len(id)
		if (start == 0 || !identifierByte(text[start-1])) && (end == len(text) || !identifierByte(text[end])) {
			return true
		}
		offset = start + 1
	}
	return false
}

func identifierByte(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_'
}

// partitionDecision reports that a placement decision is about the shown
// partition: one of its seats (subject db/partition/seat), the partition
// itself (a database hold names db/partition), its managed update, its
// volumes (named db/partition), or a hold on a seat ID the partition has.
func (current view) partitionDecision(decision decisionlog.Decision) bool {
	database, partition := current.Path["db"], current.Path["partition"]
	key := database + "/" + partition
	subject := decision.Subject
	switch {
	case decision.Attrs["database_id"] == database && decision.Attrs["partition_id"] == partition:
		return true
	case subject.Kind == "seat" && strings.HasPrefix(subject.ID, key+"/"):
		return true
	case subject.ID == key || subject.Name == key:
		return true
	case subject.Kind == "seat" && !strings.Contains(subject.ID, "/"):
		// A hold names the bare seat ID; it is shown when this partition
		// has that seat, and flagged when another partition has it too.
		if view := current.partition(); view != nil {
			return slices.ContainsFunc(view.Members, func(member observability.MemberView) bool {
				return member.SeatID == subject.ID
			})
		}
	case subject.Kind == "operation":
		if view := current.partition(); view != nil && view.Rollout != nil {
			return subject.ID == view.Rollout.OperationID
		}
	}
	return false
}

// ambiguousSeat reports that a bare seat ID also exists in another listed
// partition, so a hold that names it may be about that one.
func (current view) ambiguousSeat(seat string) bool {
	placement := current.placement()
	if placement == nil {
		return false
	}
	found := 0
	for _, database := range placement.Databases {
		if slices.ContainsFunc(database.Members, func(member observability.MemberView) bool { return member.SeatID == seat }) {
			found++
		}
	}
	return found > 1
}

// holdHistory lists the partition's placement holds and their clearing,
// newest first.
func (current view) holdHistory() []decisionlog.Decision {
	var out []decisionlog.Decision
	for _, decision := range current.entityDecisions() {
		if decision.Kind == decisionlog.KindHeld || decision.Kind == decisionlog.KindHoldCleared {
			out = append(out, decision)
		}
	}
	return out
}

// entityInsights lists the open insights whose entity is the page's
// entity, worst first.
func (current view) entityInsights() []insights.Insight {
	var out []insights.Insight
	for _, insight := range current.globalInsights() {
		if current.namesEntity(insight) {
			out = append(out, insight)
		}
	}
	return out
}

func (current view) namesEntity(insight insights.Insight) bool {
	entity := insight.Entity
	inRegion := func(region string) bool { return insight.Region == "" || insight.Region == region }
	switch current.Page.slug {
	case "member":
		id := current.Path["id"]
		return inRegion(current.localRegion()) && (entity.ID == id || strings.HasPrefix(entity.ID, id+":"))
	case "host":
		id := current.Path["h"]
		return inRegion(current.Path["r"]) && (entity.ID == id || strings.HasPrefix(entity.ID, id+":"))
	case "partition":
		key := current.Path["db"] + "/" + current.Path["partition"]
		return inRegion(current.localRegion()) && (entity.ID == key || strings.HasPrefix(entity.ID, key+"/"))
	case "rollout", "volume":
		return entity.ID == current.Path["id"]
	}
	return false
}

// detailMember is the member a member page shows, if it answered.
func (current view) detailMember() *observability.MemberSnapshot {
	members := current.members()
	for index := range members {
		if members[index].Member == current.Path["id"] {
			return &members[index]
		}
	}
	return nil
}

// detailMissing reports that the shown member is expected but did not
// answer the cell-wide snapshot request.
func (current view) detailMissing() bool {
	return slices.Contains(current.missing(), current.Path["id"])
}

// memberChecks are the shown member's readiness checks, freshly evaluated
// when it is this member.
func (current view) memberChecks(member observability.MemberSnapshot) ([]observability.CheckResult, bool) {
	if current.Local != nil && member.Member == current.Local.Member && len(current.Checks) > 0 {
		return current.Checks, current.Ready
	}
	return member.Checks, member.Ready
}

// partition is the TerraBase partition a partition page shows.
func (current view) partition() *observability.DatabaseView {
	placement := current.placement()
	if placement == nil {
		return nil
	}
	for index := range placement.Databases {
		database := &placement.Databases[index]
		if database.DatabaseID == current.Path["db"] && database.PartitionID == current.Path["partition"] {
			return database
		}
	}
	return nil
}

// partitionChart charts the partition's desired and serving seats.
func (current view) partitionChart() chartSpec {
	labels := map[string]string{"database": current.Path["db"], "partition": current.Path["partition"]}
	var series []chartSeries
	if desired := current.historyRange(observability.HistPartitionDesired, labels, "", false); len(desired) > 0 {
		desired[0].Name, desired[0].Dashed, desired[0].Status = "desired", true, "idle"
		series = append(series, desired[0])
	}
	if serving := current.historyRange(observability.HistPartitionServing, labels, "", false); len(serving) > 0 {
		serving[0].Name, serving[0].Status = "serving", "ok"
		series = append(series, serving[0])
	}
	spec := current.lineChart("line", "count", series, "No seat history for this partition yet.")
	spec.Min = float(0)
	return spec
}

// detailRollout is the release rollout a rollout page shows, if the rollout
// provider knows it.
func (current view) detailRollout() *insights.Rollout {
	return current.Rollout
}

// managedUpdate is the managed TerraBase update whose operation ID the
// rollout page shows, with its partition.
func (current view) managedUpdate() *observability.DatabaseView {
	for _, database := range current.rollouts() {
		if database.Rollout.OperationID == current.Path["id"] {
			return &database
		}
	}
	return nil
}

// rolloutProgressChart charts a managed update's completed fraction.
func (current view) rolloutProgressChart() chartSpec {
	series := current.historyRange(observability.HistRolloutProgress,
		map[string]string{"operation": current.Path["id"]}, "", false)
	if len(series) > 0 {
		series[0].Name, series[0].Status = "completed", "ok"
	}
	spec := current.lineChart("area", "percent", series, "No progress history for this update in the selected range.")
	spec.Min, spec.Max = float(0), float(1)
	return spec
}

// detailVolume is the volume a volume page shows.
func (current view) detailVolume() *insights.Volume {
	for index := range current.Volumes {
		if current.Volumes[index].ID == current.Path["id"] {
			return &current.Volumes[index]
		}
	}
	return nil
}

// hostSeat is one TerraBase seat on a host.
type hostSeat struct {
	Database observability.DatabaseView
	Seat     observability.MemberView
}

// hostSeats lists the seats placed on the shown host. Placement is this
// member's region's view, so another region's host has none here.
func (current view) hostSeats() []hostSeat {
	placement := current.placement()
	if placement == nil || current.Path["r"] != current.localRegion() {
		return nil
	}
	var out []hostSeat
	for _, database := range placement.Databases {
		for _, member := range database.Members {
			if member.HostNode == current.Path["h"] {
				out = append(out, hostSeat{Database: database, Seat: member})
			}
		}
	}
	return out
}

// hostVolumes lists the volumes attached to the shown host.
func (current view) hostVolumes() []insights.Volume {
	if current.Path["r"] != current.localRegion() {
		return nil
	}
	var out []insights.Volume
	for _, volume := range current.Volumes {
		if volume.Host == current.Path["h"] {
			out = append(out, volume)
		}
	}
	return out
}

func (current view) hostChart(metric, unit, nameBy, empty string) chartSpec {
	var series []chartSeries
	var warning string
	node := current.detailHostNode()
	member := node.Name
	if current.Path["r"] == current.localRegion() && current.Journal != nil && current.Journal.History != nil {
		result := current.Journal.History.Range(observability.HistoryQuery{Metric: metric,
			Labels: map[string]string{"member": strings.ToLower(member)},
			Start:  current.Now.Add(-current.State.Range.Duration), End: current.Now, MaxSeries: 64})
		series = historyChartSeries(result, metric, nameBy)
		if result.Incomplete {
			warning = "Regional metric history is incomplete: some retained measurements are unavailable."
		}
		if result.Pending {
			empty = "Loading regional metric history"
			warning = strings.TrimSpace(warning + " Regional metric history is loading.")
		}
	}
	spec := current.lineChart("line", unit, series, empty)
	spec.Warning = warning
	return spec
}

// detailWindow names how far back the page's decision query looks: the
// selected range, but at least a day (a week for rollouts and volumes).
func (current view) detailWindow() string {
	minimum := detailHistory
	if current.Page.slug == "rollout" || current.Page.slug == "volume" {
		minimum = rolloutHistory
	}
	if window := max(current.State.Range.Duration, minimum); window > 24*time.Hour {
		return "last " + itoa(int(window/(24*time.Hour))) + " days"
	}
	return "last 24h"
}

// journalSearch is the decision journal search that lists the page's
// entity.
func (current view) journalSearch() string {
	switch current.Page.slug {
	case "partition":
		return current.Path["db"] + "/" + current.Path["partition"]
	case "host":
		return current.Path["h"]
	}
	return current.Path["id"]
}

// truncatedNote explains a partition missing from a truncated placement
// view.
func truncatedNote(current view) string {
	if placement := current.placement(); placement != nil && placement.Truncated {
		return " (the view is truncated at its bound)"
	}
	return ""
}

// detailFilter narrows member series to the member or host a detail page
// shows.
func (current view) detailFilter() map[string]string {
	switch current.Page.slug {
	case "member":
		return map[string]string{"member": current.Path["id"]}
	case "host":
		return map[string]string{"member": current.Path["h"]}
	}
	return nil
}
