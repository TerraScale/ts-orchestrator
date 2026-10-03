package dashboard

import (
	"maps"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// knownSlices are the deciding slices the journal filter offers even before
// they recorded anything.
var knownSlices = []string{"authority", "autoscale", "bootstrap", "cluster", "delivery", "hostpool", "membership", "netbird",
	"placement", "regionplanner", "rollout", "selfupdate", "storage"}

var knownKinds = []decisionlog.Kind{decisionlog.KindReleaseAdmitted, decisionlog.KindUpgradeStarted,
	decisionlog.KindCanaryPromoted, decisionlog.KindBatchPromoted, decisionlog.KindRolloutCompleted,
	decisionlog.KindRollback, decisionlog.KindHeld, decisionlog.KindHoldCleared, decisionlog.KindFrozen,
	decisionlog.KindScaleUp, decisionlog.KindScaleDown, decisionlog.KindHostLaunched, decisionlog.KindHostReclaimed,
	decisionlog.KindMemberReplaced, decisionlog.KindControllerReplaced, decisionlog.KindStageChanged,
	decisionlog.KindVolumeResized, decisionlog.KindVolumeReattached, decisionlog.KindBackupTaken,
	decisionlog.KindRegionProposed, decisionlog.KindLeaderChanged, decisionlog.KindQuorumDegraded,
	decisionlog.KindQuorumRestored, decisionlog.KindDeliveryApplied, decisionlog.KindDeliveryHeld,
	decisionlog.KindDeliveryRejected, decisionlog.KindFounderLaunched, decisionlog.KindPeerEnrolled}

var decisionStatuses = []decisionlog.Status{decisionlog.StatusPending, decisionlog.StatusInProgress,
	decisionlog.StatusSucceeded, decisionlog.StatusFailed, decisionlog.StatusRolledBack}

func (current view) actorOptions() []string {
	seen := map[string]bool{}
	for _, name := range knownSlices {
		seen[name] = true
	}
	for _, decision := range current.decisions() {
		if decision.Actor.Slice != "" {
			seen[decision.Actor.Slice] = true
		}
	}
	// The active filter stays selectable even when nothing matches it now.
	for _, actor := range current.State.list("actor") {
		seen[actor] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

func (current view) kindOptions() []string {
	seen := map[string]bool{}
	for _, kind := range knownKinds {
		seen[string(kind)] = true
	}
	for _, decision := range current.decisions() {
		seen[string(decision.Kind)] = true
	}
	for _, kind := range current.State.list("kind") {
		seen[kind] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

func (current view) regionOptions() []string {
	var regions []string
	for _, region := range current.switcher() {
		regions = append(regions, region.ID)
	}
	for _, region := range current.State.regionFilter() {
		if !slices.Contains(regions, region) {
			regions = append(regions, region)
		}
	}
	return regions
}

// decisionCounts tallies the loaded decisions per kind for the bar chart.
func (current view) decisionKindChart() chartSpec {
	counts := map[string]map[string]float64{}
	regions := map[string]bool{}
	for _, decision := range current.decisions() {
		kind := kindLabel(decision.Kind)
		if counts[kind] == nil {
			counts[kind] = map[string]float64{}
		}
		counts[kind][upper(decision.Region)]++
		regions[upper(decision.Region)] = true
	}
	kinds := slices.SortedFunc(maps.Keys(counts), func(left, right string) int {
		return strings.Compare(left, right)
	})
	spec := chartSpec{Kind: "hbar", Unit: "count", Categories: kinds}
	for _, region := range slices.Sorted(maps.Keys(regions)) {
		bars := barSeries{Name: region}
		for _, kind := range kinds {
			bars.Values = append(bars.Values, counts[kind][region])
		}
		spec.Bars = append(spec.Bars, bars)
	}
	if len(kinds) == 0 {
		spec.Empty = "No decisions match these filters."
	}
	return spec
}

func signalValue(signal decisionlog.Signal) string {
	if signal.Text != "" {
		return signal.Text
	}
	return formatUnit(signal.Value, signal.Unit)
}

func signalGate(signal decisionlog.Signal) string {
	if signal.Threshold == nil {
		return ""
	}
	return signal.Comparison + " " + formatUnit(*signal.Threshold, signal.Unit)
}

func signalPassed(signal decisionlog.Signal) string {
	switch {
	case signal.Passed == nil:
		return ""
	case *signal.Passed:
		return "pass"
	default:
		return "fail"
	}
}

func signalMark(signal decisionlog.Signal) string {
	switch signalPassed(signal) {
	case "pass":
		return "✓ passed"
	case "fail":
		return "✗ failed"
	default:
		return "observed"
	}
}

// unansweredRegions lists the regions of a cross-region query that did not
// answer. Result.Partial alone can also mean older history was not
// searched in a region that did answer.
func unansweredRegions(result *decisionlog.Result) []decisionlog.RegionStatus {
	var out []decisionlog.RegionStatus
	for _, status := range result.Regions {
		if status.State != decisionlog.RegionOK {
			out = append(out, status)
		}
	}
	return out
}

// filterActive reports whether any journal filter is set.
func (current view) filterActive() bool {
	for _, name := range []string{"region", "kind", "actor", "status", "q"} {
		if current.State.param(name) != "" {
			return true
		}
	}
	return false
}

func attrsText(attrs map[string]string) string { return eventAttrs(attrs) }
