package dashboard

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// releaseStages are the columns of a release timeline, in order.
var releaseStages = []string{"qualified", "signed", "staged", "canary", "soak", "batches", "outcome"}

var releaseStageTitles = map[string]string{"qualified": "CI qualified", "signed": "Signed", "staged": "Staged",
	"canary": "Canary", "soak": "Soak", "batches": "Batches", "outcome": "Complete"}

// releaseView is one release's journey through every region, built from the
// decision journal: each step links the decision that took it.
type releaseView struct {
	ID     string
	Name   string
	First  time.Time
	Last   time.Time
	Status string
	Label  string
	Lanes  []releaseLane
	// Reason is the rollback or hold reason, when there is one.
	Reason string
}

type releaseLane struct {
	Region string
	Steps  []releaseStep
}

type releaseStep struct {
	Stage    string
	Decision *decisionlog.Decision
	Label    string
	Status   string
	// Count is how many decisions the step folds (batches).
	Count int
}

func releaseID(decision decisionlog.Decision) (id, name string) {
	if decision.Subject.Kind == "release" && decision.Subject.ID != "" {
		return decision.Subject.ID, cmp.Or(decision.Subject.Name, decision.Attrs["version"], decision.Subject.ID)
	}
	if id := decision.Attrs["release"]; id != "" {
		return id, cmp.Or(decision.Attrs["version"], id)
	}
	return "", ""
}

// releaseStage places a decision on the timeline.
func releaseStage(decision decisionlog.Decision) string {
	if stage := decision.Attrs["stage"]; slices.Contains(releaseStages, stage) {
		return stage
	}
	switch decision.Kind {
	case decisionlog.KindReleaseAdmitted:
		return "signed"
	case decisionlog.KindUpgradeStarted:
		return "staged"
	case decisionlog.KindCanaryPromoted:
		return "canary"
	case decisionlog.KindHeld, decisionlog.KindHoldCleared, decisionlog.KindFrozen:
		return "soak"
	case decisionlog.KindBatchPromoted:
		return "batches"
	case decisionlog.KindRolloutCompleted, decisionlog.KindRollback:
		return "outcome"
	default:
		return ""
	}
}

// releases groups the loaded decisions into release timelines, newest
// first.
func (current view) releases() []releaseView {
	byID := map[string]*releaseView{}
	lanes := map[string]map[string]map[string]*releaseStep{}
	// Oldest first, so a later decision for the same step wins.
	decisions := slices.Clone(current.decisions())
	slices.Reverse(decisions)
	for index := range decisions {
		decision := &decisions[index]
		id, name := releaseID(*decision)
		stage := releaseStage(*decision)
		if id == "" || stage == "" {
			continue
		}
		release := byID[id]
		if release == nil {
			release = &releaseView{ID: id, Name: name, First: decision.Time}
			byID[id] = release
			lanes[id] = map[string]map[string]*releaseStep{}
		}
		release.Last = decision.Time
		if lanes[id][decision.Region] == nil {
			lanes[id][decision.Region] = map[string]*releaseStep{}
		}
		steps := lanes[id][decision.Region]
		step := steps[stage]
		if step == nil {
			step = &releaseStep{Stage: stage}
			steps[stage] = step
		}
		step.Count++
		step.Decision = decision
		step.Status = decisionStatus(decision.Status)
		step.Label = kindLabel(decision.Kind)
		switch decision.Kind {
		case decisionlog.KindReleaseAdmitted:
			step.Label = cmp.Or(decision.Attrs["delegation"], "admitted")
			qualified := &releaseStep{Stage: "qualified", Decision: decision, Count: 1, Status: "ok",
				Label: cmp.Or(decision.Attrs["qualification"], "qualified")}
			if decision.Attrs["qualification"] == "failed" {
				qualified.Status = "bad"
			}
			steps["qualified"] = qualified
		case decisionlog.KindBatchPromoted:
			step.Label = "batch " + cmp.Or(decision.Attrs["batch"], strconv.Itoa(step.Count))
			if total := decision.Attrs["batches"]; total != "" {
				step.Label += " of " + total
			}
		case decisionlog.KindRollback:
			step.Label, step.Status = "rolled back", "serious"
			release.Reason = cmp.Or(decision.Reason, decision.Summary)
		case decisionlog.KindRolloutCompleted:
			step.Label = "complete"
		case decisionlog.KindHeld, decisionlog.KindFrozen:
			step.Label, step.Status = kindLabel(decision.Kind), "warn"
			if release.Reason == "" {
				release.Reason = cmp.Or(decision.Reason, decision.Summary)
			}
		case decisionlog.KindHoldCleared:
			step.Label = "soak passed"
		}
	}
	out := make([]releaseView, 0, len(byID))
	for id, release := range byID {
		complete, rolledBack, running := 0, 0, 0
		for _, region := range current.orderRegions(slices.Collect(maps.Keys(lanes[id]))) {
			steps := lanes[id][region]
			lane := releaseLane{Region: region}
			for _, stage := range releaseStages {
				if step := steps[stage]; step != nil {
					lane.Steps = append(lane.Steps, *step)
				} else {
					lane.Steps = append(lane.Steps, releaseStep{Stage: stage})
				}
			}
			release.Lanes = append(release.Lanes, lane)
			switch outcome := steps["outcome"]; {
			case outcome != nil && outcome.Decision.Kind == decisionlog.KindRollback:
				rolledBack++
			case outcome != nil:
				complete++
			default:
				running++
			}
		}
		switch {
		case rolledBack > 0:
			release.Status, release.Label = "serious", "rolled back in "+itoa(rolledBack)+" region(s)"
		case running == 0:
			release.Status, release.Label = "ok", "complete everywhere"
		default:
			release.Status, release.Label = "run", "in progress: "+itoa(complete)+" of "+itoa(len(release.Lanes))+" regions complete"
		}
		out = append(out, *release)
	}
	slices.SortFunc(out, func(left, right releaseView) int { return right.Last.Compare(left.Last) })
	return out
}

// orderRegions sorts regions as the region summaries list them (this region
// first), then by name.
func (current view) orderRegions(regions []string) []string {
	rank := map[string]int{}
	for index, summary := range current.Regions {
		rank[summary.Region] = index + 1
	}
	slices.SortFunc(regions, func(left, right string) int {
		leftRank, rightRank := rank[left], rank[right]
		if leftRank == 0 {
			leftRank = len(rank) + 1
		}
		if rightRank == 0 {
			rightRank = len(rank) + 1
		}
		return cmp.Or(cmp.Compare(leftRank, rightRank), cmp.Compare(left, right))
	})
	return regions
}

// knownBad lists releases rolled back anywhere, newest first.
func (current view) knownBad() []releaseView {
	var out []releaseView
	for _, release := range current.releases() {
		if release.Status == "serious" {
			out = append(out, release)
		}
	}
	return out
}

// versionCell is one region x unit-kind cell of the version matrix.
type versionCell struct {
	Versions []versionCount
	Total    int
	Drift    bool
}

type versionCount struct {
	Version string
	Count   int
	Target  bool
}

// unitKinds are the matrix rows, in order.
var unitKinds = []string{"controller", "host", "seat"}

var unitKindTitles = map[string]string{"controller": "Controllers", "host": "Hosts", "seat": "TerraBase seats"}

// targetVersion is the newest healthy release a unit of the kind runs, or
// else the version most units of the kind run, ties broken by the newest
// name; units of that kind on any other version are drifted. Kinds run
// different software (orchestrator, TerraBase), so each has its own target.
func (current view) targetVersion(kind string) string {
	counts := map[string]int{}
	for _, unit := range current.Versions {
		if unit.Version != "" && unit.Kind == kind {
			counts[unit.Version]++
		}
	}
	// The newest release that is rolling out or complete (not rolled back)
	// is the target when units of this kind run it.
	for _, release := range current.releases() {
		if release.Status != "serious" && counts[release.Name] > 0 {
			return release.Name
		}
	}
	best := ""
	for _, version := range slices.Sorted(maps.Keys(counts)) {
		if counts[version] >= counts[best] {
			best = version
		}
	}
	return best
}

func (current view) matrixRegions() []string {
	seen := map[string]bool{}
	var regions []string
	for _, summary := range current.Regions {
		seen[summary.Region] = true
		regions = append(regions, summary.Region)
	}
	for _, unit := range current.Versions {
		if !seen[unit.Region] {
			seen[unit.Region] = true
			regions = append(regions, unit.Region)
		}
	}
	return regions
}

func (current view) matrixKinds() []string {
	present := map[string]bool{}
	for _, unit := range current.Versions {
		present[unit.Kind] = true
	}
	var kinds []string
	for _, kind := range unitKinds {
		if present[kind] {
			kinds = append(kinds, kind)
			delete(present, kind)
		}
	}
	return append(kinds, slices.Sorted(maps.Keys(present))...)
}

func (current view) versionCell(region, kind string) versionCell {
	target := current.targetVersion(kind)
	counts := map[string]int{}
	cell := versionCell{}
	for _, unit := range current.Versions {
		if unit.Region == region && unit.Kind == kind {
			counts[unit.Version]++
			cell.Total++
		}
	}
	for _, version := range slices.Sorted(maps.Keys(counts)) {
		cell.Versions = append(cell.Versions, versionCount{Version: version, Count: counts[version], Target: version == target})
		if version != target {
			cell.Drift = true
		}
	}
	cell.Drift = cell.Drift || len(cell.Versions) > 1
	return cell
}

// driftedUnits lists units off the target version.
func (current view) driftedUnits() []UnitVersion {
	targets := map[string]string{}
	var out []UnitVersion
	for _, unit := range current.Versions {
		if _, ok := targets[unit.Kind]; !ok {
			targets[unit.Kind] = current.targetVersion(unit.Kind)
		}
		if unit.Version != targets[unit.Kind] {
			out = append(out, unit)
		}
	}
	slices.SortFunc(out, func(left, right UnitVersion) int {
		return cmp.Or(cmp.Compare(left.Region, right.Region), cmp.Compare(left.Kind, right.Kind),
			cmp.Compare(left.Unit, right.Unit))
	})
	return out
}

func versionStatus(target bool) string {
	if target {
		return "ok"
	}
	return "warn"
}

func qualificationStatus(status string) string {
	switch status {
	case "passed", "pass", "ok", "succeeded":
		return "ok"
	case "failed", "fail", "error":
		return "bad"
	case "running", "in_progress":
		return "run"
	case "skipped", "flaky":
		return "warn"
	default:
		return "idle"
	}
}

func unitKindTitle(kind string) string {
	if title, ok := unitKindTitles[kind]; ok {
		return title
	}
	return kind
}
