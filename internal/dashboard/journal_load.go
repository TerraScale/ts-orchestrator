package dashboard

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
)

// summaryWindows are the plain-language summary windows every overview shows.
var summaryWindows = []time.Duration{time.Hour, 24 * time.Hour}

// loadJournal fills the journal-backed parts of a view. Every provider is
// optional; a failing one is named in Unavailable and its section renders
// an explicit unavailable state.
func (dashboard *Dashboard) loadJournal(ctx context.Context, current *view) {
	holder := dashboard.journal.Load()
	if holder == nil {
		return
	}
	journal := *holder
	current.Journal = &journal
	needs := current.Page.needs
	// The region switcher and the attention badge are on every page; both
	// providers answer from short caches or memory.
	if journal.Regions != nil {
		current.Regions = journal.Regions.Regions(ctx)
	}
	if journal.Insights != nil {
		evaluation := journal.Insights.Current()
		current.Evaluation = &evaluation
	}
	if needs&needSummaries != 0 && journal.Summaries != nil {
		for _, window := range summaryWindows {
			summary, err := dashboard.summaries.get(ctx, window.String(), func(ctx context.Context) (insights.Summary, error) {
				return journal.Summaries.Summary(ctx, window)
			})
			if err != nil {
				current.Unavailable = append(current.Unavailable, "summary "+window.String())
				continue
			}
			current.Summaries = append(current.Summaries, summary)
		}
	}
	if current.Page.decisions != nil && journal.Decisions != nil {
		if query := current.Page.decisions(*current); query != nil {
			key, _ := json.Marshal(query)
			result, err := dashboard.decisions.get(ctx, string(key), func(ctx context.Context) (decisionlog.Result, error) {
				return journal.Decisions.Query(ctx, *query)
			})
			if err != nil {
				current.Unavailable = append(current.Unavailable, "decision journal")
			} else {
				current.Decisions = &result
			}
		}
	}
	if id := current.State.param("id"); needs&needChain != 0 && id != "" && journal.Decisions != nil {
		if chain, err := journal.Decisions.Chain(ctx, id); err == nil {
			current.Chain = &chain
		}
	}
	if needs&needVersions != 0 {
		current.loadVersions(ctx)
	}
	if needs&needRollouts != 0 && journal.Rollouts != nil {
		if rollouts, err := journal.Rollouts.Rollouts(ctx); err != nil {
			current.Unavailable = append(current.Unavailable, "rollouts")
		} else {
			current.Rollouts = rollouts
		}
	}
	if needs&needVolumes != 0 && journal.Volumes != nil {
		if volumes, err := journal.Volumes.Volumes(ctx); err != nil {
			current.Unavailable = append(current.Unavailable, "volumes")
		} else {
			current.Volumes = volumes
		}
	}
	if needs&needQualification != 0 && journal.Qualification != nil {
		if runs, err := journal.Qualification.Qualifications(ctx); err != nil {
			current.Unavailable = append(current.Unavailable, "qualification")
		} else {
			current.Qualifications = runs
		}
	}
	if needs&needInventory != 0 && journal.Inventory != nil {
		if items, err := journal.Inventory.Inventory(ctx); err != nil {
			current.Unavailable = append(current.Unavailable, "OCI inventory")
		} else {
			current.Inventory = items
		}
	}
}

// loadVersions reads the version source, or derives orchestrator member
// versions from the region summaries and the local cluster snapshot.
func (current *view) loadVersions(ctx context.Context) {
	if source := current.Journal.Versions; source != nil {
		versions, err := source.Versions(ctx)
		if err == nil {
			current.Versions = versions
			return
		}
		current.Unavailable = append(current.Unavailable, "unit versions")
	}
	current.VersionsDerived = true
	local := current.localRegion()
	roles := map[string]string{}
	for _, member := range current.members() {
		roles[member.Member] = member.Role
	}
	for _, summary := range current.Regions {
		for _, version := range summary.Versions {
			for _, member := range version.Members {
				kind := "controller"
				if summary.Region == local && roles[member] != "" {
					kind = roles[member]
				}
				current.Versions = append(current.Versions, UnitVersion{Region: summary.Region, Kind: kind,
					Unit: member, Version: version.Version})
			}
		}
	}
	if len(current.Regions) == 0 {
		for _, member := range current.members() {
			current.Versions = append(current.Versions, UnitVersion{Region: local, Kind: member.Role,
				Unit: member.Member, Version: member.BuildVersion})
		}
	}
}

// localRegion is this member's region token.
func (current view) localRegion() string { return strings.ToLower(current.cell()) }

// region is the selected region, defaulting to this member's.
func (current view) region() string {
	if current.State.Region != "" {
		return current.State.Region
	}
	return current.localRegion()
}

// remote reports that the selected region is not this member's, so only its
// summary (not its live member detail) is available here.
func (current view) remote() bool {
	return current.State.Region != "" && current.State.Region != current.localRegion()
}

// queryNow rounds the clock so repeated ticks share the decision cache.
func (current view) queryNow() time.Time { return current.Now.Truncate(decisionCacheTTL) }

func (current view) since(minimum time.Duration) time.Time {
	return current.queryNow().Add(-max(current.State.Range.Duration, minimum))
}

func globalDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Since: current.since(0), Limit: 300}
}

func regionDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.region()}, Since: current.since(0), Limit: 100}
}

// journalDecisions reads the decisions page filters.
func journalDecisions(current view) *decisionlog.Query {
	regions := current.State.list("region")
	if len(regions) == 0 && current.State.Region != "" {
		regions = []string{current.State.Region}
	}
	query := decisionlog.Query{Regions: regions, Actors: current.State.list("actor"),
		Subject: strings.ToLower(current.State.param("q")), Since: current.since(0), Limit: 500}
	for _, kind := range current.State.list("kind") {
		query.Kinds = append(query.Kinds, decisionlog.Kind(kind))
	}
	for _, status := range current.State.list("status") {
		query.Statuses = append(query.Statuses, decisionlog.Status(status))
	}
	return &query
}

// releaseKinds are the decisions a release timeline is built from.
var releaseKinds = []decisionlog.Kind{decisionlog.KindReleaseAdmitted, decisionlog.KindUpgradeStarted,
	decisionlog.KindCanaryPromoted, decisionlog.KindBatchPromoted, decisionlog.KindRolloutCompleted,
	decisionlog.KindRollback, decisionlog.KindHeld, decisionlog.KindHoldCleared, decisionlog.KindFrozen}

const releaseHistory = 7 * 24 * time.Hour

func releaseDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Kinds: releaseKinds, Since: current.since(releaseHistory),
		Limit: decisionlog.MaxQueryLimit}
}

func rolloutDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Kinds: releaseKinds,
		Since: current.since(releaseHistory), Limit: 300}
}

func qualificationDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindReleaseAdmitted},
		Since: current.since(releaseHistory), Limit: 100}
}

func natsDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.region()}, Since: current.since(24 * time.Hour), Limit: 200,
		Kinds: []decisionlog.Kind{decisionlog.KindLeaderChanged, decisionlog.KindQuorumDegraded,
			decisionlog.KindQuorumRestored}}
}

func terrabaseDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.region()}, Since: current.since(24 * time.Hour), Limit: 300,
		Kinds: []decisionlog.Kind{decisionlog.KindScaleUp, decisionlog.KindScaleDown, decisionlog.KindStageChanged,
			decisionlog.KindMemberReplaced, decisionlog.KindHostLaunched, decisionlog.KindHostReclaimed,
			decisionlog.KindHeld}}
}

func storageDecisions(current view) *decisionlog.Query {
	return &decisionlog.Query{Regions: []string{current.region()}, Since: current.since(24 * time.Hour), Limit: 200,
		Kinds: []decisionlog.Kind{decisionlog.KindBackupTaken, decisionlog.KindVolumeResized,
			decisionlog.KindVolumeReattached}}
}

// decisions returns the loaded decisions, newest first.
func (current view) decisions() []decisionlog.Decision {
	if current.Decisions == nil {
		return nil
	}
	return current.Decisions.Decisions
}

// decisionsOf filters the loaded decisions by kind.
func (current view) decisionsOf(kinds ...decisionlog.Kind) []decisionlog.Decision {
	var out []decisionlog.Decision
	for _, decision := range current.decisions() {
		if slices.Contains(kinds, decision.Kind) {
			out = append(out, decision)
		}
	}
	return out
}
