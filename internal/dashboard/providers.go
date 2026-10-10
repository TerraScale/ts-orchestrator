package dashboard

import (
	"context"
	"errors"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// Journal holds the read-only providers behind the global view, the
// decision journal, the insights panel, the release views and every chart.
// A controller attaches it once its journal, history sampler, insight engine
// and region provider run; every field is optional and a missing one renders
// a "no data yet" state, never invented data.
type Journal struct {
	// Decisions answers decision queries, usually federated across regions.
	Decisions decisionlog.Source
	// Live streams this region's new decisions.
	Live decisionlog.LiveSource
	// History is the metric ring-buffer store the charts read.
	History observability.HistorySource
	// Insights is the ranked needs-attention list; its changes raise toasts.
	Insights insights.Source
	// Summaries writes the plain-language 1h and 24h paragraphs.
	Summaries SummarySource
	// Local summarizes this region. It never asks another region.
	Local func(context.Context) regionview.Summary
	// Global holds every region's newest rollup, in memory (TS-805).
	Global *globalview.View
	// Budget reads TS-804's global capacity document from the local mirror.
	Budget BudgetSource

	// The providers below belong to slices built in parallel (rollout,
	// storage, CI, OCI inventory). They stay nil until those slices land.
	Versions      VersionSource
	Rollouts      RolloutSource
	Volumes       insights.VolumeProvider
	Qualification QualificationSource
	Inventory     InventorySource
}

// BudgetSource reads TS-804's global capacity document (budget cap,
// projection and state) from the region's mirror; ok is false before the
// home first writes one.
type BudgetSource interface {
	Capacity(ctx context.Context) (budget.Capacity, bool, error)
}

// ErrRolloutNotFound means no retained release record exists for this exact ID.
var ErrRolloutNotFound = errors.New("rollout record not found")

// RolloutSource supplies recent regional stages and an independent exact lookup.
type RolloutSource interface {
	insights.RolloutProvider
	Rollout(ctx context.Context, id string) (insights.Rollout, error)
}

// SummarySource writes a deterministic summary of a window ending now.
// insights.Summarizer implements it.
type SummarySource interface {
	Summary(ctx context.Context, window time.Duration) (insights.Summary, error)
}

var _ SummarySource = insights.Summarizer{}

// VersionSource lists the build every unit runs, in every region. Without
// one the version matrix is derived from this region's summary and the
// other regions' rollups, which only know orchestrator members.
type VersionSource interface {
	Versions(ctx context.Context) ([]UnitVersion, error)
}

// UnitVersion is one unit's running version.
type UnitVersion struct {
	Region string `json:"region"`
	// Kind is controller, host or seat.
	Kind    string `json:"kind"`
	Unit    string `json:"unit"`
	Version string `json:"version"`
	// Since is when the unit started running Version, when known.
	Since time.Time `json:"since,omitzero"`
}

// QualificationSource lists the latest CI qualification runs.
type QualificationSource interface {
	Qualifications(ctx context.Context) ([]Qualification, error)
}

// Qualification is one CI qualification run of a release candidate.
type Qualification struct {
	Release string    `json:"release"`
	Commit  string    `json:"commit,omitempty"`
	Time    time.Time `json:"time"`
	// Status is passed, failed or running.
	Status string              `json:"status"`
	Suites []QualificationStep `json:"suites,omitempty"`
}

// QualificationStep is one suite of a qualification run.
type QualificationStep struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration"`
	Detail   string        `json:"detail,omitempty"`
}

// InventorySource lists the OCI resources a region owns and their drift.
type InventorySource interface {
	Inventory(ctx context.Context) ([]InventoryItem, error)
}

// InventoryItem is one OCI resource.
type InventoryItem struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region"`
	State  string `json:"state"`
	// Drift is in_sync, drifted, missing or unmanaged.
	Drift string `json:"drift"`
}
