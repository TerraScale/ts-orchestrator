package regionview

import (
	"context"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// LinkProbe is the most recent scheduled request to another region.
type LinkProbe struct {
	Region        string    `json:"region"`
	Member        string    `json:"member"`
	StartedAt     time.Time `json:"started_at"`
	ObservedAt    time.Time `json:"observed_at"`
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	Reach         string    `json:"reach"`
	RoundTripMS   float64   `json:"round_trip_ms"`
	WAN           string    `json:"wan"`
	Lag           *float64  `json:"lag,omitzero"`
	Detail        string    `json:"detail,omitempty"`
	Recovery      string    `json:"recovery,omitempty"`
}

// WANPeer is one region's received TerraBase replication stream.
type WANPeer struct {
	SourceRegion     string    `json:"source_region"`
	Node             string    `json:"node"`
	ObservedAt       time.Time `json:"observed_at"`
	Lag              float64   `json:"lag"`
	Members          int       `json:"members"`
	StalenessSeconds float64   `json:"staleness_seconds"`
	Conflicts        float64   `json:"conflicts"`
	Unregistered     float64   `json:"unregistered"`
	AheadFailures    *float64  `json:"ahead_failures,omitzero"`
}

// Probe bypasses the dashboard cache so each scheduled request tests the link.
func (provider *Provider) Probe(ctx context.Context, region string) Summary {
	summary := provider.remote(ctx, region)
	if summary.Reach == decisionlog.RegionOK && (summary.ObservedAt.IsZero() ||
		provider.now().Sub(summary.ObservedAt) > 2*time.Minute || summary.ObservedAt.After(provider.now().Add(time.Minute))) {
		summary.Reach = decisionlog.RegionError
		summary.Health = Health{Status: StatusUnknown, Reasons: []string{"region answered with stale telemetry"}}
	}
	return summary
}
