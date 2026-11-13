package observability

import (
	"time"
)

// History tiers. Raw samples are kept for an hour, one-minute rollups for
// six hours, five-minute rollups for a day and hourly rollups for 14 days.
// A range query reads the finest tier that still covers its start.
const (
	TierRaw = "raw"
	Tier1m  = "1m"
	Tier5m  = "5m"
	Tier1h  = "1h"

	DefaultHistoryInterval = 10 * time.Second
	DefaultHistorySeries   = 4096
	rawRetention           = time.Hour
	oneMinuteRetention     = 6 * time.Hour
	fiveMinuteRetention    = 24 * time.Hour
	// HistoryRetention is the oldest metric data retained for queries.
	HistoryRetention = 14 * 24 * time.Hour
)

// Point is one value of a series at a time. Min and Max are the range of the
// raw samples a rollup covers; for a raw point they equal Value.
type Point struct {
	Time  time.Time `json:"t"`
	Value float64   `json:"v"`
	Min   float64   `json:"min"`
	Max   float64   `json:"max"`
	// Samples lets in-process charts detect omitted observations within a bucket.
	Samples uint32 `json:"-"`
}

var ()

// HistoryQuery selects series and a time range.
type HistoryQuery struct {
	Metric string
	// Labels must all match; an empty value matches any value of the
	// label as long as the series has it.
	Labels map[string]string
	Start  time.Time
	End    time.Time
	// Tier forces a tier; empty picks the finest tier covering Start.
	Tier string
	// Rate turns a counter into its per-second rate between points.
	Rate bool
	// MaxSeries bounds the result; zero means 64.
	MaxSeries int
}

// HistorySeries is one matching series in a range.
type HistorySeries struct {
	Metric         string            `json:"metric"`
	Labels         map[string]string `json:"labels,omitempty"`
	Tier           string            `json:"tier"`
	Points         []Point           `json:"points"`
	LastObservedAt time.Time         `json:"last_observed_at"`
	Stale          bool              `json:"stale,omitzero"`
	Gaps           bool              `json:"gaps,omitzero"`
}

// HistoryResult is a range query's answer.
type HistoryResult struct {
	RetentionStart  time.Time `json:"retention_start"`
	IntervalSeconds float64   `json:"interval_seconds"`
	// DroppedSeries counts rejected new series over this store's lifetime.
	DroppedSeries     uint64          `json:"dropped_series,omitzero"`
	Series            []HistorySeries `json:"series"`
	UnsupportedReason string          `json:"unsupported_reason,omitempty"`
	// Truncated reports that more series matched than MaxSeries.
	Truncated bool `json:"truncated,omitzero"`
	// Pending marks regional history that has not completed archive replay.
	Pending bool `json:"pending,omitzero"`
	// Incomplete marks retained samples omitted or rejected during regional replay.
	Incomplete bool `json:"incomplete,omitzero"`
}

// HistorySource is the range-query interface the dashboard charts and the
// insight rules depend on. History implements it.
type HistorySource interface {
	Range(query HistoryQuery) HistoryResult
	Metrics() []string
}

// TierFor returns the finest tier whose retention covers start, given now.
func TierFor(start, now time.Time) string {
	age := now.Sub(start)
	switch {
	case age <= rawRetention:
		return TierRaw
	case age <= oneMinuteRetention:
		return Tier1m
	case age <= fiveMinuteRetention:
		return Tier5m
	default:
		return Tier1h
	}
}
