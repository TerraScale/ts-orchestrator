// Egress telemetry per Region for the D-66 network cost model.
//
// Cross-Region journal frames, bootstrap snapshots, and direct member reads
// bill as OCI outbound at the source Region's rate; intra-Region traffic is
// free. D-66 bounds that spend with a Grafana alert at 8 TB/month per
// Region. This file wires the dashboard side of that contract: a bounded,
// label-checked egress observation per Region and the hourly pace predicate
// that mirrors the production alert expression.
//
// Egress observations are dashboard-only. They carry no paging method and
// can only reach the dashboard sink through EventRouter.EmitObservation.
// Only SLO burn-rate events may page.
package observability

import (
	"errors"
	"math"
	"time"
)

const (
	// EgressBytesTotalName is the canonical dashboard metric for billable
	// OCI outbound bytes attributed to one Region. The Prometheus
	// export layer renders the dots as underscores.
	EgressBytesTotalName = "egress.bytes_total"

	// EgressMonthlyBudgetBytes is the D-66 alert line: 8 TB/month per
	// Region, in decimal bytes to match OCI metering.
	EgressMonthlyBudgetBytes = 8_000_000_000_000.0

	// EgressHourlyPaceThresholdBytes is the hourly pace that reaches the
	// monthly budget in a 720-hour month: 8e12 / 720 rounded down. It
	// mirrors the terrabase EgressMonthlyHigh rule
	// (increase(...[1h]) > 11111111111 sustained) so the orchestrator
	// dashboard and the engine alert agree on the pace.
	EgressHourlyPaceThresholdBytes = 11_111_111_111.0

	// maxEgressBytesTotal bounds one observation to 1 EiB, far above any
	// real Region total but finite for the dashboard sink.
	maxEgressBytesTotal = 1 << 60
)

// EgressObservation builds the dashboard-only egress total for one Region.
// region must be an admitted allow-list value (gru, sfo, fra, unknown by
// default); bytesTotal is the cumulative billable outbound bytes for that
// Region and must be finite, non-negative, and bounded.
func EgressObservation(allow LabelAllowList, region string, bytesTotal float64, timestamp time.Time) (DashboardObservation, error) {
	if err := allow.Validate(); err != nil {
		return DashboardObservation{}, err
	}
	if math.IsNaN(bytesTotal) || math.IsInf(bytesTotal, 0) {
		return DashboardObservation{}, errors.New("egress total must be finite")
	}
	if bytesTotal < 0 || bytesTotal > maxEgressBytesTotal {
		return DashboardObservation{}, errors.New("egress total must be between 0 and 1 EiB")
	}
	labels := map[string]string{"region": region}
	if err := allow.ValidateLabels(labels); err != nil {
		return DashboardObservation{}, err
	}
	return DashboardObservation{
		Name:      EgressBytesTotalName,
		Labels:    labels,
		Value:     bytesTotal,
		Timestamp: timestamp,
	}, nil
}

// EgressPaceExceedsMonthlyBudget reports whether one hourly egress increase
// is on pace to pass the D-66 monthly budget. hourlyBytes is the
// increase(egress_bytes_total[1h]) for one Region. A positive result is a
// dashboard fact, never a page: only SLO burn-rate events may page.
func EgressPaceExceedsMonthlyBudget(hourlyBytes float64) (bool, error) {
	if math.IsNaN(hourlyBytes) || math.IsInf(hourlyBytes, 0) {
		return false, errors.New("hourly egress increase must be finite")
	}
	if hourlyBytes < 0 || hourlyBytes > maxEgressBytesTotal {
		return false, errors.New("hourly egress increase must be between 0 and 1 EiB")
	}
	return hourlyBytes > EgressHourlyPaceThresholdBytes, nil
}

// EgressExceedsMonthlyBudget reports whether a cumulative Region total has
// crossed the dashboard warning line. This is intentionally a predicate,
// not a page event: egress remains a cause condition and only SLO burn may
// reach the paging sink.
func EgressExceedsMonthlyBudget(bytesTotal float64) (bool, error) {
	if math.IsNaN(bytesTotal) || math.IsInf(bytesTotal, 0) {
		return false, errors.New("egress total must be finite")
	}
	if bytesTotal < 0 || bytesTotal > maxEgressBytesTotal {
		return false, errors.New("egress total must be between 0 and 1 EiB")
	}
	return bytesTotal > EgressMonthlyBudgetBytes, nil
}
