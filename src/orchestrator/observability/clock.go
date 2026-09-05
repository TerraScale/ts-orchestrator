// Clock-offset metric wiring for the D-69 clock rule.
//
// ts-node samples chrony on every host and publishes the offset, the
// measured marker, and the write-health flag in its heartbeat facts
// (hostagent.HostFacts). Grafana Cloud never sees those facts directly:
// this file is the wiring seam that turns one sampled clock fact into
// bounded dashboard observations the composition root forwards through
// EventRouter.EmitObservation.
//
// ClockSample mirrors hostplatform.ClockOffsetSample without importing the
// hostagent package, keeping the observability boundary a leaf in the
// package graph. The composition root converts one HostFacts heartbeat
// (ClockOffsetMillis, ClockMeasured, ClockUnhealthy) into a ClockSample
// field-for-field.
//
// Fail-closed rules, matching the host agent: an unreadable clock
// (Measured=false) reports unhealthy with a zero offset and still emits
// both observations, so silence can never read as healthy. Clock facts are
// dashboard-only and can never page; only SLO burn-rate events may page.
package observability

import (
	"errors"
	"time"
)

const (
	// ClockOffsetSecondsName is the signed chrony system-time offset of one
	// host, in seconds. Positive means the local clock is fast of NTP time.
	ClockOffsetSecondsName = "host.clock_offset_seconds"

	// ClockUnhealthyName is 1 while the host is beyond the D-69
	// write-refusal threshold (or its clock is unreadable) and 0 while it
	// is healthy for writes.
	ClockUnhealthyName = "host.clock_unhealthy"

	// ClockWriteRefusalOffsetMillis mirrors the host agent's D-69 bound:
	// beyond 500 ms magnitude a member never mints HLC timestamps from its
	// local clock. It is repeated here so this leaf package does not
	// import the host agent.
	ClockWriteRefusalOffsetMillis = 500

	// ClockWarnOffsetMillis is the dashboard warn line at 400 ms magnitude,
	// mirroring the terrabase ClockOffsetHigh rule. Crossing it means the
	// host is approaching the refusal line.
	ClockWarnOffsetMillis = 400

	// maxClockOffsetMillis bounds one sample to one hour of magnitude. A
	// real chrony offset beyond that is either a misconfigured clock the
	// operator must fix out of band or a corrupt fact; either way the
	// boundary rejects it rather than charting it.
	maxClockOffsetMillis = 3_600_000
)

// ClockSample is one sampled clock fact, converted field-for-field from the
// host agent's heartbeat (HostFacts.ClockOffsetMillis, ClockMeasured,
// ClockUnhealthy).
type ClockSample struct {
	// OffsetMillis is the signed system-time offset from NTP time.
	OffsetMillis int64
	// Measured is false when chrony could not be read.
	Measured bool
	// Unhealthy reports whether the host is beyond the write-refusal
	// threshold. An unreadable clock always reports unhealthy.
	Unhealthy bool
}

// Validate enforces the fail-closed shape: bounded offset magnitude and an
// unreadable clock that claims to be healthy is rejected.
func (s ClockSample) Validate() error {
	if s.OffsetMillis < -maxClockOffsetMillis || s.OffsetMillis > maxClockOffsetMillis {
		return errors.New("clock offset exceeds one hour")
	}
	if !s.Measured && !s.Unhealthy {
		return errors.New("an unreadable clock must report unhealthy")
	}
	if !s.Measured && s.OffsetMillis != 0 {
		return errors.New("an unreadable clock must carry a zero offset")
	}
	if s.Measured {
		magnitude := s.OffsetMillis
		if magnitude < 0 {
			magnitude = -magnitude
		}
		expectedUnhealthy := magnitude > ClockWriteRefusalOffsetMillis
		if s.Unhealthy != expectedUnhealthy {
			return errors.New("clock unhealthy flag does not match measured offset")
		}
	}
	return nil
}

// ClockApproachingRefusal reports whether a measured sample has reached the
// 400 ms warn line. Unreadable clocks report false here: they are already
// unhealthy, and the warn line is about a measured drift approaching the
// 500 ms refusal bound.
func ClockApproachingRefusal(sample ClockSample) (bool, error) {
	if err := sample.Validate(); err != nil {
		return false, err
	}
	if !sample.Measured {
		return false, nil
	}
	magnitude := sample.OffsetMillis
	if magnitude < 0 {
		magnitude = -magnitude
	}
	return magnitude >= ClockWarnOffsetMillis, nil
}

// ClockObservations wires one clock sample into its two dashboard
// observations: the signed offset in seconds and the 0/1 unhealthy flag.
// Both carry region and host labels, which must be admitted by the
// allow-list; host values are added explicitly by the regional composition
// root so the cardinality decision stays visible in config.
func ClockObservations(allow LabelAllowList, region, host string, sample ClockSample, timestamp time.Time) ([]DashboardObservation, error) {
	if err := allow.Validate(); err != nil {
		return nil, err
	}
	if err := sample.Validate(); err != nil {
		return nil, err
	}
	labels := map[string]string{"region": region, "host": host}
	if err := allow.ValidateLabels(labels); err != nil {
		return nil, err
	}
	unhealthy := 0.0
	if sample.Unhealthy {
		unhealthy = 1.0
	}
	return []DashboardObservation{
		{
			Name:      ClockOffsetSecondsName,
			Labels:    cloneLabels(labels),
			Value:     float64(sample.OffsetMillis) / 1000.0,
			Timestamp: timestamp,
		},
		{
			Name:      ClockUnhealthyName,
			Labels:    cloneLabels(labels),
			Value:     unhealthy,
			Timestamp: timestamp,
		},
	}, nil
}
