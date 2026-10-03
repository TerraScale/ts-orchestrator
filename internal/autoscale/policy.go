// Package autoscale is the pure replica-count decision core. It turns windowed
// load signals into a desired replica count with a tolerance band,
// stabilization windows, cooldowns and step limits. It performs no I/O and
// never actuates: callers own observation, fencing and desired-state writes.
package autoscale

import (
	"errors"
	"fmt"
	"math"
	"time"
)

var ErrInvalidPolicy = errors.New("invalid autoscaling policy")

const (
	MaxReplicas        = 1024
	maxSignals         = 8
	maxDurationSeconds = 24 * 60 * 60
	maxWindowSeconds   = 60 * 60
	maxMinSamples      = 1000
	maxTolerance       = 0.5
)

// SignalName names one per-replica load measurement. Every signal is compared
// with its Target as "value per current replica"; utilization signals are
// fractions in [0,1] and count signals are absolute per-replica quantities.
type SignalName string

const (
	SignalCPUUtilization                SignalName = "cpu_util"
	SignalMemoryUtilization             SignalName = "mem_util"
	SignalDiskUtilization               SignalName = "disk_util"
	SignalRequestRatePerReplica         SignalName = "request_rate_per_replica"
	SignalTerraBaseConnectionsPerMember SignalName = "tb_connections_per_member"
	SignalTerraBaseStorageBytes         SignalName = "tb_storage_bytes"
	SignalTerraBaseReplicationLag       SignalName = "tb_replication_lag_seq"
	SignalTerraBaseWriteQPS             SignalName = "tb_write_qps"
)

func knownSignal(name SignalName) bool {
	switch name {
	case SignalCPUUtilization, SignalMemoryUtilization, SignalDiskUtilization, SignalRequestRatePerReplica,
		SignalTerraBaseConnectionsPerMember, SignalTerraBaseStorageBytes, SignalTerraBaseReplicationLag,
		SignalTerraBaseWriteQPS:
		return true
	default:
		return false
	}
}

// Aggregation reduces the samples inside a signal window to one value.
type Aggregation string

const (
	AggregateAverage Aggregation = "avg"
	AggregateMax     Aggregation = "max"
	AggregateP95     Aggregation = "p95"
)

func knownAggregation(aggregation Aggregation) bool {
	switch aggregation {
	case AggregateAverage, AggregateMax, AggregateP95:
		return true
	default:
		return false
	}
}

// Signal is one scaling input. Samples older than WindowSeconds are ignored;
// fewer than MinSamples (default 1) makes the signal unavailable.
type Signal struct {
	Name          SignalName  `json:"name"`
	Target        float64     `json:"target"`
	WindowSeconds int         `json:"window_seconds,omitzero"`
	Aggregation   Aggregation `json:"aggregation,omitempty"`
	MinSamples    int         `json:"min_samples,omitzero"`
}

// Window is the signal's sample window, defaulting to one minute.
func (s Signal) Window() time.Duration {
	if s.WindowSeconds == 0 {
		return time.Minute
	}
	return time.Duration(s.WindowSeconds) * time.Second
}

// AggregationOrDefault returns the configured aggregation or the average.
func (s Signal) AggregationOrDefault() Aggregation {
	if s.Aggregation == "" {
		return AggregateAverage
	}
	return s.Aggregation
}

func (s Signal) minSamples() int {
	if s.MinSamples == 0 {
		return 1
	}
	return s.MinSamples
}

// Policy is the horizontal scaling behaviour of one service. Signals are
// evaluated independently: the largest recommendation wins a scale-up, and a
// scale-down requires every signal to be available and agree. Zero step
// limits mean unbounded steps; zero durations disable that guard.
type Policy struct {
	Signals                  []Signal `json:"signals"`
	UpStabilizationSeconds   int      `json:"up_stabilization_seconds,omitzero"`
	DownStabilizationSeconds int      `json:"down_stabilization_seconds,omitzero"`
	UpCooldownSeconds        int      `json:"up_cooldown_seconds,omitzero"`
	DownCooldownSeconds      int      `json:"down_cooldown_seconds,omitzero"`
	MaxStepUp                int      `json:"max_step_up,omitzero"`
	MaxStepDown              int      `json:"max_step_down,omitzero"`
	Tolerance                float64  `json:"tolerance,omitzero"`
}

func seconds(value int) time.Duration { return time.Duration(value) * time.Second }

func (p Policy) upStabilization() time.Duration   { return seconds(p.UpStabilizationSeconds) }
func (p Policy) downStabilization() time.Duration { return seconds(p.DownStabilizationSeconds) }
func (p Policy) upCooldown() time.Duration        { return seconds(p.UpCooldownSeconds) }
func (p Policy) downCooldown() time.Duration      { return seconds(p.DownCooldownSeconds) }

// Validate checks every policy field is bounded and well formed.
func (p Policy) Validate() error {
	if len(p.Signals) == 0 || len(p.Signals) > maxSignals {
		return fmt.Errorf("%w: policy needs 1 to %d signals", ErrInvalidPolicy, maxSignals)
	}
	seen := make(map[SignalName]struct{}, len(p.Signals))
	for _, signal := range p.Signals {
		if !knownSignal(signal.Name) {
			return fmt.Errorf("%w: unknown signal %q", ErrInvalidPolicy, signal.Name)
		}
		if _, exists := seen[signal.Name]; exists {
			return fmt.Errorf("%w: repeated signal %q", ErrInvalidPolicy, signal.Name)
		}
		seen[signal.Name] = struct{}{}
		if !(signal.Target > 0) || math.IsInf(signal.Target, 0) || math.IsNaN(signal.Target) {
			return fmt.Errorf("%w: signal %q target must be positive and finite", ErrInvalidPolicy, signal.Name)
		}
		if signal.WindowSeconds < 0 || signal.WindowSeconds > maxWindowSeconds ||
			signal.MinSamples < 0 || signal.MinSamples > maxMinSamples {
			return fmt.Errorf("%w: signal %q window or sample floor", ErrInvalidPolicy, signal.Name)
		}
		if signal.Aggregation != "" && !knownAggregation(signal.Aggregation) {
			return fmt.Errorf("%w: signal %q aggregation %q", ErrInvalidPolicy, signal.Name, signal.Aggregation)
		}
	}
	for _, value := range []int{p.UpStabilizationSeconds, p.DownStabilizationSeconds, p.UpCooldownSeconds, p.DownCooldownSeconds} {
		if value < 0 || value > maxDurationSeconds {
			return fmt.Errorf("%w: stabilization and cooldown must be within 0..%ds", ErrInvalidPolicy, maxDurationSeconds)
		}
	}
	if p.MaxStepUp < 0 || p.MaxStepUp > MaxReplicas || p.MaxStepDown < 0 || p.MaxStepDown > MaxReplicas {
		return fmt.Errorf("%w: step limits must be within 0..%d", ErrInvalidPolicy, MaxReplicas)
	}
	if !(p.Tolerance >= 0 && p.Tolerance <= maxTolerance) {
		return fmt.Errorf("%w: tolerance must be within 0..%.1f", ErrInvalidPolicy, maxTolerance)
	}
	return nil
}

// Bounds are the inclusive replica limits a decision is clamped to.
type Bounds struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Validate requires 0 <= Min <= Max <= MaxReplicas.
func (b Bounds) Validate() error {
	if b.Min < 0 || b.Max < b.Min || b.Max > MaxReplicas {
		return fmt.Errorf("%w: replica bounds %d..%d", ErrInvalidPolicy, b.Min, b.Max)
	}
	return nil
}

func (b Bounds) clamp(value int) int {
	return min(max(value, b.Min), b.Max)
}
