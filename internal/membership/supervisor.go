package membership

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultInterval is how often the supervisor observes the local broker.
	DefaultInterval = 10 * time.Second
	// DefaultLagThreshold is the metadata lag, in operations, beyond which an
	// otherwise current peer is reported as lagging.
	DefaultLagThreshold uint64 = 1000
)

// Reporter receives every evaluated status. A metrics or KV publisher can
// implement it; it must return quickly and must not block the supervisor.
type Reporter interface {
	ReportClusterHealth(Status)
}

// ReporterFunc adapts a function to Reporter.
type ReporterFunc func(Status)

func (report ReporterFunc) ReportClusterHealth(status Status) { report(status) }

// Supervisor periodically observes the local broker and keeps the latest
// evaluated status. It logs only state transitions so a steady degraded
// cluster does not flood the journal, plus a periodic reminder while not
// healthy.
type Supervisor struct {
	Observe      func() (Observation, error)
	Interval     time.Duration
	LagThreshold uint64
	// Remind repeats the current non-healthy status at this interval even
	// without a transition. Zero uses ten observation intervals.
	Remind   time.Duration
	Logger   *slog.Logger
	Reporter Reporter
	Now      func() time.Time

	mu       sync.Mutex
	current  Status
	have     bool
	loggedAt time.Time
}

// Current returns the most recent status and whether one was observed yet.
func (supervisor *Supervisor) Current() (Status, bool) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.current, supervisor.have
}

// Run observes until ctx ends. It returns nil on cancellation and an error
// only when the supervisor is misconfigured; observation failures are
// reported as PhaseUnknown and never stop the loop.
func (supervisor *Supervisor) Run(ctx context.Context) error {
	if supervisor == nil || supervisor.Observe == nil {
		return errors.New("cluster health supervisor requires an observer")
	}
	interval := supervisor.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		supervisor.Tick()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Tick performs one observation, evaluation, report, and transition log.
func (supervisor *Supervisor) Tick() Status {
	now := time.Now
	if supervisor.Now != nil {
		now = supervisor.Now
	}
	threshold := supervisor.LagThreshold
	if threshold == 0 {
		threshold = DefaultLagThreshold
	}
	observedAt := now().UTC()
	observation, err := supervisor.Observe()
	var status Status
	if err != nil {
		status = Status{ObservedAt: observedAt, Phase: PhaseUnknown, ServerName: observation.ServerName,
			Error: err.Error()}
	} else {
		status = Evaluate(observation, threshold, observedAt)
	}
	supervisor.mu.Lock()
	previous, had := supervisor.current, supervisor.have
	supervisor.current, supervisor.have = status, true
	remind := supervisor.Remind
	if remind <= 0 {
		interval := supervisor.Interval
		if interval <= 0 {
			interval = DefaultInterval
		}
		remind = 10 * interval
	}
	changed := !had || !status.sameState(previous)
	due := !status.Healthy() && observedAt.Sub(supervisor.loggedAt) >= remind
	if changed || due {
		supervisor.loggedAt = observedAt
	}
	supervisor.mu.Unlock()
	if changed || due {
		supervisor.log(status, changed)
	}
	if supervisor.Reporter != nil {
		supervisor.Reporter.ReportClusterHealth(status)
	}
	return status
}

func (supervisor *Supervisor) log(status Status, transition bool) {
	logger := supervisor.Logger
	if logger == nil {
		logger = slog.Default()
	}
	level := slog.LevelWarn
	if status.Healthy() {
		level = slog.LevelInfo
	}
	message := "regional cluster health"
	if transition {
		message = "regional cluster health changed"
	}
	attrs := []any{"phase", string(status.Phase), "server", status.ServerName,
		"meta_leader", status.MetaLeader, "meta_size", status.MetaSize, "quorum_needed", status.QuorumNeeded,
		"online", status.Online, "offline", status.Offline, "missing", status.Missing,
		"unknown", status.Unknown, "unrouted", status.Unrouted}
	if len(status.Lagging) != 0 {
		attrs = append(attrs, "lagging", status.Lagging)
	}
	if status.Error != "" {
		attrs = append(attrs, "error", status.Error)
	}
	logger.Log(context.Background(), level, message, attrs...)
}
