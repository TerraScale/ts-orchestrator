package ocicost

import (
	"context"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Reader reads a region's report; *Usage implements it.
type Reader interface {
	Read(ctx context.Context, now time.Time) (Report, error)
}

// ReportStore is where the collector keeps the report; *Store implements it.
type ReportStore interface {
	Put(ctx context.Context, report Report) error
	Report(ctx context.Context) (Report, error)
}

const (
	// Interval is how often the leader reads OCI usage.
	Interval       = time.Hour
	retryInterval  = 5 * time.Minute
	followInterval = time.Minute
	readTimeout    = 2 * time.Minute
)

// Collector keeps the region's report fresh. Only the regional authority
// leader reads OCI and writes; a new leader reuses a report younger than
// Interval, so failovers do not multiply Usage API calls.
type Collector struct {
	Store  ReportStore
	Leader func() bool
	// Connect returns the Usage API reader; it is retried until it succeeds.
	Connect func(ctx context.Context) (Reader, error)
	Now     func() time.Time

	reader  Reader
	failure string
}

// Run collects until ctx ends, then returns nil.
func (c *Collector) Run(ctx context.Context) error {
	for {
		timer := time.NewTimer(c.step(ctx))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// step does one collection pass and returns how long to wait before the next.
func (c *Collector) step(ctx context.Context) time.Duration {
	if !c.Leader() {
		return followInterval
	}
	now := c.now()
	// A report younger than Interval is still fresh, whoever wrote it.
	if stored, err := c.Store.Report(ctx); err == nil {
		if age := now.Sub(stored.ObservedAt); age >= 0 && age < Interval {
			return Interval - age
		}
	}
	if c.reader == nil {
		reader, err := c.Connect(ctx)
		if err != nil {
			c.fail(err)
			return retryInterval
		}
		c.reader = reader
	}
	readCtx, cancel := context.WithTimeout(ctx, readTimeout)
	report, err := c.reader.Read(readCtx, now)
	cancel()
	if err != nil {
		c.fail(err)
		return retryInterval
	}
	// Leadership can lapse during the read; the new leader writes instead.
	if !c.Leader() {
		return followInterval
	}
	if err := c.Store.Put(ctx, report); err != nil {
		c.fail(err)
		return retryInterval
	}
	c.recovered()
	return Interval
}

func (c *Collector) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// fail logs once per distinct error, so a long outage does not flood the log.
func (c *Collector) fail(err error) {
	if err.Error() != c.failure {
		slog.Warn("OCI cost report not refreshed", observability.ComponentKey, "ocicost", "error", err)
	}
	c.failure = err.Error()
}

func (c *Collector) recovered() {
	if c.failure != "" {
		slog.Info("OCI cost report is current again", observability.ComponentKey, "ocicost")
	}
	c.failure = ""
}
