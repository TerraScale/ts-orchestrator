package observability

import (
	"context"
	"errors"
	"io"
	"runtime/debug"
	"sync"
	"time"
)

const (
	// DefaultMaxMetricsBytes bounds the exposition embedded in a snapshot so
	// a cell-wide reply stays well under the NATS payload limit.
	DefaultMaxMetricsBytes = 384 << 10
	// sectionCacheTTL keeps scrapes, dashboard ticks and cross-member
	// requests from repeatedly listing JetStream state or reading /proc.
	sectionCacheTTL = 3 * time.Second
	sectionTimeout  = 2 * time.Second
)

// CollectorConfig wires the per-slice providers of one member. Every
// provider is optional; a nil provider leaves its section out.
type CollectorConfig struct {
	Cell     string
	Member   string
	Role     string
	Registry *Registry
	Health   ReadinessSource
	// Authority must be cheap; it reads the latest lease snapshot.
	Authority func() AuthorityView
	NATS      func(context.Context) (NATSView, error)
	Placement func(context.Context) (PlacementView, error)
	Delivery  func() DeliveryView
	OCI       func() OCIView
	// Filesystems are the mount roles reported by the system section.
	Filesystems []FilesystemRole
	// System replaces ReadSystem, for tests and non-Linux builds.
	System          func() (SystemView, error)
	MaxMetricsBytes int
}

// Collector builds MemberSnapshot values and renders the scrape-time
// series derived from them. It implements SnapshotSource.
type Collector struct {
	config    CollectorConfig
	startedAt time.Time
	version   string
	nats      Cache[NATSView]
	placement Cache[PlacementView]
	system    Cache[SystemView]
}

// NewCollector validates the identity and registers the collector's
// scrape-time writer with config.Registry.
func NewCollector(config CollectorConfig) (*Collector, error) {
	if config.Cell == "" || config.Member == "" || config.Role == "" {
		return nil, errors.New("observability collector requires a cell, member and role")
	}
	if config.MaxMetricsBytes <= 0 {
		config.MaxMetricsBytes = DefaultMaxMetricsBytes
	}
	if config.System == nil {
		filesystems := append([]FilesystemRole(nil), config.Filesystems...)
		config.System = func() (SystemView, error) { return ReadSystem(filesystems) }
	}
	collector := &Collector{config: config, startedAt: time.Now().UTC(), version: buildVersion()}
	collector.nats.TTL, collector.placement.TTL, collector.system.TTL = sectionCacheTTL, sectionCacheTTL, sectionCacheTTL
	config.Registry.RegisterWriter(collector.writeMetrics)
	return collector, nil
}

// Snapshot returns this member's current view. Sections that fail are
// listed in Errors by a short class; the snapshot itself still succeeds.
func (collector *Collector) Snapshot(ctx context.Context, includeMetrics bool) (MemberSnapshot, error) {
	config := collector.config
	snapshot := MemberSnapshot{Version: SnapshotVersion, Cell: config.Cell, Member: config.Member,
		Role: config.Role, BuildVersion: collector.version, StartedAt: collector.startedAt,
		ObservedAt: time.Now().UTC()}
	if config.Health != nil {
		snapshot.Ready, snapshot.Checks = config.Health.Evaluate(ctx)
	}
	fail := func(section string, err error) {
		if snapshot.Errors == nil {
			snapshot.Errors = map[string]string{}
		}
		snapshot.Errors[section] = errorClass(err)
	}
	if config.Authority != nil {
		view := config.Authority()
		snapshot.Authority = &view
	}
	if view, err := collector.natsView(ctx); err != nil {
		fail("nats", err)
	} else if view != nil {
		snapshot.NATS = view
	}
	if view, err := collector.placementView(ctx); err != nil {
		fail("placement", err)
	} else if view != nil {
		snapshot.Placement = view
	}
	if config.Delivery != nil {
		view := config.Delivery()
		snapshot.Delivery = &view
	}
	if config.OCI != nil {
		view := config.OCI()
		snapshot.OCI = &view
	}
	if view, err := collector.systemView(ctx); err != nil {
		fail("system", err)
	} else {
		snapshot.System = &view
	}
	if includeMetrics && config.Registry != nil {
		snapshot.Metrics, snapshot.MetricsTruncated = config.Registry.Text(config.MaxMetricsBytes)
	}
	return snapshot, nil
}

func (collector *Collector) natsView(ctx context.Context) (*NATSView, error) {
	if collector.config.NATS == nil {
		return nil, nil
	}
	view, err := collector.nats.Get(ctx, collector.config.NATS)
	return &view, err
}

func (collector *Collector) placementView(ctx context.Context) (*PlacementView, error) {
	if collector.config.Placement == nil {
		return nil, nil
	}
	view, err := collector.placement.Get(ctx, collector.config.Placement)
	return &view, err
}

func (collector *Collector) systemView(ctx context.Context) (SystemView, error) {
	return collector.system.Get(ctx, func(context.Context) (SystemView, error) { return collector.config.System() })
}

// writeMetrics renders the provider views as gauges at scrape time.
func (collector *Collector) writeMetrics(w io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), sectionTimeout)
	defer cancel()
	config := collector.config
	WriteGauge(w, Series(MetricPrefix+"build_info", "version", collector.version, "role", config.Role), 1)
	WriteGauge(w, MetricPrefix+"start_time_seconds", float64(collector.startedAt.Unix()))
	if config.Health != nil {
		ready, results := config.Health.Evaluate(ctx)
		WriteGauge(w, MetricPrefix+"ready", Bool(ready))
		for _, result := range results {
			WriteGauge(w, Series(MetricPrefix+"ready_check", "check", result.Name), Bool(result.OK))
		}
	}
	if config.Authority != nil {
		WriteAuthorityMetrics(w, config.Authority())
	}
	if view, err := collector.natsView(ctx); view != nil {
		WriteGauge(w, Series(MetricPrefix+"collect_ok", "section", "nats"), Bool(err == nil))
		if err == nil {
			WriteNATSMetrics(w, *view)
		}
	}
	if view, err := collector.placementView(ctx); view != nil {
		WriteGauge(w, Series(MetricPrefix+"collect_ok", "section", "placement"), Bool(err == nil))
		if err == nil {
			WritePlacementMetrics(w, *view)
		}
	}
	view, err := collector.systemView(ctx)
	WriteGauge(w, Series(MetricPrefix+"collect_ok", "section", "system"), Bool(err == nil))
	if err == nil {
		WriteSystemMetrics(w, view)
	}
}

// Cache memoizes one section for TTL. Concurrent callers share a load; a
// failed load is cached for the same TTL so an unhealthy dependency is not
// hammered by every scrape and dashboard tick.
type Cache[T any] struct {
	TTL    time.Duration
	mu     sync.Mutex
	at     time.Time
	value  T
	err    error
	flight *cacheFlight[T]
}

// cacheFlight is one load shared by every caller that arrives while it runs.
type cacheFlight[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// Get returns the cached value or the result of one shared load bounded by
// sectionTimeout. Only bookkeeping happens under the lock: a caller waiting
// for another caller's load returns its own ctx.Err() as soon as its context
// ends, instead of waiting for the unrelated load to finish.
func (cache *Cache[T]) Get(ctx context.Context, load func(context.Context) (T, error)) (T, error) {
	cache.mu.Lock()
	if !cache.at.IsZero() && time.Since(cache.at) < cache.TTL {
		value, err := cache.value, cache.err
		cache.mu.Unlock()
		return value, err
	}
	flight := cache.flight
	if flight == nil {
		flight = &cacheFlight[T]{done: make(chan struct{})}
		cache.flight = flight
		// The load is shared, so no single caller's cancellation may cut
		// it short; sectionTimeout bounds it.
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sectionTimeout)
		go func() {
			defer cancel()
			value, err := load(loadCtx)
			cache.mu.Lock()
			cache.value, cache.err, cache.at = value, err, time.Now()
			cache.flight = nil
			cache.mu.Unlock()
			flight.value, flight.err = value, err
			close(flight.done)
		}()
	}
	cache.mu.Unlock()
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case <-flight.done:
		return flight.value, flight.err
	}
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "unavailable"
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return info.Main.Version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}
