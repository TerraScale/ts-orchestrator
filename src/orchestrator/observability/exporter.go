package observability

// This file is the runtime seam between host agents and the telemetry
// transport.  It deliberately deals in small JSON records and BatchSender
// interfaces: an OTLP encoder (and an HTTP transport) can be supplied by the
// composition root, while tests never need a network or a Grafana account.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultExporterItems       = 1000
	defaultExporterBytes       = 1 << 20
	defaultExporterAttempts    = 3
	defaultExporterInitialWait = time.Second
	defaultExporterMaxWait     = 30 * time.Second
	defaultLogsPerSecond       = 100
	// The D-72 contract is a hard per-host cap, rather than a tuning range:
	// info logs above 100 lines/s are sampled out before they enter a batch.
	maxLogsPerSecond   = 100
	maxTrackedLogHosts = 1024
	maxCounterValue    = 1 << 60
	// LogRetentionDays is the D-72 Grafana retention contract.  Retention is
	// enforced by the Grafana tenant, while the exporter keeps the contract
	// visible to composition roots and tests.
	LogRetentionDays = 14
)

// ExporterConfig controls the bounded runtime exporter.  Batches are flushed
// synchronously when full; while a sender is slow, producers wait (and may
// cancel their context), which is the intentional backpressure boundary.
type ExporterConfig struct {
	Labels LabelAllowList
	Batch  BatchConfig
	Retry  RetryPolicy

	// LogsPerSecond is the per-host log admission limit.  Records after the
	// first limit in a one-second window are sampled out.  Zero selects 100.
	LogsPerSecond int
	Now           func() time.Time
}

// ExporterSinks are deliberately separate so metrics and logs cannot be
// accidentally sent to the wrong endpoint.  The same BatchSender is valid
// for both fields (Batch.Signal still selects the protocol endpoint).
type ExporterSinks struct {
	Metrics BatchSender
	Logs    BatchSender
	Page    PageSink
}

// Sink is the transport abstraction used by the exporter.  It is an alias so
// existing BatchSender implementations can be passed without adapters.
type Sink = BatchSender
type ExporterSink = BatchSender

// Exporter is a concurrency-safe, bounded producer for infrastructure
// metrics and structured logs.  It has no provider or network dependency.
type Exporter struct {
	labels LabelAllowList
	now    func() time.Time
	limit  int

	metrics *Batcher
	logs    *Batcher
	page    PageSink

	sampleMu sync.Mutex
	samples  map[string]logSample
	closeMu  sync.Mutex
	closed   bool
}

type logSample struct {
	window time.Time
	count  int
}

// NewExporter builds an exporter from injected sinks.  It accepts either an
// ExporterSinks value or positional BatchSender values (metrics, logs, and an
// optional PageSink), which keeps small composition roots convenient while
// retaining one strongly validated implementation.
func NewExporter(configuration any, arguments ...any) (*Exporter, error) {
	config, err := exporterConfig(configuration)
	if err != nil {
		return nil, err
	}
	config = withExporterDefaults(config)
	if config.Labels == nil {
		return nil, errors.New("exporter label allow-list is required")
	}
	if err := config.Labels.Validate(); err != nil {
		return nil, err
	}
	if err := config.Batch.Validate(); err != nil {
		return nil, err
	}
	if err := config.Retry.Validate(); err != nil {
		return nil, err
	}
	if config.LogsPerSecond < 1 || config.LogsPerSecond > maxLogsPerSecond {
		return nil, errors.New("LogsPerSecond must be between 1 and 100")
	}
	if config.Now == nil {
		return nil, errors.New("exporter clock is required")
	}

	sinks, err := exporterSinks(arguments)
	if err != nil {
		return nil, err
	}
	if sinks.Metrics == nil || sinks.Logs == nil {
		return nil, errors.New("metrics and logs sinks are required")
	}
	metrics, err := NewBatcher(config.Batch, config.Retry, sinks.Metrics)
	if err != nil {
		return nil, err
	}
	logs, err := NewBatcher(config.Batch, config.Retry, sinks.Logs)
	if err != nil {
		return nil, err
	}
	return &Exporter{
		labels:  config.Labels.Clone(),
		now:     config.Now,
		limit:   config.LogsPerSecond,
		metrics: metrics,
		logs:    logs,
		page:    sinks.Page,
		samples: make(map[string]logSample),
	}, nil
}

func exporterConfig(configuration any) (ExporterConfig, error) {
	switch config := configuration.(type) {
	case ExporterConfig:
		return config, nil
	case *ExporterConfig:
		if config == nil {
			return ExporterConfig{}, errors.New("exporter configuration is required")
		}
		return *config, nil
	case Config:
		return ExporterConfig{Labels: config.Labels, Batch: config.Batch, Retry: config.Retry}, nil
	case *Config:
		if config == nil {
			return ExporterConfig{}, errors.New("exporter configuration is required")
		}
		return ExporterConfig{Labels: config.Labels, Batch: config.Batch, Retry: config.Retry}, nil
	default:
		return ExporterConfig{}, errors.New("unsupported exporter configuration")
	}
}

func withExporterDefaults(config ExporterConfig) ExporterConfig {
	if config.Batch.MaxItems == 0 {
		config.Batch.MaxItems = defaultExporterItems
	}
	if config.Batch.MaxBytes == 0 {
		config.Batch.MaxBytes = defaultExporterBytes
	}
	if config.Retry.MaxAttempts == 0 {
		config.Retry.MaxAttempts = defaultExporterAttempts
	}
	if config.Retry.InitialDelay == 0 {
		config.Retry.InitialDelay = defaultExporterInitialWait
	}
	if config.Retry.MaxDelay == 0 {
		config.Retry.MaxDelay = defaultExporterMaxWait
	}
	if config.Retry.Multiplier == 0 {
		config.Retry.Multiplier = 2
	}
	if config.LogsPerSecond == 0 {
		config.LogsPerSecond = defaultLogsPerSecond
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config
}

func exporterSinks(arguments []any) (ExporterSinks, error) {
	if len(arguments) == 1 {
		if sinks, ok := arguments[0].(ExporterSinks); ok {
			return sinks, nil
		}
		if sink, ok := arguments[0].(BatchSender); ok {
			return ExporterSinks{Metrics: sink, Logs: sink}, nil
		}
	}
	var result ExporterSinks
	for index, argument := range arguments {
		// An optional page sink is commonly passed as an untyped nil by
		// compositions that only want dashboard telemetry. Keep that form
		// equivalent to omitting the sink entirely.
		if argument == nil {
			if index == 2 {
				continue
			}
			return ExporterSinks{}, errors.New("nil batch sink is not permitted")
		}
		switch value := argument.(type) {
		case BatchSender:
			switch index {
			case 0:
				result.Metrics = value
			case 1:
				result.Logs = value
			default:
				return ExporterSinks{}, errors.New("too many batch sinks")
			}
		case PageSink:
			result.Page = value
		default:
			return ExporterSinks{}, errors.New("exporter sink has an unsupported type")
		}
	}
	return result, nil
}

// NewHTTPExporter connects the runtime exporter to the existing validated
// OTLP-over-HTTP/Grafana transport.  Constructing it performs no I/O; the
// injected encoders also make the wire protocol a composition-root choice.
func NewHTTPExporter(config Config, client *http.Client, metricsEncoder, logsEncoder BatchEncoder, page PageSink) (*Exporter, error) {
	transport, err := NewHTTPTransport(config, client, metricsEncoder, logsEncoder)
	if err != nil {
		return nil, err
	}
	return NewExporter(ExporterConfig{
		Labels: config.Labels,
		Batch:  config.Batch,
		Retry:  config.Retry,
	}, ExporterSinks{Metrics: transport, Logs: transport, Page: page})
}

// Metric is the only metric record shape admitted by Exporter.  Labels are
// always exactly host, region, and subsystem: customer/database/view
// dimensions therefore cannot become time-series cardinality.
type Metric struct {
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Value     float64           `json:"value"`
	Timestamp time.Time         `json:"timestamp"`
}

// MetricRecord and StructuredLog make the two wire-facing record roles
// explicit for callers that prefer record terminology.
type MetricRecord = Metric
type StructuredLog = LogRecord

func (e *Exporter) validateMetric(metric Metric) error {
	if e == nil || e.metrics == nil {
		return errors.New("observability exporter is unavailable")
	}
	if err := validateEventName(metric.Name); err != nil {
		return fmt.Errorf("metric: %w", err)
	}
	if math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) {
		return errors.New("metric value must be finite")
	}
	if len(metric.Labels) != 3 {
		return errors.New("metric labels must be exactly host, region, and subsystem")
	}
	for _, key := range []string{"host", "region", "subsystem"} {
		if _, ok := metric.Labels[key]; !ok {
			return errors.New("metric labels must be exactly host, region, and subsystem")
		}
	}
	if err := e.labels.ValidateLabels(metric.Labels); err != nil {
		return err
	}
	return nil
}

// EmitMetric admits one bounded-cardinality metric and copies its labels
// before batching.  A full/failed batch propagates backpressure or the
// bounded retry error to the caller.
func (e *Exporter) EmitMetric(ctx context.Context, metric Metric) error {
	if e == nil {
		return errors.New("observability exporter is unavailable")
	}
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return errors.New("observability exporter is closed")
	}
	if ctx == nil {
		return errors.New("metric context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if metric.Timestamp.IsZero() {
		metric.Timestamp = e.now().UTC()
	} else {
		metric.Timestamp = metric.Timestamp.UTC()
	}
	if err := e.validateMetric(metric); err != nil {
		return err
	}
	metric.Labels = cloneLabels(metric.Labels)
	payload, err := json.Marshal(metric)
	if err != nil {
		return fmt.Errorf("encode metric: %w", err)
	}
	return e.metrics.Add(ctx, SignalMetrics, payload)
}

// RecordCounter records a monotonic or delta counter supplied by a host
// agent.  The caller chooses a stable metric name; no customer identifier is
// accepted in the dimensions.
func (e *Exporter) RecordCounter(ctx context.Context, name, host, region, subsystem string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > maxCounterValue {
		return errors.New("counter value must be between 0 and 1 EiB")
	}
	return e.EmitMetric(ctx, Metric{Name: name, Labels: map[string]string{
		"host": host, "region": region, "subsystem": subsystem,
	}, Value: value})
}

// Counter is a concise alias for RecordCounter.
func (e *Exporter) Counter(ctx context.Context, name, host, region, subsystem string, value float64) error {
	return e.RecordCounter(ctx, name, host, region, subsystem, value)
}

// ExportMetric is an alias for callers that use export terminology.
func (e *Exporter) ExportMetric(ctx context.Context, metric Metric) error {
	return e.EmitMetric(ctx, metric)
}

// RecordCloudflareCounter and RecordWorkerCounter use the provider subsystem
// while keeping the source visible in the metric name.  They are counters,
// not labels, so Worker version, route, and zone identifiers never create
// unbounded time series.
func (e *Exporter) RecordCloudflareCounter(ctx context.Context, name, host, region string, value float64) error {
	return e.RecordCounter(ctx, prefixMetricName("cloudflare", name), host, region, "provider", value)
}

func (e *Exporter) RecordWorkerCounter(ctx context.Context, name, host, region string, value float64) error {
	return e.RecordCounter(ctx, prefixMetricName("cloudflare_worker", name), host, region, "provider", value)
}

func (e *Exporter) EmitCloudflareCounter(ctx context.Context, name, host, region string, value float64) error {
	return e.RecordCloudflareCounter(ctx, name, host, region, value)
}

func (e *Exporter) EmitWorkerCounter(ctx context.Context, name, host, region string, value float64) error {
	return e.RecordWorkerCounter(ctx, name, host, region, value)
}

func prefixMetricName(prefix, name string) string {
	name = strings.TrimPrefix(name, prefix+".")
	return prefix + "." + name
}

// RecordEgress records the billable OCI egress fact for one host and Region.
// Egress remains a dashboard metric and never pages.
func (e *Exporter) RecordEgress(ctx context.Context, host, region string, bytesTotal float64) error {
	if e == nil {
		return errors.New("observability exporter is unavailable")
	}
	if _, err := EgressObservation(e.labels, region, bytesTotal, e.now()); err != nil {
		return err
	}
	return e.RecordCounter(ctx, EgressBytesTotalName, host, region, "provider", bytesTotal)
}

// RecordClock emits the signed offset and write-health observations from a
// host agent.  An unreadable clock is represented by ClockObservations' safe
// unhealthy value rather than silence.
func (e *Exporter) RecordClock(ctx context.Context, host, region string, sample ClockSample) error {
	if e == nil {
		return errors.New("observability exporter is unavailable")
	}
	observations, err := ClockObservations(e.labels, region, host, sample, e.now())
	if err != nil {
		return err
	}
	// Offset is a signed gauge; only the unhealthy marker uses the
	// non-negative counter path.
	if err := e.EmitMetric(ctx, Metric{Name: observations[0].Name, Labels: map[string]string{
		"host": host, "region": region, "subsystem": "hostagent",
	}, Value: observations[0].Value}); err != nil {
		return err
	}
	if err := e.RecordCounter(ctx, observations[1].Name, host, region, "hostagent", observations[1].Value); err != nil {
		return err
	}
	return nil
}

// RecordSLOBurn always exports the four burn facts as dashboard metrics.  It
// invokes the page sink only when EvaluateSLOBurn confirms both windows of a
// supported SLO tier; cause-level or one-window spikes never page.
func (e *Exporter) RecordSLOBurn(ctx context.Context, host, region string, windows SLOBurnWindows, timestamp time.Time) error {
	if e == nil {
		return errors.New("observability exporter is unavailable")
	}
	if ctx == nil {
		return errors.New("SLO context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if timestamp.IsZero() {
		timestamp = e.now().UTC()
	} else {
		timestamp = timestamp.UTC()
	}
	event, err := EvaluateSLOBurn(e.labels, map[string]string{"host": host, "region": region}, windows, timestamp)
	if err != nil {
		return err
	}
	if event != nil && e.page == nil {
		return errors.New("SLO burn page sink is unavailable")
	}
	labels := map[string]string{"host": host, "region": region, "subsystem": "observability"}
	values := []struct {
		name  string
		value float64
	}{
		{"slo.burn_rate.fast_long", windows.FastLong},
		{"slo.burn_rate.fast_short", windows.FastShort},
		{"slo.burn_rate.slow_long", windows.SlowLong},
		{"slo.burn_rate.slow_short", windows.SlowShort},
	}
	for _, value := range values {
		if err := e.EmitMetric(ctx, Metric{Name: value.name, Labels: labels, Value: value.value, Timestamp: timestamp}); err != nil {
			return err
		}
	}
	if event != nil {
		if err := e.EmitPage(ctx, *event); err != nil {
			return err
		}
	}
	return nil
}

// EmitPage is a guarded page boundary.  Callers cannot page arbitrary cause
// observations through the exporter; EventRouter enforces the canonical SLO
// burn event contract before the injected sink is reached.
func (e *Exporter) EmitPage(ctx context.Context, event SLOBurnRatePageEvent) error {
	if e == nil || e.page == nil {
		return errors.New("SLO burn page sink is unavailable")
	}
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return errors.New("observability exporter is closed")
	}
	router, err := NewEventRouter(e.labels, discardDashboardSink{}, e.page)
	if err != nil {
		return err
	}
	return router.EmitPage(ctx, event)
}

type discardDashboardSink struct{}

func (discardDashboardSink) Observe(context.Context, DashboardObservation) error { return nil }

// EmitLog redacts a structured record before sampling and batching.  It
// returns nil when the host's per-second budget samples the record out; this
// is normal telemetry loss, not a customer-path error.
func (e *Exporter) EmitLog(ctx context.Context, record LogRecord) error {
	if e == nil || e.logs == nil {
		return errors.New("observability exporter is unavailable")
	}
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return errors.New("observability exporter is closed")
	}
	if ctx == nil {
		return errors.New("log context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = e.now().UTC()
	} else {
		record.Timestamp = record.Timestamp.UTC()
	}
	redacted, err := RedactLog(record)
	if err != nil {
		return err
	}
	host := redacted.Attributes["host"]
	if host == "" {
		host = "unknown"
	}
	if !e.admitLog(host, redacted.Timestamp) {
		return nil
	}
	payload, err := json.Marshal(struct {
		Timestamp  time.Time         `json:"timestamp"`
		Body       string            `json:"body"`
		Attributes map[string]string `json:"attributes,omitempty"`
	}{
		Timestamp:  redacted.Timestamp,
		Body:       redacted.Body,
		Attributes: redacted.Attributes,
	})
	if err != nil {
		return fmt.Errorf("encode log: %w", err)
	}
	return e.logs.Add(ctx, SignalLogs, payload)
}

// Log is a concise alias for EmitLog.
func (e *Exporter) Log(ctx context.Context, record LogRecord) error { return e.EmitLog(ctx, record) }

// ExportLog is an alias for callers that use export terminology.
func (e *Exporter) ExportLog(ctx context.Context, record LogRecord) error {
	return e.EmitLog(ctx, record)
}

func (e *Exporter) admitLog(host string, _ time.Time) bool {
	// Host names come from structured log attributes and must not be allowed
	// to turn the sampler's bookkeeping map into an unbounded allocation. A
	// bounded overflow bucket preserves the per-second cap for unexpected
	// hosts while keeping the exporter memory bound independent of input.
	if host == "" {
		host = "unknown"
	}
	// Caller timestamps are retained for correlation but cannot reset a host's
	// budget by moving backwards or creating arbitrary future windows.
	window := e.now().UTC().Truncate(time.Second)
	e.sampleMu.Lock()
	defer e.sampleMu.Unlock()
	if _, exists := e.samples[host]; !exists && len(e.samples) >= maxTrackedLogHosts-1 {
		host = "__overflow__"
	}
	sample := e.samples[host]
	if sample.window.IsZero() || window.After(sample.window) {
		sample = logSample{window: window}
	}
	// A backwards wall-clock step leaves sample.window unchanged and therefore
	// cannot reopen a spent budget until the trusted clock catches up again.
	if sample.count >= e.limit {
		e.samples[host] = sample
		return false
	}
	sample.count++
	e.samples[host] = sample
	return true
}

// Flush applies the caller's cancellation deadline to both bounded batches.
func (e *Exporter) Flush(ctx context.Context) error {
	if e == nil {
		return errors.New("observability exporter is unavailable")
	}
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return errors.New("observability exporter is closed")
	}
	if err := e.metrics.Flush(ctx); err != nil {
		return err
	}
	return e.logs.Flush(ctx)
}

// Close flushes both streams and then rejects future records.  Batcher.Close
// is itself safe and bounded by ctx; the exporter additionally prevents a
// close racing with a new stream from being mistaken for successful delivery.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return nil
	}
	metricErr := e.metrics.Close(ctx)
	logsErr := e.logs.Close(ctx)
	e.closed = true
	if metricErr != nil {
		return metricErr
	}
	return logsErr
}
