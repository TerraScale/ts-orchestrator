package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type exporterSender struct {
	mu       sync.Mutex
	batches  []Batch
	failures int
	started  chan struct{}
}

func (s *exporterSender) SendBatch(ctx context.Context, batch Batch) error {
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return errors.New("temporary sink failure")
	}
	copyOf := Batch{Signal: batch.Signal, Bytes: batch.Bytes, Records: make([][]byte, len(batch.Records))}
	for i := range batch.Records {
		copyOf.Records[i] = append([]byte(nil), batch.Records[i]...)
	}
	s.batches = append(s.batches, copyOf)
	return nil
}

type exporterPage struct {
	mu     sync.Mutex
	events []SLOBurnRatePageEvent
}

func (p *exporterPage) Page(_ context.Context, event SLOBurnRatePageEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
	return nil
}

func exporterAllow() LabelAllowList {
	allow := DefaultLabelAllowList.Clone()
	allow["host"] = []string{"host-a", "host-b", "edge"}
	return allow
}

func testExporterConfig(now func() time.Time) ExporterConfig {
	return ExporterConfig{
		Labels: exporterAllow(),
		Batch:  BatchConfig{MaxItems: 100, MaxBytes: 64 * 1024},
		Retry: RetryPolicy{
			MaxAttempts: 3, InitialDelay: time.Nanosecond, MaxDelay: time.Nanosecond,
			Multiplier: 1, Sleep: func(context.Context, time.Duration) error { return nil },
		},
		LogsPerSecond: 100,
		Now:           now,
	}
}

func newExporterForTest(t *testing.T, config ExporterConfig, page PageSink) (*Exporter, *exporterSender, *exporterSender) {
	t.Helper()
	metrics, logs := &exporterSender{}, &exporterSender{}
	exporter, err := NewExporter(config, ExporterSinks{Metrics: metrics, Logs: logs, Page: page})
	if err != nil {
		t.Fatal(err)
	}
	return exporter, metrics, logs
}

func TestExporterRejectsCustomerDimensionsAndBoundsMetricLabels(t *testing.T) {
	exporter, _, _ := newExporterForTest(t, testExporterConfig(time.Now), nil)
	ctx := context.Background()
	valid := Metric{Name: "host.health", Labels: map[string]string{
		"host": "host-a", "region": "gru", "subsystem": "hostagent",
	}, Value: 1}
	if err := exporter.EmitMetric(ctx, valid); err != nil {
		t.Fatal(err)
	}
	for name, labels := range map[string]map[string]string{
		"tenant":       {"host": "host-a", "region": "gru", "subsystem": "hostagent", "tenant_id": "secret"},
		"database":     {"host": "host-a", "region": "gru", "subsystem": "hostagent", "database": "db"},
		"view":         {"host": "host-a", "region": "gru", "subsystem": "hostagent", "view_id": "view"},
		"missing host": {"region": "gru", "subsystem": "hostagent"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Labels = labels
			if err := exporter.EmitMetric(ctx, candidate); err == nil {
				t.Fatal("customer or unbounded metric dimensions were accepted")
			}
		})
	}
}

func TestExporterEmitsCloudflareWorkerEgressClockAndSLOFacts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	page := &exporterPage{}
	config := testExporterConfig(func() time.Time { return now })
	config.Batch.MaxItems = 20
	exporter, metrics, _ := newExporterForTest(t, config, page)
	ctx := context.Background()
	if err := exporter.RecordCloudflareCounter(ctx, "cache_hits", "edge", "gru", 4); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordWorkerCounter(ctx, "requests", "edge", "gru", 5); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordEgress(ctx, "host-a", "gru", 123); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordClock(ctx, "host-a", "gru", ClockSample{OffsetMillis: 450, Measured: true}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordSLOBurn(ctx, "host-a", "gru", SLOBurnWindows{
		FastLong: 1, FastShort: 100, SlowLong: 1, SlowShort: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
	if len(page.events) != 0 {
		t.Fatal("one-window spike paged")
	}
	if err := exporter.RecordSLOBurn(ctx, "host-a", "gru", SLOBurnWindows{
		FastLong: 14.4, FastShort: 15, SlowLong: 1, SlowShort: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
	if len(page.events) != 1 || page.events[0].Name != SLOAPIBurnMetric {
		t.Fatalf("unexpected page events: %#v", page.events)
	}
	if err := exporter.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(metrics.batches) != 1 {
		t.Fatalf("metric batches = %d, want 1", len(metrics.batches))
	}
	joined := string(metrics.batches[0].Records[0])
	if !strings.Contains(joined, "cloudflare.cache_hits") {
		t.Fatalf("Cloudflare counter missing: %s", joined)
	}
}

func TestExporterRedactsAndSamplesLogsPerHost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	config := testExporterConfig(func() time.Time { return now })
	config.LogsPerSecond = 2
	exporter, _, logs := newExporterForTest(t, config, nil)
	for i := 0; i < 3; i++ {
		if err := exporter.EmitLog(context.Background(), LogRecord{
			Timestamp: now,
			Body:      "authorization: Bearer top-secret password=hunter2",
			Attributes: map[string]string{
				"host": "host-a", "api_key": "another-secret", "line": "safe",
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := exporter.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs.batches) != 1 || len(logs.batches[0].Records) != 2 {
		t.Fatalf("sampled log count = %#v, want 2", logs.batches)
	}
	for _, payload := range logs.batches[0].Records {
		text := string(payload)
		for _, secret := range []string{"top-secret", "hunter2", "another-secret"} {
			if strings.Contains(text, secret) {
				t.Fatalf("secret leaked in log payload: %s", text)
			}
		}
	}
	// A different host receives its own budget in the same second.
	if err := exporter.EmitLog(context.Background(), LogRecord{Timestamp: now, Attributes: map[string]string{"host": "host-b"}, Body: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs.batches) != 2 || len(logs.batches[1].Records) != 1 {
		t.Fatalf("host budgets were not independent: %#v", logs.batches)
	}
}

func TestExporterLogLimitCannotExceedD72Cap(t *testing.T) {
	config := testExporterConfig(time.Now)
	config.LogsPerSecond = maxLogsPerSecond + 1
	metrics, logs := &exporterSender{}, &exporterSender{}
	if _, err := NewExporter(config, ExporterSinks{Metrics: metrics, Logs: logs}); err == nil {
		t.Fatal("log limit above 100 lines/s was accepted")
	}
}

func TestExporterSamplerDoesNotReopenBudgetOnClockStepBack(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	config := testExporterConfig(func() time.Time { return now })
	config.LogsPerSecond = 1
	exporter, _, logs := newExporterForTest(t, config, nil)
	for _, timestamp := range []time.Time{now, now.Add(24 * time.Hour), now.Add(-24 * time.Hour)} {
		if err := exporter.EmitLog(context.Background(), LogRecord{Timestamp: timestamp, Attributes: map[string]string{"host": "host-a"}, Body: "bounded"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := exporter.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs.batches) != 1 || len(logs.batches[0].Records) != 1 {
		t.Fatalf("clock step reopened sampling budget: %#v", logs.batches)
	}
}

func TestExporterRetriesWithBoundAndHonorsCancellationBackpressure(t *testing.T) {
	config := testExporterConfig(time.Now)
	config.Batch.MaxItems = 1
	metrics := &exporterSender{failures: 2}
	logs := &exporterSender{}
	exporter, err := NewExporter(config, ExporterSinks{Metrics: metrics, Logs: logs})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordCounter(context.Background(), "host.health", "host-a", "gru", "hostagent", 1); err != nil {
		t.Fatal(err)
	}
	if len(metrics.batches) != 1 {
		t.Fatal("bounded retries did not eventually send")
	}
	blocking := &exporterSender{started: make(chan struct{}, 1)}
	exporter, err = NewExporter(config, ExporterSinks{Metrics: blocking, Logs: logs})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- exporter.RecordCounter(ctx, "host.health", "host-a", "gru", "hostagent", 1)
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("sender did not observe backpressure")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled backpressure call = %v", err)
	}
}

func TestExporterPageBoundaryRejectsCauseEvents(t *testing.T) {
	page := &exporterPage{}
	exporter, _, _ := newExporterForTest(t, testExporterConfig(time.Now), page)
	if err := exporter.EmitPage(context.Background(), SLOBurnRatePageEvent{
		Name: "host.disk_full", Labels: map[string]string{"region": "gru"}, BurnRate: 20, Window: "5m",
	}); err == nil {
		t.Fatal("cause event reached page boundary")
	}
	if len(page.events) != 0 {
		t.Fatal("cause event was delivered")
	}
}

func TestExporterMetricPayloadIsStructuredAndDefensive(t *testing.T) {
	metrics := &exporterSender{}
	config := testExporterConfig(time.Now)
	config.Batch.MaxItems = 2
	exporter, err := NewExporter(config, ExporterSinks{Metrics: metrics, Logs: &exporterSender{}})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"host": "host-a", "region": "gru", "subsystem": "nats"}
	if err := exporter.EmitMetric(context.Background(), Metric{Name: "nats.messages", Labels: labels, Value: 3}); err != nil {
		t.Fatal(err)
	}
	labels["host"] = "host-b"
	if err := exporter.EmitMetric(context.Background(), Metric{Name: "nats.messages", Labels: map[string]string{"host": "host-a", "region": "gru", "subsystem": "nats"}, Value: 4}); err != nil {
		t.Fatal(err)
	}
	var metric Metric
	if err := json.Unmarshal(metrics.batches[0].Records[0], &metric); err != nil {
		t.Fatal(err)
	}
	if metric.Labels["host"] != "host-a" || metric.Name != "nats.messages" {
		t.Fatalf("metric was not defensively structured: %#v", metric)
	}
}

func TestExporterLogSamplerHasBoundedHostBookkeeping(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	config := testExporterConfig(func() time.Time { return now })
	config.Batch.MaxItems = 10_000
	config.LogsPerSecond = 1
	exporter, _, _ := newExporterForTest(t, config, nil)
	for i := 0; i < maxTrackedLogHosts+100; i++ {
		if err := exporter.EmitLog(context.Background(), LogRecord{Timestamp: now, Attributes: map[string]string{
			"host": fmt.Sprintf("untrusted-host-%d", i),
		}, Body: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	exporter.sampleMu.Lock()
	tracked := len(exporter.samples)
	exporter.sampleMu.Unlock()
	if tracked > maxTrackedLogHosts {
		t.Fatalf("log sampler tracked %d hosts, max %d", tracked, maxTrackedLogHosts)
	}
}

func TestNewExporterAcceptsOmittedOptionalPageSink(t *testing.T) {
	config := testExporterConfig(time.Now)
	metrics, logs := &exporterSender{}, &exporterSender{}
	if _, err := NewExporter(config, metrics, logs, nil); err != nil {
		t.Fatalf("untyped nil optional page sink rejected: %v", err)
	}
}

func TestExporterCloseRejectsConcurrentWrites(t *testing.T) {
	config := testExporterConfig(time.Now)
	config.Batch.MaxItems = 1
	exporter, _, _ := newExporterForTest(t, config, nil)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_ = exporter.RecordCounter(context.Background(), "host.health", "host-a", "gru", "hostagent", 1)
		}()
	}
	close(start)
	if err := exporter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if err := exporter.Flush(context.Background()); err == nil {
		t.Fatal("closed exporter allowed flush")
	}
}
