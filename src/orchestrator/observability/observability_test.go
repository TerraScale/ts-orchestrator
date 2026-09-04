package observability

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		MetricsEndpoint: "https://metrics.example.test/api/v1/push",
		LogsEndpoint:    "https://logs.example.test/otlp/v1/logs",
		Credentials:     Credentials{Username: "12345", APIKey: "secret-key"},
		Labels:          DefaultLabelAllowList.Clone(),
		Batch:           BatchConfig{MaxItems: 2, MaxBytes: 8},
		Retry:           RetryPolicy{MaxAttempts: 3, InitialDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Multiplier: 1},
	}
}

func TestValidateConfigFailsClosed(t *testing.T) {
	config := testConfig()
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"metrics must be https":             func(c *Config) { c.MetricsEndpoint = "http://metrics.example.test/push" },
		"logs must not contain credentials": func(c *Config) { c.LogsEndpoint = "https://user:pass@logs.example.test/otlp" },
		"username required":                 func(c *Config) { c.Credentials.Username = "" },
		"key required":                      func(c *Config) { c.Credentials.APIKey = "" },
		"labels required":                   func(c *Config) { c.Labels = nil },
		"batch required":                    func(c *Config) { c.Batch.MaxItems = 0 },
		"retry required":                    func(c *Config) { c.Retry.MaxAttempts = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			mutate(&candidate)
			if err := ValidateConfig(candidate); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}

func TestLabelAllowListRejectsCustomerDimensions(t *testing.T) {
	labels := DefaultLabelAllowList.Clone()
	if err := labels.ValidateLabels(map[string]string{"region": "gru", "tenant_id": "customer-1"}); err == nil {
		t.Fatal("customer dimension was accepted")
	}
	if err := labels.ValidateLabels(map[string]string{"region": "iad"}); err == nil {
		t.Fatal("unknown label value was accepted")
	}
	if err := (LabelAllowList{"customer_dimension": {"value"}}).Validate(); err == nil {
		t.Fatal("unknown label key was accepted")
	}
	if err := labels.ValidateLabels(map[string]string{"region": "gru", "subsystem": "nats"}); err != nil {
		t.Fatalf("valid labels rejected: %v", err)
	}
}

type recordingSender struct {
	mu      sync.Mutex
	batches []Batch
	fails   int
}

func (s *recordingSender) SendBatch(_ context.Context, batch Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fails > 0 {
		s.fails--
		return errors.New("temporary transport failure")
	}
	s.batches = append(s.batches, batch)
	return nil
}

func TestBatcherBoundsCopiesAndSeparatesSignals(t *testing.T) {
	sender := &recordingSender{}
	config := testConfig()
	batcher, err := NewBatcher(config.Batch, config.Retry, sender)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first := []byte("one")
	if err := batcher.Add(ctx, SignalMetrics, first); err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	if err := batcher.Add(ctx, SignalMetrics, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if len(sender.batches) != 1 || sender.batches[0].Signal != SignalMetrics || string(sender.batches[0].Records[0]) != "one" {
		t.Fatalf("unexpected metric batch: %#v", sender.batches)
	}
	if err := batcher.Add(ctx, SignalLogs, []byte("log")); err != nil {
		t.Fatal(err)
	}
	if err := batcher.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sender.batches) != 2 || sender.batches[1].Signal != SignalLogs {
		t.Fatalf("signals were mixed: %#v", sender.batches)
	}
	if err := batcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := batcher.Add(ctx, SignalLogs, []byte("late")); err == nil {
		t.Fatal("closed batcher accepted a record")
	}
}

func TestRetryHonorsAttemptsAndCancellation(t *testing.T) {
	attempts := 0
	policy := RetryPolicy{MaxAttempts: 3, InitialDelay: time.Second, MaxDelay: time.Second, Multiplier: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
	errWant := errors.New("failed")
	err := Retry(context.Background(), policy, func(context.Context) error {
		attempts++
		return errWant
	})
	if !errors.Is(err, errWant) || attempts != 3 {
		t.Fatalf("retry = %v, attempts = %d", err, attempts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Retry(ctx, policy, func(context.Context) error { t.Fatal("operation called"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retry = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestHTTPTransportUsesEndpointAuthAndDoesNotLeakErrorBody(t *testing.T) {
	config := testConfig()
	var got *http.Request
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		got = request
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("api_key=secret-key")), Header: make(http.Header)}, nil
	})}
	encoder := func(Batch) (EncodedBatch, error) {
		return EncodedBatch{Body: []byte("payload"), ContentType: "application/x-protobuf", ContentEncoding: "snappy"}, nil
	}
	transport, err := NewHTTPTransport(config, client, encoder, encoder)
	if err != nil {
		t.Fatal(err)
	}
	err = transport.SendBatch(context.Background(), Batch{Signal: SignalMetrics, Records: [][]byte{[]byte("record")}})
	if err == nil || strings.Contains(err.Error(), "secret-key") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if got == nil || got.URL.String() != config.MetricsEndpoint {
		t.Fatalf("request endpoint = %v", got)
	}
	username, key, ok := got.BasicAuth()
	if !ok || username != config.Credentials.Username || key != config.Credentials.APIKey {
		t.Fatal("request did not carry configured basic auth")
	}
}

type recordingDashboard struct{ observations []DashboardObservation }

func (s *recordingDashboard) Observe(_ context.Context, observation DashboardObservation) error {
	s.observations = append(s.observations, observation)
	return nil
}

type recordingPage struct{ events []SLOBurnRatePageEvent }

func (s *recordingPage) Page(_ context.Context, event SLOBurnRatePageEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestEventRouterSeparatesPageEvents(t *testing.T) {
	dashboard := &recordingDashboard{}
	page := &recordingPage{}
	router, err := NewEventRouter(DefaultLabelAllowList, dashboard, page)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.EmitObservation(context.Background(), DashboardObservation{Name: "nats.partition", Labels: map[string]string{"region": "gru"}}); err != nil {
		t.Fatal(err)
	}
	if err := router.EmitPage(context.Background(), SLOBurnRatePageEvent{Name: "nats.partition", Labels: map[string]string{"region": "gru"}, BurnRate: 2, Window: "5m"}); err == nil {
		t.Fatal("cause observation was accepted as a page")
	}
	if err := router.EmitPage(context.Background(), SLOBurnRatePageEvent{Name: "slo.burn_rate.api", Labels: map[string]string{"region": "gru"}, BurnRate: 2, Window: "5m"}); err != nil {
		t.Fatal(err)
	}
	if len(dashboard.observations) != 1 || len(page.events) != 1 {
		t.Fatalf("events crossed sinks: dashboard=%d page=%d", len(dashboard.observations), len(page.events))
	}
}

func TestRedactLog(t *testing.T) {
	record, err := RedactLog(LogRecord{Body: "authorization: Bearer abc123", Attributes: map[string]string{"api_key": "secret", "region": "gru"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(record.Body, "abc123") || record.Attributes["api_key"] != "[redacted]" || record.Attributes["region"] != "gru" {
		t.Fatalf("redaction failed: %#v", record)
	}
}

func TestRedactLogRejectsCustomerDimensions(t *testing.T) {
	for _, key := range []string{"tenant_id", "database", "view_id", "request_id"} {
		t.Run(key, func(t *testing.T) {
			if _, err := RedactLog(LogRecord{Attributes: map[string]string{key: "customer-value"}}); err == nil {
				t.Fatalf("customer dimension %q was accepted", key)
			}
		})
	}
}

func TestEventNameRejectsMalformedSegments(t *testing.T) {
	allow := DefaultLabelAllowList.Clone()
	dashboard := &recordingDashboard{}
	page := &recordingPage{}
	router, err := NewEventRouter(allow, dashboard, page)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".leading", "trailing.", "double..dot"} {
		t.Run(name, func(t *testing.T) {
			if err := router.EmitObservation(context.Background(), DashboardObservation{Name: name, Labels: map[string]string{"region": "gru"}}); err == nil {
				t.Fatalf("malformed event name %q was accepted", name)
			}
		})
	}
}
