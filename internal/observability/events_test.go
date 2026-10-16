package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEventBusRingKeepsNewestInOrder(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(3)
	for _, message := range []string{"one", "two", "three", "four", "five"} {
		bus.Publish(Event{Message: message})
	}
	recent := eventsOverHTTP(t, bus, "")
	if len(recent) != 3 || recent[0].Message != "three" || recent[2].Message != "five" {
		t.Fatalf("Recent() = %+v", recent)
	}
	if recent[0].Sequence != 3 || recent[2].Sequence != 5 || recent[0].Time.IsZero() {
		t.Fatalf("sequence or time not assigned: %+v", recent)
	}
	if since := eventsOverHTTP(t, bus, "?after=4"); len(since) != 1 || since[0].Message != "five" {
		t.Fatalf("Since(4) = %+v", since)
	}
	if limited := eventsOverHTTP(t, bus, "?limit=2"); len(limited) != 2 || limited[0].Message != "four" {
		t.Fatalf("Recent(2) = %+v", limited)
	}
}

func TestEventBusSubscriberDropsInsteadOfBlocking(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(16)
	ctx, cancel := context.WithCancel(t.Context())
	events := bus.Subscribe(ctx, 2)
	for index := range 5 {
		bus.Publish(Event{Message: string(rune('a' + index))})
	}
	if published, dropped := bus.Stats(); published != 5 || dropped != 3 {
		t.Fatalf("Stats() = %d published, %d dropped; want 5 and 3", published, dropped)
	}
	if recent := eventsOverHTTP(t, bus, ""); len(recent) != 5 {
		t.Fatalf("API lost published events: %+v", recent)
	}
	if first := <-events; first.Message != "a" {
		t.Fatalf("first event = %q", first.Message)
	}
	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, open := <-events:
			if !open {
				// Publishing after the subscriber left must not panic.
				bus.Publish(Event{Message: "after"})
				return
			}
		case <-deadline:
			t.Fatal("subscription was not closed after its context ended")
		}
	}
}

func TestEventBusConcurrentPublishAndSubscribe(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(64)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			ctx, cancel := context.WithCancel(t.Context())
			events := bus.Subscribe(ctx, 8)
			for range 10 {
				select {
				case <-events:
				case <-time.After(time.Millisecond):
				}
			}
			cancel()
		})
		group.Go(func() {
			for range 100 {
				bus.Publish(Event{Message: "x"})
			}
		})
	}
	group.Wait()
	if events := eventsOverHTTP(t, bus, ""); len(events) != 64 || events[len(events)-1].Sequence != 400 {
		t.Fatalf("concurrent events API = %+v", events)
	}
	if published, _ := bus.Stats(); published != 400 {
		t.Fatalf("published = %d", published)
	}
}

func TestLoggerTeesWarningsAndMarkedEvents(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(16)
	output := newLogOutput(t)
	logger, err := NewLogger(output, LogConfig{}, bus, slog.String("cell", "gru"), slog.String("role", "controller"))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("routine tick")
	logger.Debug("hidden")
	logger.With(ComponentKey, "placement").Warn("placement held", "reason", "awaiting host")
	logger.Info("member serving", EventKey, true, "seat", "a")
	logger.WithGroup("lease").Error("lost", "epoch", 7)
	events := eventsOverHTTP(t, bus, "")
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Component != "placement" || events[0].Level != "WARN" || events[0].Attrs["reason"] != "awaiting host" {
		t.Fatalf("warning event = %+v", events[0])
	}
	if _, leaked := events[0].Attrs["cell"]; leaked {
		t.Fatalf("static identity attribute copied into event: %+v", events[0])
	}
	if events[1].Message != "member serving" || events[1].Attrs["seat"] != "a" || events[1].Attrs[EventKey] != "" {
		t.Fatalf("marked event = %+v", events[1])
	}
	if events[2].Attrs["lease.epoch"] != "7" {
		t.Fatalf("grouped event = %+v", events[2])
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("log lines = %q", lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if first["msg"] != "routine tick" || first["cell"] != "gru" || first["role"] != "controller" {
		t.Fatalf("JSON log line = %v", first)
	}
}

func TestLoggerLogfmtAndValidation(t *testing.T) {
	t.Parallel()
	output := newLogOutput(t)
	logger, err := NewLogger(output, LogConfig{Format: "logfmt", Level: "warn"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("shown", "key", "value with space")
	if text := output.String(); !strings.Contains(text, `msg=shown key="value with space"`) || strings.Contains(text, "hidden") {
		t.Fatalf("logfmt output = %q", text)
	}
	for _, config := range []LogConfig{{Format: "xml"}, {Level: "trace"}} {
		if _, err := NewLogger(output, config, nil); err == nil {
			t.Fatalf("NewLogger(%+v) accepted an invalid setting", config)
		}
	}
}

func eventsOverHTTP(t *testing.T, bus *EventBus, query string) []Event {
	t.Helper()
	service, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Events: bus})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(service)
	defer endpoint.Close()
	response, err := endpoint.Client().Get(endpoint.URL + "/v1/events" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var events []Event
	if err := json.NewDecoder(response.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	return events
}
