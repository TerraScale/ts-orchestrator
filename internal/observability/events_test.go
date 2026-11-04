package observability

import (
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

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
