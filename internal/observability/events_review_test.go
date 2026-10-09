package observability

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestZeroValueEventBusPublishesAndSubscribes(t *testing.T) {
	t.Parallel()
	var bus EventBus
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := bus.Subscribe(ctx, 4)
	bus.Publish(Event{Message: "first"})
	if events := bus.Recent(0); len(events) != 1 || events[0].Message != "first" {
		t.Fatalf("events = %+v", events)
	}
	if event := <-stream; event.Message != "first" {
		t.Fatalf("streamed = %+v", event)
	}
}

func TestEventAttrTruncationKeepsValidUTF8(t *testing.T) {
	t.Parallel()
	attrs := map[string]string{}
	// 511 ASCII bytes followed by three-byte runes straddle the 512-byte cut.
	flattenAttr(attrs, "", slog.String("value", strings.Repeat("a", 511)+strings.Repeat("€", 10)))
	value := attrs["value"]
	if !utf8.ValidString(value) || !strings.HasSuffix(value, "...") || len(value) > maxEventAttrBytes+3 {
		t.Fatalf("truncated value = %q", value)
	}
}

func TestEventBusReceivesEventsBelowConfiguredLogLevel(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(16)
	var output bytes.Buffer
	logger, err := NewLogger(&output, LogConfig{Level: "error"}, bus)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("routine tick")
	logger.Info("controller ready", EventKey, true)
	logger.Warn("placement held")
	logger.Error("lease lost")
	events := bus.Recent(0)
	if len(events) != 3 || events[0].Message != "controller ready" || events[1].Message != "placement held" {
		t.Fatalf("events = %+v", events)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "lease lost") {
		t.Fatalf("log output must still honour the level: %q", lines)
	}
}

func TestRepeatedWarningsDoNotFloodEventRing(t *testing.T) {
	t.Parallel()
	bus := NewEventBus(16)
	var output bytes.Buffer
	logger, err := NewLogger(&output, LogConfig{}, bus)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("controller ready", EventKey, true)
	for range 50 {
		logger.Warn("placement reconcile failed", "error", "timeout")
	}
	logger.Warn("placement reconcile failed", "error", "0000000000V4MRM46HP1SNGDYW")
	events := bus.Recent(0)
	if len(events) != 3 || events[0].Message != "controller ready" || events[2].Attrs["error"] != "0000000000V4MRM46HP1SNGDYW" {
		t.Fatalf("events = %+v", events)
	}
	if lines := strings.Count(output.String(), "\n"); lines != 52 {
		t.Fatalf("every record must still be logged, got %d lines", lines)
	}
	repeats := newEventRepeats()
	event := Event{Level: "WARN", Message: "same"}
	start := time.Unix(1000, 0)
	if !repeats.admit(event, start) || repeats.admit(event, start.Add(time.Minute)) ||
		!repeats.admit(event, start.Add(eventRepeatWindow)) {
		t.Fatal("repeat window not applied")
	}
}
