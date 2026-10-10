package observability

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
)

var (
	traceparentForm = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)
	traceIDForm     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func TestContinueTraceAcceptsOnlyValidTraceparents(t *testing.T) {
	const trace = "4bf92f3577b34da6a3ce929d0e0e4736"
	const span = "00f067aa0ba902b7"
	valid := "00-" + trace + "-" + span + "-01"
	for name, traceparent := range map[string]string{
		"valid":          valid,
		"unknown flags":  "00-" + trace + "-" + span + "-00",
		"wrong version":  "01-" + trace + "-" + span + "-01",
		"uppercase":      "00-4BF92F3577B34DA6A3CE929D0E0E4736-" + span + "-01",
		"zero trace":     "00-00000000000000000000000000000000-" + span + "-01",
		"zero span":      "00-" + trace + "-0000000000000000-01",
		"short trace":    "00-" + trace[1:] + "-" + span + "-01",
		"long span":      "00-" + trace + "-" + span + "00-01",
		"missing fields": "00-" + trace + "-" + span,
		"not hex":        "00-" + strings.Repeat("g", 32) + "-" + span + "-01",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			got := TraceID(ContinueTrace(context.Background(), traceparent))
			if name == "valid" || name == "unknown flags" {
				if got != trace {
					t.Fatalf("TraceID = %q, want continued trace %q", got, trace)
				}
				return
			}
			if got == trace || !traceIDForm.MatchString(got) {
				t.Fatalf("TraceID = %q, want a new 32-hex trace", got)
			}
		})
	}
}

func TestStartTraceIDsAreULIDsThatSortByTime(t *testing.T) {
	before := time.Now().Add(-time.Second)
	var ids []string
	for range 50 {
		ids = append(ids, TraceID(StartTrace(context.Background())))
	}
	if !slices.IsSorted(ids) || len(slices.Compact(slices.Clone(ids))) != len(ids) {
		t.Fatalf("trace IDs are not distinct and in time order: %q", ids)
	}
	raw, err := hex.DecodeString(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	var id ulid.ULID
	copy(id[:], raw)
	if at := time.UnixMilli(int64(id.Time())); at.Before(before) || at.After(time.Now().Add(time.Second)) {
		t.Fatalf("trace ID timestamp %s is not near now", at)
	}
}

func TestTraceparentRendersTheTraceWithAFreshSpan(t *testing.T) {
	ctx := StartTrace(context.Background())
	first, second := Traceparent(ctx), Traceparent(ctx)
	if !traceparentForm.MatchString(first) {
		t.Fatalf("traceparent = %q, want 00-<trace>-<span>-01", first)
	}
	if first[3:35] != TraceID(ctx) || second[3:35] != TraceID(ctx) {
		t.Fatalf("traceparents %q and %q do not carry trace %q", first, second, TraceID(ctx))
	}
	if first == second {
		t.Fatal("each traceparent needs its own span ID")
	}
	if got := ContinueTrace(context.Background(), first); TraceID(got) != TraceID(ctx) {
		t.Fatalf("receiver continued trace %q, want %q", TraceID(got), TraceID(ctx))
	}
	if Traceparent(context.Background()) != "" || TraceID(context.Background()) != "" {
		t.Fatal("a context without a trace renders no traceparent")
	}
}

func TestTraceHeaderSetsTheTraceparent(t *testing.T) {
	ctx := StartTrace(context.Background())
	header := TraceHeader(ctx, nil)
	if got := header.Get("traceparent"); !traceparentForm.MatchString(got) || got[3:35] != TraceID(ctx) {
		t.Fatalf("header traceparent = %q, want trace %q", got, TraceID(ctx))
	}
	existing := nats.Header{"X-Keep": []string{"1"}}
	if TraceHeader(ctx, existing).Get("X-Keep") != "1" || existing.Get("traceparent") == "" {
		t.Fatal("TraceHeader must keep the header's other fields")
	}
	if TraceHeader(context.Background(), nil) != nil {
		t.Fatal("a context without a trace must leave a nil header nil")
	}
}

func TestTraceHTTPContinuesOrStartsTheTrace(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	var seen string
	handler := TraceHTTP(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = TraceID(request.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("traceparent", incoming)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if seen != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("handler trace = %q, want the incoming trace", seen)
	}
	if got := recorder.Header().Get("traceparent"); !traceparentForm.MatchString(got) || got[3:35] != seen {
		t.Fatalf("response traceparent = %q, want trace %q", got, seen)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "4bf92f3577b34da6a3ce929d0e0e4736" || seen == "" {
		t.Fatalf("handler trace = %q, want a new trace", seen)
	}
	if got := recorder.Header().Get("traceparent"); got[3:35] != seen {
		t.Fatalf("response traceparent = %q, want trace %q", got, seen)
	}
}

func TestTraceIDAppearsOnlyOnContextCallsWithATrace(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(&output, LogConfig{Format: "json"}, nil, slog.String("service", "ts-orchestrator"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := StartTrace(context.Background())
	logger.InfoContext(ctx, "traced", "key", "value")
	logger.InfoContext(context.Background(), "untraced context")
	logger.Info("no context")
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d records, want 3: %q", len(lines), output.String())
	}
	var traced, untraced, plain map[string]any
	for i, target := range []*map[string]any{&traced, &untraced, &plain} {
		if err := json.Unmarshal([]byte(lines[i]), target); err != nil {
			t.Fatal(err)
		}
	}
	if traced[TraceIDKey] != TraceID(ctx) {
		t.Fatalf("trace_id = %v, want %q", traced[TraceIDKey], TraceID(ctx))
	}
	if _, ok := untraced[TraceIDKey]; ok {
		t.Fatalf("background context record has trace_id: %s", lines[1])
	}
	if _, ok := plain[TraceIDKey]; ok {
		t.Fatalf("plain record has trace_id: %s", lines[2])
	}
	// The trace follows the static attributes and precedes the call's own.
	order := []string{`"service"`, `"trace_id"`, `"key"`}
	for i := 1; i < len(order); i++ {
		if strings.Index(lines[0], order[i-1]) > strings.Index(lines[0], order[i]) {
			t.Fatalf("%s is after %s in %s", order[i-1], order[i], lines[0])
		}
	}
}

func TestEventCopyLeavesTheTraceOut(t *testing.T) {
	record := slog.NewRecord(time.Now(), slog.LevelWarn, "retrying", 0)
	record.AddAttrs(slog.String(TraceIDKey, "4bf92f3577b34da6a3ce929d0e0e4736"), slog.String("role", "terrabase"))
	event := eventFromRecord(record, nil, nil)
	if _, ok := event.Attrs[TraceIDKey]; ok || event.Attrs["role"] != "terrabase" {
		t.Fatalf("event attrs = %v, want role without trace_id", event.Attrs)
	}
}
