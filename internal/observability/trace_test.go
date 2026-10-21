package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestTracePropagatesAcrossHTTPNATSAndLogFile(t *testing.T) {
	t.Parallel()
	const trace = "4bf92f3577b34da6a3ce929d0e0e4736"
	const span = "00f067aa0ba902b7"
	form := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)
	conn := startTestNATS(t)
	output := newLogOutput(t)
	bus := NewEventBus(32)
	logger, err := NewLogger(output, LogConfig{}, bus)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Subscribe("trace.integration", func(message *nats.Msg) {
		ctx := ContinueTrace(t.Context(), message.Header.Get("traceparent"))
		logger.WarnContext(ctx, "received", "keep", message.Header.Get("X-Keep"))
		reply := &nats.Msg{Subject: message.Reply, Header: TraceHeader(ctx, nil)}
		_ = conn.PublishMsg(reply)
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(TraceHTTP(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message := &nats.Msg{Subject: "trace.integration", Header: TraceHeader(request.Context(), nats.Header{"X-Keep": {"1"}})}
		reply, err := conn.RequestMsgWithContext(request.Context(), message)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		writer.Header().Set("NATS-Traceparent", reply.Header.Get("traceparent"))
	})))
	defer endpoint.Close()
	for name, parent := range map[string]string{
		"valid":          "00-" + trace + "-" + span + "-01",
		"unknown flags":  "00-" + trace + "-" + span + "-00",
		"wrong version":  "01-" + trace + "-" + span + "-01",
		"uppercase":      "00-" + strings.ToUpper(trace) + "-" + span + "-01",
		"zero trace":     "00-" + strings.Repeat("0", 32) + "-" + span + "-01",
		"zero span":      "00-" + trace + "-0000000000000000-01",
		"short trace":    "00-" + trace[1:] + "-" + span + "-01",
		"long span":      "00-" + trace + "-" + span + "00-01",
		"missing fields": "00-" + trace + "-" + span,
		"not hex":        "00-" + strings.Repeat("g", 32) + "-" + span + "-01",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("traceparent", parent)
			response, err := endpoint.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			httpTrace, natsTrace := response.Header.Get("traceparent"), response.Header.Get("NATS-Traceparent")
			if response.StatusCode != http.StatusOK || !form.MatchString(httpTrace) || !form.MatchString(natsTrace) || httpTrace[3:35] != natsTrace[3:35] || httpTrace == natsTrace {
				t.Fatalf("trace propagation = %d %q %q", response.StatusCode, httpTrace, natsTrace)
			}
			continued := name == "valid" || name == "unknown flags"
			if (httpTrace[3:35] == trace) != continued {
				t.Fatalf("trace acceptance = %q", httpTrace)
			}
			lines := strings.Split(strings.TrimSpace(output.String()), "\n")
			var record map[string]any
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &record); err != nil {
				t.Fatal(err)
			}
			if record[TraceIDKey] != httpTrace[3:35] || record["keep"] != "1" {
				t.Fatalf("trace lost at file sink: %v", record)
			}
		})
	}
	for _, event := range eventsOverHTTP(t, bus, "") {
		if _, present := event.Attrs[TraceIDKey]; present {
			t.Fatal("trace leaked into event identity")
		}
	}
	logger.InfoContext(t.Context(), "untraced")
	var record map[string]any
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &record); err != nil {
		t.Fatal(err)
	}
	if _, present := record[TraceIDKey]; present {
		t.Fatal("untraced log gained a trace ID")
	}
	_ = slog.LevelInfo
}
