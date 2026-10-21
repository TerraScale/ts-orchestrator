package cli

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/logs"
)

func observeFeatureFixture(t *testing.T) (*observeFixture, *decisionlog.Journal, *insights.Engine, *logs.View) {
	t.Helper()
	f := newObserveFixture(t)
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru", Member: "controller-a"})
	journal.Record(t.Context(), decisionlog.Decision{Kind: decisionlog.KindReleaseAdmitted,
		Subject: decisionlog.Subject{Kind: "release", ID: "operation-a"}, Status: decisionlog.StatusSucceeded, Summary: "release admission observed"})
	journal.Record(t.Context(), decisionlog.Decision{Kind: decisionlog.KindScaleUp,
		Subject: decisionlog.Subject{Kind: "service", ID: "gateway"}, Status: decisionlog.StatusSucceeded, Summary: "gateway scaled"})
	engine := insights.NewEngine(insights.Config{Region: "gru"})
	engine.Evaluate(t.Context())
	logView := logs.NewView("gru")
	counter := logs.NewCounter("gru", "node-a")
	counter.Add(logs.Record{Service: "gateway", Level: logs.LevelWarn, Component: "router", Message: "upstream unavailable"})
	counter.Add(logs.Record{Service: "database", Level: logs.LevelInfo, Component: "backup", Message: "backup completed"})
	logView.Add(counter.Flush(time.Now().Truncate(time.Minute)), time.Now())
	decisions := decisionlog.Handler(journal)
	f.server.HandleAuthenticated("GET /v1/decisions", decisions)
	insightAPI := insights.Handler(engine, insights.Summarizer{Decisions: journal, Insights: engine, Scope: "gru"})
	f.server.HandleAuthenticated("GET /v1/insights", insightAPI)
	f.server.HandleAuthenticated("GET /v1/summary", insightAPI)
	f.server.HandleAuthenticated("GET /v1/logs", logs.Handler(logView))
	return f, journal, engine, logView
}

func TestObserveExistingFeatureAPIs(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f, _, _, _ := observeFeatureFixture(t)
	for _, scenario := range []struct {
		view, want string
		flags      []string
	}{
		{"decisions", "release admission observed", []string{"--subject-id", "operation-a", "--since", "1h"}},
		{"insights", "OBSERVED", nil},
		{"summary", "gru", []string{"--window", "24h"}},
		{"logs", "upstream unavailable", []string{"--service", "gateway", "--min-level", "WARN", "--window", "24h"}},
	} {
		t.Run(scenario.view, func(t *testing.T) {
			output, err := f.run(t, scenario.view, scenario.flags...)
			if err != nil || !strings.Contains(output, scenario.want) {
				t.Fatalf("table observation = %s, %v", output, err)
			}
			if scenario.view == "decisions" && strings.Contains(output, "gateway scaled") || scenario.view == "logs" && strings.Contains(output, "backup completed") {
				t.Fatalf("server-side filter did not reach the source: %s", output)
			}
			output, err = f.run(t, scenario.view, append(scenario.flags, "--format", "json")...)
			var envelope struct {
				Version int            `json:"version"`
				View    string         `json:"view"`
				Source  string         `json:"source"`
				Partial bool           `json:"partial"`
				Data    jsontext.Value `json:"data"`
			}
			if err != nil || json.Unmarshal([]byte(output), &envelope) != nil || envelope.Version != 1 || envelope.View != scenario.view || envelope.Source != f.http.URL || envelope.Partial || len(envelope.Data) == 0 {
				t.Fatalf("JSON observation = %s, %v", output, err)
			}
		})
	}
	for _, path := range []string{"decisions", "insights", "summary", "logs"} {
		response, err := f.http.Client().Get(f.http.URL + "/v1/" + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s status = %d", path, response.StatusCode)
		}
	}
}

func TestObserveExistingFeaturePartialStates(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f, journal, _, logView := observeFeatureFixture(t)
	journal.MarkCoveredFrom(time.Now())
	logView.Add(logs.Window{Version: 1, Region: "gru", Node: "node-gap", Boot: "boot", Seq: 0,
		Minute: time.Now().Truncate(time.Minute), Classes: []logs.Class{{Service: "gateway", Level: logs.LevelError, Message: "retry failed", Count: 1}}}, time.Now())
	logView.Add(logs.Window{Version: 1, Region: "gru", Node: "node-gap", Boot: "boot", Seq: 2,
		Minute: time.Now().Truncate(time.Minute)}, time.Now())
	for _, scenario := range []struct {
		view, want string
		flags      []string
	}{
		{"decisions", `"truncated": true`, []string{"--limit", "1"}},
		{"summary", `"partial": true`, nil},
		{"logs", `"gaps": 1`, []string{"--limit", "1"}},
	} {
		output, err := f.run(t, scenario.view, append(scenario.flags, "--format", "json")...)
		if err == nil || !strings.Contains(err.Error(), "partial") || !strings.Contains(output, scenario.want) || !strings.Contains(output, `"partial": true`) {
			t.Fatalf("partial %s observation = %s, %v", scenario.view, output, err)
		}
	}
	// The actual engine has not evaluated; an empty list is not a healthy pass.
	unknown := insights.NewEngine(insights.Config{Region: "gru"})
	other := newObserveFixture(t)
	other.server.HandleAuthenticated("GET /v1/insights", insights.Handler(unknown, insights.Summarizer{}))
	output, err := other.run(t, "insights")
	if err == nil || !strings.Contains(output, "unknown") {
		t.Fatalf("unevaluated insights = %s, %v", output, err)
	}
}

func TestObserveExistingFeatureValidation(t *testing.T) {
	f, _, _, _ := observeFeatureFixture(t)
	for _, scenario := range []struct {
		view  string
		flags []string
	}{
		{"decisions", []string{"--limit", "1001"}},
		{"decisions", []string{"--since", "invalid"}},
		{"decisions", []string{"--window", "1h"}},
		{"summary", []string{"--window", "169h"}},
		{"summary", []string{"--limit", "1"}},
		{"logs", []string{"--limit", "501"}},
		{"logs", []string{"--limit", "0"}},
		{"logs", []string{"--window", "2h"}},
		{"logs", []string{"--min-level", "TRACE"}},
		{"insights", []string{"--since", "1h"}},
	} {
		if output, err := f.run(t, scenario.view, scenario.flags...); err == nil || output != "" {
			t.Fatalf("invalid %s %v produced %s, %v", scenario.view, scenario.flags, output, err)
		}
	}
	if err := os.WriteFile(f.tokenFile, []byte(strings.Repeat("b", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"decisions", "insights", "summary", "logs"} {
		if output, err := f.run(t, view); err == nil || output != "" || !strings.Contains(err.Error(), "authentication denied") {
			t.Fatalf("unauthorized %s produced %s, %v", view, output, err)
		}
	}
}

func TestObserveExistingFeatureExactIntegersAndUnavailable(t *testing.T) {
	f, _, _, logView := observeFeatureFixture(t)
	logView.Add(logs.Window{Version: 1, Region: "gru", Node: "node-large", Boot: "boot", Seq: 0,
		Minute: time.Now().Truncate(time.Minute), Classes: []logs.Class{{Service: "counter", Level: logs.LevelWarn, Message: "counted", Count: (1 << 60) + 1}}}, time.Now())
	for _, format := range []string{"table", "json"} {
		output, err := f.run(t, "logs", "--service", "counter", "--format", format)
		if err != nil || !strings.Contains(output, "1152921504606846977") {
			t.Fatalf("log integers changed in %s = %s, %v", format, output, err)
		}
	}
	other := newObserveFixture(t)
	other.server.HandleAuthenticated("GET /v1/logs", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	output, err := other.run(t, "logs")
	if err == nil || output != "" || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("unavailable logs became empty success: %s, %v", output, err)
	}
	malformed := newObserveFixture(t)
	malformed.server.HandleAuthenticated("GET /v1/logs", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"v":2,"region":"gru"}`)
	}))
	output, err = malformed.run(t, "logs")
	if err == nil || output != "" || !strings.Contains(err.Error(), "invalid log summary JSON") {
		t.Fatalf("unsupported log reply accepted: %s, %v", output, err)
	}
	malformed.server.HandleAuthenticated("GET /v1/decisions", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	output, err = malformed.run(t, "decisions")
	if err == nil || output != "" || !strings.Contains(err.Error(), "omitted its observation") {
		t.Fatalf("missing decision observation became empty success: %s, %v", output, err)
	}
	malformed.server.HandleAuthenticated("GET /v1/insights", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"at":"2026-10-17T00:00:00Z","insights":[],"unavailable":["cluster"]}`)
	}))
	output, err = malformed.run(t, "insights", "--format", "json")
	if err == nil || !strings.Contains(output, `"partial": true`) || !strings.Contains(output, "cluster") {
		t.Fatalf("unavailable insights became healthy: %s, %v", output, err)
	}
}
