package cli

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
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
