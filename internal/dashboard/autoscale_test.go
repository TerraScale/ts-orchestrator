package dashboard

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestAutoscaledServicesChartReplicasGoalAndSignals(t *testing.T) {
	t.Parallel()
	now := time.Now()
	journal := historyJournal(now, func(_ time.Time, minute int) []observability.Sample {
		api := observability.L("service", "api")
		signal := observability.L("service", "api", "signal", "cpu_util")
		return []observability.Sample{
			{Metric: observability.HistAutoscaleReplicas, Labels: api, Value: 2},
			{Metric: observability.HistAutoscaleGoal, Labels: api, Value: 3},
			{Metric: observability.HistAutoscaleSignal, Labels: signal, Value: 0.9},
			{Metric: observability.HistAutoscaleSignalTarget, Labels: signal, Value: 0.6},
			// A service without a policy has replicas but no signals.
			{Metric: observability.HistAutoscaleReplicas, Labels: observability.L("service", "web"), Value: 1},
			{Metric: observability.HistTerraBaseLagSeq, Labels: observability.L("member", "tb-1", "role", "terrabase"),
				Value: float64(minute)},
		}
	})
	current := view{State: parseState(url.Values{}), Now: now, Journal: journal}

	body := fixturePage(t, current, "/terrabase")
	for _, want := range []string{"api", "web", "cpu_util", "cpu_util target", "scaling policy", "tb-1 / terrabase"} {
		if !strings.Contains(body, want) {
			t.Errorf("autoscale page lacks %q", want)
		}
	}
	found := false
	for _, chart := range pageCharts(t, body) {
		if len(chart.Series) == 2 && chart.Series[0].Name == "replicas" && chart.Series[1].Name == "goal" && chart.Series[1].Dashed {
			found = true
		}
	}
	if !found {
		t.Fatal("replicas and dashed goal missing from delivered chart")
	}
	many := historyJournal(now, func(time.Time, int) []observability.Sample {
		var samples []observability.Sample
		for i := range maxAutoscaledServices + 2 {
			samples = append(samples, observability.Sample{Metric: observability.HistAutoscaleReplicas, Labels: observability.L("service", "svc-"+string(rune('a'+i))), Value: 1})
		}
		return samples
	})
	if body := fixturePage(t, view{Now: now, Journal: many}, "/terrabase"); !strings.Contains(body, "svc-m, svc-n") {
		t.Fatal("bounded charts silently omitted services")
	}
	body = fixturePage(t, view{Now: now, Journal: &Journal{History: observability.NewHistory(observability.HistoryConfig{})}}, "/terrabase")
	if !strings.Contains(body, "host telemetry") {
		t.Fatal("empty history invented TerraBase load")
	}
}
