package dashboard

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
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
	services := current.autoscaledServices()
	if len(services) != 2 || services[0].Name != "api" || services[1].Name != "web" {
		t.Fatalf("services = %+v", services)
	}
	api := services[0]
	if len(api.Replicas.Series) != 2 || api.Replicas.Series[0].Name != "replicas" || api.Replicas.Series[1].Name != "goal" ||
		!api.Replicas.Series[1].Dashed {
		t.Fatalf("replica chart = %+v", api.Replicas.Series)
	}
	if len(api.Signals.Series) != 2 || api.Signals.Series[0].Name != "cpu_util" ||
		api.Signals.Series[1].Name != "cpu_util target" || api.Signals.Empty != "" {
		t.Fatalf("signal chart = %+v", api.Signals.Series)
	}
	if web := services[1]; len(web.Signals.Series) != 0 || !strings.Contains(web.Signals.Empty, "scaling policy") {
		t.Fatalf("policy-less service signal chart = %+v", web.Signals)
	}
	lag := current.terraBaseLoadChart(observability.HistTerraBaseLagSeq, "count")
	if len(lag.Series) != 1 || lag.Series[0].Name != "tb-1 / terrabase" {
		t.Fatalf("lag chart = %+v", lag.Series)
	}
	empty := view{State: parseState(url.Values{}), Now: now,
		Journal: &Journal{History: observability.NewHistory(observability.HistoryConfig{})}}
	if len(empty.autoscaledServices()) != 0 ||
		!strings.Contains(empty.terraBaseLoadChart(observability.HistTerraBaseConnections, "count").Empty, "host telemetry") {
		t.Fatal("empty history invented autoscale or TerraBase load data")
	}
}
