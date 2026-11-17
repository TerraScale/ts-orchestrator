package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func latencyRules() (group, error) {
	data, err := os.ReadFile("deploy/observability/production/latency-budgets.json")
	if err != nil {
		return group{}, err
	}
	var budgets []struct {
		Name    string  `json:"name"`
		Kind    string  `json:"kind"`
		EdgeP95 float64 `json:"edge_p95"`
	}
	if err := json.Unmarshal(data, &budgets); err != nil {
		return group{}, err
	}
	g := group{Name: "edge-latency"}
	for _, b := range budgets {
		if b.Kind != "http" {
			continue
		}
		if b.EdgeP95 <= 0 {
			return g, fmt.Errorf("missing edge p95 budget for %s", b.Name)
		}
		g.Rules = append(g.Rules, rule{
			Alert:  "EdgeLatencyBudgetExceeded",
			Expr:   fmt.Sprintf(`histogram_quantile(0.95, sum by (name, region, le) (rate(ts_orch_edge_request_duration_seconds_bucket{name=%q,stage="total"}[15m]))) > %g`, b.Name, b.EdgeP95),
			For:    "15m",
			Labels: map[string]string{"severity": "critical", "service": "edge"},
			Annotations: map[string]string{
				"summary":     `Edge p95 exceeds its budget for {{ $labels.name }} in {{ $labels.region }}`,
				"description": "The fifteen-minute total handler p95 has exceeded its name budget for fifteen minutes. Inspect upstream time and regional placement. Streaming handler lifetimes contribute to this histogram.",
				"runbook_url": "https://github.com/TerraScale/ts-orchestrator/blob/main/docs/edge-latency.md",
			},
		})
	}
	return g, nil
}
