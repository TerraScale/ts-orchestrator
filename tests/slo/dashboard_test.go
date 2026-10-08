package slo

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestDashboardContract(t *testing.T) {
	data, err := os.ReadFile("../../deploy/observability/slo-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	type datasource struct{ Type, UID string }
	var dashboard struct {
		Inputs     []struct{ Name, Type, PluginID string } `json:"__inputs"`
		Templating struct {
			List []struct{ Name, Query string }
		}
		Panels []struct {
			Type        string
			Datasource  datasource
			Targets     []struct{ Expr string }
			FieldConfig struct {
				Defaults struct {
					NoValue  string
					Min, Max *float64
					Mappings []struct {
						Type    string
						Options struct {
							Match  string
							Result struct{ Text, Color string }
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatal(err)
	}
	if len(dashboard.Inputs) != 1 || dashboard.Inputs[0].Name != "DS_PROMETHEUS" || dashboard.Inputs[0].Type != "datasource" || dashboard.Inputs[0].PluginID != "prometheus" {
		t.Fatal("dashboard must allow selecting a Prometheus datasource on import")
	}
	if len(dashboard.Templating.List) != 1 || dashboard.Templating.List[0].Name != "service" || !slices.Equal(strings.Split(dashboard.Templating.List[0].Query, ","), services) {
		t.Fatal("service selector must cover all five SLO services")
	}
	rules, err := os.ReadFile("../../deploy/observability/slo-rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^\s+- record: (\S+)`).FindAllStringSubmatch(string(rules), -1) {
		records[match[1]] = true
	}
	queried := map[string]bool{}
	metricNames := regexp.MustCompile(`\bslo:[a-z_0-9:]+`)
	for _, panel := range dashboard.Panels {
		if panel.Type == "text" {
			continue
		}
		if panel.Datasource != (datasource{Type: "prometheus", UID: "${DS_PROMETHEUS}"}) {
			t.Error("data panels must use the datasource selected during import")
		}
		defaults := panel.FieldConfig.Defaults
		if defaults.NoValue != "No data" {
			t.Error("missing telemetry must display No data")
		}
		for _, mapping := range defaults.Mappings {
			if mapping.Type == "special" && (mapping.Options.Match == "null" || mapping.Options.Match == "nan") && (mapping.Options.Result.Text != "No data" || mapping.Options.Result.Color == "green") {
				t.Error("null/NaN telemetry must never map to healthy")
			}
		}
		for _, target := range panel.Targets {
			if !strings.Contains(target.Expr, "${service:regex}") {
				t.Errorf("query ignores service selection: %s", target.Expr)
			}
			for _, metric := range metricNames.FindAllString(target.Expr, -1) {
				if !records[metric] {
					t.Errorf("query references undefined rule: %s", metric)
				}
				queried[metric] = true
			}
			if strings.Contains(target.Expr, "slo:budget_remaining:ratio30d") && (defaults.Min != nil || defaults.Max != nil || strings.Contains(target.Expr, "clamp")) {
				t.Error("negative remaining budgets must stay visible")
			}
		}
	}
	for _, metric := range []string{"slo:objective", "slo:errors:ratio30d", "slo:budget_remaining:ratio30d", "slo:requests:rate5m"} {
		if !queried[metric] {
			t.Errorf("dashboard lacks %s", metric)
		}
	}
	for _, window := range []string{"5m", "30m", "1h", "2h", "6h", "1d", "3d"} {
		if !queried["slo:burn_rate:ratio"+window] {
			t.Errorf("dashboard lacks burn window %s", window)
		}
	}
}
