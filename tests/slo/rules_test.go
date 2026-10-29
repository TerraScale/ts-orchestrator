package slo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var services = []string{"terrabase", "ts-auth", "ts-dashboard"}

// Promtool evaluates the shipped PromQL, including counter resets and vector
// matching. TS_SLO_PROMTOOL is mandatory in the SLO workflow; ordinary Go
// checks can run without installing a second executable.
func TestPrometheusRules(t *testing.T) {
	tool := os.Getenv("TS_SLO_PROMTOOL")
	if tool == "" {
		t.Skip("set TS_SLO_PROMTOOL to run the Prometheus rule evaluations")
	}
	rules, err := filepath.Abs("../../deploy/observability/slo-rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), tool, args...)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("promtool %v: %v\n%s", args, err, output)
		}
	}
	t.Run("fleet cleanup scrape", func(t *testing.T) { testCleanupFleetScrape(t, tool) })
	run("check", "rules", rules)
	run("test", "rules", "../../deploy/observability/production/host-storage-rules.test.yml")
	var fixture strings.Builder
	fmt.Fprintf(&fixture, "rule_files: [%q]\nevaluation_interval: 1m\nfuzzy_compare: true\ntests:\n", rules)
	add := func(name, good, bad string, checks string) {
		fmt.Fprintf(&fixture, "  - name: %s\n    interval: 1m\n    input_series:\n", name)
		for _, service := range services {
			for outcome, values := range map[string]string{"good": good, "bad": bad} {
				fmt.Fprintf(&fixture, "      - series: 'terrascale_slo_requests_total{service=%q,outcome=%q}'\n        values: %q\n", service, outcome, values)
			}
		}
		fixture.WriteString(checks)
	}
	noBurn := "    alert_rule_test:\n"
	for _, suffix := range []string{"Fast", "Slow", "Daily", "Steady"} {
		noBurn += fmt.Sprintf("      - eval_time: 1h\n        alertname: ServiceSLOBurn%s\n        exp_alerts: []\n", suffix)
	}
	noBurn += "      - eval_time: 1h\n        alertname: ServiceSLOTelemetryMissing\n        exp_alerts: []\n"
	add("healthy and fully initialized", "0+1000x60", "0+0x60", noBurn+samples("slo:budget_remaining:ratio30d", "1h", 1))
	add("no traffic is not a burn or missing telemetry", "0+0x60", "0+0x60", noBurn+`    promql_expr_test:
      - expr: 'slo:burn_rate:ratio5m > 0'
        eval_time: 1h
        exp_samples: []
      - expr: 'slo:errors:ratio30d == bool 0'
        eval_time: 1h
        exp_samples:
`+serviceSamples("", 0))
	checks := "    alert_rule_test:\n"
	for _, window := range []struct {
		suffix, long, short, severity, threshold string
	}{
		{"Fast", "1h", "5m", "critical", "14.4"},
		{"Slow", "6h", "30m", "critical", "6"},
		{"Daily", "1d", "2h", "warning", "3"},
		{"Steady", "3d", "6h", "warning", "1"},
	} {
		// Feed recorded burn series directly to exercise each shipped alert's
		// pairing and strict threshold without simulating three days of traffic.
		for _, rates := range []struct {
			name, long, short, shortService string
		}{
			{"long only", "20", "0", "terrabase"},
			{"short only", "0", "20", "terrabase"},
			{"at threshold", window.threshold, window.threshold, "terrabase"},
			{"services separated", "20", "20", "ts-auth"},
		} {
			fmt.Fprintf(&fixture, `  - name: '%s %s'
    interval: 1m
    input_series:
      - series: 'slo:burn_rate:ratio%s{service="terrabase",slo="availability"}'
        values: '%s+0x2'
      - series: 'slo:burn_rate:ratio%s{service=%q,slo="availability"}'
        values: '%s+0x2'
    alert_rule_test:
      - eval_time: 2m
        alertname: ServiceSLOBurn%s
        exp_alerts: []
`, window.suffix, rates.name, window.long, rates.long, window.short, rates.shortService, rates.short, window.suffix)
		}
		fmtChecks := fmt.Sprintf("      - eval_time: 1h\n        alertname: ServiceSLOBurn%s\n        exp_alerts:\n", window.suffix)
		checks += fmtChecks
		for _, service := range services {
			checks += fmt.Sprintf(`          - exp_labels:
              service: %s
              slo: availability
              severity: %s
              long_window: %s
              short_window: %s
            exp_annotations:
              summary: '%s availability error budget is burning'
              description: 'Burn exceeds %sx in both %s and %s; inspect service failures before changing capacity or releases.'
`, service, window.severity, window.long, window.short, service, window.threshold, window.long, window.short)
		}
	}
	add("sustained burn for all services", "0+980x60", "0+20x60", checks+samples("round(slo:budget_remaining:ratio30d)", "1h", -19))
	add("recent recovery clears fast burn", "0+980x60 59800+1000x10", "0+20x60 1200+0x10", `    alert_rule_test:
      - eval_time: 70m
        alertname: ServiceSLOBurnFast
        exp_alerts: []
    promql_expr_test:
      - expr: 'slo:burn_rate:ratio1h > bool 14.4'
        eval_time: 70m
        exp_samples:
`+serviceSamples("", 1))
	add("short burst alone does not page", "0+1000x60 60800+800x2", "0+0x60 200+200x2", `    alert_rule_test:
      - eval_time: 62m
        alertname: ServiceSLOBurnFast
        exp_alerts: []
    promql_expr_test:
      - expr: 'slo:burn_rate:ratio5m > bool 14.4'
        eval_time: 62m
        exp_samples:
`+serviceSamples("", 1))
	// Rate before sum preserves independent resets and weights by request
	// volume: one replica fails 2/100 requests, another succeeds 900/900.
	fixture.WriteString(`  - name: counter reset and request weighted fleet aggregation
    interval: 1m
    input_series:
      - series: 'terrascale_slo_requests_total{service="terrabase",instance="a",outcome="good"}'
        values: '0+98x30 0+98x29'
      - series: 'terrascale_slo_requests_total{service="terrabase",instance="a",outcome="bad"}'
        values: '0+2x30 0+2x29'
      - series: 'terrascale_slo_requests_total{service="terrabase",instance="b",outcome="good"}'
        values: '0+900x60'
      - series: 'terrascale_slo_requests_total{service="terrabase",instance="b",outcome="bad"}'
        values: '0+0x60'
    promql_expr_test:
      - expr: round(slo:burn_rate:ratio5m * 1000) / 1000
        eval_time: 35m
        exp_samples:
          - labels: '{service="terrabase",slo="availability"}'
            value: 1.633
`)
	fixture.WriteString("  - name: missing telemetry is not healthy\n    interval: 1m\n    alert_rule_test:\n      - eval_time: 15m\n        alertname: ServiceSLOTelemetryMissing\n        exp_alerts:\n")
	for _, service := range services {
		fixture.WriteString(missingAlert(service))
	}
	// Any outcome proves telemetry: a healthy service may expose good counters
	// alone, so an absent bad counter is not missing telemetry.
	fixture.WriteString("  - name: good-only traffic is not missing telemetry\n    interval: 1m\n    input_series:\n")
	for _, service := range services {
		fmt.Fprintf(&fixture, "      - series: 'terrascale_slo_requests_total{service=%q,outcome=\"good\"}'\n        values: '0+1000x15'\n", service)
	}
	fixture.WriteString("    alert_rule_test:\n      - eval_time: 15m\n        alertname: ServiceSLOTelemetryMissing\n        exp_alerts: []\n")
	// Only a service with no counter of any outcome is missing telemetry.
	fixture.WriteString("  - name: partial missing service\n    interval: 1m\n    input_series:\n")
	for _, service := range services {
		if service == "ts-auth" {
			continue
		}
		fmt.Fprintf(&fixture, "      - series: 'terrascale_slo_requests_total{service=%q,outcome=\"good\"}'\n        values: '0+1000x15'\n", service)
		fmt.Fprintf(&fixture, "      - series: 'terrascale_slo_requests_total{service=%q,outcome=\"bad\"}'\n        values: '0+0x15'\n", service)
	}
	fixture.WriteString("    alert_rule_test:\n      - eval_time: 15m\n        alertname: ServiceSLOTelemetryMissing\n        exp_alerts:\n" + missingAlert("ts-auth"))
	fixture.WriteString(`  - name: native HTTP normalization keeps process counters and excludes probes
    interval: 1m
    input_series:
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/v1/projects/{project}/databases",http_response_status_code="200"}'
        values: '0+98x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/v1/projects/{project}/databases",http_response_status_code="404"}'
        values: '0+1x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/v1/projects/{project}/databases",http_response_status_code="503",error_type="503"}'
        values: '0+1x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/readyz",http_response_status_code="503"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/metrics",http_response_status_code="200"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/terrabase.v1.Replication/Push",http_response_status_code="500"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/v1/admin/node/pressure",http_response_status_code="200"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="terrabase",instance="base-one",region="gru",http_route="/v1/catalog-gate",http_response_status_code="503"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="ts-auth",instance="auth-one",region="gru",http_route="/v1/{slug}/deletions/{id}/acknowledge",http_response_status_code="503"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="ts-auth",instance="auth-one",region="gru",http_route="/{slug}/oauth/token",http_response_status_code="401"}'
        values: '0+100x15'
      - series: 'http_server_request_duration_seconds_count{service="ts-auth",instance="auth-two",region="gru",http_route="/readyz",http_response_status_code="200"}'
        values: '0+1000x15'
      - series: 'http_server_request_duration_seconds_count{service="ts-auth",instance="auth-two",region="gru",http_response_status_code="200"}'
        values: '0+1000x15'
      - series: 'terrascale_slo_requests_total{service="ts-dashboard",instance="dash-one",region="gru",outcome="good"}'
        values: '0+100x15'
      - series: 'terrascale_slo_requests_total{service="ts-dashboard",instance="dash-one",region="gru",outcome="bad"}'
        values: '0+0x15'
    alert_rule_test:
      - eval_time: 15m
        alertname: ServiceSLOTelemetryMissing
        exp_alerts: []
    promql_expr_test:
      - expr: terrascale_slo_requests_total{service="terrabase"}
        eval_time: 15m
        exp_samples:
          - labels: 'terrascale_slo_requests_total{service="terrabase",instance="base-one",region="gru",outcome="good"}'
            value: 1485
          - labels: 'terrascale_slo_requests_total{service="terrabase",instance="base-one",region="gru",outcome="bad"}'
            value: 15
      - expr: terrascale_slo_requests_total{service="ts-auth"}
        eval_time: 15m
        exp_samples:
          - labels: 'terrascale_slo_requests_total{service="ts-auth",instance="auth-one",region="gru",outcome="good"}'
            value: 1500
          - labels: 'terrascale_slo_requests_total{service="ts-auth",instance="auth-one",region="gru",outcome="bad"}'
            value: 0
          - labels: 'terrascale_slo_requests_total{service="ts-auth",instance="auth-two",region="gru",outcome="good"}'
            value: 0
          - labels: 'terrascale_slo_requests_total{service="ts-auth",instance="auth-two",region="gru",outcome="bad"}'
            value: 0
      - expr: round(slo:burn_rate:ratio5m{service="terrabase"})
        eval_time: 15m
        exp_samples:
          - labels: '{service="terrabase",slo="availability"}'
            value: 10
`)
	path := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.WriteFile(path, []byte(fixture.String()), 0600); err != nil {
		t.Fatal(err)
	}
	run("test", "rules", path)
	operational, err := filepath.Abs("../../deploy/observability/production/operational-rules.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), tool, "test", "rules", filepath.Base(operational))
	cmd.Dir = filepath.Dir(operational)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production operational rules: %v\n%s", err, output)
	}
}

func samples(metric, at string, value float64) string {
	return fmt.Sprintf("    promql_expr_test:\n      - expr: %s\n        eval_time: %s\n        exp_samples:\n", metric, at) + serviceSamples(sampleMetric(metric), value)
}

func serviceSamples(metric string, value float64) string {
	var out strings.Builder
	for _, service := range services {
		fmt.Fprintf(&out, "          - labels: '%s{service=%q,slo=\"availability\"}'\n            value: %g\n", metric, service, value)
	}
	return out.String()
}

func missingAlert(service string) string {
	return fmt.Sprintf(`          - exp_labels:
              service: %s
              slo: availability
              severity: warning
            exp_annotations:
              summary: '%s SLO telemetry is missing'
              description: 'No recent good or bad request counter; restore instrumentation or collection. Missing telemetry is not availability success.'
`, service, service)
}

func sampleMetric(expr string) string {
	if strings.HasPrefix(expr, "round(") {
		return ""
	}
	return expr
}
