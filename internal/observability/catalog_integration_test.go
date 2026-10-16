package observability

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

func TestMetricCatalogHTTPRegistryAndHistoryIntegration(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(true)
	set := metrics.NewSet()
	counter := set.NewCounter(`ts_orch_catalog_requests_total{service="first",token="private-payload"}`)
	counter.Add(3)
	registry.Register(set)
	registry.RegisterWriter(func(writer io.Writer) {
		fmt.Fprint(writer, "# HELP ts_orch_catalog_latency Request latency.\n# TYPE ts_orch_catalog_latency histogram\n# UNIT ts_orch_catalog_latency seconds\n")
		fmt.Fprint(writer, "ts_orch_catalog_latency_bucket{le=\"+Inf\"} 4\nts_orch_catalog_latency_sum 2\nts_orch_catalog_latency_count 4\n")
		fmt.Fprint(writer, "ts_orch_catalog_nonfinite NaN\n")
	})
	token := strings.Repeat("t", 40)
	server, err := NewTokenServer(Config{}, token, ServerDeps{Registry: registry, Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	shared := server.MetricCatalog()
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	get := func(path, auth string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			request.Header.Set("Authorization", auth)
		}
		response, err := listener.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(data)
	}
	for _, auth := range []string{"", "Bearer wrong"} {
		if code, _ := get("/v1/metrics/catalog", auth); code != http.StatusUnauthorized {
			t.Fatalf("unauthorized catalog status %d", code)
		}
	}
	code, body := get("/v1/metrics/catalog", "Bearer "+token)
	if code != http.StatusOK {
		t.Fatalf("catalog status %d: %s", code, body)
	}
	if strings.Contains(body, "private-payload") || strings.Contains(body, `service=\"first`) {
		t.Fatal("catalog exposed label values")
	}
	var catalog CatalogResult
	if err := json.Unmarshal([]byte(body), &catalog); err != nil {
		t.Fatal(err)
	}
	find := func(name string) CatalogMetric {
		t.Helper()
		for _, metric := range catalog.Metrics {
			if metric.Name == name {
				return metric
			}
		}
		t.Fatalf("metric %s missing", name)
		return CatalogMetric{}
	}
	if catalog.Version != 1 || catalog.ObservedAt.IsZero() {
		t.Fatalf("missing version or collection time: %+v", catalog)
	}
	if catalog.Truncated {
		t.Fatal("standard runtime metric families exceeded the catalog budget")
	}
	goMetrics, processMetrics := false, false
	for _, metric := range catalog.Metrics {
		goMetrics = goMetrics || strings.HasPrefix(metric.Name, "go_")
		processMetrics = processMetrics || strings.HasPrefix(metric.Name, "process_")
	}
	if !goMetrics || !processMetrics {
		t.Fatal("actual Go/process metrics missing")
	}
	metric := find("ts_orch_catalog_requests_total")
	if metric.Type != "counter" || len(metric.Samples) != 1 || metric.Samples[0].Value != "3" || !slices.Equal(metric.Labels, []string{"service", "token"}) || !slices.Contains(metric.Unsupported, "description") || !slices.Contains(metric.Unsupported, "unit") {
		t.Fatalf("registry metric %+v", metric)
	}
	latency := find("ts_orch_catalog_latency")
	if latency.Type != "histogram" || latency.Unit != "seconds" || latency.Description != "Request latency." || len(latency.Samples) != 3 {
		t.Fatalf("exported family metadata %+v", latency)
	}
	if find("ts_orch_catalog_nonfinite").Samples[0].Value != "NaN" {
		t.Fatal("non-finite numeric text lost")
	}
	// A later write appears without rebuilding a separate telemetry inventory.
	counter.Add(2)
	catalog, err = shared.Catalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if find("ts_orch_catalog_requests_total").Samples[0].Value != "5" {
		t.Fatal("catalog did not read current registry")
	}
	unsupported, err := shared.History(t.Context(), HistoryQuery{Metric: "not_retained"})
	if err != nil || unsupported.State != "unsupported" {
		t.Fatalf("missing history source: %+v %v", unsupported, err)
	}
	history := NewHistory(HistoryConfig{})
	now := time.Now().UTC().Truncate(time.Second)
	history.Append(now.Add(-10*time.Second), []Sample{{Metric: "retained_metric", Labels: L("member", "host-a"), Value: 2}})
	history.Append(now, []Sample{{Metric: "retained_metric", Labels: L("member", "host-a"), Value: 3}})
	server.HandleMetricHistory(history)
	if server.MetricCatalog() != shared {
		t.Fatal("history replaced shared catalog instance")
	}
	for _, path := range []string{"/v1/history?metric=retained_metric", "/v1/history/metrics"} {
		if code, _ := get(path, ""); code != http.StatusUnauthorized {
			t.Fatalf("unauthorized %s status %d", path, code)
		}
	}
	code, body = get("/v1/history?metric=retained_metric&tier=raw", "Bearer "+token)
	var retained CatalogHistory
	if err := json.Unmarshal([]byte(body), &retained); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || retained.Version != 1 || retained.State != "available" || len(retained.Series) != 1 || len(retained.Series[0].Points) != 2 {
		t.Fatalf("retained range status %d: %s", code, body)
	}
	catalog, err = shared.Catalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	retainedMetric := find("retained_metric")
	if retainedMetric.HistoryState != "available" || len(retainedMetric.HistoryTiers) != 4 || retainedMetric.HistoryRetentionSeconds != int64(HistoryRetention/time.Second) || !retainedMetric.ObservedAt.IsZero() || !slices.Contains(retainedMetric.Unsupported, "collection_time") {
		t.Fatalf("retained metadata %+v", retainedMetric)
	}
	stale, err := shared.History(t.Context(), HistoryQuery{Metric: "retained_metric", Start: now.Add(-time.Minute), End: now.Add(time.Minute), Tier: TierRaw})
	if err != nil || stale.State != "stale" {
		t.Fatalf("stale retained history %+v: %v", stale, err)
	}
	missing, err := shared.History(t.Context(), HistoryQuery{Metric: "retained_metric", Start: now.Add(-time.Hour), End: now.Add(-time.Minute), Tier: TierRaw})
	if err != nil || missing.State != "missing" {
		t.Fatalf("missing range %+v: %v", missing, err)
	}
	if code, _ := get("/v1/history?metric=retained_metric&start=2020-01-01T00:00:00Z", "Bearer "+token); code != http.StatusBadRequest {
		t.Fatalf("unbounded history status %d", code)
	}
	// Replacing the regional provider updates both routes without a mux panic.
	server.HandleMetricHistory(NewHistory(HistoryConfig{}))
	if code, body := get("/v1/history/metrics", "Bearer "+token); code != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Fatalf("replaced source status %d: %s", code, body)
	}
}

func TestMetricCatalogHTTPBoundedExpositionIntegration(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(false)
	registry.RegisterWriter(func(writer io.Writer) {
		for index := range catalogMaxMetrics + 10 {
			fmt.Fprintf(writer, "bounded_metric_%d 1\n", index)
		}
		fmt.Fprint(writer, strings.Repeat("x", catalogMaxBytes))
	})
	token := strings.Repeat("b", 40)
	server, err := NewTokenServer(Config{}, token, ServerDeps{Registry: registry, Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/v1/metrics/catalog", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := listener.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var catalog CatalogResult
	if err := json.NewDecoder(response.Body).Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !catalog.Truncated || catalog.State != "truncated" || len(catalog.Metrics) != catalogMaxMetrics {
		t.Fatalf("bounded response: status %d, state %s, truncated %t, metrics %d", response.StatusCode, catalog.State, catalog.Truncated, len(catalog.Metrics))
	}
	// A loopback address alone must not authorize this new discovery API.
	local, err := NewServer(Config{}, ServerDeps{Registry: registry, Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	local.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/metrics/catalog", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("tokenless discovery status %d", recorder.Code)
	}
}
