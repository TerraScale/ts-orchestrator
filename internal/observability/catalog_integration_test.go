package observability

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
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
	// Append after the existing history replacement assertion, before this root closes.
	{
		start := func(t *testing.T, service *Server) (string, *http.Client) {
			t.Helper()
			probe := httptest.NewServer(http.NotFoundHandler())
			address := strings.TrimPrefix(probe.URL, "http://")
			probe.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			result, err := service.Start(ctx, Config{ListenAddress: address})
			if err != nil {
				cancel()
				t.Fatalf("start loopback listener: %v", err)
			}
			client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
			t.Cleanup(func() {
				client.CloseIdleConnections()
				cancel()
				closed := make(chan error, 1)
				go func() { closed <- service.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Errorf("close listener: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("listener cleanup did not finish within 5 seconds")
				}
				select {
				case err := <-result:
					if err != nil {
						t.Errorf("serve result: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("serve result did not arrive within 5 seconds")
				}
			})
			return "http://" + service.Addr().String(), client
		}
		request := func(t *testing.T, client *http.Client, base, method, path, authorization, host string, headers ...string) (int, string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			if host != "" {
				req.Host = host
			}
			for index := 0; index+1 < len(headers); index += 2 {
				req.Header.Set(headers[index], headers[index+1])
			}
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			return response.StatusCode, string(body)
		}
		t.Run("server private listeners and token files", func(t *testing.T) {
			tokenFile := filepath.Join(t.TempDir(), "token")
			token := strings.Repeat("t", 40)
			if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			deps := ServerDeps{Registry: NewRegistry(false), Health: new(Health)}
			for _, address := range []string{"127.0.0.1:9464", "[::1]:9464", "10.0.1.5:9464", "172.16.4.2:9464", "192.168.1.10:9464", "10.200.106.253:9464", "[fd00::1]:9464"} {
				t.Run(address, func(t *testing.T) {
					service, err := NewServer(Config{ListenAddress: address, BearerTokenFile: tokenFile}, deps)
					if err != nil {
						t.Fatalf("NewServer(%q): %v", address, err)
					}
					base, client := start(t, service)
					if code, _ := request(t, client, base, http.MethodGet, "/metrics", "Bearer "+token, ""); code != http.StatusOK {
						t.Fatalf("listener %q metrics = %d", address, code)
					}
				})
			}
			service, err := NewServer(Config{}, deps)
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range []string{"0.0.0.0:9464", "[::]:9464", ":9464", "localhost:9464", "8.8.8.8:9464", "169.254.1.1:9464", "224.0.0.1:9464", "127.0.0.1:0", "127.0.0.1", "[fe80::1%eth0]:9464", "127.000.0.1:9464", "[::ffff:8.8.8.8]:9464", "100.90.12.3:9464", "off"} {
				if _, err := service.Start(t.Context(), Config{ListenAddress: address}); err == nil {
					_ = service.Close()
					t.Fatalf("Start accepted %q", address)
				}
			}
			for _, config := range []Config{{ListenAddress: "10.0.0.4:9464"}, {TLSCertFile: "/cert"}, {LogFormat: "xml"}, {LogLevel: "trace"}} {
				if _, err := NewServer(config, deps); err == nil {
					t.Fatalf("NewServer accepted %+v", config)
				}
			}
		})
		t.Run("server routes and bearer token", func(t *testing.T) {
			tokenFile := filepath.Join(t.TempDir(), "token")
			token := strings.Repeat("t", 40)
			if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			registry := NewRegistry(false)
			set := metrics.NewSet()
			set.NewCounter(MetricPrefix + "test_total").Add(3)
			registry.Register(set)
			health := new(Health)
			var ready atomic.Bool
			health.Add(Check{Name: "nats", Run: func(context.Context) (bool, string) { return ready.Load(), "not connected" }})
			bus := NewEventBus(8)
			bus.Publish(Event{Message: "hello"})
			service, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile}, ServerDeps{Registry: registry, Health: health, Events: bus})
			if err != nil {
				t.Fatal(err)
			}
			base, client := start(t, service)
			get := func(path, authorization string, headers ...string) (int, string) {
				t.Helper()
				return request(t, client, base, http.MethodGet, path, authorization, "", headers...)
			}
			if code, _ := get("/healthz", ""); code != http.StatusOK {
				t.Fatalf("/healthz = %d", code)
			}
			if code, body := get("/readyz", ""); code != http.StatusServiceUnavailable || !strings.Contains(body, "nats failing: not connected") {
				t.Fatalf("/readyz = %d %q", code, body)
			}
			ready.Store(true)
			if code, _ := get("/readyz", ""); code != http.StatusOK {
				t.Fatalf("ready /readyz = %d", code)
			}
			if code, _ := get("/metrics", ""); code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated /metrics = %d", code)
			}
			if code, _ := get("/metrics", "Bearer wrong"); code != http.StatusUnauthorized {
				t.Fatalf("wrong token /metrics = %d", code)
			}
			if code, body := get("/metrics", "Bearer "+token); code != http.StatusOK || !strings.Contains(body, "ts_orch_test_total 3") {
				t.Fatalf("/metrics = %d %q", code, body)
			}
			if code, _ := get("/metrics", "Bearer "+token, "X-Forwarded-For", "1.2.3.4"); code != http.StatusBadRequest {
				t.Fatalf("proxied /metrics = %d", code)
			}
			_, body := get("/v1/events?limit=5", "Bearer "+token)
			var events []Event
			if err := json.Unmarshal([]byte(body), &events); err != nil || len(events) != 1 || events[0].Message != "hello" {
				t.Fatalf("/v1/events = %q, %v", body, err)
			}
			if code, _ := get("/v1/cluster", "Bearer "+token); code != http.StatusNotFound {
				t.Fatalf("unconfigured /v1/cluster = %d", code)
			}
			if code, _ := request(t, client, base, http.MethodPost, "/metrics", "", ""); code != http.StatusMethodNotAllowed && code != http.StatusUnauthorized {
				t.Fatalf("POST /metrics = %d", code)
			}
		})
		t.Run("server refuses tokenless network address", func(t *testing.T) {
			service, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Start(t.Context(), Config{ListenAddress: "10.0.0.1:9464"}); err == nil || !strings.Contains(err.Error(), "bearer_token_file") {
				_ = service.Close()
				t.Fatalf("Start(tokenless private address) error = %v", err)
			}
			base, client := start(t, service)
			if code, _ := request(t, client, base, http.MethodGet, "/metrics", "", ""); code != http.StatusOK {
				t.Fatalf("tokenless loopback /metrics = %d", code)
			}
		})
		t.Run("tokenless server refuses hostnames on every route", func(t *testing.T) {
			service, err := NewServer(Config{}, ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
			if err != nil {
				t.Fatal(err)
			}
			service.Handle("GET /v1/extra", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) }))
			base, client := start(t, service)
			for _, path := range []string{"/metrics", "/healthz", "/v1/extra"} {
				for host, want := range map[string]int{"rebind.attacker.example:9464": http.StatusMisdirectedRequest, "127.0.0.1:9464": http.StatusOK, "[::1]:9464": http.StatusOK, "localhost:9464": http.StatusOK} {
					if code, _ := request(t, client, base, http.MethodGet, path, "", host); code != want {
						t.Fatalf("GET %s with Host %q = %d, want %d", path, host, code, want)
					}
				}
			}
		})
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

func TestMetricCatalogLiveSystemHistoryHTTPIntegration(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("system statistics require Linux")
	}
	registry := NewRegistry(false)
	collector, err := NewCollector(CollectorConfig{
		Cell: "live-cell", Member: "live-host", Role: "controller", Registry: registry,
		Filesystems: []FilesystemRole{{Role: "tmp", Path: t.TempDir()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Snapshot(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.System == nil || len(snapshot.Errors) != 0 {
		t.Fatalf("live system snapshot: %+v", snapshot)
	}
	system := snapshot.System
	if system.CPUCount < 1 || system.MemTotalBytes == 0 || system.ProcessRSSBytes == 0 ||
		len(system.Filesystems) != 1 || system.Filesystems[0].SizeBytes == 0 {
		t.Fatalf("live procfs/statfs observations: %+v", system)
	}
	history := NewHistory(HistoryConfig{})
	token := strings.Repeat("l", 40)
	server, err := NewTokenServer(Config{}, token, ServerDeps{Registry: registry, Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	server.HandleMetricHistory(history)
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- (HistorySampler{Store: history, Collect: ClusterCollect(nil, collector)}).Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != context.Canceled {
			t.Errorf("live sampler stopped: %v", err)
		}
	})
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for !slices.Contains(history.Metrics(), HistFSSize) {
		select {
		case <-deadline.C:
			t.Fatal("live sampler did not retain filesystem observations")
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-poll.C:
		}
	}
	for _, metric := range []string{HistMemoryTotal, HistFSSize} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			listener.URL+"/v1/history?metric="+metric+"&tier=raw&range=1m&label.member=live-host", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := listener.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read live history: %v; close: %v", readErr, closeErr)
		}
		var result CatalogHistory
		if err := jsonv2.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || result.State != "available" || len(result.Series) != 1 ||
			result.IntervalSeconds != DefaultHistoryInterval.Seconds() || result.Pending || result.Incomplete || result.Truncated {
			t.Fatalf("live %s history: status %d, %+v", metric, response.StatusCode, result)
		}
		series := result.Series[0]
		if series.Metric != metric || series.Tier != TierRaw || series.Labels["member"] != "live-host" ||
			len(series.Points) == 0 || series.LastObservedAt.IsZero() {
			t.Fatalf("live %s series: %+v", metric, series)
		}
		if metric == HistFSSize && series.Labels["role"] != "tmp" {
			t.Fatalf("live filesystem role: %+v", series.Labels)
		}
		for _, point := range series.Points {
			if !(point.Value > 0) || math.IsInf(point.Value, 0) || point.Min != point.Value || point.Max != point.Value ||
				point.Time.Before(snapshot.ObservedAt.Truncate(time.Millisecond)) || point.Time.After(result.ObservedAt) {
				t.Fatalf("live %s point: %+v", metric, point)
			}
		}
	}
}
