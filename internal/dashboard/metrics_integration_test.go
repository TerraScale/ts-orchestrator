package dashboard

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Exercise the private listener, real exporter registry and real tiered history
// together: rendering helpers alone cannot prove catalog/API/dashboard parity.
func TestMetricDashboardRegistryHistoryHTTP(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	registry := observability.NewRegistry(true)
	set := metrics.NewSet()
	queue := set.NewGauge("obs_dashboard_queue", nil)
	queue.Set(0)
	set.NewCounter("obs_dashboard_actions_total").Add(3)
	longMetric := "obs_dashboard_" + strings.Repeat("a", 180)
	set.NewGauge(longMetric, nil).Set(7)
	registry.Register(set)
	registry.RegisterWriter(func(writer io.Writer) {
		_, _ = io.WriteString(writer, "# HELP obs_dashboard_queue Work waiting for placement\n# TYPE obs_dashboard_queue gauge\n# UNIT obs_dashboard_queue count\n")
	})
	history := observability.NewHistory(observability.HistoryConfig{})
	for _, second := range []int{50, 40, 10, 0} {
		history.Append(now.Add(-time.Duration(second)*time.Second), []observability.Sample{{Metric: "obs_dashboard_queue", Value: float64(second)}})
	}
	for worker := range 33 {
		history.Append(now, []observability.Sample{{Metric: "obs_dashboard_worker", Value: float64(worker),
			Labels: observability.L("member", fmt.Sprintf("worker-%02d", worker))}})
	}
	const token = "metric-dashboard-integration-private-token"
	listener, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: registry, Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.HandleMetricHistory(history)
	dashboard := New(Options{Now: func() time.Time { return now }, Interval: 10 * time.Millisecond,
		Journal: &Journal{Metrics: listener.MetricCatalog()}})
	dashboard.Mount(listener)
	server := httptest.NewServer(listener)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	request := func(path string, authenticated bool) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Accept", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	read := func(path string) string {
		t.Helper()
		response := request(path, true)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d err=%v body=%s", path, response.StatusCode, err, body)
		}
		return string(body)
	}
	unauthorized := request("/metric-catalog", false)
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics page: %d", unauthorized.StatusCode)
	}
	queuePath := "/metric-catalog?metric=obs_dashboard_queue&range=15m"
	body := read(queuePath)
	for _, want := range []string{"Work waiting for placement", "gauge / count", "registry,history", "Current samples",
		"Retained resolutions", "raw, 1m, 5m, 1h", "Gaps / partial observations: 1", "Retained metric observations",
		"Events at this time", "this is not a fleet coverage inventory", "metric-catalog/stream?"} {
		if !strings.Contains(body, want) {
			t.Errorf("metric page lacks %q", want)
		}
	}
	if !regexp.MustCompile(`>\s*0\s*<`).MatchString(body) {
		t.Fatal("a genuine zero sample is not visible")
	}
	chartMatch := regexp.MustCompile(`<ts-chart[^>]*data-spec="([^"]*)"`).FindStringSubmatch(body)
	if len(chartMatch) != 2 {
		t.Fatal("metric page has no chart spec")
	}
	var chart struct {
		Series []struct {
			Points [][2]float64 `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(chartMatch[1])), &chart); err != nil {
		t.Fatal(err)
	}
	if len(chart.Series) != 2 || len(chart.Series[0].Points) != 2 || len(chart.Series[1].Points) != 2 {
		t.Fatalf("chart must break at missing intervals: %+v", chart)
	}
	filtered := read("/metric-catalog?q=Work+waiting")
	if !strings.Contains(filtered, "obs_dashboard_queue") || strings.Contains(filtered, ">obs_dashboard_actions_total</a>") {
		t.Fatal("description search did not filter registry families")
	}
	if process := read("/metric-catalog?q=go_"); !strings.Contains(process, ">go_") || strings.Contains(process, ">obs_dashboard_queue</a>") {
		t.Fatal("Go runtime metrics are not searchable")
	}
	if long := read("/metric-catalog?metric=" + url.QueryEscape(longMetric)); !regexp.MustCompile(`>\s*7\s*<`).MatchString(long) || !strings.Contains(long, "Unsupported metadata:") {
		t.Fatal("long family selection or unsupported metadata is missing")
	}
	if missing := read("/metric-catalog?metric=absent_metric"); !strings.Contains(missing, "selected metric is absent") {
		t.Fatal("missing family is not explicit")
	}
	if unsupported := read("/metric-catalog?metric=obs_dashboard_actions_total"); !strings.Contains(unsupported, "not retained by the history source") {
		t.Fatal("unsupported history is not explained")
	}
	if truncated := read("/metric-catalog?metric=obs_dashboard_worker"); !strings.Contains(truncated, "Truncated: more series exist") {
		t.Fatal("series truncation is not visible")
	}
	// Live rendering follows the same registry rather than a second UI sampler.
	stream := request("/metric-catalog/stream?metric=obs_dashboard_queue&range=15m", true)
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK || !strings.Contains(stream.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("metric stream response: %d %v", stream.StatusCode, stream.Header)
	}
	scanner := bufio.NewScanner(stream.Body)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	reader := &sseReader{t: t, scanner: scanner}
	sample := regexp.MustCompile(`<th[^>]*>\s*obs_dashboard_queue\s*</th>\s*<td[^>]*>\s*([0-9]+)\s*</td>`)
	event, data := reader.next()
	initial := sample.FindStringSubmatch(data)
	if event != "datastar-patch-elements" || len(initial) != 2 || initial[1] != "0" {
		t.Fatalf("initial Datastar registry sample: event=%s sample=%q", event, initial)
	}
	queue.Set(9)
	for {
		event, data = reader.next()
		updated := sample.FindStringSubmatch(data)
		if event == "datastar-patch-elements" && len(updated) == 2 && updated[1] == "9" {
			break
		}
	}
}

func TestMetricDashboardMissingProviderHTTP(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(New(Options{}).Handler())
	t.Cleanup(server.Close)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metric-catalog", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "metric catalog provider is not attached") {
		t.Fatalf("missing provider: status=%d err=%v body=%s", response.StatusCode, err, body)
	}
	read := func(server *httptest.Server, path string) string {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d err=%v body=%s", path, response.StatusCode, err, body)
		}
		return string(body)
	}
	for _, page := range pages {
		if body := read(server, page.href()); !strings.Contains(body, "still starting") {
			t.Errorf("GET %s does not explain the missing providers", page.href())
		}
	}
	failing := newTestDashboard(Options{Health: readyHealth(false),
		Snapshots: fixedSnapshots{err: errors.New("boom")},
		Cluster:   fixedCluster{err: errors.New("no responders")}})
	failedServer := httptest.NewServer(failing.Handler())
	t.Cleanup(failedServer.Close)
	failedBody := read(failedServer, "/")
	for _, want := range []string{"snapshot is unavailable", "cell-wide view is unavailable",
		"nats: regional broker is not connected", "not ready"} {
		if !strings.Contains(failedBody, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(failedBody, "boom") || strings.Contains(failedBody, "no responders") {
		t.Error("overview leaked raw provider error text")
	}
}

func TestMetricDashboardUsesSourceCadenceHTTP(t *testing.T) {
	t.Parallel()
	observed := time.Now().UTC()
	now := observed.Add(40 * time.Second)
	history := observability.NewHistory(observability.HistoryConfig{Interval: time.Minute})
	for _, ago := range []time.Duration{2 * time.Minute, time.Minute, 0} {
		history.Append(observed.Add(-ago), []observability.Sample{{Metric: "host_cadence", Value: 1}})
	}
	const token = "cadence-private-integration-token"
	listener, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
	if err != nil {
		t.Fatal(err)
	}
	listener.HandleMetricHistory(history)
	New(Options{Now: func() time.Time { return now }, Journal: &Journal{Metrics: listener.MetricCatalog()}}).Mount(listener)
	server := httptest.NewServer(listener)
	defer server.Close()
	get := func(path string) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d error=%v", path, response.StatusCode, err)
		}
		return body
	}
	query := url.Values{"metric": {"host_cadence"}, "tier": {"raw"}, "end": {now.Format(time.RFC3339Nano)}}
	var result observability.CatalogHistory
	body := get("/v1/history?" + query.Encode())
	if err := json.Unmarshal(body, &result); err != nil || result.State != "available" || result.IntervalSeconds != 60 {
		t.Fatalf("source cadence state=%s body=%s error=%v", result.State, body, err)
	}
	for _, window := range []string{"15m", "6h"} {
		body := string(get("/metric-catalog?metric=host_cadence&range=" + window))
		if strings.Contains(body, "Gaps / partial observations:") || strings.Contains(body, "gap / partial observation") || strings.Contains(body, "predates the requested range end") {
			t.Fatalf("normal minute cadence shown as missing: %s", body)
		}
		match := regexp.MustCompile(`<ts-chart[^>]*data-spec="([^"]*)"`).FindStringSubmatch(body)
		if len(match) != 2 {
			t.Fatal("cadence chart missing")
		}
		var chart struct {
			Series []struct {
				Points [][2]float64 `json:"points"`
			} `json:"series"`
		}
		if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &chart); err != nil || len(chart.Series) != 1 || len(chart.Series[0].Points) != 3 {
			t.Fatalf("normal cadence chart split: %+v error=%v", chart, err)
		}
	}
}
