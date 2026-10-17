package app

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestJournalAPISharesAuthenticatedCatalogHistory(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	token := strings.Repeat("c", 40)
	registry := observability.NewRegistry(true)
	set := metrics.NewSet()
	capacity := set.NewGauge("app_catalog_capacity", nil)
	capacity.Set(0)
	registry.Register(set)
	server, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: registry, Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	board := dashboard.New(dashboard.Options{Interval: 10 * time.Millisecond})
	board.Mount(server)
	runtime := new(runtimeObservability)
	runtime.addBoard(board, server)
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	request := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listener.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := listener.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("authenticated %s = %d", path, response.StatusCode)
		}
		return response
	}
	currentAPI := func(value, historyState string) {
		t.Helper()
		response := request("/v1/metrics/catalog")
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var catalog observability.CatalogResult
		if err := json.Unmarshal(body, &catalog); err != nil {
			t.Fatal(err)
		}
		for _, metric := range catalog.Metrics {
			if metric.Name == "app_catalog_capacity" {
				if len(metric.Samples) != 1 || metric.Samples[0].Value != value || metric.HistoryState != historyState {
					t.Fatalf("catalog current/history differs: %+v", metric)
				}
				return
			}
		}
		t.Fatal("registered capacity metric is absent from the API")
	}
	currentAPI("0", "unsupported")
	response := request("/metric-catalog?metric=app_catalog_capacity")
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	sample := regexp.MustCompile(`<th[^>]*>\s*app_catalog_capacity\s*</th>\s*<td[^>]*>\s*([0-9]+)\s*</td>`)
	initial := sample.FindStringSubmatch(string(body))
	if len(initial) != 2 || initial[1] != "0" || strings.Contains(string(body), "provider is not attached") {
		t.Fatalf("pre-journal HTML lacks registered zero: sample=%q", initial)
	}
	stream := request("/metric-catalog/stream?metric=app_catalog_capacity")
	defer stream.Body.Close()
	if !strings.Contains(stream.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("catalog stream content type: %s", stream.Header.Get("Content-Type"))
	}
	scanner := bufio.NewScanner(stream.Body)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	next := func() (string, string) {
		t.Helper()
		var event string
		var data []string
		frameBytes := 0
		for scanner.Scan() {
			line := scanner.Text()
			frameBytes += len(line)
			if frameBytes > 2<<20 {
				t.Fatal("catalog SSE frame exceeds bound")
			}
			switch {
			case line == "":
				if event != "" {
					return event, strings.Join(data, "\n")
				}
				data, frameBytes = nil, 0
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = append(data, strings.TrimPrefix(line, "data: "))
			}
		}
		t.Fatalf("catalog stream ended before complete frame: %v", scanner.Err())
		return "", ""
	}
	event, data := next()
	initial = sample.FindStringSubmatch(data)
	if event != "datastar-patch-elements" || len(initial) != 2 || initial[1] != "0" {
		t.Fatalf("pre-journal initial SSE differs: event=%s sample=%q", event, initial)
	}
	capacity.Set(9)
	for {
		event, data = next()
		updated := sample.FindStringSubmatch(data)
		if event == "datastar-patch-elements" && len(updated) == 2 && updated[1] == "9" {
			break
		}
	}
	currentAPI("9", "unsupported")
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(time.Now(), []observability.Sample{{Metric: "app_catalog_capacity", Value: 3}})
	runtime.attachBoards(func() { runtime.boardJournal = &dashboard.Journal{History: history} })
	mountJournalAPI(server, journalProviders{History: history})
	currentAPI("9", "available")
	for {
		event, data = next()
		updated := sample.FindStringSubmatch(data)
		if event == "datastar-patch-elements" && len(updated) == 2 && updated[1] == "9" &&
			strings.Contains(data, "History state: <strong>available</strong>") {
			break
		}
	}
	for _, path := range []string{"/v1/metrics/catalog", "/v1/history/metrics", "/v1/history?metric=app_catalog_capacity&tier=raw", "/metric-catalog?metric=app_catalog_capacity"} {
		for _, authenticated := range []bool{false, true} {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, listener.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if authenticated {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response, err := listener.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !authenticated {
				if response.StatusCode != http.StatusUnauthorized {
					t.Fatalf("unauthenticated %s = %d", path, response.StatusCode)
				}
				continue
			}
			if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "app_catalog_capacity") {
				t.Fatalf("authenticated %s = %d %s", path, response.StatusCode, body)
			}
			if strings.HasPrefix(path, "/v1/history?") {
				var result observability.CatalogHistory
				if err := json.Unmarshal(body, &result); err != nil || result.State != "available" || len(result.Series) != 1 {
					t.Fatalf("history differs from shared catalog: %+v %v", result, err)
				}
			}
		}
	}
}
