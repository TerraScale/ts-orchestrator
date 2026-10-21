package observability

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const historyTestToken = "history-integration-token-32-bytes-minimum"

func historyHTTPServer(t *testing.T, source HistorySource) *httptest.Server {
	t.Helper()
	service, err := NewTokenServer(Config{}, historyTestToken, ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	service.HandleMetricHistory(source)
	endpoint := httptest.NewServer(service)
	t.Cleanup(endpoint.Close)
	response, err := endpoint.Client().Get(endpoint.URL + "/v1/history/metrics")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated history = %d", response.StatusCode)
	}
	return endpoint
}

func historyHTTPRequest(t *testing.T, endpoint *httptest.Server, path string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+historyTestToken)
	response, err := endpoint.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func historyHTTPRange(t *testing.T, source HistorySource, query HistoryQuery) HistoryResult {
	t.Helper()
	endpoint := historyHTTPServer(t, source)
	defer endpoint.Close()
	values := url.Values{"metric": {query.Metric}}
	if !query.Start.IsZero() {
		values.Set("start", query.Start.Format(time.RFC3339Nano))
	}
	if !query.End.IsZero() {
		values.Set("end", query.End.Format(time.RFC3339Nano))
	}
	if query.Tier != "" {
		values.Set("tier", query.Tier)
	}
	if query.Rate {
		values.Set("rate", "1")
	}
	if query.MaxSeries != 0 {
		values.Set("max", strconv.Itoa(query.MaxSeries))
	}
	for name, value := range query.Labels {
		values.Set("label."+name, value)
	}
	status, data := historyHTTPRequest(t, endpoint, "/v1/history?"+values.Encode())
	if status != http.StatusOK {
		t.Fatalf("history status %d: %s", status, data)
	}
	var result HistoryResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func historySampleValues(t *testing.T, samples []Sample) map[string]float64 {
	t.Helper()
	history := NewHistory(HistoryConfig{})
	history.Append(time.Now().Add(-time.Second), samples)
	endpoint := historyHTTPServer(t, history)
	defer endpoint.Close()
	values := map[string]float64{}
	for _, metric := range history.Metrics() {
		status, data := historyHTTPRequest(t, endpoint, "/v1/history?metric="+url.QueryEscape(metric))
		if status != http.StatusOK {
			t.Fatalf("sample history status %d: %s", status, data)
		}
		var result HistoryResult
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		for _, series := range result.Series {
			var pairs []string
			for _, name := range slices.Sorted(maps.Keys(series.Labels)) {
				pairs = append(pairs, name, series.Labels[name])
			}
			values[Series(metric, pairs...)] = series.Points[len(series.Points)-1].Value
		}
	}
	return values
}

func TestHistoryHTTPQueryValidationAndAuthentication(t *testing.T) {
	history := NewHistory(HistoryConfig{})
	history.Append(time.Now(), []Sample{{Metric: "m", Labels: L("member", "c1"), Value: 2}})
	endpoint := historyHTTPServer(t, history)
	for path, want := range map[string]string{
		"/v1/history?metric=m&label.member=c1":    `"v":2`,
		"/v1/history/metrics":                     `["m"]`,
		"/v1/history?metric=m&range=336h&tier=1h": `"tier":"1h"`,
	} {
		status, data := historyHTTPRequest(t, endpoint, path)
		if status != http.StatusOK || !strings.Contains(string(data), want) {
			t.Fatalf("%s = %d %s", path, status, data)
		}
	}
	for _, query := range []string{"", "metric=m&tier=1s", "metric=m&range=-1h", "metric=m&max=9999", "metric=m&range=337h", "metric=m&start=bad", "metric=m&end=bad", "metric=m&start=2026-01-01T00:00:00Z&end=2026-02-01T00:00:00Z", "metric=m&start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"} {
		status, data := historyHTTPRequest(t, endpoint, "/v1/history?"+query)
		if status != http.StatusBadRequest {
			t.Fatalf("%s = %d %s", query, status, data)
		}
	}
	// An end-only historical query measures its default hour from that end.
	past := time.Now().Add(-3 * time.Hour).Truncate(time.Minute)
	history.Append(past, []Sample{{Metric: "past", Value: 7}})
	status, data := historyHTTPRequest(t, endpoint, "/v1/history?metric=past&end="+url.QueryEscape(past.Add(time.Minute).Format(time.RFC3339)))
	if status != http.StatusOK || !strings.Contains(string(data), `"v":7`) {
		t.Fatalf("historical end-only query = %d %s", status, data)
	}
}

func TestHistoryHTTPDisclosesGapsLossFreshnessAndRateSupport(t *testing.T) {
	now := time.Now().UTC().Truncate(10 * time.Second)
	history := NewHistory(HistoryConfig{MaxSeries: 1})
	for _, second := range []int{50, 40, 10, 0} {
		history.Append(now.Add(-time.Duration(second)*time.Second), []Sample{{Metric: "requests", Value: float64(50 - second), Counter: true}})
	}
	history.Append(now, []Sample{{Metric: "dropped", Value: 1}})
	endpoint := historyHTTPServer(t, history)
	query := url.Values{"metric": {"requests"}, "tier": {TierRaw}, "start": {now.Add(-time.Minute).Format(time.RFC3339)}, "end": {now.Add(30 * time.Second).Format(time.RFC3339)}}
	status, data := historyHTTPRequest(t, endpoint, "/v1/history?"+query.Encode())
	var result CatalogHistory
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || !result.Incomplete || result.DroppedSeries != 1 || result.IntervalSeconds != 10 || result.RetentionStart.IsZero() || len(result.Series) != 1 {
		t.Fatalf("history API lost retention or drop evidence: %d %s", status, data)
	}
	series := result.Series[0]
	if !series.Gaps || !series.Stale || !series.LastObservedAt.Equal(now) {
		t.Fatalf("history API hid stale or missing samples: %+v", series)
	}
	query.Set("start", now.Add(-25*time.Second).Format(time.RFC3339))
	query.Set("end", now.Format(time.RFC3339))
	query.Set("rate", "1")
	status, data = historyHTTPRequest(t, endpoint, "/v1/history?"+query.Encode())
	if err := json.Unmarshal(data, &result); err != nil || status != http.StatusOK || len(result.Series) != 1 || len(result.Series[0].Points) != 2 {
		t.Fatalf("rate baseline outside range was lost: %d %s err=%v", status, data, err)
	}
	for _, point := range result.Series[0].Points {
		if point.Value != 1 {
			t.Fatalf("gap-aware counter rate = %g, want 1/s", point.Value)
		}
	}
	gauges := NewHistory(HistoryConfig{})
	gauges.Append(now, []Sample{{Metric: "queue", Value: 0}})
	endpoint = historyHTTPServer(t, gauges)
	status, data = historyHTTPRequest(t, endpoint, "/v1/history?metric=queue&rate=1")
	if err := json.Unmarshal(data, &result); err != nil || status != http.StatusOK || result.State != "unsupported" || result.UnsupportedReason != "rate_requires_counter" {
		t.Fatalf("gauge derivative did not disclose unsupported semantics: %d %s err=%v", status, data, err)
	}
}
