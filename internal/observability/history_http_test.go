package observability

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	for _, query := range []string{"metric=m&start=bad"} {
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
