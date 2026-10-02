package observability

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseHistoryQuery(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	query, err := ParseHistoryQuery(url.Values{"metric": {"m"}, "label.member": {"c1"}, "range": {"6h"},
		"rate": {"1"}, "tier": {"1m"}, "max": {"10"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if query.Metric != "m" || query.Labels["member"] != "c1" || !query.Start.Equal(now.Add(-6*time.Hour)) ||
		!query.Rate || query.Tier != Tier1m || query.MaxSeries != 10 {
		t.Fatalf("query = %+v", query)
	}
	for _, bad := range []url.Values{{}, {"metric": {"m"}, "tier": {"1s"}}, {"metric": {"m"}, "range": {"-1h"}},
		{"metric": {"m"}, "start": {"2026-10-03T00:00:00Z"}}, {"metric": {"m"}, "max": {"9999"}}} {
		if _, err := ParseHistoryQuery(bad, now); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestHistoryHandler(t *testing.T) {
	history := NewHistory(HistoryConfig{})
	history.Append(time.Now(), []Sample{{Metric: "m", Labels: L("member", "c1"), Value: 2}})
	handler := HistoryHandler(history)
	for path, want := range map[string]string{
		"/v1/history?metric=m&label.member=c1": `"v":2`,
		"/v1/history/metrics":                  `["m"]`,
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("%s = %d %s", path, recorder.Code, recorder.Body)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/history", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing metric = %d", recorder.Code)
	}
}
