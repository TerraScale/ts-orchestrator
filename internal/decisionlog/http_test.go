package decisionlog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestParseQuery(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	values := url.Values{"region": {"GRU,sfo"}, "kind": {"held", "scale_up"}, "actor": {"placement"},
		"status": {"failed"}, "subject": {"Orders"}, "since": {"1h"}, "until": {"2026-10-02T11:30:00Z"},
		"limit": {"5000"}, "parent": {"p"}}
	query, err := ParseQuery(values, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(query.Regions) != 2 || query.Regions[0] != "gru" || len(query.Kinds) != 2 || query.Subject != "orders" ||
		!query.Since.Equal(now.Add(-time.Hour)) || query.Until.Hour() != 11 || query.Limit != MaxQueryLimit ||
		query.ParentID != "p" || len(query.Statuses) != 1 {
		t.Fatalf("query = %+v", query)
	}
	for _, bad := range []url.Values{{"since": {"yesterday"}}, {"until": {"x"}}, {"limit": {"-1"}}} {
		if _, err := ParseQuery(bad, now); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestHandler(t *testing.T) {
	journal := NewJournal(JournalConfig{Region: "gru"})
	root := journal.Record(t.Context(), Decision{Kind: KindReleaseAdmitted})
	journal.Record(t.Context(), Decision{Kind: KindCanaryPromoted, ParentID: root})
	handler := Handler(journal)
	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	recorder := request("/v1/decisions?kind=canary_promoted")
	var result Result
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &result) != nil || len(result.Decisions) != 1 {
		t.Fatalf("list = %d %s", recorder.Code, recorder.Body)
	}
	recorder = request("/v1/decisions/" + result.Decisions[0].ID)
	var chain Chain
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &chain) != nil || chain.Root.ID != root {
		t.Fatalf("chain = %d %s", recorder.Code, recorder.Body)
	}
	if recorder = request("/v1/decisions/missing"); recorder.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", recorder.Code)
	}
	if recorder = request("/v1/decisions?limit=x"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad = %d", recorder.Code)
	}
}
