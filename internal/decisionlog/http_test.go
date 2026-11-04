package decisionlog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
