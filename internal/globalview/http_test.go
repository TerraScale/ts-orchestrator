package globalview

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandlerListsListedRegionsAndRejectsOthers(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	view := NewView("gru", func() []string { return []string{"sfo"} }, func() time.Time { return now })
	view.Accept(Rollup{Version: Version, Cell: "gru", ObservedAt: now, Health: Health{Status: Healthy}})
	handler := Handler(view)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/regions", nil))
	var entries []Region
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &entries) != nil {
		t.Fatalf("list = %d %s", recorder.Code, recorder.Body)
	}
	if len(entries) != 2 || entries[0].Cell != "gru" || entries[0].Rollup == nil || entries[1].Cell != "sfo" || entries[1].Rollup != nil {
		t.Fatalf("entries = %+v", entries)
	}
	for path, want := range map[string]int{"/v1/regions/GRU": http.StatusOK, "/v1/regions/sfo": http.StatusOK,
		"/v1/regions/fra": http.StatusNotFound} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != want {
			t.Fatalf("%s = %d, want %d", path, recorder.Code, want)
		}
	}
}
