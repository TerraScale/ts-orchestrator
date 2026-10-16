package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestJournalAPISharesAuthenticatedCatalogHistory(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("c", 40)
	server, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: observability.NewRegistry(true), Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(time.Now(), []observability.Sample{{Metric: "app_catalog_capacity", Value: 3}})
	mountJournalAPI(server, journalProviders{History: history})
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	for _, path := range []string{"/v1/metrics/catalog", "/v1/history/metrics", "/v1/history?metric=app_catalog_capacity&tier=raw"} {
		for _, authenticated := range []bool{false, true} {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+path, nil)
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
			if strings.Contains(path, "?metric=") {
				var result observability.CatalogHistory
				if err := json.Unmarshal(body, &result); err != nil || result.State != "available" || len(result.Series) != 1 {
					t.Fatalf("history differs from shared catalog: %+v %v", result, err)
				}
			}
		}
	}
}
