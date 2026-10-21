package app

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func TestFoundationObservationAuthenticatedRuntimeAPI(t *testing.T) {
	token := strings.Repeat("d", 40)
	server, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: observability.NewRegistry(true), Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	mountFoundationObservation(server, region.FoundationResolver{})
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	for _, scenario := range []struct {
		name, bearer string
		status       int
	}{{"missing credentials", "", http.StatusUnauthorized}, {"wrong credentials", "wrong", http.StatusUnauthorized}, {"unavailable source", token, http.StatusServiceUnavailable}} {
		t.Run(scenario.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/v1/regions/gru/foundation", nil)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+scenario.bearer)
			}
			response, err := listener.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != scenario.status {
				t.Fatalf("HTTP status = %d, body=%s, err=%v", response.StatusCode, body, err)
			}
			if scenario.status == http.StatusServiceUnavailable {
				var result struct {
					SchemaVersion int    `json:"schemaVersion"`
					State         string `json:"state"`
					Reason        string `json:"reason"`
				}
				if err := json.Unmarshal(body, &result, json.RejectUnknownMembers(true)); err != nil || result.SchemaVersion != 1 || result.State != "unavailable" || result.Reason != "foundation-observation-unavailable" {
					t.Fatalf("unsafe unavailable response: %s, %v", body, err)
				}
				if response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("progress API must not cache unavailable observations")
				}
			}
		})
	}
}
