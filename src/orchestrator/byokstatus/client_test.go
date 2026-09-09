package byokstatus

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublishBindsStatusRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("x-terrascale-byok-status-key") != "secret" {
			t.Fatalf("request = %s %s", r.Method, r.URL)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(Config{Endpoint: "https://dashboard.example/status", ServiceKey: "secret", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client.endpoint = server.URL
	if err := client.Publish(t.Context(), Update{ProjectID: "project", Status: "verified", ConfigurationUpdatedAt: "2026-09-09T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInsecureEndpoint(t *testing.T) {
	if _, err := New(Config{Endpoint: "http://dashboard.example/status", ServiceKey: "secret"}); err == nil {
		t.Fatal("insecure endpoint accepted")
	}
}
