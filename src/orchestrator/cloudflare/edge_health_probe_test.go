package cloudflare_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
)

func TestCanaryEdgeHealthProbeChecksCandidateAndPredecessor(t *testing.T) {
	const (
		project   = "project-1"
		database  = "database-1"
		marker    = "candidate-marker"
		candidate = "candidate-version"
		previous  = "previous-version"
	)
	var mu sync.Mutex
	var checks []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/projects/"+project+"/databases/"+database {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		override := r.Header.Get("Cloudflare-Workers-Version-Overrides")
		if r.Header.Get("Cache-Control") != "no-store" {
			http.Error(w, "missing cache control", http.StatusBadRequest)
			return
		}
		mu.Lock()
		checks = append(checks, r.Header.Get("Authorization")+" "+override)
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer foreign" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"denied"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"projectId":"`+project+`","databaseId":"`+database+`","marker":"`+marker+`","revision":7}`)
	}))
	defer server.Close()

	client := cf.NewClient("token", "zone", "account")
	client.BaseURL = "https://cloudflare.invalid"
	client.HTTP = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body string
		switch {
		case strings.Contains(req.URL.Path, "/versions"):
			body = `{"success":true,"result":{"items":[{"id":"` + candidate + `","annotations":{"workers/message":"terrascale-artifact:sha256:` + strings.Repeat("a", 64) + `"}},{"id":"` + previous + `","annotations":{"workers/message":"terrascale-artifact:sha256:` + strings.Repeat("b", 64) + `"}}]}}`
		case strings.Contains(req.URL.Path, "/deployments"):
			body = `{"success":true,"result":{"deployments":[{"id":"deployment-1","versions":[{"version_id":"` + candidate + `","percentage":10},{"version_id":"` + previous + `","percentage":90}]}]}}`
		default:
			return nil, io.ErrUnexpectedEOF
		}
		return jsonResponse(body), nil
	})
	probe := cf.CanaryEdgeHealthProbe{
		Client: client, HTTPClient: server.Client(), RouteURL: server.URL + "/api/v1/projects/" + project + "/databases/" + database,
		ProjectID: project, DatabaseID: database, CanaryToken: "canary", ForeignToken: "foreign", ExpectedMarker: marker, MinimumRevision: 7,
	}
	if err := probe.CheckEdge(t.Context(), "site", "ts-proxy", "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(checks) != 4 {
		t.Fatalf("requests = %d, want candidate and predecessor with two credentials", len(checks))
	}
	for _, id := range []string{candidate, previous} {
		for _, token := range []string{"Bearer canary", "Bearer foreign"} {
			want := token + ` ts-proxy="` + id + `"`
			found := false
			for _, check := range checks {
				if check == want {
					found = true
				}
			}
			if !found {
				t.Errorf("missing check %q", want)
			}
		}
	}
}

func TestCanaryEdgeHealthProbeRequiresCurrentCandidate(t *testing.T) {
	client := cf.NewClient("token", "zone", "account")
	client.HTTP = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/versions") {
			return jsonResponse(`{"success":true,"result":{"items":[{"id":"candidate","annotations":{"workers/message":"terrascale-artifact:sha256:` + strings.Repeat("e", 64) + `"}}]}}`), nil
		}
		return jsonResponse(`{"success":true,"result":{"deployments":[{"id":"deployment","versions":[{"version_id":"other","percentage":100}]}]}}`), nil
	})
	probe := cf.CanaryEdgeHealthProbe{Client: client, RouteURL: "https://api.terrascale.tech/api", ProjectID: "p", DatabaseID: "d", CanaryToken: "c", ForeignToken: "f", ExpectedMarker: "m"}
	if err := probe.CheckEdge(t.Context(), "site", "service", "sha256:"+strings.Repeat("e", 64)); err == nil {
		t.Fatal("candidate outside current deployment was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
