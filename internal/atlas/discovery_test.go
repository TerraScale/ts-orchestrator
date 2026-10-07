package atlas

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const discoveryBody = `{"v":1,"updated":1791159807,"stale":false,"closest":"gru-1",
"regions":[{"id":"gru-1","name":"São Paulo","country":"BR","lat":-23.43,"lon":-46.47,
"api":"https://gru.api.terrascale.tech","auth":"https://gru.auth.terrascale.tech","health":"ok","distanceKm":12},
{"id":"sfo-1","name":"San Jose","country":"US","lat":37.34,"lon":-121.89,
"api":"https://sfo.api.terrascale.tech","auth":"https://sfo.auth.terrascale.tech","health":"unknown","distanceKm":null}],
"services":[{"id":"status","name":"Status","url":"https://status.terrascale.tech"}]}`

func TestDiscoverReadsTheListedRegions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/discovery" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(discoveryBody))
	}))
	defer server.Close()
	discovery, err := Discover(t.Context(), server.Client(), server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	sfo, ok := discovery.Region("sfo-1")
	if !ok || sfo.Health != "unknown" || sfo.Country != "US" || sfo.API != "https://sfo.api.terrascale.tech" ||
		discovery.Closest != "gru-1" || discovery.Updated != 1791159807 || len(discovery.Services) != 1 {
		t.Fatalf("discovery = %+v", discovery)
	}
	if _, ok := discovery.Region("fra-1"); ok {
		t.Fatal("fra-1 is not listed")
	}
}

func TestDiscoverRefusesRedirectsErrorsAndOversizeBodies(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		// Following it would read a valid document.
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery == "moved" {
				_, _ = w.Write([]byte(discoveryBody))
				return
			}
			http.Redirect(w, r, "/v1/discovery?moved", http.StatusFound)
		},
		"non-200": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"code":"discovery_unavailable"}}`, http.StatusServiceUnavailable)
		},
		"oversize": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"v":1,"regions":[],"pad":"` + strings.Repeat("x", maxDiscoveryBytes) + `"}`))
		},
		"version": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"v":2}`)) },
		"garbage": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
	} {
		server := httptest.NewTLSServer(handler)
		if _, err := Discover(t.Context(), server.Client(), server.URL); err == nil {
			t.Errorf("%s was accepted", name)
		}
		server.Close()
	}
	if _, err := Discover(t.Context(), http.DefaultClient, "http://atlas.terrascale.tech"); err == nil {
		t.Error("plain http was accepted")
	}
}
