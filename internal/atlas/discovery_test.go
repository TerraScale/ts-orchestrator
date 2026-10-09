package atlas

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
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

func TestServingDiscoveryIncludesUnhealthyRegionsAndNewAdmittedRegions(t *testing.T) {
	now := time.Now().UTC()
	discovery := Discovery{V: 1, Updated: now.Unix(), Regions: []DiscoveredRegion{
		{Region: Region{ID: "sfo-1"}, Health: "down"},
		{Region: Region{ID: "gru-1"}, Health: "unknown"},
	}}
	cells, err := discovery.ServingCells(now)
	if err != nil || !slices.Equal(cells, []string{"GRU", "SFO"}) {
		t.Fatalf("unhealthy region excluded or unfounded catalog region included: %v %v", cells, err)
	}
	discovery.Regions = append(discovery.Regions, DiscoveredRegion{Region: Region{ID: "fra-1"}})
	cells, err = discovery.ServingCells(now)
	if err != nil || !slices.Equal(cells, []string{"FRA", "GRU", "SFO"}) {
		t.Fatalf("new admitted region requires a caller list edit: %v %v", cells, err)
	}
}

func TestServingDiscoveryRejectsEmptyStaleDuplicateAndUnsupportedMembership(t *testing.T) {
	now := time.Now().UTC()
	for name, change := range map[string]func(*Discovery){
		"empty":              func(d *Discovery) { d.Regions = nil },
		"wrong version":      func(d *Discovery) { d.V = 2 },
		"stale flag":         func(d *Discovery) { d.Stale = true },
		"stale timestamp":    func(d *Discovery) { d.Updated = now.Add(-StaleAfter - time.Second).Unix() },
		"future timestamp":   func(d *Discovery) { d.Updated = now.Add(Interval + time.Second).Unix() },
		"duplicate":          func(d *Discovery) { d.Regions = append(d.Regions, d.Regions[0]) },
		"unknown cell":       func(d *Discovery) { d.Regions[0].ID = "unknown-1" },
		"unbound cell index": func(d *Discovery) { d.Regions[0].ID = "gru-2" },
	} {
		t.Run(name, func(t *testing.T) {
			discovery := Discovery{V: 1, Updated: now.Unix(), Regions: []DiscoveredRegion{{Region: Region{ID: "gru-1"}}}}
			change(&discovery)
			if cells, err := discovery.ServingCells(now); err == nil {
				t.Fatalf("invalid discovery accepted: %v", cells)
			}
		})
	}
}
