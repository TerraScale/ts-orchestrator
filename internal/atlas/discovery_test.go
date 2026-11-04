package atlas

import (
	"slices"
	"testing"
	"time"
)

func TestServingDiscoveryIncludesUnhealthyRegionsAndNewAdmittedRegions(t *testing.T) {
	now := time.Now().UTC()
	discovery := Discovery{V: 1, Updated: now.Unix(), Regions: []DiscoveredRegion{
		{Region: Region{ID: "sjc-1"}, Health: "down"},
		{Region: Region{ID: "gru-1"}, Health: "unknown"},
	}}
	cells, err := discovery.ServingCells(now)
	if err != nil || !slices.Equal(cells, []string{"GRU", "SJC"}) {
		t.Fatalf("unhealthy region excluded or unfounded catalog region included: %v %v", cells, err)
	}
	discovery.Regions = append(discovery.Regions, DiscoveredRegion{Region: Region{ID: "fra-1"}})
	cells, err = discovery.ServingCells(now)
	if err != nil || !slices.Equal(cells, []string{"FRA", "GRU", "SJC"}) {
		t.Fatalf("new admitted region requires a caller list edit: %v %v", cells, err)
	}
}
