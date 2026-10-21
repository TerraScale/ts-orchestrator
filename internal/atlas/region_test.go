package atlas

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func gruSection(t *testing.T) Config {
	t.Helper()
	data, err := os.ReadFile("../../deploy/oci-region/atlas-gru-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := protocol.DecodeStrict(data, &config, 64<<10); err != nil {
		t.Fatal(err)
	}
	config.Regions = config.Regions[:1] // only gru-1, as before sfo-1
	return config
}

func ids(config Config) []string {
	var ids []string
	for _, region := range config.Regions {
		ids = append(ids, region.ID)
	}
	return ids
}

// The catalog alone yields the region's entry: gru-1's hand-written one is
// exactly what AddRegion would plan, so the derivation matches production.
func TestAddRegionListsTheCatalogRegion(t *testing.T) {
	gru := gruSection(t)
	if _, added, err := (Config{}).AddRegion("gru-1"); err != nil || !added {
		t.Fatalf("gru-1: %v %v", added, err)
	}
	if next, added, err := gru.AddRegion("gru-1"); err != nil || added || !slices.Equal(next.Regions, gru.Regions) {
		t.Fatalf("listed gru-1 must plan nothing: %v %v", added, err)
	}
	next, added, err := gru.AddRegion("sfo-1")
	if err != nil || !added {
		t.Fatal(added, err)
	}
	want := Region{ID: "sfo-1", Name: "San Jose", Country: "US", Lat: 37.34, Lon: -121.89,
		API: "https://sfo.api.terrascale.tech", Auth: "https://sfo.auth.terrascale.tech"}
	if !slices.Equal(ids(next), []string{"gru-1", "sfo-1"}) || next.Regions[1] != want {
		t.Fatalf("regions = %+v", next.Regions)
	}
	if len(gru.Regions) != 1 {
		t.Fatal("AddRegion changed its receiver's regions")
	}
	if err := next.Validate("gru"); err != nil {
		t.Fatal(err)
	}
	if again, added, err := next.AddRegion("sfo-1"); err != nil || added || !slices.Equal(again.Regions, next.Regions) {
		t.Fatalf("rerun must plan nothing: %v %v", added, err)
	}
	// Catalog order, whatever order the regions are added in.
	fra, _, _ := gru.AddRegion("fra-1")
	both, _, _ := fra.AddRegion("sfo-1")
	if !slices.Equal(ids(both), []string{"gru-1", "sfo-1", "fra-1"}) {
		t.Fatalf("order = %v", ids(both))
	}
}

func TestAddRegionRefusesConflictsAndUnknownCells(t *testing.T) {
	gru := gruSection(t)
	conflicting := gru
	conflicting.Regions = append(slices.Clone(gru.Regions), Region{ID: "sfo-1", Name: "San Francisco", Country: "US",
		API: "https://sfo.api.terrascale.tech", Auth: "https://sfo.auth.terrascale.tech"})
	if _, _, err := conflicting.AddRegion("sfo-1"); err == nil || !strings.Contains(err.Error(), "already lists") {
		t.Fatalf("conflicting entry: %v", err)
	}
	for _, cell := range []string{"xxx-1", "sfo", "sfo-0", "sfo-01", "SFO-1", "sfo-1-a", ""} {
		if _, _, err := gru.AddRegion(cell); err == nil {
			t.Errorf("%q was accepted", cell)
		}
	}
}

func TestRegionForAndWithRegionsRefuseBadCells(t *testing.T) {
	gru := gruSection(t)
	for _, cell := range []string{"xxx-1", "gru", "gru-0", "gru-01", "GRU-1", ""} {
		if _, err := RegionFor(cell); err == nil {
			t.Errorf("RegionFor(%q) was accepted", cell)
		}
		if _, err := gru.WithRegions([]string{"gru-1", cell}); err == nil {
			t.Errorf("WithRegions with %q was accepted", cell)
		}
	}
	if _, err := gru.WithRegions(nil); err == nil {
		t.Error("an empty roster was accepted")
	}
}
