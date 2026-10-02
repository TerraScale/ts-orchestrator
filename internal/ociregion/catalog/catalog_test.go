package catalog

import (
	"slices"
	"testing"
)

func TestCatalogIsClosedAndOrdered(t *testing.T) {
	if got := Cells(); !slices.Equal(got, []string{GRU, SFO, FRA}) {
		t.Fatalf("cells=%v", got)
	}
	if Len != 3 || OCIRegion(Bootstrap) != "sa-saopaulo-1" {
		t.Fatal("bootstrap cell mapping changed")
	}
	for _, entry := range Entries() {
		back, ok := CellForOCIRegion(entry.OCIRegion)
		if !ok || back != entry || !IsCell(entry.Cell) || !IsOCIRegion(entry.OCIRegion) || !MatchesName(entry.Name(), entry.Cell) {
			t.Fatalf("entry %v does not round-trip", entry)
		}
	}
	for _, rejected := range []string{"", "gru", "LHR", "GRU ", "sa-saopaulo-1"} {
		if IsCell(rejected) || OCIRegion(rejected) != "" {
			t.Fatalf("accepted cell %q", rejected)
		}
	}
	for _, rejected := range []string{"", "GRU", "SA-SAOPAULO-1", "uk-london-1"} {
		if IsOCIRegion(rejected) {
			t.Fatalf("accepted OCI region %q", rejected)
		}
	}
	if MatchesName("sfo", GRU) || MatchesName("GRU", GRU) {
		t.Fatal("name match is not exact")
	}
	m := Map()
	m[GRU] = "tampered"
	e := Entries()
	e[0].OCIRegion = "tampered"
	if OCIRegion(GRU) != "sa-saopaulo-1" {
		t.Fatal("a copy exposed the catalog")
	}
}
