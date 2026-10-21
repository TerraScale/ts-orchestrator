package catalog

import (
	"slices"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestCellOfNamesOCIRegionsAsTheCatalogDoes(t *testing.T) {
	cases := []struct{ name, key, cell string }{
		{"us-sanjose-1", "SJC", "sjc"},
		{"sa-saopaulo-1", "GRU", "gru"},
		{"uk-london-1", "LHR", "lhr"},
	}
	for _, tt := range cases {
		if got := CellOf(tt.name, tt.key); got != tt.cell {
			t.Fatalf("CellOf(%s, %s) = %q, want %q", tt.name, tt.key, got, tt.cell)
		}
	}
}

func TestCatalogIsClosedAndOrdered(t *testing.T) {
	if got := Names()[:3]; !slices.Equal(got, []string{"gru", "sjc", "fra"}) {
		t.Fatalf("leading cells=%v", got)
	}
	if OCIRegion(Bootstrap) != "sa-saopaulo-1" {
		t.Fatal("bootstrap cell mapping changed")
	}
	for _, entry := range Entries() {
		back, ok := CellForOCIRegion(entry.OCIRegion)
		if !ok || back != entry || !IsCell(entry.Cell) || !IsOCIRegion(entry.OCIRegion) || !MatchesName(entry.Name(), entry.Cell) {
			t.Fatalf("entry %v does not round-trip", entry)
		}
	}
	for _, rejected := range []string{"", "gru", "XXX", "GRU ", "sa-saopaulo-1"} {
		if IsCell(rejected) || OCIRegion(rejected) != "" {
			t.Fatalf("accepted cell %q", rejected)
		}
	}
	for _, rejected := range []string{"", "GRU", "SA-SAOPAULO-1", "xx-nowhere-1"} {
		if IsOCIRegion(rejected) {
			t.Fatalf("accepted OCI region %q", rejected)
		}
	}
	if MatchesName("sjc", GRU) || MatchesName("GRU", GRU) {
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

func TestFoundedIsExactlyTheAddressPlanCells(t *testing.T) {
	var cells []string
	for _, entry := range Founded() {
		cells = append(cells, entry.Cell)
	}
	if !slices.Equal(cells, []string{GRU, SJC, FRA}) {
		t.Fatalf("founded cells=%v", cells)
	}
}

func TestEveryCatalogRegionIsKnownToTheOCISDK(t *testing.T) {
	cells := map[string]bool{}
	regions := map[string]bool{}
	for _, entry := range Entries() {
		if cells[entry.Cell] || regions[entry.OCIRegion] {
			t.Fatalf("entry %v repeats a cell or OCI region", entry)
		}
		cells[entry.Cell], regions[entry.OCIRegion] = true, true
		if got := string(common.StringToRegion(entry.OCIRegion)); got != entry.OCIRegion {
			t.Fatalf("OCI SDK maps %q to %q", entry.OCIRegion, got)
		}
		short := strings.ToLower(entry.Cell)
		if entry.Cell == SJC {
			short = "sjc"
		}
		if got := string(common.StringToRegion(short)); got != entry.OCIRegion {
			t.Fatalf("OCI SDK maps %q to %q, not %q", short, got, entry.OCIRegion)
		}
	}
}
