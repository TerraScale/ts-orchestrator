// Package catalog is the single source of the product cell to OCI region
// mapping. Every admission check, flag default, and signed-format validator
// that names a region reads it from here, so adding a region is one reviewed
// change instead of an edit to every validator.
//
// The catalog is a closed allowlist: it authorizes nothing by itself, and a
// region absent from it is rejected everywhere it is consulted.
package catalog

import "strings"

// Entry binds one logical product cell to its OCI region identifier.
type Entry struct {
	// Cell is the upper-case product region code, for example GRU.
	Cell string
	// OCIRegion is the canonical OCI region identifier, for example sa-saopaulo-1.
	OCIRegion string
	// OCIRegionKey is the OCI region key a tenancy subscribes with, for
	// example SJC for us-sanjose-1; it differs from the product cell code.
	OCIRegionKey string
	// City, Country (ISO 3166-1 alpha-2), Latitude and Longitude are display
	// metadata for operator views (the dashboard world map) and the cell's
	// Atlas region entry. They authorize nothing.
	City                string
	Country             string
	Latitude, Longitude float64
}

// Name is the lower-case cell token used in NATS subjects and host descriptors.
func (e Entry) Name() string { return strings.ToLower(e.Cell) }

const (
	GRU = "GRU"
	SFO = "SFO"
	FRA = "FRA"
	// Bootstrap is the only cell that may found a deployment until a
	// separately reviewed migration exists.
	Bootstrap = GRU
)

// entries is ordered: placement assigns permanent members in this order.
var entries = [...]Entry{
	{Cell: GRU, OCIRegion: "sa-saopaulo-1", OCIRegionKey: "GRU", City: "São Paulo", Country: "BR", Latitude: -23.43, Longitude: -46.47},
	{Cell: SFO, OCIRegion: "us-sanjose-1", OCIRegionKey: "SJC", City: "San Jose", Country: "US", Latitude: 37.34, Longitude: -121.89},
	{Cell: FRA, OCIRegion: "eu-frankfurt-1", OCIRegionKey: "FRA", City: "Frankfurt", Country: "DE", Latitude: 50.11, Longitude: 8.68},
}

// Len is the number of supported cells.
const Len = len(entries)

// Entries returns a copy of the ordered catalog.
func Entries() []Entry { return append([]Entry(nil), entries[:]...) }

// Cells returns the ordered upper-case cell codes.
func Cells() []string {
	cells := make([]string, 0, Len)
	for _, entry := range entries {
		cells = append(cells, entry.Cell)
	}
	return cells
}

// Names returns the ordered lower-case cell tokens used in NATS subjects.
func Names() []string {
	names := make([]string, 0, Len)
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// LookupName returns the entry whose lower-case token is name.
func LookupName(name string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Name() == name {
			return entry, true
		}
	}
	return Entry{}, false
}

// Lookup returns the entry for an exact upper-case cell code.
func Lookup(cell string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Cell == cell {
			return entry, true
		}
	}
	return Entry{}, false
}

// IsCell reports whether cell is an exact upper-case supported cell code.
func IsCell(cell string) bool {
	_, ok := Lookup(cell)
	return ok
}

// OCIRegion returns the OCI region for an exact cell code, or "" when the cell
// is not supported.
func OCIRegion(cell string) string {
	entry, _ := Lookup(cell)
	return entry.OCIRegion
}

// IsOCIRegion reports whether region is the OCI identifier of a supported cell.
func IsOCIRegion(region string) bool {
	_, ok := CellForOCIRegion(region)
	return ok
}

// CellForOCIRegion maps an exact OCI region identifier back to its cell.
func CellForOCIRegion(region string) (Entry, bool) {
	for _, entry := range entries {
		if entry.OCIRegion == region {
			return entry, true
		}
	}
	return Entry{}, false
}

// MatchesName reports whether name is the lower-case token of exactly cell.
func MatchesName(name, cell string) bool {
	entry, ok := Lookup(cell)
	return ok && entry.Name() == name
}

// Map returns a fresh cell to OCI region map.
func Map() map[string]string {
	result := make(map[string]string, Len)
	for _, entry := range entries {
		result[entry.Cell] = entry.OCIRegion
	}
	return result
}
