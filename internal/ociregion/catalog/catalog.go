// Package catalog is the table of OCI commercial regions TerraScale can run
// in. It holds facts about Oracle, not inventory: any listed region is a valid
// cell, and which regions serve is the live roster (docs/region-registry.md).
// A cell code is the upper-case OCI short region code.
//
// The catalog authorizes nothing by itself, and a region absent from it is
// rejected everywhere it is consulted.
package catalog

import "strings"

// Entry binds one logical product cell to its OCI region identifier.
type Entry struct {
	// Cell is the upper-case product region code, for example GRU.
	Cell string
	// OCIRegion is the canonical OCI region identifier, for example sa-saopaulo-1.
	OCIRegion string
	// OCIRegionKey is the OCI region key a tenancy subscribes with, for
	// example SJC for us-sanjose-1.
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
	SJC = "SJC"
	FRA = "FRA"
	// Bootstrap is the only cell that may found a deployment until a
	// separately reviewed migration exists.
	Bootstrap = GRU
)

// entries is ordered: placement assigns permanent members in this order.
var entries = [...]Entry{
	{Cell: GRU, OCIRegion: "sa-saopaulo-1", OCIRegionKey: "GRU", City: "São Paulo", Country: "BR", Latitude: -23.43, Longitude: -46.47},
	{Cell: SJC, OCIRegion: "us-sanjose-1", OCIRegionKey: "SJC", City: "San Jose", Country: "US", Latitude: 37.34, Longitude: -121.89},
	{Cell: FRA, OCIRegion: "eu-frankfurt-1", OCIRegionKey: "FRA", City: "Frankfurt", Country: "DE", Latitude: 50.11, Longitude: 8.68},
	{Cell: "AMS", OCIRegion: "eu-amsterdam-1", OCIRegionKey: "AMS", City: "Amsterdam", Country: "NL", Latitude: 52.37, Longitude: 4.90},
	{Cell: "ARN", OCIRegion: "eu-stockholm-1", OCIRegionKey: "ARN", City: "Stockholm", Country: "SE", Latitude: 59.33, Longitude: 18.07},
	{Cell: "AUH", OCIRegion: "me-abudhabi-1", OCIRegionKey: "AUH", City: "Abu Dhabi", Country: "AE", Latitude: 24.45, Longitude: 54.38},
	{Cell: "BOG", OCIRegion: "sa-bogota-1", OCIRegionKey: "BOG", City: "Bogotá", Country: "CO", Latitude: 4.71, Longitude: -74.07},
	{Cell: "BOM", OCIRegion: "ap-mumbai-1", OCIRegionKey: "BOM", City: "Mumbai", Country: "IN", Latitude: 19.08, Longitude: 72.88},
	{Cell: "CDG", OCIRegion: "eu-paris-1", OCIRegionKey: "CDG", City: "Paris", Country: "FR", Latitude: 48.86, Longitude: 2.35},
	{Cell: "CWL", OCIRegion: "uk-cardiff-1", OCIRegionKey: "CWL", City: "Newport", Country: "GB", Latitude: 51.59, Longitude: -2.99},
	{Cell: "DXB", OCIRegion: "me-dubai-1", OCIRegionKey: "DXB", City: "Dubai", Country: "AE", Latitude: 25.20, Longitude: 55.27},
	{Cell: "HYD", OCIRegion: "ap-hyderabad-1", OCIRegionKey: "HYD", City: "Hyderabad", Country: "IN", Latitude: 17.39, Longitude: 78.49},
	{Cell: "IAD", OCIRegion: "us-ashburn-1", OCIRegionKey: "IAD", City: "Ashburn", Country: "US", Latitude: 39.04, Longitude: -77.49},
	{Cell: "ICN", OCIRegion: "ap-seoul-1", OCIRegionKey: "ICN", City: "Seoul", Country: "KR", Latitude: 37.57, Longitude: 126.98},
	{Cell: "JED", OCIRegion: "me-jeddah-1", OCIRegionKey: "JED", City: "Jeddah", Country: "SA", Latitude: 21.49, Longitude: 39.19},
	{Cell: "JNB", OCIRegion: "af-johannesburg-1", OCIRegionKey: "JNB", City: "Johannesburg", Country: "ZA", Latitude: -26.20, Longitude: 28.05},
	{Cell: "KIX", OCIRegion: "ap-osaka-1", OCIRegionKey: "KIX", City: "Osaka", Country: "JP", Latitude: 34.69, Longitude: 135.50},
	{Cell: "LHR", OCIRegion: "uk-london-1", OCIRegionKey: "LHR", City: "London", Country: "GB", Latitude: 51.51, Longitude: -0.13},
	{Cell: "LIN", OCIRegion: "eu-milan-1", OCIRegionKey: "LIN", City: "Milan", Country: "IT", Latitude: 45.46, Longitude: 9.19},
	{Cell: "MAD", OCIRegion: "eu-madrid-1", OCIRegionKey: "MAD", City: "Madrid", Country: "ES", Latitude: 40.42, Longitude: -3.70},
	{Cell: "MEL", OCIRegion: "ap-melbourne-1", OCIRegionKey: "MEL", City: "Melbourne", Country: "AU", Latitude: -37.81, Longitude: 144.96},
	{Cell: "MRS", OCIRegion: "eu-marseille-1", OCIRegionKey: "MRS", City: "Marseille", Country: "FR", Latitude: 43.30, Longitude: 5.37},
	{Cell: "MTY", OCIRegion: "mx-monterrey-1", OCIRegionKey: "MTY", City: "Monterrey", Country: "MX", Latitude: 25.69, Longitude: -100.32},
	{Cell: "MTZ", OCIRegion: "il-jerusalem-1", OCIRegionKey: "MTZ", City: "Jerusalem", Country: "IL", Latitude: 31.77, Longitude: 35.21},
	{Cell: "NRT", OCIRegion: "ap-tokyo-1", OCIRegionKey: "NRT", City: "Tokyo", Country: "JP", Latitude: 35.68, Longitude: 139.69},
	{Cell: "ORD", OCIRegion: "us-chicago-1", OCIRegionKey: "ORD", City: "Chicago", Country: "US", Latitude: 41.88, Longitude: -87.63},
	{Cell: "PHX", OCIRegion: "us-phoenix-1", OCIRegionKey: "PHX", City: "Phoenix", Country: "US", Latitude: 33.45, Longitude: -112.07},
	{Cell: "QRO", OCIRegion: "mx-queretaro-1", OCIRegionKey: "QRO", City: "Querétaro", Country: "MX", Latitude: 20.59, Longitude: -100.39},
	{Cell: "RUH", OCIRegion: "me-riyadh-1", OCIRegionKey: "RUH", City: "Riyadh", Country: "SA", Latitude: 24.71, Longitude: 46.68},
	{Cell: "SCL", OCIRegion: "sa-santiago-1", OCIRegionKey: "SCL", City: "Santiago", Country: "CL", Latitude: -33.45, Longitude: -70.67},
	{Cell: "SIN", OCIRegion: "ap-singapore-1", OCIRegionKey: "SIN", City: "Singapore", Country: "SG", Latitude: 1.35, Longitude: 103.82},
	{Cell: "SYD", OCIRegion: "ap-sydney-1", OCIRegionKey: "SYD", City: "Sydney", Country: "AU", Latitude: -33.87, Longitude: 151.21},
	{Cell: "VAP", OCIRegion: "sa-valparaiso-1", OCIRegionKey: "VAP", City: "Valparaíso", Country: "CL", Latitude: -33.05, Longitude: -71.62},
	{Cell: "VCP", OCIRegion: "sa-vinhedo-1", OCIRegionKey: "VCP", City: "Vinhedo", Country: "BR", Latitude: -23.03, Longitude: -46.98},
	{Cell: "YNY", OCIRegion: "ap-chuncheon-1", OCIRegionKey: "YNY", City: "Chuncheon", Country: "KR", Latitude: 37.88, Longitude: 127.73},
	{Cell: "YUL", OCIRegion: "ca-montreal-1", OCIRegionKey: "YUL", City: "Montreal", Country: "CA", Latitude: 45.50, Longitude: -73.57},
	{Cell: "YYZ", OCIRegion: "ca-toronto-1", OCIRegionKey: "YYZ", City: "Toronto", Country: "CA", Latitude: 43.65, Longitude: -79.38},
	{Cell: "ZRH", OCIRegion: "eu-zurich-1", OCIRegionKey: "ZRH", City: "Zurich", Country: "CH", Latitude: 47.38, Longitude: 8.54},
}

// foundedCount is the number of leading entries with a reserved address plan.
const foundedCount = 3

// MaxRegions bounds the regions in one deployment's roster; it matches the
// roster limit in globalcontrol.
const MaxRegions = 32

// Len is the number of catalog entries.
const Len = len(entries)

// Entries returns a copy of the ordered catalog.
func Entries() []Entry { return append([]Entry(nil), entries[:]...) }

// Founded returns the regions with a reserved address plan
// (docs/network/address-plan.md). ts-orch region create (TS-804) extends it.
func Founded() []Entry { return append([]Entry(nil), entries[:foundedCount]...) }

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

// CellOf names the cell of an OCI region: the catalog's name when the region is
// in the catalog, otherwise its lower-case OCI key.
func CellOf(name, key string) string {
	if entry, ok := CellForOCIRegion(name); ok {
		return entry.Name()
	}
	return strings.ToLower(key)
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
