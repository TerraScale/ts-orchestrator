// Package globalcontrol owns the small, single-writer global state shared by
// every region: the region roster, the database directory, and the monthly
// budget and capacity documents. The home region
// (GRU) writes it to the TS_GLOBAL_CONTROL stream under the global-scope
// authority lease; every other region holds a read-only JetStream mirror and
// keeps serving from it when the home region is unreachable. Only global
// changes stop during a partition, never regional work.
package globalcontrol

import (
	"regexp"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Kind selects one family of global records. Each record is the latest value
// on its own subject, ts.global.v1.<kind>.<key>.
type Kind string

const (
	KindRoster    Kind = "roster"
	KindDirectory Kind = "directory"
	// KindTerm is the global writer's term barrier (see Writer).
	KindTerm Kind = "term"
	// KindCellSpec relays a region's signed cell spec (internal/cellspec),
	// keyed by the region's cell (see Document).
	KindCellSpec Kind = "cellspec"
	// KindBudget is the tenancy's monthly OCI budget (internal/budget), cell global.
	KindBudget Kind = "budget"
	// KindCapacity is every region's node allowance (internal/budget), cell global.
	KindCapacity Kind = "capacity"
)

// RosterKey is the single key of the region roster record.
const RosterKey = "current"

const (
	recordVersion  = 1
	maxRecordBytes = 64 << 10
	// maxMessageBytes bounds a stored record: its payload is base64 in JSON.
	maxMessageBytes = 96 << 10
	maxRegions      = catalog.MaxRegions
	maxActive       = 5
)

var (
	cellToken = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
)

// RegionState is the roster's view of a region's lifecycle; only active regions are placeable.
type RegionState string

const (
	RegionProvisioning RegionState = "provisioning"
	RegionActive       RegionState = "active"
	RegionRetiring     RegionState = "retiring"
	RegionRetired      RegionState = "retired"
)

// RosterEntry binds a cell to its OCI region and roster state.
type RosterEntry struct {
	Cell      string      `json:"cell"`
	OCIRegion string      `json:"oci_region"`
	State     RegionState `json:"state"`
}

// Roster is the global list of regions. HomeRegion owns TS_GLOBAL_CONTROL and
// the global authority lease; moving it needs an operator-signed transfer.
type Roster struct {
	Generation uint64        `json:"generation"`
	HomeRegion string        `json:"home_region"`
	Regions    []RosterEntry `json:"regions"`
}

// DirectoryEntry maps one database partition to its home region. The home
// region applies mutations; ActiveRegions lists every region allowed to hold
// members. Regional admission must match Generation and the record digest.
type DirectoryEntry struct {
	DatabaseID    string   `json:"database_id"`
	PartitionID   string   `json:"partition_id"`
	HomeRegion    string   `json:"home_region"`
	ActiveRegions []string `json:"active_regions"`
	Generation    uint64   `json:"generation"`
}
