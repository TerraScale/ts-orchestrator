// Package globalcontrol owns the small, single-writer global state shared by
// every region: the region roster and the database directory. The home region
// (GRU) writes it to the TS_GLOBAL_CONTROL stream under the global-scope
// authority lease; every other region holds a read-only JetStream mirror and
// keeps serving from it when the home region is unreachable. Only global
// changes stop during a partition, never regional work.
package globalcontrol

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
)

// RosterKey is the single key of the region roster record.
const RosterKey = "current"

const (
	recordVersion  = 1
	maxRecordBytes = 64 << 10
	// maxMessageBytes bounds a stored record: its payload is base64 in JSON.
	maxMessageBytes = 96 << 10
	maxRegions      = 32
	maxActive       = 5
)

var (
	cellToken = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
)

// RegionState is the roster's view of a region's lifecycle. It mirrors the
// coarse phases of internal/regionlifecycle; only Active regions are placeable.
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

// Validate requires sorted, unique cells, a known Active home region, and a
// bounded size.
func (r Roster) Validate() error {
	if r.Generation == 0 || len(r.Regions) == 0 || len(r.Regions) > maxRegions {
		return errors.New("region roster needs a generation and 1 to 32 regions")
	}
	home := false
	for index, entry := range r.Regions {
		if !cellToken.MatchString(entry.Cell) || entry.Cell == protocol.GlobalScope {
			return fmt.Errorf("roster cell %q is invalid", entry.Cell)
		}
		if index > 0 && r.Regions[index-1].Cell >= entry.Cell {
			return errors.New("roster cells must be sorted and unique")
		}
		if !validOCIRegion(entry.OCIRegion) {
			return fmt.Errorf("roster cell %q has an invalid OCI region", entry.Cell)
		}
		switch entry.State {
		case RegionProvisioning, RegionActive, RegionRetiring, RegionRetired:
		default:
			return fmt.Errorf("roster cell %q has an invalid state", entry.Cell)
		}
		if entry.Cell == r.HomeRegion {
			if entry.State != RegionActive {
				return errors.New("roster home region must be active")
			}
			home = true
		}
	}
	if !home {
		return errors.New("roster home region is not in the roster")
	}
	return nil
}

// Active reports whether cell is a placeable roster region.
func (r Roster) Active(cell string) bool {
	index := slices.IndexFunc(r.Regions, func(entry RosterEntry) bool { return entry.Cell == cell })
	return index >= 0 && r.Regions[index].State == RegionActive
}

func validOCIRegion(value string) bool {
	if len(value) < 3 || len(value) > 63 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
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

// Key is the subject key of the entry, <database>.<partition>: two subject
// tokens, so distinct identities can never share a record subject.
func (d DirectoryEntry) Key() string { return DirectoryKey(d.DatabaseID, d.PartitionID) }

// DirectoryKey is the record key for a database partition.
func DirectoryKey(databaseID, partitionID string) string {
	return entityid.Derive("directory", databaseID, partitionID)
}

// Validate requires valid identities, the home region among ActiveRegions,
// sorted unique regions, and a bounded active set.
func (d DirectoryEntry) Validate() error {
	if !entityid.Valid(d.DatabaseID) || !entityid.Valid(d.PartitionID) || d.Generation == 0 {
		return errors.New("directory entry needs database, partition and generation")
	}
	if len(DirectoryKey(d.DatabaseID, d.PartitionID)) > 128 {
		return errors.New("directory entry key is too long")
	}
	if len(d.ActiveRegions) == 0 || len(d.ActiveRegions) > maxActive {
		return errors.New("directory entry needs 1 to 5 active regions")
	}
	for index, cell := range d.ActiveRegions {
		if !cellToken.MatchString(cell) || cell == protocol.GlobalScope {
			return fmt.Errorf("directory active region %q is invalid", cell)
		}
		if index > 0 && d.ActiveRegions[index-1] >= cell {
			return errors.New("directory active regions must be sorted and unique")
		}
	}
	if !slices.Contains(d.ActiveRegions, d.HomeRegion) {
		return errors.New("directory home region must be an active region")
	}
	return nil
}

// ValidateAgainst additionally requires every active region to be an Active
// roster region.
func (d DirectoryEntry) ValidateAgainst(roster Roster) error {
	if err := d.Validate(); err != nil {
		return err
	}
	for _, cell := range d.ActiveRegions {
		if !roster.Active(cell) {
			return fmt.Errorf("directory region %q is not an active roster region", cell)
		}
	}
	return nil
}
