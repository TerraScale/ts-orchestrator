package globalview

import (
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// the registry's region limit

// Region is one region of the view. Rollup is nil until one arrives.
type Region struct {
	Cell   string  `json:"cell"`
	Rollup *Rollup `json:"rollup"`
	Stale  bool    `json:"stale"`
}

// View holds the newest rollup of every listed region, in memory.
type View struct {
	mu          sync.Mutex
	local       string
	regions     func() []string
	now         func() time.Time
	rollups     map[string]*Rollup
	persisted   map[string]time.Time // ObservedAt last written to the bucket
	persistedAt map[string]time.Time // wall time of that write
	changed     chan struct{}
}

// Regions lists local first, then every other listed region by cell.
func (v *View) Regions() []Region {
	v.mu.Lock()
	defer v.mu.Unlock()
	cells := v.listed()
	out := make([]Region, 0, len(cells))
	for _, cell := range cells {
		out = append(out, v.region(cell))
	}
	return out
}

// listed is local first, then every other listed region sorted. Callers hold mu.
func (v *View) listed() []string {
	var others []string
	if v.regions != nil {
		for _, raw := range v.regions() {
			cell := normalize(raw)
			if cell == "" || cell == v.local || slices.Contains(others, cell) {
				continue
			}
			others = append(others, cell)
		}
	}
	slices.Sort(others)
	if v.local == "" {
		return others
	}
	return append([]string{v.local}, others...)
}

// region reads one listed cell. Callers hold mu.
func (v *View) region(cell string) Region {
	r := v.rollups[cell]
	return Region{
		Cell:   cell,
		Rollup: r,
		Stale:  r != nil && v.now().Sub(r.ObservedAt) > StaleAfter,
	}
}

// normalize returns the region token of cell, or "" when cell is not one.
func normalize(cell string) string {
	token, err := protocol.RegionToken(cell)
	if err != nil {
		return ""
	}
	return token
}
