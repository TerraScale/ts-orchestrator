package globalview

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const maxRegions = 32 // the registry's region limit

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

// Region returns one listed region; false when cell is not listed.
func (v *View) Region(cell string) (Region, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cell = normalize(cell)
	if !slices.Contains(v.listed(), cell) {
		return Region{}, false
	}
	return v.region(cell), true
}

// Accept keeps r when it is newer than the held rollup of its cell.
func (v *View) Accept(r Rollup) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if validate(r, v.now()) != nil {
		return false
	}
	held := v.rollups[r.Cell]
	if held != nil && !r.ObservedAt.After(held.ObservedAt) {
		return false
	}
	if held == nil && len(v.rollups) >= maxRegions {
		v.prune()
		if len(v.rollups) >= maxRegions {
			return false
		}
	}
	v.rollups[r.Cell] = &r
	close(v.changed)
	v.changed = make(chan struct{})
	return true
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

// prune drops held cells that are no longer listed. Callers hold mu.
func (v *View) prune() {
	listed := v.listed()
	for cell := range v.rollups {
		if slices.Contains(listed, cell) {
			continue
		}
		delete(v.rollups, cell)
		delete(v.persisted, cell)
		delete(v.persistedAt, cell)
	}
}

// validate checks what a rollup must hold whatever its subject.
func validate(r Rollup, now time.Time) error {
	if r.Version != Version {
		return fmt.Errorf("rollup version %d, want %d", r.Version, Version)
	}
	if token, err := protocol.RegionToken(r.Cell); err != nil || token != r.Cell {
		return fmt.Errorf("rollup cell %q is not a region token", r.Cell)
	}
	if r.ObservedAt.IsZero() || r.ObservedAt.After(now.Add(time.Minute)) {
		return fmt.Errorf("rollup observed_at %s is outside the clock window", r.ObservedAt)
	}
	return nil
}

// normalize returns the region token of cell, or "" when cell is not one.
func normalize(cell string) string {
	token, err := protocol.RegionToken(cell)
	if err != nil {
		return ""
	}
	return token
}
