package registry

import (
	"time"
)

// Pins is the complete admitted current/rollback/live-task inventory for this
// repository. Children must contain an entry for every reachable digest,
// including leaves with no children. Producers pin before admitting or starting.
type Pins struct {
	Generation uint64              `json:"generation"`
	ObservedAt time.Time           `json:"observed_at"`
	Current    []string            `json:"current,omitempty"`
	Rollback   []string            `json:"rollback,omitempty"`
	Tasks      []string            `json:"tasks,omitempty"`
	Children   map[string][]string `json:"children"`
}
