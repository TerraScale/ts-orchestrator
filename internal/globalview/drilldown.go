package globalview

import (
	"time"
)

// ResourceView retains the observation metadata alongside a node, service or
// volume. Data is nil when the resource cannot be established from this view.
type ResourceView struct {
	Version    int       `json:"version"`
	Cell       string    `json:"cell"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
	State      string    `json:"state"`
	Truncated  bool      `json:"truncated"`
	Data       any       `json:"data"`
}

// ResourceState distinguishes an absent observation from a confirmed absence.
// A retained, incomplete list cannot establish that an omitted resource is gone.
func (region Region) ResourceState(found bool) string {
	switch {
	case region.Rollup == nil:
		return "missing"
	case region.Stale:
		return "stale"
	case !found && region.Rollup.Truncated:
		return "truncated"
	case !found:
		return "not_found"
	default:
		return "current"
	}
}
