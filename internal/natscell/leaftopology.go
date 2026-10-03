package natscell

import (
	"errors"
	"fmt"
	"slices"
)

// LeafTopology is the interregion leafnode graph: a tree rooted at the global
// home region (the hub, GRU). Each other region dials exactly one parent: the
// hub by default, or another spoke when a direct spoke-to-spoke link is
// preferred for latency. NATS leafnode loop detection disconnects cycles in one
// account, so the graph must stay a tree; transit between spokes is carried by
// interest propagation through their common ancestors.
type LeafTopology struct {
	Hub     string            `json:"hub"`
	Parents map[string]string `json:"parents"`
}

// HubAndSpoke links every spoke directly to the hub.
func HubAndSpoke(hub string, spokes []string) LeafTopology {
	parents := make(map[string]string, len(spokes))
	for _, spoke := range spokes {
		parents[spoke] = hub
	}
	return LeafTopology{Hub: hub, Parents: parents}
}

// WithSpokeParent returns a copy where spoke dials parent instead of the hub.
func (t LeafTopology) WithSpokeParent(spoke, parent string) LeafTopology {
	parents := make(map[string]string, len(t.Parents))
	for child, current := range t.Parents {
		parents[child] = current
	}
	parents[spoke] = parent
	return LeafTopology{Hub: t.Hub, Parents: parents}
}

// Validate requires a tree rooted at the hub whose every region is a valid cell.
func (t LeafTopology) Validate() error {
	if !cellName.MatchString(t.Hub) {
		return errors.New("leaf topology hub is not a valid cell")
	}
	if _, dials := t.Parents[t.Hub]; dials {
		return errors.New("leaf topology hub must not dial a parent")
	}
	for child, parent := range t.Parents {
		if !cellName.MatchString(child) || !cellName.MatchString(parent) || child == parent {
			return fmt.Errorf("leaf topology link %q -> %q is invalid", child, parent)
		}
		if parent != t.Hub {
			if _, known := t.Parents[parent]; !known {
				return fmt.Errorf("leaf topology parent %q is not a region", parent)
			}
		}
		seen := map[string]bool{child: true}
		for current := parent; current != t.Hub; current = t.Parents[current] {
			if seen[current] {
				return fmt.Errorf("leaf topology has a cycle through %q", current)
			}
			seen[current] = true
		}
	}
	return nil
}

// Regions returns the hub followed by the sorted spokes.
func (t LeafTopology) Regions() []string {
	regions := make([]string, 0, len(t.Parents)+1)
	for child := range t.Parents {
		regions = append(regions, child)
	}
	slices.Sort(regions)
	return append([]string{t.Hub}, regions...)
}

// Parent returns the region cell dials, if any.
func (t LeafTopology) Parent(cell string) (string, bool) {
	parent, ok := t.Parents[cell]
	return parent, ok
}

// Children returns the sorted regions that dial cell; cell listens if any.
func (t LeafTopology) Children(cell string) []string {
	var children []string
	for child, parent := range t.Parents {
		if parent == cell {
			children = append(children, child)
		}
	}
	slices.Sort(children)
	return children
}

// Peers returns every region except cell, sorted.
func (t LeafTopology) Peers(cell string) []string {
	var peers []string
	for _, region := range t.Regions() {
		if region != cell {
			peers = append(peers, region)
		}
	}
	slices.Sort(peers)
	return peers
}

// Subtrees maps each child of cell to the sorted regions reached through it,
// the child included: the InterRegion.Subtrees of cell's leaf listener.
func (t LeafTopology) Subtrees(cell string) map[string][]string {
	children := t.Children(cell)
	if len(children) == 0 {
		return nil
	}
	subtrees := make(map[string][]string, len(children))
	for _, child := range children {
		var subtree []string
		for region := range t.Parents {
			// Bounded walk to the root, so an unvalidated cycle cannot hang.
			current := region
			for range len(t.Parents) + 1 {
				if current == child {
					subtree = append(subtree, region)
					break
				}
				parent, ok := t.Parents[current]
				if !ok {
					break
				}
				current = parent
			}
		}
		slices.Sort(subtree)
		subtrees[child] = subtree
	}
	return subtrees
}

// Links is the number of leafnode links incident to cell.
func (t LeafTopology) Links(cell string) int {
	links := len(t.Children(cell))
	if _, ok := t.Parents[cell]; ok {
		links++
	}
	return links
}
