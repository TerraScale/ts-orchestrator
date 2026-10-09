package hostload

import "time"

// UsageInterval is a registered node or allocated role's active lifetime.
// An empty Role describes the node; bounds are exclusive at To.
type UsageInterval struct {
	Node, Environment, Role string
	From, To                time.Time
}
