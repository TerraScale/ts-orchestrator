package rollout

import (
	"time"
)

// Spec is the caller-supplied rollout definition. KnownBad is the cell's
// durable known-bad list; a target in it can never start.
type Spec struct {
	RolloutID      string
	Kind           Kind
	Cell           string
	FromDigest     string
	ToDigest       string
	Units          []Unit
	Policy         Policy
	KnownBad       []string
	AuthorityEpoch uint64
	StartedAt      time.Time
}
