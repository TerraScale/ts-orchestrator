package insights

import (
	"context"
	"time"
)

const ()

// Evaluation is the result of one pass.
type Evaluation struct {
	At       time.Time `json:"at"`
	Insights []Insight `json:"insights"`
	Counts   Counts    `json:"counts"`
	// Unavailable names inputs that could not be read this pass.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Source is the read side the dashboard and the region provider use.
// Engine implements it.
type Source interface {
	// Current returns the latest evaluation's ranked insights.
	Current() Evaluation
	// Changes returns transitions at or after since, oldest first.
	Changes(since time.Time) []Change
	// Subscribe streams transitions until ctx ends.
	Subscribe(ctx context.Context, buffer int) <-chan Change
}
