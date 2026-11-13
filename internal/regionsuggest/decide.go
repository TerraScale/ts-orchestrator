// Package regionsuggest suggests when the home region should add or remove a
// region. The global leader computes a suggestion every Interval from the load
// each region reports and the monthly budget. Nothing acts on it and nothing
// journals it: regions change only when the user runs ts-orch region create or
// remove. The latest suggestion is saved for the capacity page.
package regionsuggest

import (
	"time"
)

const ()

// Suggestion actions.
const ()

// Suggestion is the suggester's latest suggestion. Reason is always set.
type Suggestion struct {
	Action    string    `json:"action"` // "none", "add" or "remove"
	Cell      string    `json:"cell,omitempty"`
	OCIRegion string    `json:"oci_region,omitempty"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	// MonthlyCents and Currency price an add: NodesPerNewRegion nodes a month.
	MonthlyCents uint64 `json:"monthly_cents,omitempty"`
	Currency     string `json:"currency,omitempty"`
}
