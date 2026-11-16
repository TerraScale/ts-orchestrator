package regionsuggest

import (
	"time"
)

// Suggestion actions.

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
