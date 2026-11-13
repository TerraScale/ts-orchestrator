package ocicost

// View is one region's cost as its summary carries it.
type View struct {
	Cell      string `json:"cell"`
	OCIRegion string `json:"oci_region,omitempty"`
	// Missing says why the region has no report yet; Forecast and the
	// lines are then empty.
	Missing    string   `json:"missing,omitempty"`
	Forecast   Forecast `json:"forecast"`
	Services   []Line   `json:"services,omitempty"`
	Components []Line   `json:"components,omitempty"`
	// UntaggedCents is this month's cost without a component tag.
	UntaggedCents uint64 `json:"untagged_cents"`
}
