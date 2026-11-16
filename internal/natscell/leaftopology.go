package natscell

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
