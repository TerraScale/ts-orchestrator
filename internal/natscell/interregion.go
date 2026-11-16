package natscell

// InterRegion links this regional cluster to peer regions with NATS
// leafnodes. The block describes reviewed topology and link credentials.
//
// Each region keeps its own operator. A leafnode binds only the dedicated
// interregion account on both sides, never the regional cell account. The cell
// and interregion accounts exchange only the explicit exports and imports in
// InterRegionContract, so only those subjects can cross a link. A remote
// authenticates with credentials issued under the peer region's operator for
// the peer's interregion account, which is why it pins that account key.
//
// The production JetStream domain is the cell name so a peer can address
// this region's JetStream API as $JS.<cell>.API without colliding with its own.
type InterRegion struct {
	// Peers lists every other region cell in the signed roster. The contract
	// exports and imports per-peer subjects only, never wildcards over cells.
	Peers []string `json:"peers"`
	// AccountJWTFile is this region's interregion account JWT, signed by the
	// regional operator and matching InterRegionContract exactly.
	AccountJWTFile string       `json:"account_jwt_file"`
	Listen         *LeafListen  `json:"listen,omitempty"`
	Remotes        []LeafRemote `json:"remotes,omitempty"`
	// GlobalHome is the region that owns TS_GLOBAL_CONTROL. The
	// contract carries the subjects of one home-created durable mirror
	// consumer per peer and nothing else of JetStream. It must be this cell
	// or a roster peer, and agrees with Topology.Hub when supplied.
	GlobalHome string `json:"global_home,omitempty"`
	// Subtrees maps every direct child region that dials Listen to the
	// regions reached through it, the child included. Each child gets its
	// own leaf users, bound by a scoped signing key of the interregion
	// account to permissions for its subtree alone (see
	// InterRegionContract.ChildLeafPermissions). Required with Listen.
	Subtrees map[string][]string `json:"subtrees,omitempty"`
	// Topology is the whole reviewed leaf tree. When set, startup derives
	// this region's view from it and refuses any other: Peers must be every
	// other region of the tree, Subtrees exactly this region's children and
	// their subtrees, Remotes exactly one link to this region's parent (none
	// at the root), and GlobalHome, if set, the tree's hub. Configuration
	// rendered from interregion material always carries it; without it only
	// this region's local view is checked.
	Topology *LeafTopology `json:"topology,omitempty"`
}

// LeafListen accepts leafnodes from child regions in the leaf topology. TLS is
// mutual and should use the reviewed interregion CA, not the regional one.
// Host must be 0.0.0.0: controllers have no public IP, and children dial
// both their private peering address and their NetBird address.
type LeafListen struct {
	Host string   `json:"host"`
	Port int      `json:"port"`
	TLS  TLSFiles `json:"tls"`
}

// LeafRemote dials the parent region in the leaf topology. URLs are tried in
// order, never shuffled: the parent controllers' addresses from the reviewed
// private peering receipt first, then their NetBird fallbacks. They are IPs,
// so ServerName is the DNS name every parent leaf certificate is verified
// against. CredentialsFile is a user issued by PeerAccount, the parent's
// interregion account, under the parent's operator.
type LeafRemote struct {
	Peer            string   `json:"peer"`
	URLs            []string `json:"urls"`
	CredentialsFile string   `json:"credentials_file"`
	PeerAccount     string   `json:"peer_account"`
	TLS             TLSFiles `json:"tls"`
	ServerName      string   `json:"server_name"`
}

// InterRegionContract is the complete subject contract between a region's
// cell account and its interregion account. Peers must exclude Cell.
//
// GlobalHome, when set, adds what a read-only mirror of the home region's
// TS_GLOBAL_CONTROL stream needs, and nothing more. The home region creates
// one durable consumer per peer itself, with a fixed delivery subject under
// that peer's contract prefix, and each peer mirrors through that consumer
// (durable sourcing). Per peer only three subjects cross: the fixed delivery
// subject, the reset verb of that one consumer (remapped under the link API
// prefix), and that consumer's flow-control replies, which are also its acks.
// No consumer-create, stream or account API is exported, so a peer can never
// pick a delivery subject: the probe that made GRU deliver global records onto
// its own placement subject has nothing to call.
//
// Subtrees lists, per direct child accepted on this region's leaf listener,
// the regions reached through that child. Each child's leaf users are bound
// to that child's permissions by a scoped signing key, so one child can never
// act for a sibling's regions.
type InterRegionContract struct {
	Cell       string
	Peers      []string
	GlobalHome string
	Subtrees   map[string][]string
}
