package natscell

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// InterRegion links this regional cluster to peer regions with NATS
// leafnodes. It is off unless Enabled is set; a disabled or absent block keeps
// the regional server exactly as before (no JetStream domain, no leafnodes).
//
// Each region keeps its own operator. A leafnode binds only the dedicated
// interregion account on both sides, never the regional cell account. The cell
// and interregion accounts exchange only the explicit exports and imports in
// InterRegionContract, so only those subjects can cross a link. A remote
// authenticates with credentials issued under the peer region's operator for
// the peer's interregion account, which is why it pins that account key.
//
// When enabled, the JetStream domain is the cell name so a peer can address
// this region's JetStream API as $JS.<cell>.API without colliding with its own.
type InterRegion struct {
	Enabled bool `json:"enabled"`
	// Peers lists every other region cell in the signed roster. The contract
	// exports and imports per-peer subjects only, never wildcards over cells.
	Peers []string `json:"peers"`
	// AccountJWTFile is this region's interregion account JWT, signed by the
	// regional operator and matching InterRegionContract exactly.
	AccountJWTFile string       `json:"account_jwt_file"`
	Listen         *LeafListen  `json:"listen,omitempty"`
	Remotes        []LeafRemote `json:"remotes,omitempty"`
	// GlobalHome is the region that owns TS_GLOBAL_CONTROL. When set, the
	// contract carries the subjects of one home-created durable mirror
	// consumer per peer and nothing else of JetStream. It must be this cell
	// or a roster peer.
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

// leafServerName is a lower-case DNS name; validate also refuses IPs.
var leafServerName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// leafReplyGrant is the service-import reply namespace. NATS maps the reply
// subject of every request that crosses an account service import into it.
const leafReplyGrant = "_R_.>"

// maxLeafConnectionsPerLink bounds leaf connections per linked region; every
// broker of an R5 child cluster opens its own connection.
const maxLeafConnectionsPerLink = 5

func (ir *InterRegion) active() bool { return ir != nil && ir.Enabled }

func (ir *InterRegion) validate(cfg Config) error {
	if !ir.active() {
		return nil
	}
	if cfg.Lab {
		return errors.New("interregion leafnodes require production operator accounts")
	}
	if ir.AccountJWTFile == "" {
		return errors.New("interregion account JWT is required")
	}
	if len(ir.Peers) == 0 || len(ir.Peers) > 63 {
		return errors.New("interregion peers must list between 1 and 63 regions")
	}
	seen := map[string]bool{cfg.Cell: true}
	for _, peer := range ir.Peers {
		if !cellName.MatchString(peer) || peer == protocol.GlobalScope || seen[peer] {
			return fmt.Errorf("interregion peer %q is invalid or repeated", peer)
		}
		seen[peer] = true
	}
	if ir.GlobalHome != "" && ir.GlobalHome != cfg.Cell && !slices.Contains(ir.Peers, ir.GlobalHome) {
		return errors.New("interregion global home must be this region or a roster peer")
	}
	// The leaf tree is rooted at the global home. LeafPermissions relies on
	// it: an accepted leaf never speaks for the home, so a home that dialed
	// a parent would have its health, queries and mirror feeds refused there.
	if ir.GlobalHome == cfg.Cell && len(ir.Remotes) != 0 {
		return errors.New("the interregion global home is the leaf tree root and must not dial remotes")
	}
	if ir.Listen == nil && len(ir.Remotes) == 0 {
		return errors.New("interregion needs a leaf listener or at least one remote")
	}
	// The home is the tree root and never dials out, so a non-home region
	// reaches it, and its mirror feed, only through a parent remote.
	if ir.GlobalHome != "" && ir.GlobalHome != cfg.Cell && len(ir.Remotes) == 0 {
		return errors.New("a non-home region must dial a remote to reach the interregion global home")
	}
	if ir.Listen != nil && (ir.Listen.Host != "0.0.0.0" || ir.Listen.Port <= 0 || !ir.Listen.TLS.complete()) {
		return errors.New("interregion leaf listener requires host 0.0.0.0, port, and mutual TLS")
	}
	if (ir.Listen != nil) != (len(ir.Subtrees) != 0) {
		return errors.New("interregion leaf listener and child subtrees must be configured together")
	}
	reached := map[string]bool{}
	for child, subtree := range ir.Subtrees {
		if !slices.Contains(subtree, child) {
			return fmt.Errorf("interregion child %q must be in its own subtree", child)
		}
		for _, region := range subtree {
			if !slices.Contains(ir.Peers, region) || region == ir.GlobalHome || reached[region] {
				return fmt.Errorf("interregion subtree of %q names %q, which is not a unique non-home peer", child, region)
			}
			reached[region] = true
		}
	}
	// The tree root (no parent remote) reaches every peer through its child
	// subtrees; a peer in none would be in the contract yet unreachable,
	// and every request to it would hang without a responder. A region
	// with a parent reaches the rest of the tree through it.
	if len(ir.Remotes) == 0 {
		for _, peer := range ir.Peers {
			if !reached[peer] {
				return fmt.Errorf("interregion roster peer %q is in no child subtree and this region dials no parent", peer)
			}
		}
	}
	remotes := map[string]bool{}
	for _, remote := range ir.Remotes {
		if !slices.Contains(ir.Peers, remote.Peer) || remotes[remote.Peer] || reached[remote.Peer] {
			return fmt.Errorf("interregion remote %q is not a unique roster peer outside the child subtrees", remote.Peer)
		}
		remotes[remote.Peer] = true
		if len(remote.URLs) == 0 || remote.CredentialsFile == "" || !remote.TLS.complete() ||
			!nkeys.IsValidPublicAccountKey(remote.PeerAccount) {
			return fmt.Errorf("interregion remote %q requires URLs, credentials, peer account, and mutual TLS", remote.Peer)
		}
		if len(remote.ServerName) > 253 || !leafServerName.MatchString(remote.ServerName) || net.ParseIP(remote.ServerName) != nil {
			return fmt.Errorf("interregion remote %q server_name must be a DNS name", remote.Peer)
		}
		for _, raw := range remote.URLs {
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Scheme != "nats-leaf" || parsed.Host == "" || parsed.User != nil ||
				parsed.Path != "" || parsed.RawQuery != "" {
				return fmt.Errorf("interregion remote %q URL must be nats-leaf://host:port", remote.Peer)
			}
		}
	}
	if ir.Topology != nil {
		return ir.matchTopology(cfg.Cell, *ir.Topology)
	}
	return nil
}

// matchTopology requires this region's configuration to be exactly its view
// of the whole leaf tree, so every region of one deployment links the same
// acyclic tree: each child that dials this region is one this region accepts
// with that child's subtree, and nothing outside the tree is in the contract.
func (ir *InterRegion) matchTopology(cell string, topology LeafTopology) error {
	if err := topology.Validate(); err != nil {
		return fmt.Errorf("interregion topology: %w", err)
	}
	if !slices.Contains(topology.Regions(), cell) {
		return fmt.Errorf("interregion topology does not contain this region %q", cell)
	}
	if ir.GlobalHome != "" && ir.GlobalHome != topology.Hub {
		return fmt.Errorf("interregion global home %q is not the topology hub %q", ir.GlobalHome, topology.Hub)
	}
	if !slices.Equal(slices.Sorted(slices.Values(ir.Peers)), topology.Peers(cell)) {
		return errors.New("interregion peers differ from the other regions of the topology")
	}
	expected := topology.Subtrees(cell)
	if len(expected) != len(ir.Subtrees) {
		return errors.New("interregion child subtrees differ from the topology")
	}
	for child, subtree := range expected {
		if !slices.Equal(slices.Sorted(slices.Values(ir.Subtrees[child])), subtree) {
			return fmt.Errorf("interregion subtree of child %q differs from the topology", child)
		}
	}
	parent, dials := topology.Parent(cell)
	if !dials && len(ir.Remotes) != 0 || dials && (len(ir.Remotes) != 1 || ir.Remotes[0].Peer != parent) {
		return errors.New("interregion remotes must be exactly this region's topology parent")
	}
	return nil
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

// links is the number of leaf links of a region with this contract and
// remotes outbound links.
func (c InterRegionContract) links(remotes int) int { return len(c.Subtrees) + remotes }

// contractFlow is one subject that crosses between the two accounts. The cell
// side uses cellSubject; the interregion side uses linkSubject, which differs
// only for the home region's consumer-reset verb, remapped under a link prefix
// so peers never address the raw JetStream API namespace.
type contractFlow struct {
	kind        jwt.ExportType
	cellSubject string
	linkSubject string
}

func sameFlow(kind jwt.ExportType, subject string) contractFlow {
	return contractFlow{kind: kind, cellSubject: subject, linkSubject: subject}
}

// globalMirrorFlows are the home-side subjects of peer's global mirror.
func globalMirrorFlows(home, peer string) []contractFlow {
	consumer := protocol.GlobalMirrorConsumer(peer)
	return []contractFlow{
		sameFlow(jwt.Stream, protocol.InterRegionGlobalDeliverSubject(peer)),
		{
			kind:        jwt.Service,
			cellSubject: protocol.JSConsumerResetSubject(protocol.JSLocalAPIPrefix, protocol.GlobalControlStream, consumer),
			linkSubject: protocol.JSConsumerResetSubject(protocol.InterRegionJSAPIPrefix(home), protocol.GlobalControlStream, consumer),
		},
		sameFlow(jwt.Service, protocol.JSFlowControlSubject(protocol.GlobalControlStream, consumer)),
	}
}

// observabilityFlows are cell's read-only telemetry services: exact
// request/reply subjects (region summary, decision query), never a wildcard
// over the observability leaves, so member snapshots and the raw journal
// stream stay regional. Their responders validate every request strictly.
func observabilityFlows(cell string) []contractFlow {
	var flows []contractFlow
	for _, leaf := range protocol.InterRegionObservabilityLeaves() {
		flows = append(flows, sameFlow(jwt.Service, protocol.InterRegionObservabilitySubject(cell, leaf)))
	}
	return flows
}

// outbound flows are exported by the cell account and imported by the
// interregion account: what this region offers to its peers.
func (c InterRegionContract) outbound() []contractFlow {
	flows := []contractFlow{
		sameFlow(jwt.Stream, protocol.RegionHealthSubject(c.Cell)),
		sameFlow(jwt.Service, protocol.Regional(c.Cell, "query", ">")),
	}
	flows = append(flows, observabilityFlows(c.Cell)...)
	if c.GlobalHome == c.Cell {
		for _, peer := range c.Peers {
			flows = append(flows, globalMirrorFlows(c.Cell, peer)...)
		}
	}
	return flows
}

// inbound flows are exported by the interregion account and imported by the
// cell account: what this region takes from its peers.
func (c InterRegionContract) inbound() []contractFlow {
	var flows []contractFlow
	for _, peer := range c.Peers {
		flows = append(flows,
			sameFlow(jwt.Stream, protocol.RegionHealthSubject(peer)),
			sameFlow(jwt.Service, protocol.Regional(peer, "query", ">")))
		flows = append(flows, observabilityFlows(peer)...)
	}
	if c.GlobalHome != "" && c.GlobalHome != c.Cell {
		// A mirror addresses the home region only by the link subjects.
		for _, flow := range globalMirrorFlows(c.GlobalHome, c.Cell) {
			flows = append(flows, sameFlow(flow.kind, flow.linkSubject))
		}
	}
	return flows
}

// ChildLeafPermissions is the deny-by-default permission set of child's leaf
// users. It is the template of child's scoped signing key in the interregion
// account, so the server applies it to every user that key issues, whatever
// the user JWT says. NATS reads leaf user permissions from the remote's point
// of view: Pub is what the child may send into this region, Sub is what this
// region may send to it.
//
// In the leaf tree, rooted at the global home which never dials, an accepted
// leaf is always a child of this region. Each contract subject is allowed
// only in the direction it legitimately travels from that child, for the
// regions in the child's subtree alone (transit for regions further down
// included): the child may send its subtree's health, requests to any
// region's query service, and its subtree's mirror resets and flow-control
// acks; it may receive any health, requests for its subtree's query services,
// and its subtree's mirror feeds. Neither this region, the global home, nor a
// sibling's subtree is ever in it, so a child can never speak for, reset the
// mirror of, or take the requests of any of them, and it can never send a
// mirror feed: that would forge another region's copy of global state.
//
// Replies cross only on the service-import reply namespace "_R_", which NATS
// creates per request for the contract's service imports. The hub closes a
// link that sends anything else. An unknown child gets nothing.
//
// Known limit of static NATS permissions: "_R_" cannot be narrowed per child.
// NATS exempts inbound "_R_" publishes from leaf permission checks, and a
// child must receive "_R_" deliveries for replies to its own requests, whose
// account-level prefix is random per server start. So a child that
// subscribes to "_R_.>" also sees replies addressed to other regions'
// requests, and could answer an in-flight request only by guessing its
// random per-request token (six base-62 characters). Requests themselves
// (the query and observability subjects) never reach a sibling.
func (c InterRegionContract) ChildLeafPermissions(child string) jwt.Permissions {
	subtree, ok := c.Subtrees[child]
	if !ok {
		return denyAllPermissions()
	}
	return c.leafPermissionsFor(func(region string) bool { return slices.Contains(subtree, region) })
}

// LeafPermissions is the union of every possible child's permissions: the
// most any leaf of this region could be granted. It is a review aid; leaf
// users get ChildLeafPermissions through their child's scoped signing key.
func (c InterRegionContract) LeafPermissions() jwt.Permissions {
	return c.leafPermissionsFor(func(string) bool { return true })
}

// denyAllPermissions are the interregion account's default permissions: a
// leaf user not issued by a child's scoped signing key may do nothing.
func denyAllPermissions() jwt.Permissions {
	var permissions jwt.Permissions
	permissions.Pub.Deny.Add(">")
	permissions.Sub.Deny.Add(">")
	return permissions
}

func (c InterRegionContract) leafPermissionsFor(inSubtree func(string) bool) jwt.Permissions {
	var permissions jwt.Permissions
	for _, region := range append([]string{c.Cell}, c.Peers...) {
		permissions.Sub.Allow.Add(protocol.RegionHealthSubject(region))
		permissions.Pub.Allow.Add(protocol.Regional(region, "query", ">"))
		for _, flow := range observabilityFlows(region) {
			permissions.Pub.Allow.Add(flow.linkSubject)
		}
		if region == c.Cell || region == c.GlobalHome || !inSubtree(region) {
			continue
		}
		permissions.Pub.Allow.Add(protocol.RegionHealthSubject(region))
		permissions.Sub.Allow.Add(protocol.Regional(region, "query", ">"))
		for _, flow := range observabilityFlows(region) {
			permissions.Sub.Allow.Add(flow.linkSubject)
		}
		if c.GlobalHome == "" {
			continue
		}
		for _, flow := range globalMirrorFlows(c.GlobalHome, region) {
			if flow.kind == jwt.Stream {
				permissions.Sub.Allow.Add(flow.linkSubject)
			} else {
				permissions.Pub.Allow.Add(flow.linkSubject)
			}
		}
	}
	permissions.Pub.Allow.Add(leafReplyGrant)
	permissions.Sub.Allow.Add(leafReplyGrant)
	return permissions
}

// CellExports is what the cell account offers to its interregion account.
func (c InterRegionContract) CellExports() jwt.Exports {
	var exports jwt.Exports
	for _, flow := range c.outbound() {
		exports.Add(&jwt.Export{Name: "interregion", Subject: jwt.Subject(flow.cellSubject), Type: flow.kind})
	}
	return exports
}

// CellImports is what the cell account takes from its interregion account.
func (c InterRegionContract) CellImports(interregionAccount string) jwt.Imports {
	var imports jwt.Imports
	for _, flow := range c.inbound() {
		imports.Add(&jwt.Import{Name: "interregion", Account: interregionAccount, Subject: jwt.Subject(flow.cellSubject), Type: flow.kind})
	}
	return imports
}

// InterRegionExports is what the interregion account offers the cell account:
// exactly the per-peer subjects carried in from leafnodes.
func (c InterRegionContract) InterRegionExports() jwt.Exports {
	var exports jwt.Exports
	for _, flow := range c.inbound() {
		exports.Add(&jwt.Export{Name: "peer", Subject: jwt.Subject(flow.linkSubject), Type: flow.kind})
	}
	return exports
}

// InterRegionImports is what the interregion account takes from the cell
// account and therefore what peers can reach over a leafnode.
func (c InterRegionContract) InterRegionImports(cellAccount string) jwt.Imports {
	var imports jwt.Imports
	for _, flow := range c.outbound() {
		imported := &jwt.Import{Name: "cell", Account: cellAccount, Subject: jwt.Subject(flow.cellSubject), Type: flow.kind}
		if flow.linkSubject != flow.cellSubject {
			imported.LocalSubject = jwt.RenamingSubject(flow.linkSubject)
		}
		imports.Add(imported)
	}
	return imports
}

// ApplyCell sets the cell account's interregion exports, imports, and the
// leafnode prohibition. Existing imports and exports on claim are replaced.
func (c InterRegionContract) ApplyCell(claim *jwt.AccountClaims, interregionAccount string) {
	claim.Exports = c.CellExports()
	claim.Imports = c.CellImports(interregionAccount)
	claim.Limits.LeafNodeConn = 0
}

// ApplyInterRegion sets the interregion account's exports, imports, its
// deny-all default leaf permissions, one scoped signing key per child (from
// childKeys, child to signing public key) whose template is that child's
// leaf permissions, and limits. It never holds JetStream state of its own.
func (c InterRegionContract) ApplyInterRegion(claim *jwt.AccountClaims, cellAccount string, links int,
	childKeys map[string]string,
) {
	claim.Exports = c.InterRegionExports()
	claim.Imports = c.InterRegionImports(cellAccount)
	claim.DefaultPermissions = denyAllPermissions()
	// Leaf users must prove possession of their key (nonce signature); a
	// bearer JWT alone never links a region.
	claim.Limits.DisallowBearer = true
	claim.SigningKeys = jwt.SigningKeys{}
	for child, key := range childKeys {
		claim.SigningKeys.AddScopedSigner(c.childScope(child, key))
	}
	claim.Limits.LeafNodeConn = int64(links * maxLeafConnectionsPerLink)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{}
	claim.Limits.JetStreamTieredLimits = nil
}

// childScope is the scoped signing key of child's leaf users.
func (c InterRegionContract) childScope(child, key string) *jwt.UserScope {
	scope := jwt.NewUserScope()
	scope.Key = key
	scope.Role = child
	scope.Description = "interregion leaf users of child region " + child
	scope.Template.Permissions = c.ChildLeafPermissions(child)
	scope.Template.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode}
	return scope
}

// verifyChildScopes requires exactly one scoped signing key per child whose
// template is exactly that child's leaf permissions, leafnode-only. An
// unscoped signing key could issue users with any permissions.
func (c InterRegionContract) verifyChildScopes(claim *jwt.AccountClaims) error {
	if len(claim.SigningKeys) != len(c.Subtrees) {
		return errors.New("interregion account needs exactly one scoped signing key per child region")
	}
	seen := map[string]bool{}
	for key, scope := range claim.SigningKeys {
		user, ok := scope.(*jwt.UserScope)
		if !ok || user == nil || user.Key != key || key == claim.Subject || !nkeys.IsValidPublicAccountKey(key) {
			return errors.New("interregion account signing keys must all be scoped child keys")
		}
		if _, child := c.Subtrees[user.Role]; !child || seen[user.Role] {
			return fmt.Errorf("interregion signing key role %q is not a unique child region", user.Role)
		}
		seen[user.Role] = true
		template := user.Template
		if !samePermissions(template.Permissions, c.ChildLeafPermissions(user.Role)) || template.BearerToken ||
			template.ProxyRequired || len(template.AllowedConnectionTypes) != 1 ||
			template.AllowedConnectionTypes[0] != jwt.ConnectionTypeLeafnode ||
			len(template.Src) != 0 || len(template.Times) != 0 || template.Locale != "" {
			return fmt.Errorf("interregion leaf template of %q differs from its child permissions", user.Role)
		}
	}
	return nil
}

// verify requires the installed claims to match the contract exactly, the
// system and cell accounts to refuse leafnodes, and the interregion account
// to be JetStream-free with deny-by-default leaf permissions. Any extra
// export, import or permission is a widened boundary.
func (c InterRegionContract) verify(system, cell, interregion *jwt.AccountClaims, links int) error {
	if system.Limits.LeafNodeConn != 0 || cell.Limits.LeafNodeConn != 0 {
		return errors.New("interregion requires the system and cell accounts to deny leafnode connections")
	}
	if len(system.Imports) != 0 || len(system.Exports) != 0 {
		return errors.New("interregion requires a system account without imports or exports")
	}
	// Account subject mappings apply after a service import is selected, so
	// a mapping could send contract traffic onto a subject the contract does
	// not export (for example query.admin onto placement.apply).
	if len(system.Mappings) != 0 || len(cell.Mappings) != 0 || len(interregion.Mappings) != 0 {
		return errors.New("interregion requires accounts without subject mappings")
	}
	if !sameExports(cell.Exports, c.CellExports()) || !sameImports(cell.Imports, c.CellImports(interregion.Subject)) {
		return errors.New("cell account interregion exports or imports differ from the contract")
	}
	if !sameExports(interregion.Exports, c.InterRegionExports()) ||
		!sameImports(interregion.Imports, c.InterRegionImports(cell.Subject)) {
		return errors.New("interregion account exports or imports differ from the contract")
	}
	if !denyAll(interregion.DefaultPermissions) {
		return errors.New("interregion account default leaf permissions must deny everything")
	}
	if !interregion.Limits.DisallowBearer {
		return errors.New("interregion account must disallow bearer leaf users")
	}
	if err := c.verifyChildScopes(interregion); err != nil {
		return err
	}
	if interregion.Limits.LeafNodeConn <= 0 || interregion.Limits.LeafNodeConn > int64(links*maxLeafConnectionsPerLink) ||
		interregion.Limits.IsJSEnabled() {
		return errors.New("interregion account limits are not bounded to its leaf links")
	}
	return nil
}

// VerifyClaims applies exactly the startup check of the installed account
// JWTs to claims a tool is about to issue, so material that would make the
// server refuse to start is never written.
func (c InterRegionContract) VerifyClaims(system, cell, interregion *jwt.AccountClaims, links int) error {
	return c.verify(system, cell, interregion, links)
}

// Contract checks an enabled block of cell's configuration as startup does
// and returns its subject contract and leaf link count, so a tool can check
// account claims against a configuration it has not started (TS-668).
func (ir *InterRegion) Contract(cell string) (InterRegionContract, int, error) {
	if !ir.active() {
		return InterRegionContract{}, 0, errors.New("interregion is not enabled")
	}
	if err := ir.validate(Config{Cell: cell}); err != nil {
		return InterRegionContract{}, 0, err
	}
	contract := InterRegionContract{Cell: cell, Peers: ir.Peers, GlobalHome: ir.GlobalHome, Subtrees: ir.Subtrees}
	return contract, contract.links(len(ir.Remotes)), nil
}

// ValidateLeafCredentials is the remote-side check of a leaf credentials
// file: a leaf-only user of peerAccount, issued by one of its scoped child
// signing keys, without permissions or limits of its own.
func ValidateLeafCredentials(path, peerAccount string) error {
	return validateLeafCredentials(path, peerAccount)
}

func denyAll(permissions jwt.Permissions) bool {
	return len(permissions.Pub.Allow) == 0 && len(permissions.Sub.Allow) == 0 &&
		slices.Equal(permissions.Pub.Deny, jwt.StringList{">"}) && slices.Equal(permissions.Sub.Deny, jwt.StringList{">"}) &&
		permissions.Resp == nil
}

// samePermissions compares allow lists as sets and requires no deny lists:
// the allow lists already deny everything else.
func samePermissions(actual, expected jwt.Permissions) bool {
	sameSet := func(left, right jwt.StringList) bool {
		return len(left) == len(right) && slices.Equal(slices.Sorted(slices.Values(left)), slices.Sorted(slices.Values(right)))
	}
	return sameSet(actual.Pub.Allow, expected.Pub.Allow) && sameSet(actual.Sub.Allow, expected.Sub.Allow) &&
		len(actual.Pub.Deny) == 0 && len(actual.Sub.Deny) == 0 && actual.Resp == nil && expected.Resp == nil
}

// sameExports compares as sets; account JWT encoding sorts exports.
func sameExports(actual, expected jwt.Exports) bool {
	if len(actual) != len(expected) || slices.Contains(actual, nil) {
		return false
	}
	order := func(left, right *jwt.Export) int {
		return strings.Compare(string(left.Subject)+"|"+left.Type.String(), string(right.Subject)+"|"+right.Type.String())
	}
	actual, expected = slices.SortedFunc(slices.Values(actual), order), slices.SortedFunc(slices.Values(expected), order)
	for index := range expected {
		left, right := actual[index], expected[index]
		if left == nil || left.Subject != right.Subject || left.Type != right.Type || left.TokenReq ||
			left.ResponseType != "" && left.ResponseType != jwt.ResponseTypeSingleton ||
			left.AccountTokenPosition != 0 || left.Advertise || left.AllowTrace || len(left.Revocations) != 0 {
			return false
		}
	}
	return true
}

// sameImports compares as sets; account JWT encoding sorts imports.
func sameImports(actual, expected jwt.Imports) bool {
	if len(actual) != len(expected) || slices.Contains(actual, nil) {
		return false
	}
	order := func(left, right *jwt.Import) int {
		return strings.Compare(string(left.Subject)+"|"+left.Type.String()+"|"+left.Account,
			string(right.Subject)+"|"+right.Type.String()+"|"+right.Account)
	}
	actual, expected = slices.SortedFunc(slices.Values(actual), order), slices.SortedFunc(slices.Values(expected), order)
	for index := range expected {
		left, right := actual[index], expected[index]
		if left == nil || left.Subject != right.Subject || left.Type != right.Type || left.Account != right.Account ||
			left.LocalSubject != right.LocalSubject || left.To != right.To || left.Token != "" || left.Share ||
			left.AllowTrace {
			return false
		}
	}
	return true
}

// interRegionServerOptions applies the leafnode listener, remotes and the
// JetStream domain. resolver must already admit the interregion account.
func interRegionServerOptions(cfg Config, options *server.Options, resolver *accountResolver,
	operator *jwt.OperatorClaims,
) error {
	ir := cfg.Embedded.InterRegion
	raw, err := readSignedJWT(ir.AccountJWTFile)
	if err != nil {
		return fmt.Errorf("read interregion account JWT: %w", err)
	}
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil || !nkeys.IsValidPublicAccountKey(claim.Subject) || !operator.DidSign(claim) ||
		claim.Subject == resolver.system || claim.Subject == resolver.cell {
		return errors.New("interregion account JWT is invalid")
	}
	systemClaim, err := jwt.DecodeAccountClaims(resolver.claims[resolver.system])
	if err != nil {
		return err
	}
	cellClaim, err := jwt.DecodeAccountClaims(resolver.claims[resolver.cell])
	if err != nil {
		return err
	}
	contract := InterRegionContract{Cell: cfg.Cell, Peers: ir.Peers, GlobalHome: ir.GlobalHome, Subtrees: ir.Subtrees}
	links := contract.links(len(ir.Remotes))
	if err := contract.verify(systemClaim, cellClaim, claim, links); err != nil {
		return err
	}
	resolver.admitInterRegion(claim.Subject, raw, contract, links)
	options.JetStreamDomain = cfg.Cell
	options.LeafNode.NoAdvertise = true
	// Leafnodes have no ping knob of their own. With these, a silently
	// dropped path is closed after 3 unanswered pings and the remote fails
	// over to its next URL within about 40 s, not the default 2 minutes and
	// 2 pings. Routes (otherwise 30 s and 2 pings) and bridged clients get
	// the same faster stale detection.
	options.PingInterval, options.MaxPingsOut = 10*time.Second, 3
	if ir.Listen != nil {
		listenTLS, err := loadTLS(ir.Listen.TLS, true)
		if err != nil {
			return fmt.Errorf("interregion leaf listener TLS: %w", err)
		}
		options.LeafNode.Host = ir.Listen.Host
		options.LeafNode.Port = ir.Listen.Port
		options.LeafNode.TLSConfig = listenTLS
		options.LeafNode.TLSTimeout = 5
	}
	for _, remote := range ir.Remotes {
		if err := validateLeafCredentials(remote.CredentialsFile, remote.PeerAccount); err != nil {
			return fmt.Errorf("interregion remote %q: %w", remote.Peer, err)
		}
		remoteTLS, err := loadTLS(remote.TLS, false)
		if err != nil {
			return fmt.Errorf("interregion remote %q TLS: %w", remote.Peer, err)
		}
		// NATS otherwise names the TLS server after the first non-IP URL,
		// or each IP itself.
		remoteTLS.ServerName = remote.ServerName
		leaf := &server.RemoteLeafOpts{
			LocalAccount: claim.Subject, Credentials: remote.CredentialsFile,
			TLS: true, TLSConfig: remoteTLS, TLSTimeout: 5, NoRandomize: true,
		}
		for _, raw := range remote.URLs {
			parsed, err := url.Parse(raw)
			if err != nil {
				return err
			}
			leaf.URLs = append(leaf.URLs, parsed)
		}
		options.LeafNode.Remotes = append(options.LeafNode.Remotes, leaf)
	}
	return nil
}

// validateLeafCredentials requires a leaf-only user of the pinned peer
// interregion account without permissions of its own, so the peer account's
// deny-by-default contract permissions are the ones that apply. The peer's
// server verifies the operator chain.
func validateLeafCredentials(path, peerAccount string) error {
	data, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return err
	}
	defer clear(data)
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	// The peer binds a child's leaf users to that child's permissions only
	// through the child's scoped signing key, whose template (leafnode-only)
	// replaces anything in the user JWT; the server refuses a scoped user
	// that carries permissions or limits of its own. A user signed by the
	// account identity key would get the account's deny-all defaults.
	if claim.IssuerAccount != peerAccount || claim.Issuer == peerAccount {
		return errors.New("leaf credentials must be issued by a scoped child signing key of the pinned peer interregion account")
	}
	if !claim.HasEmptyPermissions() {
		return errors.New("leaf credentials must not carry permissions or limits that override the child template")
	}
	return nil
}
