package natscell

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

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
}

// LeafListen accepts leafnodes from child regions in the leaf topology. TLS is
// mutual and should use the reviewed interregion CA, not the regional one.
type LeafListen struct {
	Host string   `json:"host"`
	Port int      `json:"port"`
	TLS  TLSFiles `json:"tls"`
}

// LeafRemote dials the parent region in the leaf topology. URLs must come from
// the reviewed private peering receipt; CredentialsFile is a user issued by
// PeerAccount, the parent's interregion account, under the parent's operator.
type LeafRemote struct {
	Peer            string   `json:"peer"`
	URLs            []string `json:"urls"`
	CredentialsFile string   `json:"credentials_file"`
	PeerAccount     string   `json:"peer_account"`
	TLS             TLSFiles `json:"tls"`
}

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
	if ir.Listen == nil && len(ir.Remotes) == 0 {
		return errors.New("interregion needs a leaf listener or at least one remote")
	}
	if ir.Listen != nil && (ir.Listen.Host == "" || ir.Listen.Port <= 0 || !ir.Listen.TLS.complete()) {
		return errors.New("interregion leaf listener requires host, port, and mutual TLS")
	}
	remotes := map[string]bool{}
	for _, remote := range ir.Remotes {
		if !slices.Contains(ir.Peers, remote.Peer) || remotes[remote.Peer] {
			return fmt.Errorf("interregion remote %q is not a unique roster peer", remote.Peer)
		}
		remotes[remote.Peer] = true
		if len(remote.URLs) == 0 || remote.CredentialsFile == "" || !remote.TLS.complete() ||
			!nkeys.IsValidPublicAccountKey(remote.PeerAccount) {
			return fmt.Errorf("interregion remote %q requires URLs, credentials, peer account, and mutual TLS", remote.Peer)
		}
		for _, raw := range remote.URLs {
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Scheme != "nats-leaf" || parsed.Host == "" || parsed.User != nil ||
				parsed.Path != "" || parsed.RawQuery != "" {
				return fmt.Errorf("interregion remote %q URL must be nats-leaf://host:port", remote.Peer)
			}
		}
	}
	return nil
}

// InterRegionContract is the complete subject contract between a region's
// cell account and its interregion account. Peers must exclude Cell.
type InterRegionContract struct {
	Cell  string
	Peers []string
}

func (c InterRegionContract) streamSubjects(cell string) []string {
	return []string{protocol.RegionHealthSubject(cell)}
}

func (c InterRegionContract) serviceSubjects(cell string) []string {
	return []string{protocol.Regional(cell, "query", ">")}
}

// CellExports is what the cell account offers to its interregion account.
func (c InterRegionContract) CellExports() jwt.Exports {
	var exports jwt.Exports
	for _, subject := range c.streamSubjects(c.Cell) {
		exports.Add(&jwt.Export{Name: "interregion-stream", Subject: jwt.Subject(subject), Type: jwt.Stream})
	}
	for _, subject := range c.serviceSubjects(c.Cell) {
		exports.Add(&jwt.Export{Name: "interregion-service", Subject: jwt.Subject(subject), Type: jwt.Service})
	}
	return exports
}

// CellImports is what the cell account takes from its interregion account.
func (c InterRegionContract) CellImports(interregionAccount string) jwt.Imports {
	var imports jwt.Imports
	for _, peer := range c.Peers {
		for _, subject := range c.streamSubjects(peer) {
			imports.Add(&jwt.Import{Name: "peer-stream", Account: interregionAccount, Subject: jwt.Subject(subject), Type: jwt.Stream})
		}
		for _, subject := range c.serviceSubjects(peer) {
			imports.Add(&jwt.Import{Name: "peer-service", Account: interregionAccount, Subject: jwt.Subject(subject), Type: jwt.Service})
		}
	}
	return imports
}

// InterRegionExports is what the interregion account offers the cell account:
// exactly the per-peer subjects carried in from leafnodes.
func (c InterRegionContract) InterRegionExports() jwt.Exports {
	var exports jwt.Exports
	for _, peer := range c.Peers {
		for _, subject := range c.streamSubjects(peer) {
			exports.Add(&jwt.Export{Name: "peer-stream", Subject: jwt.Subject(subject), Type: jwt.Stream})
		}
		for _, subject := range c.serviceSubjects(peer) {
			exports.Add(&jwt.Export{Name: "peer-service", Subject: jwt.Subject(subject), Type: jwt.Service})
		}
	}
	return exports
}

// InterRegionImports is what the interregion account takes from the cell
// account and therefore what peers can reach over a leafnode.
func (c InterRegionContract) InterRegionImports(cellAccount string) jwt.Imports {
	var imports jwt.Imports
	for _, subject := range c.streamSubjects(c.Cell) {
		imports.Add(&jwt.Import{Name: "cell-stream", Account: cellAccount, Subject: jwt.Subject(subject), Type: jwt.Stream})
	}
	for _, subject := range c.serviceSubjects(c.Cell) {
		imports.Add(&jwt.Import{Name: "cell-service", Account: cellAccount, Subject: jwt.Subject(subject), Type: jwt.Service})
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

// ApplyInterRegion sets the interregion account's exports, imports and limits.
// It never holds JetStream state of its own.
func (c InterRegionContract) ApplyInterRegion(claim *jwt.AccountClaims, cellAccount string, links int) {
	claim.Exports = c.InterRegionExports()
	claim.Imports = c.InterRegionImports(cellAccount)
	claim.Limits.LeafNodeConn = int64(links * maxLeafConnectionsPerLink)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{}
	claim.Limits.JetStreamTieredLimits = nil
}

// verify requires the installed claims to match the contract exactly, the
// system and cell accounts to refuse leafnodes, and the interregion account
// to be JetStream-free. Any extra export or import is a widened boundary.
func (c InterRegionContract) verify(system, cell, interregion *jwt.AccountClaims, links int) error {
	if system.Limits.LeafNodeConn != 0 || cell.Limits.LeafNodeConn != 0 {
		return errors.New("interregion requires the system and cell accounts to deny leafnode connections")
	}
	if len(system.Imports) != 0 || len(system.Exports) != 0 {
		return errors.New("interregion requires a system account without imports or exports")
	}
	if !sameExports(cell.Exports, c.CellExports()) || !sameImports(cell.Imports, c.CellImports(interregion.Subject)) {
		return errors.New("cell account interregion exports or imports differ from the contract")
	}
	if !sameExports(interregion.Exports, c.InterRegionExports()) ||
		!sameImports(interregion.Imports, c.InterRegionImports(cell.Subject)) {
		return errors.New("interregion account exports or imports differ from the contract")
	}
	if interregion.Limits.LeafNodeConn <= 0 || interregion.Limits.LeafNodeConn > int64(links*maxLeafConnectionsPerLink) ||
		interregion.Limits.IsJSEnabled() || len(interregion.SigningKeys) != 0 {
		return errors.New("interregion account limits are not bounded to its leaf links")
	}
	return nil
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
			left.LocalSubject != "" || left.Token != "" || left.Share || left.AllowTrace {
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
	links := len(ir.Remotes)
	if ir.Listen != nil {
		links = len(ir.Peers)
	}
	contract := InterRegionContract{Cell: cfg.Cell, Peers: ir.Peers}
	if err := contract.verify(systemClaim, cellClaim, claim, links); err != nil {
		return err
	}
	resolver.admitInterRegion(claim.Subject, raw, contract, links)
	options.JetStreamDomain = cfg.Cell
	options.LeafNode.NoAdvertise = true
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
		leaf := &server.RemoteLeafOpts{
			LocalAccount: claim.Subject, Credentials: remote.CredentialsFile,
			TLS: true, TLSConfig: remoteTLS, TLSTimeout: 5,
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
// interregion account. The peer's server verifies the operator chain.
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
	if credentialAccount(claim) != peerAccount || claim.BearerToken ||
		len(claim.AllowedConnectionTypes) != 1 || !claim.AllowedConnectionTypes.Contains(jwt.ConnectionTypeLeafnode) {
		return errors.New("leaf credentials must be a leafnode-only user of the pinned peer interregion account")
	}
	return nil
}
