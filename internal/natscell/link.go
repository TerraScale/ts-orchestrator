package natscell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// LinkHome is the global home every other region dials. One correct value:
// the home's controllers listen on LinkPort at ts-gru-<n>.nb.ts.internal.
const LinkHome = "gru"

// LinkPort is the leafnode port of the home's controllers.
const LinkPort = 7422

// linkLeafConnections bounds the home's leaf connections: 32 regions with 5
// brokers each.
const linkLeafConnections = 160

// linkRole names the link signing key in the cell account's signing keys.
const linkRole = "link"

// Production values, held in variables only so tests can point a region at a
// local listener. linkServerName is the DNS name of the home's leaf
// certificate, which the interregion CA signs.
var (
	linkListenPort = LinkPort
	linkHomeURLs   = []string{"nats-leaf://ts-gru-1.nb.ts.internal:7422", "nats-leaf://ts-gru-2.nb.ts.internal:7422", "nats-leaf://ts-gru-3.nb.ts.internal:7422"}
	linkServerName = "leaf.gru.interregion.terrascale.internal"
)

// Link joins this region to the home with mutual-TLS leafnodes that bind the
// cell account on both sides. Every cell account carries one link signer, so
// a region needs no list of peers and the home needs no list of regions.
type Link struct {
	// CredentialsFile is a spoke's link user, issued by the home's link signer
	// for the home's cell account and tagged cell:<this cell>. The home has none.
	CredentialsFile string `json:"credentials_file,omitempty"`
	// TLS is this controller's interregion certificate, key and CA, the same
	// files the interregion block uses.
	TLS TLSFiles `json:"tls"`
}

// LinkScope is the link signer's scope. A link user reaches only the requests,
// health and mirror of its own region, and the template is the same for every
// region, so one signer serves them all.
func LinkScope(signer string) *jwt.UserScope {
	cell := "{{tag(cell)}}"
	root := protocol.SubjectRoot
	consumer := "global-mirror-" + cell
	scope := jwt.NewUserScope()
	scope.Key = signer
	scope.Role = linkRole
	scope.Description = "region links to the global home"
	scope.Template.Pub.Allow = jwt.StringList{
		root + ".*.query.>", root + ".*.obs." + protocol.ObservabilityRegionLeaf, root + ".*.obs." + protocol.ObservabilityDecisionsLeaf,
		// Region broadcasts (heartbeat, dashboard rollup, ...): its own only.
		root + "." + cell + ".region.>",
		protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix(LinkHome), protocol.GlobalControlStream, consumer),
		protocol.JSFlowControlSubject(protocol.GlobalControlStream, consumer),
		// Replies to a relayed request: a leaf's Resp grant does not cover them.
		root + ".*.inbox.>", "_INBOX.>",
	}
	// A region reads its own requests, observability and inbox, every region's
	// broadcasts, and its own mirror feed; _INBOX lets it see TerraBase replies
	// relayed through the home, like the old _R_ limit. The mirror's reset
	// replies come back on the server's own $JSC.R reply subjects, which the
	// server does not name per consumer.
	scope.Template.Sub.Allow = jwt.StringList{
		root + "." + cell + ".query.>", root + "." + cell + ".obs." + protocol.ObservabilityRegionLeaf,
		root + "." + cell + ".obs." + protocol.ObservabilityDecisionsLeaf, root + ".*.region.>",
		protocol.InterRegionRoot + "." + cell + ".global", root + "." + cell + ".inbox.>", "_INBOX.>", "$JSC.R.>",
	}
	scope.Template.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode}
	// A member answers each request once, on the requester's reply subject.
	scope.Template.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Minute}
	return scope
}

// ApplyLink adds the link signer to a cell account claim and bounds its leaf
// connections to the link.
func ApplyLink(claim *jwt.AccountClaims, signer string) {
	claim.SigningKeys.AddScopedSigner(LinkScope(signer))
	claim.Limits.LeafNodeConn = linkLeafConnections
}

// IssueLinkUser issues a spoke's link user: a new user key of homeAccount,
// tagged cell:<cell>, with no permissions or limits of its own, so the link
// signer's template applies. The template alone makes it leafnode-only: the
// server refuses a scoped user that sets allowed connection types.
func IssueLinkUser(signer nkeys.KeyPair, homeAccount, cell string, issuedAt, expires time.Time) ([]byte, error) {
	if token, err := protocol.RegionToken(cell); err != nil || token != cell {
		return nil, errors.New("link user cell must be a lowercase regional cell")
	}
	if !nkeys.IsValidPublicAccountKey(homeAccount) {
		return nil, errors.New("link user home account must be an account public key")
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		return nil, err
	}
	seed, err := user.Seed()
	if err != nil {
		return nil, err
	}
	claim := jwt.NewUserClaims(public)
	claim.UserPermissionLimits = jwt.UserPermissionLimits{}
	claim.IssuerAccount = homeAccount
	claim.Tags = jwt.TagList{"cell:" + cell}
	claim.IssuedAt, claim.Expires = issuedAt.Unix(), expires.Unix()
	raw, err := claim.Encode(signer)
	if err != nil {
		return nil, err
	}
	return jwt.FormatUserConfig(raw, seed)
}

// Files lists the link's material: its TLS files and a spoke's credentials.
func (l *Link) Files() []string {
	if l == nil {
		return nil
	}
	files := []string{l.TLS.CAFile, l.TLS.CertFile, l.TLS.KeyFile}
	if l.CredentialsFile != "" {
		files = append(files, l.CredentialsFile)
	}
	return files
}

// validate is the configuration check of a link block for cfg's cell.
func (l *Link) validate(cfg Config) error {
	if cfg.Lab {
		return errors.New("link leafnodes require production operator accounts")
	}
	if !l.TLS.complete() {
		return errors.New("link requires mutual TLS")
	}
	if cfg.Cell == LinkHome {
		if l.CredentialsFile != "" {
			return errors.New("the link home has no link credentials")
		}
		return nil
	}
	if l.CredentialsFile == "" {
		return errors.New("a link spoke requires its link credentials")
	}
	return nil
}

// VerifyLinkScope requires the cell account to hold exactly one link signing
// key whose template is LinkScope's, and the leaf limit of the link.
func VerifyLinkScope(claim *jwt.AccountClaims) error {
	var links []*jwt.UserScope
	for _, scope := range claim.SigningKeys {
		if user, ok := scope.(*jwt.UserScope); ok && user != nil && user.Role == linkRole {
			links = append(links, user)
		}
	}
	if len(links) != 1 {
		return errors.New("home cell account needs exactly one link signing key")
	}
	actual, err := json.Marshal(links[0].Template)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(LinkScope(links[0].Key).Template)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("home link signing key template differs from the link template")
	}
	if claim.Limits.LeafNodeConn != linkLeafConnections {
		return errors.New("home cell account leaf limit differs from the link")
	}
	return nil
}

// validateLinkCredentials requires a spoke's link user: a leafnode-only user of
// a valid account, tagged for cell alone, unexpired and without permissions of
// its own. The home's server verifies the operator chain.
func validateLinkCredentials(path, cell string) error {
	data, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return err
	}
	defer clear(data)
	return ValidateLinkCredentialBytes(data, cell)
}

// ValidateLinkCredentialBytes is validateLinkCredentials for the bytes a
// material generation pins as link.creds.
func ValidateLinkCredentialBytes(data []byte, cell string) error {
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		return err
	}
	defer pair.Wipe()
	if public, err := pair.PublicKey(); err != nil || public != claim.Subject {
		return errors.New("link credential seed and user JWT differ")
	}
	if !nkeys.IsValidPublicAccountKey(claim.IssuerAccount) || claim.BearerToken || claim.ProxyRequired || len(claim.Src) != 0 {
		return errors.New("link credentials must be issued for a home account and prove their key")
	}
	if len(claim.Tags) != 1 || claim.Tags[0] != "cell:"+cell {
		return fmt.Errorf("link credentials must be tagged cell:%s alone", cell)
	}
	if claim.Expires <= time.Now().Unix() {
		return errors.New("link credentials have expired")
	}
	// The server applies a scoped key's template only to a user with no
	// permissions, limits or allowed connection types of its own.
	if !claim.HasEmptyPermissions() {
		return errors.New("link credentials must not carry permissions or limits of their own")
	}
	return nil
}

// linkServerOptions applies the link to the server: the home listens for
// links, and every other region dials the home. The home's cell account must
// carry the link signer; a spoke's link user is checked before it is used.
func linkServerOptions(cfg Config, options *server.Options, resolver *accountResolver) error {
	link := cfg.Embedded.Link
	cellClaim, err := jwt.DecodeAccountClaims(resolver.claims[resolver.cell])
	if err != nil {
		return err
	}
	// The link rides the cell account, so the leaf accounts are the cell's.
	resolver.interregion = resolver.cell
	options.LeafNode.NoAdvertise = true
	// Same fast stale-path detection as the interregion leaves.
	options.PingInterval, options.MaxPingsOut = 10*time.Second, 3
	if cfg.Cell == LinkHome {
		if err := VerifyLinkScope(cellClaim); err != nil {
			return err
		}
		listenTLS, err := loadTLS(link.TLS, true)
		if err != nil {
			return fmt.Errorf("link listener TLS: %w", err)
		}
		options.LeafNode.Host = "0.0.0.0"
		options.LeafNode.Port = linkListenPort
		options.LeafNode.TLSConfig = listenTLS
		options.LeafNode.TLSTimeout = 5
		return nil
	}
	if err := validateLinkCredentials(link.CredentialsFile, cfg.Cell); err != nil {
		return fmt.Errorf("link credentials: %w", err)
	}
	remoteTLS, err := loadTLS(link.TLS, false)
	if err != nil {
		return fmt.Errorf("link TLS: %w", err)
	}
	remoteTLS.ServerName = linkServerName
	leaf := &server.RemoteLeafOpts{
		LocalAccount: resolver.cell, Credentials: link.CredentialsFile,
		TLS: true, TLSConfig: remoteTLS, TLSTimeout: 5, NoRandomize: true,
		// The home cannot push regional-only families either.
		DenyImports: []string{"$JS.API.>", "$KV.>", "$O.>", "$SYS.>", protocol.ControlRoot + ".>", protocol.BrokerRoot + ".>"},
	}
	for _, raw := range linkHomeURLs {
		parsed, err := url.Parse(raw)
		if err != nil {
			return err
		}
		leaf.URLs = append(leaf.URLs, parsed)
	}
	options.LeafNode.Remotes = append(options.LeafNode.Remotes, leaf)
	return nil
}
