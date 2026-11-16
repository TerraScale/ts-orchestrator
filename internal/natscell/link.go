package natscell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// LinkHome is the global home every other region dials. One correct value:
// the home's controllers listen on LinkPort at ts-gru-<n>.nb.ts.internal.
const LinkHome = "gru"

// LinkPort is the leafnode port of the home's controllers.
const LinkPort = 7422

// LinkServerName is the verified DNS identity of the GRU leaf listener.
const LinkServerName = "leaf.gru.interregion.terrascale.internal"

// LinkHomeHosts are the admitted GRU controller slot names used by both
// credential material and NetBird DNS; no observed peer can add a leaf parent.
func LinkHomeHosts() []string {
	return []string{"ts-gru-1.nb.ts.internal", "ts-gru-2.nb.ts.internal", "ts-gru-3.nb.ts.internal"}
}

// linkLeafConnections bounds the home's leaf connections: 32 regions with 5
// brokers each.
const linkLeafConnections = 160

// linkRole names the link signing key in the cell account's signing keys.
const linkRole = "link"

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
	for _, action := range []string{"reserve", "revalidate", "observe"} {
		scope.Template.Pub.Allow.Add(root + "." + cell + ".capacity." + action)
	}
	// Only the home answers spending requests. A spoke may receive its own
	// replies, but cannot publish any capacity reply or receive any request.
	scope.Template.Sub.Allow.Add(root + "." + cell + ".capacity-reply.>")
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

// VerifyLinkScope requires the cell account to hold exactly one link signing
// key whose template is LinkScope's, and the leaf limit of the link.
func VerifyLinkScope(claim *jwt.AccountClaims) error {
	if claim == nil {
		return errors.New("home cell account claim is required")
	}
	var links []*jwt.UserScope
	for key, scope := range claim.SigningKeys {
		if user, ok := scope.(*jwt.UserScope); ok && user != nil && user.Role == linkRole {
			if user.Key != key || key == claim.Subject || !nkeys.IsValidPublicAccountKey(key) {
				return errors.New("home link signing key must be a scoped account key distinct from the cell account")
			}
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

// ValidateLinkCredentialBytes is validateLinkCredentials for the bytes a
// material generation pins as link.creds.
func ValidateLinkCredentialBytes(data []byte, cell string) error {
	if token, err := protocol.RegionToken(cell); err != nil || token != cell || cell == protocol.GlobalScope || cell == LinkHome {
		return errors.New("link credentials require a lowercase spoke region")
	}
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
	if !nkeys.IsValidPublicAccountKey(claim.IssuerAccount) || !nkeys.IsValidPublicAccountKey(claim.Issuer) ||
		claim.Issuer == claim.IssuerAccount || claim.BearerToken || claim.ProxyRequired || len(claim.Src) != 0 {
		return errors.New("link credentials must be issued for a home account and prove their key")
	}
	if len(claim.Tags) != 1 || claim.Tags[0] != "cell:"+cell {
		return fmt.Errorf("link credentials must be tagged cell:%s alone", cell)
	}
	now := time.Now().Unix()
	if claim.IssuedAt <= 0 || claim.IssuedAt > now || claim.NotBefore > now || claim.Expires <= now || claim.Expires <= claim.IssuedAt {
		return errors.New("link credentials must be currently valid with an expiration after their issuance")
	}
	// The server applies a scoped key's template only to a user with no
	// permissions, limits or allowed connection types of its own.
	if !claim.HasEmptyPermissions() {
		return errors.New("link credentials must not carry permissions or limits of their own")
	}
	return nil
}
