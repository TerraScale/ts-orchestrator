package natscell

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
)

// LinkHome is the global home every other region dials. One correct value:
// the home's controllers listen on LinkPort at ts-gru-<n>.nb.ts.internal.
const LinkHome = "gru"

// LinkPort is the leafnode port of the home's controllers.
const LinkPort = 7422

// LinkServerName is the verified DNS identity of the GRU leaf listener.
const LinkServerName = "leaf.gru.interregion.terrascale.internal"

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
