package natscell

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// newLinkRegion is a region with its own operator, system and cell accounts
// whose cell account carries the link signer. It has no interregion account.
func newLinkRegion(t *testing.T, root, cell, signer string) *testRegion {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := newTestRegionKeys(t)
	operator := jwt.NewOperatorClaims(keys.operatorID)
	operator.SystemAccount = keys.systemID
	cellClaim := jwt.NewAccountClaims(keys.cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	ApplyLink(cellClaim, signer)
	write := func(name string, claim interface {
		Encode(nkeys.KeyPair) (string, error)
	},
	) string {
		t.Helper()
		raw, err := claim.Encode(keys.operator)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	cfg := Config{
		Cell: cell, Instance: "broker-a", Replicas: 1, TLS: tlsFiles,
		Embedded: &Embedded{
			Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: write("operator.jwt", operator),
			SystemJWTFile:   write("system.jwt", jwt.NewAccountClaims(keys.systemID)),
			CellJWTFile:     write("cell.jwt", cellClaim),
			SystemCredentialsFile: testJWTUserCredentialsWithKey(t, root, "system.creds", keys.system, keys.systemID, systemUser,
				[]string{"$SYS.REQ.ACCOUNT." + keys.cellID + ".CLAIMS.UPDATE"}, []string{inboxPrefix(cell, systemUserID) + ".>"}),
			TicketPublicKeyFile: filepath.Join(root, "ticket.pub"),
			BrokerIDs:           []string{"broker-a"},
		},
	}
	if err := os.WriteFile(cfg.Embedded.TicketPublicKeyFile, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testRegion{testRegionKeys: keys, cfg: cfg}
}

// linkUserCredentials issues cell's link user through signer for the home
// account, as the home's material does for a spoke.
func linkUserCredentials(t *testing.T, root, name string, signer nkeys.KeyPair, homeAccount, cell string) string {
	t.Helper()
	now := time.Now()
	creds, err := IssueLinkUser(signer, homeAccount, cell, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// linkControllerCredentials is a controller's user in region: the publish and
// subscribe surface a controller serves, the observability and query services
// of the cross-region contract, one response per request.
func linkControllerCredentials(t *testing.T, root, name string, region *testRegion) string {
	t.Helper()
	cell := region.cfg.Cell
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = region.cellID
	claim.Pub.Allow = append(ControllerPublishes(cell),
		protocol.SubjectRoot+".*.obs."+protocol.ObservabilityRegionLeaf, protocol.SubjectRoot+".*.obs."+protocol.ObservabilityDecisionsLeaf,
		protocol.SubjectRoot+".*.query.>")
	claim.Sub.Allow = append(jwt.StringList(ControllerSubscriptions(cell)), protocol.ObservabilityGrant(cell),
		protocol.SubjectRoot+"."+cell+".query.>", protocol.SubjectRoot+".*.region.health", protocol.InboxGrant(cell, userID))
	claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Minute}
	raw, err := claim.Encode(region.cell)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// useLinkListener points the home's listener and every spoke's remote at a
// local port with the test certificate, restoring the production values after.
func useLinkListener(t *testing.T, port int) {
	t.Helper()
	listenPort, urls, serverName := linkListenPort, linkHomeURLs, linkServerName
	t.Cleanup(func() { linkListenPort, linkHomeURLs, linkServerName = listenPort, urls, serverName })
	linkListenPort = port
	linkHomeURLs = []string{"nats-leaf://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	linkServerName = testLeafServerName
}
