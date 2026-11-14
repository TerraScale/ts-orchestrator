package mesh

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats-server/v2/server"
)

const (
	ClusterName   = "terrascale"
	FabricAccount = "TERRABASE"
	orchAccount   = "ORCH"
	orchUser      = "orch"
	fabricUser    = "ts-orch"
	terrabaseUser = "terrabase"
	// TerraBaseSubjects is the TerraBase fabric's own subject space (PIVOT D25).
	TerraBaseSubjects = "terrabase.>"
	regionTag         = "region:"

	jetStreamMaxMemory = 1 << 30
	jetStreamMaxStore  = 16 << 30
)

func serverOptions(cfg config, tlsConfig *tls.Config, orchSecret, fabricSecret string) (*server.Options, error) {
	if len(cfg.terrabaseToken) < 16 {
		return nil, errors.New("mesh needs TerraBase's NATS token")
	}
	options := &server.Options{}
	if err := options.ProcessConfigString(accountsConfig); err != nil {
		return nil, fmt.Errorf("mesh accounts: %w", err)
	}
	options.CustomClientAuthentication = &clientAuth{
		users: map[string]credential{
			orchUser:   {secret: orchSecret, account: orchAccount},
			fabricUser: {secret: fabricSecret, account: FabricAccount},
		},
		terrabase: credential{secret: cfg.terrabaseToken, account: FabricAccount, permissions: &server.Permissions{
			Publish:   &server.SubjectPermission{Allow: terrabasePublish},
			Subscribe: &server.SubjectPermission{Allow: terrabaseSubscribe},
		}},
	}
	options.ServerName = serverName(cfg)
	options.Host, options.Port = "127.0.0.1", cfg.localPort
	options.NoSigs, options.MaxPayload = true, maxWire
	options.Tags.Add(regionTag + cfg.region)
	routes := slices.Clone(cfg.routes)
	for seeds := range maps.Values(cfg.seeds) {
		routes = append(routes, seeds...)
	}
	slices.Sort(routes)
	for _, route := range slices.Compact(routes) {
		address, err := url.Parse(route)
		if err != nil {
			return nil, err
		}
		options.Routes = append(options.Routes, address)
	}
	if len(options.Routes) > 0 {
		options.Cluster = server.ClusterOpts{
			Name: ClusterName, Host: cfg.clusterHost, Port: cfg.clusterPort, Advertise: cfg.clusterAdvertise,
			TLSConfig: tlsConfig, TLSTimeout: 5, PinnedAccounts: []string{FabricAccount},
		}
	}
	if cfg.applier != nil && len(options.Routes) > 0 {
		options.JetStream = true
		options.SyncAlways = true
		options.StoreDir = cfg.dir
		options.JetStreamMaxMemory, options.JetStreamMaxStore = jetStreamMaxMemory, jetStreamMaxStore
		options.JetStreamUniqueTag = regionTag
	}
	return options, nil
}

// TerraBase publishes its own subjects and uses JetStream inside its own
// account (D17, D25): the stream and KV API, KV writes, acks and flow-control
// replies. It subscribes to its own subjects and its reply inboxes, where
// consumers and KV watches deliver. ts-orch's ORCH account stays out of reach.
var (
	terrabasePublish   = []string{TerraBaseSubjects, "$JS.API.>", "$KV.>", "$JS.ACK.>", "$JS.FC.>"}
	terrabaseSubscribe = []string{TerraBaseSubjects, "_INBOX.>"}
)

var accountsConfig = fmt.Sprintf(`accounts {
  %s {}
  %s { jetstream: { max_memory: 1G, max_file: 36G, max_streams: 64, max_consumers: 4096 } }
}
`, orchAccount, FabricAccount)

type credential struct {
	secret, account string
	permissions     *server.Permissions // nil: the whole account
}

// clientAuth admits the loopback clients: ts-orch's users by name and
// password, and TerraBase by the token its client sends (TERRABASE_NATS_TOKEN_FILE).
// server is set before the server starts accepting clients.
type clientAuth struct {
	server    *server.Server
	users     map[string]credential
	terrabase credential
}

func (a *clientAuth) Check(c server.ClientAuthentication) bool {
	opts := c.GetOpts()
	if c.Kind() != server.CLIENT {
		return false
	}
	name, want, presented := terrabaseUser, a.terrabase, opts.Token
	if opts.Username != "" {
		user, ok := a.users[opts.Username]
		if !ok {
			return false
		}
		name, want, presented = opts.Username, user, opts.Password
	}
	if subtle.ConstantTimeCompare([]byte(want.secret), []byte(presented)) != 1 {
		if name == terrabaseUser {
			slog.Warn("mesh NATS refused a TerraBase token", "client", opts.Name, "remote", c.RemoteAddress().String())
		}
		return false
	}
	account, err := a.server.LookupAccount(want.account)
	if err != nil {
		return false
	}
	c.RegisterUser(&server.User{Username: name, Account: account, Permissions: want.permissions})
	if name == terrabaseUser {
		// The per-node proof that TerraBase follows revisions over NATS, not the sweep.
		slog.Info("mesh NATS admitted TerraBase", "client", opts.Name, "account", want.account, "subjects", TerraBaseSubjects, "jetstream", true)
	}
	return true
}

func serverName(cfg config) string {
	if cfg.applier != nil {
		if cfg.founder {
			return cfg.region
		}
		return cfg.region + "." + cfg.nodeID[:min(12, len(cfg.nodeID))]
	}
	return cfg.region + "." + cfg.server
}

func serverRegion(name string) string {
	region, _, _ := strings.Cut(name, ".")
	return region
}

func (n *Node) routes() []*server.RouteInfo {
	routes, err := n.server.Routez(nil)
	if err != nil {
		return nil
	}
	return routes.Routes
}

func (n *Node) closeConns() {
	if n.monitor != nil {
		n.monitor.Close()
	}
	n.conn.Close()
	if n.fabric != nil {
		n.fabric.Close()
	}
}

type containedLog struct {
	server.Logger
	fatal chan string
}

func newContainedLog() containedLog {
	return containedLog{Logger: logger.NewStdLogger(false, false, false, false, true), fatal: make(chan string, 1)}
}

func (l containedLog) Fatalf(format string, v ...any) {
	message := fmt.Sprintf(format, v...)
	l.Errorf("%s", message)
	select {
	case l.fatal <- message:
	default:
	}
}

func (l containedLog) failure() error {
	select {
	case message := <-l.fatal:
		return errors.New("mesh NATS server: " + message)
	default:
		return errors.New("mesh NATS server did not start listening")
	}
}

func randomHex() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return hex.EncodeToString(secret), nil
}
