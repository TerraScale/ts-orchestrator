package mesh

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats-server/v2/server"
	"golang.org/x/crypto/bcrypt"
)

const (
	ClusterName   = "terrascale"
	FabricAccount = "TERRABASE"
	orchAccount   = "ORCH"
	orchUser      = "orch"
	fabricUser    = "ts-orch"
	regionTag     = "region:"

	jetStreamMaxMemory = 1 << 30
	jetStreamMaxStore  = 16 << 30
)

func serverOptions(cfg config, tlsConfig *tls.Config, orchSecret, fabricSecret string) (*server.Options, error) {
	options := &server.Options{}
	if err := options.ProcessConfigString(accountsConfig); err != nil {
		return nil, fmt.Errorf("mesh accounts: %w", err)
	}
	for _, user := range []struct{ name, secret, account string }{{orchUser, orchSecret, orchAccount}, {fabricUser, fabricSecret, FabricAccount}} {
		hash, err := bcrypt.GenerateFromPassword([]byte(user.secret), bcrypt.MinCost)
		if err != nil {
			return nil, err
		}
		account := slices.IndexFunc(options.Accounts, func(a *server.Account) bool { return a.Name == user.account })
		options.Users = append(options.Users, &server.User{Username: user.name, Password: string(hash), Account: options.Accounts[account]})
	}
	options.ServerName = serverName(cfg)
	options.Host, options.Port = "127.0.0.1", cfg.localPort
	options.NoSigs, options.MaxPayload = true, maxWire
	options.Tags.Add(regionTag + cfg.region)
	routes := append(slices.Clone(cfg.routes), slices.Sorted(maps.Values(cfg.seeds))...)
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
		options.StoreDir = cfg.dir
		options.JetStreamMaxMemory, options.JetStreamMaxStore = jetStreamMaxMemory, jetStreamMaxStore
		options.JetStreamUniqueTag = regionTag
	}
	return options, nil
}

var accountsConfig = fmt.Sprintf(`accounts {
  %s {}
  %s { jetstream: { max_memory: 1G, max_file: 36G, max_streams: 64, max_consumers: 4096 } }
}
`, orchAccount, FabricAccount)

func serverName(cfg config) string {
	if cfg.applier != nil {
		return cfg.region
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
