// Package natscell owns the regional embedded NATS server and its client connection.
// Feature slices receive the client interfaces and do not depend on this package.
package natscell

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

var cellName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// DefaultStoreMaxBytes bounds the embedded JetStream file store when the
// operator does not specify a per-node limit.
const DefaultStoreMaxBytes int64 = 8 << 30

// TLSFiles are the certificate material for both NATS listeners and clients.
type TLSFiles struct {
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

func (f TLSFiles) complete() bool {
	return f.CAFile != "" && f.CertFile != "" && f.KeyFile != ""
}

// Embedded configures the in-process regional NATS and JetStream server.
// Routes are stable seed addresses; NATS route discovery connects the remaining
// members once any seed is reachable. A persisted StoreDir is required.
type Embedded struct {
	Host              string      `json:"host"`
	Port              int         `json:"port"`
	RouteHost         string      `json:"route_host"`
	RoutePort         int         `json:"route_port"`
	Routes            []string    `json:"routes"`
	StoreDir          string      `json:"store_dir"`
	StoreMaxBytes     int64       `json:"store_max_bytes,omitzero"`
	TLS               TLSFiles    `json:"tls"`
	RouteTLS          TLSFiles    `json:"route_tls"`
	Users             []NKeyGrant `json:"users"`
	RouteUser         string      `json:"route_user"`
	RoutePasswordFile string      `json:"route_password_file"`
}

// StoreLimitBytes returns the effective per-node JetStream file-store limit.
func (e Embedded) StoreLimitBytes() int64 {
	if e.StoreMaxBytes == 0 {
		return DefaultStoreMaxBytes
	}
	return e.StoreMaxBytes
}

// NKeyGrant binds a NATS user key to one regional role. A host grant is tied
// to the hash of its admitted node identity and a private reply inbox prefix.
type NKeyGrant struct {
	PublicKey string `json:"public_key"`
	Role      string `json:"role"`
	Node      string `json:"node,omitempty"`
}

// Config describes a single regional cell. Lab permits an unauthenticated local
// test network and must be opted into explicitly. Production requires TLS and
// an NKey or JWT credential for the controller's connection.
type Config struct {
	Cell            string    `json:"cell"`
	Instance        string    `json:"instance"`
	Replicas        int       `json:"replicas"`
	Lab             bool      `json:"lab"`
	ClientRole      string    `json:"client_role,omitempty"`
	URL             string    `json:"url"`
	NKeySeedFile    string    `json:"nkey_seed_file"`
	CredentialsFile string    `json:"credentials_file"`
	TLS             TLSFiles  `json:"tls"`
	Embedded        *Embedded `json:"embedded"`
}

// Runtime keeps the broker and client alive together. Closing it drains the
// client before stopping the server so JetStream acknowledgements can finish.
type Runtime struct {
	server *server.Server
	conn   *nats.Conn
	js     jetstream.JetStream
	cell   string
	once   sync.Once
}

func (r *Runtime) Conn() *nats.Conn { return r.conn }

func (r *Runtime) JetStream() jetstream.JetStream { return r.js }

func (r *Runtime) Ready() bool {
	return r != nil && r.conn != nil && r.conn.IsConnected() &&
		(r.server == nil || r.server.Running())
}

// URL returns the effective client URL, including the selected ephemeral port
// when a lab server was configured with port -1.
func (r *Runtime) URL() string {
	if r.server != nil {
		return r.server.ClientURL()
	}
	return r.conn.ConnectedUrl()
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		if r.conn != nil {
			r.conn.Drain()
			r.conn.Close()
		}
		if r.server != nil {
			r.server.Shutdown()
			r.server.WaitForShutdown()
		}
	})
	return nil
}

// Start starts the embedded server when requested and establishes an authenticated
// client connection. Multi-node callers must call WaitForCluster before mutations.
func Start(ctx context.Context, cfg Config) (_ *Runtime, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	r := &Runtime{cell: cfg.Cell}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	if cfg.Embedded != nil {
		options, optionsErr := serverOptions(cfg)
		if optionsErr != nil {
			return nil, optionsErr
		}
		r.server, err = server.NewServer(options)
		if err != nil {
			return nil, fmt.Errorf("create embedded NATS: %w", err)
		}
		r.server.ConfigureLogger()
		go r.server.Start()
		if !r.server.ReadyForConnections(10 * time.Second) {
			return nil, errors.New("embedded NATS did not become ready")
		}
		cfg.URL = r.server.ClientURL()
	}
	options, err := clientOptions(cfg)
	if err != nil {
		return nil, err
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connected := make(chan struct{})
	var connectErr error
	go func() {
		r.conn, connectErr = nats.Connect(cfg.URL, options...)
		close(connected)
	}()
	select {
	case <-connectCtx.Done():
		// nats.Connect has a bounded timeout of its own; wait for the goroutine
		// before cleaning up to avoid a late client after server shutdown.
		<-connected
		return nil, connectCtx.Err()
	case <-connected:
	}
	if connectErr != nil {
		return nil, fmt.Errorf("connect regional NATS: %w", connectErr)
	}
	r.js, err = jetstream.New(r.conn)
	if err != nil {
		return nil, fmt.Errorf("open regional JetStream: %w", err)
	}
	// A new R3 cell cannot elect a JetStream metadata leader until its peers
	// have also started. The app calls WaitForCluster before any mutations.
	if cfg.Replicas == 1 && cfg.ClientRole != "host" {
		infoCtx, infoCancel := context.WithTimeout(ctx, 10*time.Second)
		defer infoCancel()
		if _, err := r.js.AccountInfo(infoCtx); err != nil {
			return nil, fmt.Errorf("regional JetStream unavailable: %w", err)
		}
	}
	return r, nil
}

// WaitForCluster waits for a NATS and JetStream metadata quorum and a
// JetStream API response. Routes alone can form before JetStream metadata can
// elect a leader; an existing R3 stream may recover with one broker absent.
// A caller must do this before provisioning replicated durable resources.
func (r *Runtime) WaitForCluster(ctx context.Context, replicas int) error {
	if replicas < 1 || replicas > 5 || replicas%2 == 0 {
		return errors.New("regional replicas must be 1, 3, or 5")
	}
	quorum := replicas/2 + 1
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.Ready() && (r.server == nil || r.peerCount() >= quorum && r.metadataReady(quorum)) {
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := r.js.AccountInfo(probeCtx)
			cancel()
			if err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %d regional NATS peers: %w", quorum, ctx.Err())
		case <-ticker.C:
		}
	}
}

// FullClusterReady distinguishes a missing peer from a permanent inability to
// place a new R3/R5 stream. It does not claim every peer is caught up.
func (r *Runtime) FullClusterReady(replicas int) bool {
	return r != nil && r.Ready() && (r.server == nil ||
		r.peerCount() >= replicas && r.metadataReady(replicas))
}

func (r *Runtime) metadataReady(required int) bool {
	if required == 1 {
		return true
	}
	info, err := r.server.Jsz(nil)
	if err != nil || info.Meta == nil || info.Meta.Leader == "" || info.Meta.Size < required {
		return false
	}
	// Follower-local metadata can report an online peer as Current=false even
	// while the leader reports it caught up. Requiring Current on every local
	// view can therefore prevent a healthy follower from ever becoming ready.
	online := 1 // This embedded server is running.
	for _, peer := range info.Meta.Replicas {
		if peer != nil && !peer.Offline && !peer.Pending {
			online++
		}
	}
	return online >= required
}

func (r *Runtime) peerCount() int {
	if r.server == nil {
		return 1
	}
	routes, err := r.server.Routez(nil)
	if err != nil {
		return 0
	}
	ids := map[string]struct{}{routes.ID: {}}
	for _, route := range routes.Routes {
		if route.RemoteID != "" {
			ids[route.RemoteID] = struct{}{}
		}
	}
	return len(ids)
}

func (cfg Config) validate() error {
	if !cellName.MatchString(cfg.Cell) || !cellName.MatchString(cfg.Instance) {
		return errors.New("cell and instance must be lowercase NATS tokens")
	}
	if cfg.Replicas != 1 && cfg.Replicas != 3 && cfg.Replicas != 5 {
		return errors.New("regional replicas must be 1, 3, or 5")
	}
	if cfg.ClientRole != "" && cfg.ClientRole != "controller" && cfg.ClientRole != "operator" && cfg.ClientRole != "host" {
		return errors.New("invalid regional NATS client role")
	}
	if cfg.Embedded == nil && cfg.URL == "" {
		return errors.New("regional NATS URL or embedded server is required")
	}
	if cfg.NKeySeedFile != "" && cfg.CredentialsFile != "" {
		return errors.New("choose one regional NKey seed or JWT credentials file")
	}
	if !cfg.Lab {
		if !cfg.TLS.complete() || (cfg.NKeySeedFile == "" && cfg.CredentialsFile == "") {
			return errors.New("production regional NATS requires client TLS and NKey/JWT credentials")
		}
		if cfg.Embedded != nil && (!cfg.Embedded.TLS.complete() || !cfg.Embedded.RouteTLS.complete() || len(cfg.Embedded.Users) == 0) {
			return errors.New("production embedded NATS requires client/route TLS and role-bound NKey users")
		}
		if cfg.Embedded != nil && cfg.CredentialsFile != "" {
			return errors.New("production embedded NATS requires role-bound NKey authentication; JWT credentials need an external account resolver")
		}
	}
	if cfg.Embedded != nil {
		e := cfg.Embedded
		if e.StoreDir == "" || e.Host == "" || e.Port == 0 {
			return errors.New("embedded NATS requires store_dir, host, and port")
		}
		if e.StoreMaxBytes < 0 {
			return errors.New("embedded NATS store_max_bytes must be positive when set")
		}
		if cfg.Replicas > 1 && (e.RouteHost == "" || e.RoutePort == 0 || len(e.Routes) == 0) {
			return errors.New("clustered NATS requires route_host, route_port and at least one seed route")
		}
		if !cfg.Lab && cfg.Replicas > 1 && (e.RouteUser == "" || e.RoutePasswordFile == "") {
			return errors.New("production NATS routes require a route user and password file")
		}
	}
	return nil
}

func serverOptions(cfg Config) (*server.Options, error) {
	e := cfg.Embedded
	if err := os.MkdirAll(e.StoreDir, 0o700); err != nil {
		return nil, fmt.Errorf("create regional JetStream store: %w", err)
	}
	options := &server.Options{
		ServerName:        cfg.Cell + "-" + cfg.Instance,
		Host:              e.Host,
		Port:              e.Port,
		JetStream:         true,
		JetStreamMaxStore: e.StoreLimitBytes(),
		StoreDir:          e.StoreDir,
		// JetStream clustering uses the system account to coordinate metadata.
		SystemAccount: "$SYS",
		Accounts:      []*server.Account{server.NewAccount("$SYS")},
		Cluster: server.ClusterOpts{
			Name: cfg.Cell,
			Host: e.RouteHost,
			Port: e.RoutePort,
		},
	}
	if cfg.Replicas > 1 {
		for _, raw := range e.Routes {
			route, err := url.Parse(raw)
			if err != nil || route.Host == "" || route.User != nil || route.Scheme != "nats-route" {
				return nil, fmt.Errorf("invalid NATS route %q", raw)
			}
			options.Routes = append(options.Routes, route)
		}
	}
	if e.TLS.complete() {
		config, err := loadTLS(e.TLS, true)
		if err != nil {
			return nil, err
		}
		options.TLS = true
		options.TLSConfig = config
		options.TLSVerify = true
	}
	if cfg.Replicas > 1 && e.RouteTLS.complete() {
		config, err := loadTLS(e.RouteTLS, true)
		if err != nil {
			return nil, err
		}
		options.Cluster.TLSConfig = config
	}
	seenKeys := make(map[string]struct{}, len(e.Users))
	for _, user := range e.Users {
		if !nkeys.IsValidPublicUserKey(user.PublicKey) {
			return nil, errors.New("invalid user NKey in embedded NATS users")
		}
		if _, exists := seenKeys[user.PublicKey]; exists {
			return nil, errors.New("duplicate embedded NATS user key")
		}
		seenKeys[user.PublicKey] = struct{}{}
		permissions, err := userPermissions(cfg.Cell, user)
		if err != nil {
			return nil, err
		}
		options.Nkeys = append(options.Nkeys, &server.NkeyUser{Nkey: user.PublicKey, Permissions: permissions})
	}
	if e.RoutePasswordFile != "" {
		secret, err := readPrivateFile(e.RoutePasswordFile, 4096)
		if err != nil {
			return nil, fmt.Errorf("read NATS route secret: %w", err)
		}
		defer clear(secret)
		password := strings.TrimSpace(string(secret))
		if len(password) < 16 {
			return nil, errors.New("NATS route secret must be at least 16 bytes")
		}
		options.Cluster.Username = e.RouteUser
		options.Cluster.Password = password
		for _, route := range options.Routes {
			route.User = url.UserPassword(e.RouteUser, password)
		}
	}
	return options, nil
}

func clientOptions(cfg Config) ([]nats.Option, error) {
	options := []nats.Option{nats.Name("terrascale-" + cfg.Cell + "-" + cfg.Instance), nats.Timeout(12 * time.Second)}
	if cfg.CredentialsFile != "" {
		data, err := readPrivateFile(cfg.CredentialsFile, 64<<10)
		if err != nil {
			return nil, fmt.Errorf("regional JWT credentials: %w", err)
		}
		pair, err := nkeys.ParseDecoratedUserNKey(data)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("regional JWT credentials: %w", err)
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil {
			return nil, err
		}
		options = append(options, nats.CustomInboxPrefix(inboxPrefix(cfg.Cell, public)))
		options = append(options, nats.UserJWT(func() (string, error) {
			data, err := readPrivateFile(cfg.CredentialsFile, 64<<10)
			if err != nil {
				return "", err
			}
			defer clear(data)
			return nkeys.ParseDecoratedJWT(data)
		}, func(nonce []byte) ([]byte, error) {
			return signNKeyFile(cfg.CredentialsFile, nonce)
		}))
	}
	if cfg.NKeySeedFile != "" {
		data, err := readPrivateFile(cfg.NKeySeedFile, 4096)
		if err != nil {
			return nil, fmt.Errorf("regional NKey seed: %w", err)
		}
		pair, err := nkeys.ParseDecoratedUserNKey(data)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("regional NKey seed: %w", err)
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil {
			return nil, err
		}
		options = append(options, nats.CustomInboxPrefix(inboxPrefix(cfg.Cell, public)))
		options = append(options, nats.Nkey(public, func(nonce []byte) ([]byte, error) {
			return signNKeyFile(cfg.NKeySeedFile, nonce)
		}))
	}
	if cfg.TLS.complete() {
		tlsConfig, err := loadTLS(cfg.TLS, false)
		if err != nil {
			return nil, err
		}
		options = append(options, nats.Secure(tlsConfig))
	}
	return options, nil
}

func inboxPrefix(cell, publicKey string) string {
	return "ts.orch.v1." + cell + ".inbox." + publicKey
}

func userPermissions(cell string, user NKeyGrant) (*server.Permissions, error) {
	inbox := inboxPrefix(cell, user.PublicKey) + ".>"
	root := "ts.orch.v1." + cell
	permissions := &server.Permissions{Subscribe: &server.SubjectPermission{Allow: []string{inbox}}}
	switch user.Role {
	case "host":
		if !cellName.MatchString(user.Node) {
			return nil, errors.New("host NATS user needs a valid node identity")
		}
		sum := sha256.Sum256([]byte(user.Node))
		permissions.Publish = &server.SubjectPermission{Allow: []string{
			root + ".agent." + hex.EncodeToString(sum[:]) + ".observation.*",
		}}
	case "controller":
		if user.Node != "" {
			return nil, errors.New("controller NATS user must not carry a host node")
		}
		permissions.Publish = &server.SubjectPermission{Allow: []string{
			root + ".>", "ts.control." + cell + ".>", "$JS.API.>", "$KV.>", "$O.>",
			"$JS.ACK.TS_DELIVERY_INTENTS.TS_DELIVERY_WORKER.>",
		}}
		permissions.Subscribe.Allow = append(permissions.Subscribe.Allow,
			root+".agent.*.observation.*", root+".delivery.artifact.admit", root+".host.register", root+".placement.apply")
	case "operator":
		if user.Node != "" {
			return nil, errors.New("operator NATS user must not carry a host node")
		}
		permissions.Publish = &server.SubjectPermission{Allow: []string{
			root + ".delivery.intent", root + ".delivery.artifact.admit", root + ".host.register", root + ".placement.apply", "$JS.API.INFO", "$JS.API.STREAM.INFO.TS_DELIVERY_INTENTS",
			"$JS.API.STREAM.INFO.OBJ_TS_ARTIFACTS",
			"$JS.API.STREAM.INFO.KV_TS_DELIVERY_ADMISSIONS",
			"$JS.API.STREAM.INFO.KV_TS_DELIVERY_OPERATIONS",
			"$JS.API.STREAM.INFO.KV_TS_HOST_STATE",
			"$JS.API.STREAM.INFO.TS_CONTROL_LOG",
			"$JS.API.STREAM.MSG.GET.OBJ_TS_ARTIFACTS",
			"$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_ADMISSIONS",
			"$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_OPERATIONS",
			"$JS.API.STREAM.MSG.GET.KV_TS_HOST_STATE",
			"$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG",
			"$JS.API.CONSUMER.CREATE.OBJ_TS_ARTIFACTS.>",
			"$JS.API.CONSUMER.INFO.OBJ_TS_ARTIFACTS.*",
			"$JS.API.CONSUMER.DELETE.OBJ_TS_ARTIFACTS.*",
			"$JS.API.DIRECT.GET.OBJ_TS_ARTIFACTS.>",
			"$JS.API.DIRECT.GET.KV_TS_DELIVERY_ADMISSIONS.>",
			"$JS.API.DIRECT.GET.KV_TS_DELIVERY_OPERATIONS.>",
			"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.>",
			"$JS.API.DIRECT.GET.TS_CONTROL_LOG.>",
			"$O.TS_ARTIFACTS.>",
		}}
	default:
		return nil, fmt.Errorf("invalid NATS user role %q", user.Role)
	}
	return permissions, nil
}

func loadTLS(files TLSFiles, serverSide bool) (*tls.Config, error) {
	key, err := readPrivateFile(files.KeyFile, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("NATS TLS private key: %w", err)
	}
	clear(key)
	certificate, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load NATS certificate: %w", err)
	}
	ca, err := os.ReadFile(files.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load NATS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("NATS CA file has no certificates")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots}
	if serverSide {
		config.ClientCAs = roots
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func signNKeyFile(path string, nonce []byte) ([]byte, error) {
	data, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	pair, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		return nil, err
	}
	defer pair.Wipe()
	return pair.Sign(nonce)
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret must be a regular file readable only by its owner")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("secret must be owned by this process user")
	}
	if info.Size() > limit {
		return nil, errors.New("secret file is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("secret file is too large")
	}
	return data, nil
}

// ClientAddress returns the bound listener address for an embedded runtime.
func (r *Runtime) ClientAddress() net.Addr {
	if r.server == nil {
		return nil
	}
	return r.server.Addr()
}

// RouteAddress returns the bound route listener address for an embedded runtime.
func (r *Runtime) RouteAddress() net.Addr {
	if r.server == nil {
		return nil
	}
	return r.server.ClusterAddr()
}
