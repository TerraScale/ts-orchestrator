// Package natscell owns the regional embedded NATS server and its client connection.
// Feature slices receive the client interfaces and do not depend on this package.
package natscell

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

var cellName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// ErrEmbeddedServerStopped reports that the in-process broker has exited while
// its owning process is still alive. Callers must treat it as terminal so the
// service manager restarts the whole controller instead of waiting forever.
var ErrEmbeddedServerStopped = errors.New("embedded regional NATS server has stopped")

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
	Host                  string      `json:"host"`
	Port                  int         `json:"port"`
	RouteHost             string      `json:"route_host"`
	RoutePort             int         `json:"route_port"`
	Routes                []string    `json:"routes"`
	StoreDir              string      `json:"store_dir"`
	StoreMaxBytes         int64       `json:"store_max_bytes,omitzero"`
	TLS                   TLSFiles    `json:"tls"`
	RouteTLS              TLSFiles    `json:"route_tls"`
	Users                 []NKeyGrant `json:"users"`
	RouteUser             string      `json:"route_user"`
	RoutePasswordFile     string      `json:"route_password_file"`
	OperatorJWTFile       string      `json:"operator_jwt_file,omitempty"`
	SystemJWTFile         string      `json:"system_jwt_file,omitempty"`
	CellJWTFile           string      `json:"cell_jwt_file,omitempty"`
	SystemCredentialsFile string      `json:"system_credentials_file,omitempty"`
	// MembershipCredentialsFile is an optional system-account user limited to
	// metadata peer remove and leader step-down; see OpenMembershipAdmin.
	MembershipCredentialsFile string   `json:"membership_credentials_file,omitempty"`
	TicketPublicKeyFile       string   `json:"ticket_public_key_file,omitempty"`
	BrokerIDs                 []string `json:"broker_ids,omitempty"`
	// InterRegion links this region to peers by leafnode. Nil or disabled
	// keeps the region fully standalone.
	InterRegion *InterRegion `json:"interregion,omitempty"`
}

// ServerName is the embedded NATS server name of a cell's controller
// instance (a broker ID or controller slot). Cluster health, the controller
// slot topology (membership.Topology.ServerName) and the JetStream metadata
// peers all use this one shape, so a renamed slot reads as an unknown peer.
func ServerName(cell, instance string) string { return cell + "-" + instance }

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
	// Global adds GlobalControllerPublishes to a controller in the global
	// home region. It is refused for every other role.
	Global bool `json:"global,omitempty"`
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
	// OperatorForward is a transient CLI-only TCP route. Its keys remain the
	// configured controller TLS identities; values are local Bastion forwards.
	OperatorForward map[string]string `json:"-"`
	// ReloadClientMaterial, when set, is consulted on every connect and
	// reconnect so renewed credentials take effect without a process restart.
	// It must keep the startup NATS user key; failures use the startup files.
	ReloadClientMaterial func() (ClientMaterial, error) `json:"-"`
}

// Runtime keeps the broker and client alive together. Closing it drains the
// client before stopping the server so JetStream acknowledgements can finish.
type Runtime struct {
	server          *server.Server
	conn            *nats.Conn
	js              jetstream.JetStream
	cell            string
	diagMu          sync.Mutex
	diagAt          time.Time
	diagState       string
	endpoint        string
	resolver        *accountResolver
	operator        *jwt.OperatorClaims
	systemConn      *nats.Conn
	bridge          *Bridge
	claimMu         sync.Mutex
	appliedSequence uint64
	serverName      string
	brokerNames     []string
	once            sync.Once
}

func (r *Runtime) Conn() *nats.Conn { return r.conn }

func (r *Runtime) JetStream() jetstream.JetStream { return r.js }

func (r *Runtime) Bridge() *Bridge { return r.bridge }

// SignedByPinnedOperator checks the operator claim installed at broker startup.
func (r *Runtime) SignedByPinnedOperator(claim *jwt.AccountClaims) bool {
	return r != nil && r.operator != nil && claim != nil && r.operator.DidSign(claim)
}

func (r *Runtime) CellAccount() string {
	if r == nil || r.resolver == nil {
		return ""
	}
	return r.resolver.cell
}

func (r *Runtime) InitialCellJWT() string {
	if r == nil || r.resolver == nil {
		return ""
	}
	raw, _ := r.resolver.Fetch(r.resolver.cell)
	return raw
}

// ApplyCellClaim fences the external listener before installing a durable
// account replacement. A routed CLAIMS.UPDATE reply is never accepted as local
// proof; Accountz must report the exact raw JWT on this embedded server.
func (r *Runtime) ApplyCellClaim(ctx context.Context, sequence uint64, raw string) error {
	if r == nil || r.server == nil || r.resolver == nil || r.systemConn == nil ||
		sequence == 0 || raw == "" {
		return errors.New("production cell claim application is unavailable")
	}
	r.claimMu.Lock()
	defer r.claimMu.Unlock()
	if sequence < r.appliedSequence {
		return errors.New("cell claim sequence is stale")
	}
	if r.bridge != nil {
		r.bridge.FenceClaim(sequence)
	}
	if claim, err := jwt.DecodeAccountClaims(raw); err != nil || !r.SignedByPinnedOperator(claim) {
		return errors.New("cell claim is not signed by the pinned operator")
	}
	// Store runs the contract and issued-at checks; only then is the claim
	// installed, locally and directly. The server ignores CLAIMS.UPDATE
	// requests (see accountResolver.IsTrackingUpdate), so no routed or
	// client-sent claim can skip these checks.
	if err := r.resolver.Store(r.resolver.cell, raw); err != nil {
		return err
	}
	account, err := r.server.LookupAccount(r.resolver.cell)
	if err != nil {
		return err
	}
	current, err := r.server.Accountz(&server.AccountzOptions{Account: r.resolver.cell})
	if err != nil {
		return err
	}
	if current.Account == nil {
		return errors.New("cell account is not loaded")
	}
	if current.Account.Jwt != raw {
		if err := r.server.UpdateAccountClaimJWT(account, raw); err != nil {
			return fmt.Errorf("install cell account claim: %w", err)
		}
		current, err = r.server.Accountz(&server.AccountzOptions{Account: r.resolver.cell})
		if err != nil || current.Account == nil || current.Account.Jwt != raw {
			return errors.New("cell JWT update lacks local exact readback")
		}
	}
	r.appliedSequence = sequence
	return nil
}

func (r *Runtime) Ready() bool {
	return r != nil && r.conn != nil && r.conn.IsConnected() &&
		(r.server == nil || r.server.Running())
}

// URL returns the effective client URL, including the selected ephemeral port
// when a lab server was configured with port -1.
func (r *Runtime) URL() string {
	if r.bridge != nil {
		return "nats://" + r.bridge.Addr().String()
	}
	if r.server != nil {
		return r.server.ClientURL()
	}
	return r.conn.ConnectedUrl()
}

// logHostConnection records only the endpoint host and a fixed error class.
// URL userinfo, NKey material, request bodies, and inboxes stay out of logs.
func (r *Runtime) logHostConnection(state string, conn *nats.Conn, cause error) {
	endpoint := ""
	if conn != nil {
		if parsed, err := url.Parse(conn.ConnectedUrl()); err == nil {
			endpoint = parsed.Host
		}
	}
	r.diagMu.Lock()
	if endpoint == "" {
		endpoint = r.endpoint
	} else {
		r.endpoint = endpoint
	}
	now := time.Now()
	if state == r.diagState && now.Sub(r.diagAt) < 10*time.Second {
		r.diagMu.Unlock()
		return
	}
	r.diagState, r.diagAt = state, now
	r.diagMu.Unlock()
	class := "none"
	switch {
	case errors.Is(cause, nats.ErrStaleConnection):
		class = "stale_connection"
	case errors.Is(cause, nats.ErrDisconnected):
		class = "disconnected"
	case errors.Is(cause, nats.ErrTimeout):
		class = "timeout"
	case cause != nil:
		class = "transport"
	}
	slog.Info("host regional NATS connection transition", "state", state, "endpoint", endpoint, "cause_class", class)
}

// Close shuts the runtime down in lame-duck order: stop accepting external
// clients, drain the controller client, hand off JetStream leadership this
// broker holds, and only then stop the embedded server. Every phase is bounded
// so the whole sequence fits well inside the unit's stop timeout.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		if r.bridge != nil {
			r.bridge.Close()
		}
		if r.systemConn != nil {
			r.systemConn.Close()
		}
		if r.conn != nil {
			drainConnection(r.conn, closeDrainTimeout)
		}
		if r.server != nil {
			r.stopServer()
		}
	})
	return nil
}

// embeddedReadyTimeout bounds embedded server startup. JetStream cluster
// bootstrap on a loaded single-OCPU host can take well over ten seconds.
const embeddedReadyTimeout = time.Minute

// serverReady waits until the embedded server accepts connections, the
// caller's context ends, or embeddedReadyTimeout passes.
func serverReady(ctx context.Context, embedded *server.Server) bool {
	deadline := time.Now().Add(embeddedReadyTimeout)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		if embedded.ReadyForConnections(time.Second) {
			return true
		}
	}
	return false
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
		r.serverName = options.ServerName
		for _, id := range cfg.Embedded.BrokerIDs {
			r.brokerNames = append(r.brokerNames, ServerName(cfg.Cell, id))
		}
		go r.server.Start()
		if !serverReady(ctx, r.server) {
			return nil, errors.New("embedded NATS did not become ready")
		}
		cfg.URL = r.server.ClientURL()
		if !cfg.Lab {
			r.resolver = options.AccountResolver.(*accountResolver)
			r.operator = options.TrustedOperators[0]
			if _, err := r.server.LookupAccount(r.resolver.cell); err != nil {
				return nil, fmt.Errorf("load regional cell account: %w", err)
			}
		}
	}
	options, err := clientOptions(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Embedded != nil && !cfg.Lab {
		options = append(options, nats.InProcessServer(r.server))
	}
	if cfg.ClientRole == "host" {
		// A blackholed peer must be detected well inside the host's 25-second
		// execution window. nats.go otherwise waits two minutes between PINGs.
		options = append(options,
			nats.PingInterval(2*time.Second), nats.MaxPingsOutstanding(2),
			nats.ReconnectWait(500*time.Millisecond),
			nats.DisconnectErrHandler(func(conn *nats.Conn, cause error) {
				r.logHostConnection("disconnected", conn, cause)
			}),
			nats.ReconnectHandler(func(conn *nats.Conn) {
				r.logHostConnection("reconnected", conn, nil)
			}),
		)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connected := make(chan struct{})
	var connectErr error
	go func() {
		connectURL := cfg.URL
		if !cfg.Lab && cfg.Embedded == nil {
			if len(cfg.OperatorForward) != 0 {
				selected, _, forwardErr := operatorForwarding(cfg)
				if forwardErr != nil {
					connectErr = forwardErr
					close(connected)
					return
				}
				connectURL = selected
			}
			connectURL = bridgeClientURLs(connectURL)
		}
		r.conn, connectErr = nats.Connect(connectURL, options...)
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
	if cfg.Embedded != nil && !cfg.Lab {
		systemCfg := cfg
		systemCfg.NKeySeedFile = ""
		systemCfg.CredentialsFile = cfg.Embedded.SystemCredentialsFile
		systemOptions, optionErr := clientOptions(systemCfg)
		if optionErr != nil {
			return nil, fmt.Errorf("system account client: %w", optionErr)
		}
		systemOptions = append(systemOptions, nats.InProcessServer(r.server))
		r.systemConn, err = nats.Connect(cfg.URL, systemOptions...)
		if err != nil {
			return nil, fmt.Errorf("connect internal system account: %w", err)
		}
		bridgeTLS, tlsErr := loadTLS(cfg.Embedded.TLS, true)
		if tlsErr != nil {
			return nil, tlsErr
		}
		r.bridge, err = startBridge(r.server, net.JoinHostPort(cfg.Embedded.Host, fmt.Sprint(cfg.Embedded.Port)), bridgeTLS, r.resolver.cell)
		if err != nil {
			return nil, err
		}
	}
	if cfg.ClientRole == "host" {
		r.logHostConnection("connected", r.conn, nil)
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
// It returns ErrEmbeddedServerStopped as soon as the embedded broker exits.
func (r *Runtime) WaitForCluster(ctx context.Context, replicas int) error {
	if replicas < 1 || replicas > 5 || replicas%2 == 0 {
		return errors.New("regional replicas must be 1, 3, or 5")
	}
	quorum := replicas/2 + 1
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.server != nil && !r.server.Running() {
			return ErrEmbeddedServerStopped
		}
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
	if len(cfg.OperatorForward) != 0 {
		if _, _, err := operatorForwarding(cfg); err != nil {
			return err
		}
	}
	if !cellName.MatchString(cfg.Cell) || !cellName.MatchString(cfg.Instance) {
		return errors.New("cell and instance must be lowercase NATS tokens")
	}
	// Every protocol subject builder refuses the reserved scope as a cell
	// and returns "", which would surface far from here as empty grants.
	if cfg.Cell == protocol.GlobalScope {
		return errors.New("cell name is reserved for the global scope")
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
		if !cfg.TLS.complete() || cfg.CredentialsFile == "" || cfg.NKeySeedFile != "" {
			return errors.New("production regional NATS requires client TLS and NKey/JWT credentials")
		}
		if cfg.Embedded != nil && (!cfg.Embedded.TLS.complete() || !cfg.Embedded.RouteTLS.complete() ||
			cfg.Embedded.OperatorJWTFile == "" || cfg.Embedded.SystemJWTFile == "" ||
			cfg.Embedded.CellJWTFile == "" || cfg.Embedded.SystemCredentialsFile == "" ||
			cfg.Embedded.TicketPublicKeyFile == "" || len(cfg.Embedded.BrokerIDs) != cfg.Replicas || len(cfg.Embedded.Users) != 0) {
			return errors.New("production embedded NATS requires operator/system/cell JWTs, system credentials, and client/route TLS")
		}
	}
	if cfg.Embedded != nil {
		e := cfg.Embedded
		if err := e.InterRegion.validate(cfg); err != nil {
			return err
		}
		if !cfg.Lab {
			seen := make(map[string]struct{}, len(e.BrokerIDs))
			for _, id := range e.BrokerIDs {
				if !cellName.MatchString(id) {
					return errors.New("production broker ID is invalid")
				}
				if _, exists := seen[id]; exists {
					return errors.New("production broker IDs must be unique")
				}
				seen[id] = struct{}{}
			}
			if _, own := seen[cfg.Instance]; !own {
				return errors.New("production broker ID list excludes this instance")
			}
		}
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
		ServerName:        ServerName(cfg.Cell, cfg.Instance),
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
		LameDuckDuration:    lameDuckDuration,
		LameDuckGracePeriod: lameDuckGracePeriod,
	}
	if !cfg.Lab {
		operator, systemJWT, cellJWT, systemID, cellID, err := loadOperatorAccounts(e)
		if err != nil {
			return nil, err
		}
		if err := validateSystemCredentials(e.SystemCredentialsFile, cfg.Cell, cellID, systemID); err != nil {
			return nil, err
		}
		controller, _, err := credentialUser(cfg.CredentialsFile)
		if err != nil || credentialAccount(controller) != cellID {
			return nil, errors.New("controller credentials do not belong to the regional cell account")
		}
		resolver := newAccountResolver(systemID, systemJWT, cellID, cellJWT)
		options.TrustedOperators = []*jwt.OperatorClaims{operator}
		options.SystemAccount = systemID
		options.Accounts = nil
		options.AccountResolver = resolver
		options.DontListen = true
		options.Cluster.NoAdvertise = true
		if e.InterRegion.active() {
			if err := interRegionServerOptions(cfg, options, resolver, operator); err != nil {
				return nil, err
			}
		}
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
	if cfg.Lab && e.TLS.complete() {
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
	connectTimeout := 12 * time.Second
	if cfg.ClientRole == "host" {
		connectTimeout = 3 * time.Second
	}
	options := []nats.Option{nats.Name("terrascale-" + cfg.Cell + "-" + cfg.Instance), nats.Timeout(connectTimeout)}
	var materials *clientMaterialSource
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
		source := newClientMaterialSource(cfg, public)
		// The JWT and its signature come from one resolved file per handshake.
		var handshake ClientMaterial
		options = append(options, nats.UserJWT(func() (string, error) {
			handshake = source.current()
			data, err := readPrivateFile(handshake.CredentialsFile, 64<<10)
			if err != nil {
				return "", err
			}
			defer clear(data)
			return nkeys.ParseDecoratedJWT(data)
		}, func(nonce []byte) ([]byte, error) {
			path := handshake.CredentialsFile
			if path == "" {
				path = cfg.CredentialsFile
			}
			return signNKeyFile(path, nonce)
		}))
		materials = source
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
	if cfg.TLS.complete() && (cfg.Embedded == nil || cfg.Lab) {
		tlsConfig, err := loadTLS(cfg.TLS, false)
		if err != nil {
			return nil, err
		}
		if cfg.Lab {
			options = append(options, nats.Secure(tlsConfig))
		} else {
			dialer := &tlsFirstDialer{config: tlsConfig, timeout: connectTimeout}
			if materials != nil && cfg.ReloadClientMaterial != nil {
				dialer.reload = materials.tlsConfig
			}
			if len(cfg.OperatorForward) != 0 {
				_, destinations, err := operatorForwarding(cfg)
				if err != nil {
					return nil, err
				}
				dialer.forward = destinations
				options = append(options, nats.IgnoreDiscoveredServers())
			}
			options = append(options, nats.SetCustomDialer(dialer))
		}
	}
	return options, nil
}

func inboxPrefix(cell, publicKey string) string {
	return protocol.InboxPrefix(cell, publicKey)
}

func userPermissions(cell string, user NKeyGrant) (*server.Permissions, error) {
	inbox := inboxPrefix(cell, user.PublicKey) + ".>"
	permissions := &server.Permissions{Subscribe: &server.SubjectPermission{Allow: []string{inbox}}}
	if user.Global && user.Role != "controller" {
		return nil, errors.New("only a controller NATS user may carry global home grants")
	}
	switch user.Role {
	case "host":
		if !cellName.MatchString(user.Node) {
			return nil, errors.New("host NATS user needs a valid node identity")
		}
		permissions.Publish = &server.SubjectPermission{Allow: []string{
			protocol.AgentObservation(cell, user.PublicKey, "*"),
		}}
	case "controller":
		if user.Node != "" {
			return nil, errors.New("controller NATS user must not carry a host node")
		}
		permissions.Publish = &server.SubjectPermission{Allow: []string{
			protocol.Regional(cell, ">"), protocol.Control(cell, ">"), "$JS.API.>", "$KV.>", "$O.>",
			"$JS.ACK.TS_DELIVERY_INTENTS.TS_DELIVERY_WORKER.>",
		}}
		if user.Global {
			permissions.Publish.Allow = append(permissions.Publish.Allow, GlobalControllerPublishes()...)
		}
		permissions.Subscribe.Allow = append(permissions.Subscribe.Allow,
			ControllerSubscriptions(cell)...)
		// Read-only member telemetry: every controller answers observability
		// snapshot requests for its cell.
		permissions.Subscribe.Allow = append(permissions.Subscribe.Allow, protocol.ObservabilityGrant(cell))
	case "operator":
		if user.Node != "" {
			return nil, errors.New("operator NATS user must not carry a host node")
		}
		permissions.Publish = &server.SubjectPermission{Allow: []string(BrokerOperatorPublishPermissions(cell))}
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
	if r.bridge != nil {
		return r.bridge.Addr()
	}
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
