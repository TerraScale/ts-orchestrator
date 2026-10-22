// Package mesh joins every ordered region's single host into one NATS
// supercluster and keeps the global service desired state on it.
//
// Each region is its own one-server NATS cluster named by its region token;
// full-mesh gateways on 7222 link the regions, so any two keep talking while
// a third is down. A node dials the founded regions as seeds; gateway gossip
// announces any other region that dials one of them, so a new region joins
// without a release. Gateways accept only peers holding a leaf of the mesh
// CA, which every node derives from one shared OCI Vault secret. The only client
// listener is loopback: the root CLI and the node itself connect with a
// token the node writes at start. (:4222 is the release listener, internal/releasepush.)
//
// Desired state is a last-writer-wins map of service name to generation and
// spec (nil once removed), persisted in <state>/mesh/desired.json. A node
// merges every apply it receives and every peer map it pulls on start and
// every 30 s, then reconciles its local services, so a region that was down
// converges without operator action.
package mesh

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const (
	ApplySubject = protocol.MeshApplySubject
	StateSubject = protocol.MeshStateSubject
	PingSubject  = protocol.MeshPingSubject

	// GatewayPort links regions; every node dials <region>.Domain on it.
	GatewayPort = 7222
	// LocalPort is the loopback client listener of the root CLI.
	LocalPort = 4223
	Domain    = "mesh.terrascale.tech"

	antiEntropyEvery = 30 * time.Second
	// applyWait bounds one apply: the CLI waits this long for every region,
	// and a node replies a little earlier so its reply still arrives.
	applyWait = 120 * time.Second
	stateWait = 3 * time.Second
	maxWire   = 1 << 20
)

var serviceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Regions is the seed list every node dials; gossip adds the other regions.
func Regions() []string {
	names := []string{}
	for _, entry := range catalog.Founded() {
		names = append(names, entry.Name())
	}
	return names
}

// Entry is one service's desired state; Spec is nil once it is removed.
type Entry struct {
	Generation int64                     `json:"generation"`
	Spec       *swarmruntime.ServiceSpec `json:"spec"`
}

// ApplyRequest is the ts.svc.apply payload.
type ApplyRequest struct {
	Name  string `json:"name"`
	Entry Entry  `json:"entry"`
}

// Reply answers ts.svc.apply and ts.mesh.ping.
type Reply struct {
	Region string `json:"region"`
	Server string `json:"server"`
	// Address is the replying node's NetBird IPv4 (ping only).
	Address   string `json:"address,omitempty"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	// Phases is this region's elapsed time to each rollout phase.
	Phases string `json:"phases,omitempty"`
	// Regions is every region the replying node reaches, so a caller also
	// waits for regions that joined after its own node's seeds.
	Regions []string `json:"regions,omitempty"`
}

type stateReply struct {
	Region  string           `json:"region"`
	Desired map[string]Entry `json:"desired"`
}

// Applier changes this host's services.
type Applier interface {
	// Apply makes spec run, stamped with spec.Generation; false when it already did.
	Apply(ctx context.Context, spec swarmruntime.ServiceSpec) (bool, error)
	// Remove deletes name; false when it was absent.
	Remove(ctx context.Context, name string) (bool, error)
	// PrePull fetches image before Apply, outside the mesh lock, so a
	// replacement only creates and starts its container.
	PrePull(ctx context.Context, spec swarmruntime.ServiceSpec) error
	// Wait returns once every replica of spec runs it (and answers its ready
	// path when the spec names one).
	Wait(ctx context.Context, spec swarmruntime.ServiceSpec) (swarmruntime.ServiceRollout, error)
}

type config struct {
	region, server, dir, host string
	advertise                 string // host:port peers dial for this region's gateway
	gatewayPort, localPort    int
	gateways                  map[string]string // region -> gateway URL
	clusterHost               string            // "" runs no in-region cluster listener
	clusterPort               int
	routes                    []string // in-region route URLs to dial
	ca                        *CA
	applier                   Applier // nil on a worker, which serves no region requests
	every                     time.Duration
	peersDir                  string // host root of every service's peers file
	peersEvery                time.Duration
	address                   func() (string, error) // this node's NetBird IPv4
}

// Node is one region's running mesh server.
type Node struct {
	cfg    config
	tls    *tls.Config
	server *server.Server
	conn   *nats.Conn
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	desired map[string]Entry
	peers   *peers
}

func start(cfg config) (_ *Node, err error) {
	if err := os.MkdirAll(cfg.dir, 0o700); err != nil {
		return nil, err
	}
	desired, err := loadDesired(cfg.dir)
	if err != nil {
		return nil, err
	}
	secret, err := clientToken(cfg.dir)
	if err != nil {
		return nil, err
	}
	tlsConfig := cfg.ca.TLS(cfg.region + "." + Domain)
	options := &server.Options{
		ServerName: cfg.server, Host: "127.0.0.1", Port: cfg.localPort, Authorization: secret,
		NoSigs: true, MaxPayload: maxWire,
		Gateway: server.GatewayOpts{
			Name: cfg.region, Host: cfg.host, Port: cfg.gatewayPort, Advertise: cfg.advertise,
			TLSConfig: tlsConfig, TLSTimeout: 5,
		},
	}
	for _, region := range slices.Sorted(maps.Keys(cfg.gateways)) {
		address, err := url.Parse(cfg.gateways[region])
		if err != nil {
			return nil, err
		}
		options.Gateway.Gateways = append(options.Gateway.Gateways,
			&server.RemoteGatewayOpts{Name: region, URLs: []*url.URL{address}, TLSConfig: tlsConfig, TLSTimeout: 5})
	}
	if cfg.clusterHost != "" {
		// The region's servers form one NATS cluster with the same mesh mTLS.
		options.Cluster = server.ClusterOpts{Name: cfg.region, Host: cfg.clusterHost, Port: cfg.clusterPort, TLSConfig: tlsConfig, TLSTimeout: 5}
		for _, route := range cfg.routes {
			address, err := url.Parse(route)
			if err != nil {
				return nil, err
			}
			options.Routes = append(options.Routes, address)
		}
	}
	embedded, err := server.NewServer(options)
	if err != nil {
		return nil, err
	}
	embedded.ConfigureLogger()
	go embedded.Start()
	defer func() {
		if err != nil {
			embedded.Shutdown()
			embedded.WaitForShutdown()
		}
	}()
	if !embedded.ReadyForConnections(10 * time.Second) {
		return nil, errors.New("mesh NATS server did not start listening")
	}
	conn, err := dialLocal(cfg.localPort, secret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	node := &Node{cfg: cfg, tls: tlsConfig, server: embedded, conn: conn, ctx: ctx, cancel: cancel, desired: desired,
		peers: &peers{root: cfg.peersDir, region: cfg.region, node: cfg.server, address: cfg.address}}
	handlers := map[string]nats.MsgHandler{
		PingSubject: func(m *nats.Msg) {
			address, _ := cfg.address() // a node without NetBird still answers; peers skip it
			node.respond(m, Reply{Region: cfg.region, Server: cfg.server, Regions: node.regions(), Address: address})
		},
		StateSubject: func(m *nats.Msg) {
			node.mu.Lock()
			state := stateReply{Region: cfg.region, Desired: maps.Clone(node.desired)}
			node.mu.Unlock()
			node.respond(m, state)
		},
		// An apply waits for its tasks to run, so it must not hold up the next message.
		ApplySubject: func(m *nats.Msg) { go node.handleApply(m) },
	}
	if cfg.applier == nil {
		handlers = nil // the region's founder answers; a worker only carries messages
	}
	for subject, handler := range handlers {
		if _, err := conn.Subscribe(subject, handler); err != nil {
			conn.Close()
			cancel()
			return nil, err
		}
	}
	if err := conn.Flush(); err != nil {
		conn.Close()
		cancel()
		return nil, err
	}
	return node, nil
}

// Region is the region this node serves.
func (n *Node) Region() string { return n.cfg.region }

// TLS is the mesh mTLS config for both ends of a connection: it presents
// this node's leaf and accepts only peers the mesh CA signed.
func (n *Node) TLS() *tls.Config { return n.tls }

// RTT is the measured round trip to every region with a live outbound gateway.
func (n *Node) RTT() map[string]time.Duration {
	rtt := map[string]time.Duration{}
	gateways, err := n.server.Gatewayz(nil)
	if err != nil {
		return rtt
	}
	for region, gateway := range gateways.OutboundGateways {
		if gateway.Connection == nil {
			continue
		}
		if d, err := time.ParseDuration(gateway.Connection.RTT); err == nil && d > 0 {
			rtt[region] = d
		}
	}
	return rtt
}

func dialLocal(port int, token string) (*nats.Conn, error) {
	return nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", port), nats.Token(token),
		nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
}

// Close stops the server; desired state stays on disk.
func (n *Node) Close() {
	n.cancel()
	n.conn.Close()
	n.server.Shutdown()
	n.server.WaitForShutdown()
}

// regions is this region, its seeds and every region its gateways reach now.
func (n *Node) regions() []string {
	names := append([]string{n.cfg.region}, slices.Collect(maps.Keys(n.cfg.gateways))...)
	if gateways, err := n.server.Gatewayz(nil); err == nil {
		names = slices.AppendSeq(names, maps.Keys(gateways.OutboundGateways))
		names = slices.AppendSeq(names, maps.Keys(gateways.InboundGateways))
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// run pulls peer state now and every cfg.every until ctx ends.
func (n *Node) run(ctx context.Context) {
	go n.watchPeers(ctx)
	tick := time.NewTicker(n.cfg.every)
	defer tick.Stop()
	for {
		if n.cfg.applier != nil {
			n.sync(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// sync merges every replying peer's map, newest generation per name, then
// reconciles every entry so a missed or failed apply is retried.
func (n *Node) sync(ctx context.Context) {
	peers := map[string]map[string]Entry{}
	_ = collect(ctx, n.conn, StateSubject, nil, len(n.regions()), stateWait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			peers[reply.Region] = reply.Desired
		}
		return true
	})
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := false
	for _, desired := range peers {
		for name, entry := range desired {
			if validEntry(name, entry) == nil && entry.Generation > n.desired[name].Generation {
				n.desired[name] = entry
				changed = true
			}
		}
	}
	if changed {
		if err := saveDesired(n.cfg.dir, n.desired); err != nil {
			slog.WarnContext(ctx, "mesh desired state save failed", "error", err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(n.desired)) {
		if _, err := n.reconcile(ctx, name, n.desired[name]); err != nil {
			slog.WarnContext(ctx, "mesh reconcile failed", "service", name, "error", err)
		}
	}
}

func (n *Node) handleApply(m *nats.Msg) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(n.ctx, applyWait-10*time.Second)
	defer cancel()
	reply := Reply{Region: n.cfg.region, Server: n.cfg.server, Regions: n.regions()}
	var request ApplyRequest
	result, err := "", protocol.DecodeTolerant(m.Data, &request, maxWire)
	var pulled time.Duration
	if spec := request.Entry.Spec; err == nil && spec != nil && (len(spec.Regions) == 0 || slices.Contains(spec.Regions, n.cfg.region)) {
		// The task's own Prepare still pulls, so a failed pre-pull only costs speed.
		if pullErr := n.cfg.applier.PrePull(ctx, *spec); pullErr != nil {
			slog.WarnContext(ctx, "mesh pre-pull failed; the task pulls instead", "service", request.Name, "error", pullErr)
		}
		pulled = time.Since(start)
	}
	if err == nil {
		result, err = n.apply(ctx, request)
	}
	if err == nil && (result == "applied" || result == "unchanged") {
		submitted := time.Since(start)
		var rollout swarmruntime.ServiceRollout
		if rollout, err = n.cfg.applier.Wait(ctx, *request.Entry.Spec); err == nil {
			reply.Phases = fmt.Sprintf("pulled %dms, submitted %dms, running %dms", pulled.Milliseconds(), submitted.Milliseconds(), (submitted + rollout.Running).Milliseconds())
			if rollout.Ready != 0 {
				reply.Phases += fmt.Sprintf(", ready %dms", (submitted + rollout.Ready).Milliseconds())
			}
		}
	}
	reply.Result, reply.ElapsedMS = result, time.Since(start).Milliseconds()
	if err != nil {
		reply.Error = err.Error()
	}
	n.respond(m, reply)
}

func (n *Node) apply(ctx context.Context, request ApplyRequest) (string, error) {
	if err := validEntry(request.Name, request.Entry); err != nil {
		return "", err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	current := n.desired[request.Name]
	if current.Generation > request.Entry.Generation {
		return "", fmt.Errorf("superseded by generation %d", current.Generation)
	}
	if current.Generation < request.Entry.Generation {
		n.desired[request.Name] = request.Entry
		if err := saveDesired(n.cfg.dir, n.desired); err != nil {
			return "", err
		}
	}
	return n.reconcile(ctx, request.Name, n.desired[request.Name])
}

// reconcile makes the local service match entry; the caller holds n.mu.
func (n *Node) reconcile(ctx context.Context, name string, entry Entry) (string, error) {
	if entry.Spec == nil || len(entry.Spec.Regions) != 0 && !slices.Contains(entry.Spec.Regions, n.cfg.region) {
		if _, err := n.cfg.applier.Remove(ctx, name); err != nil {
			return "", err
		}
		if err := n.peers.untrack(name); err != nil {
			return "", err
		}
		if entry.Spec == nil {
			return "removed", nil
		}
		return "skipped-not-targeted", nil
	}
	spec := *entry.Spec
	spec.Generation, spec.Region, spec.Node = entry.Generation, n.cfg.region, n.cfg.server
	if err := n.peers.track(name, spec.Regions); err != nil {
		return "", err
	}
	changed, err := n.cfg.applier.Apply(ctx, spec)
	if err != nil {
		return "", err
	}
	if changed {
		return "applied", nil
	}
	return "unchanged", nil
}

func (n *Node) respond(m *nats.Msg, value any) {
	data, err := protocol.EncodeJSON(value)
	if err == nil {
		err = m.Respond(data)
	}
	if err != nil {
		slog.Warn("mesh reply failed", "subject", m.Subject, "error", err)
	}
}

func validEntry(name string, entry Entry) error {
	if !serviceName.MatchString(name) || entry.Generation <= 0 {
		return errors.New("invalid service name or generation")
	}
	if entry.Spec == nil {
		return nil
	}
	if entry.Spec.Name != name {
		return errors.New("spec name differs from the entry name")
	}
	for _, region := range entry.Spec.Regions {
		// Any catalog region may join; spending approval gates instance creation, not this.
		if _, ok := catalog.LookupName(region); !ok {
			return fmt.Errorf("unknown region %q", region)
		}
	}
	_, err := entry.Spec.SwarmSpec()
	return err
}

// collect publishes a request and hands each reply to each until want
// replies arrived, each returns false, or wait elapses.
func collect(ctx context.Context, conn *nats.Conn, subject string, payload []byte, want int, wait time.Duration, each func([]byte) bool) error {
	inbox := conn.NewRespInbox()
	replies := make(chan *nats.Msg, 64)
	sub, err := conn.ChanSubscribe(inbox, replies)
	if err != nil {
		return err
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := conn.PublishRequest(subject, inbox, payload); err != nil {
		return err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for got := 0; got < want; got++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case m := <-replies:
			if !each(m.Data) {
				return nil
			}
		}
	}
	return nil
}

func loadDesired(dir string) (map[string]Entry, error) {
	data, err := os.ReadFile(filepath.Join(dir, "desired.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	desired := map[string]Entry{}
	if err := protocol.DecodeTolerant(data, &desired, maxWire); err != nil {
		return nil, fmt.Errorf("decode mesh desired state: %w", err)
	}
	return desired, nil
}

func saveDesired(dir string, desired map[string]Entry) error {
	data, err := protocol.EncodeJSON(desired)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "desired.json"), data)
}

// writePrivate replaces path atomically with an owner-only file.
// clientToken keeps the root CLI's token across restarts, so a CLI that read
// it before ts-orch restarted still authenticates afterwards.
func clientToken(dir string) (string, error) {
	path := filepath.Join(dir, "client.token")
	if data, err := os.ReadFile(path); err == nil {
		if token := strings.TrimSpace(string(data)); len(token) == 64 {
			if _, err := hex.DecodeString(token); err == nil {
				return token, nil
			}
		}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(token)
	return secret, writePrivate(path, []byte(secret))
}

func writePrivate(path string, data []byte) error {
	temp := path + ".tmp" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}
