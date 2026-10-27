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
// Desired state retains operator and signed candidates per service (nil specs
// are removals), persisted in <state>/mesh/desired.json. A node
// merges every apply it receives and every peer map it pulls on start and
// every 30 s, then reconciles its local services, so a region that was down
// converges without operator action. Rollback retains its failed generation's
// ordering position so it cannot supersede an intervening apply during sync.
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
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
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
	Deployment *Deployment               `json:"deployment,omitempty"`
	RollbackOf int64                     `json:"rollbackOf,omitzero"`
	// HoldAfter stops the rollout after this region (a canary): later regions
	// keep the previous generation until `service resume` applies it without one.
	HoldAfter string `json:"holdAfter,omitempty"`
}

// supersedes orders rollback after its failed rollout, before any later apply.
func (entry Entry) supersedes(current Entry) bool {
	return swarmruntime.ServiceGenerationAfter(entry.Generation, entry.RollbackOf, current.Generation, current.RollbackOf)
}

// ApplyRequest is the ts.svc.apply payload.
type ApplyRequest struct {
	Name               string `json:"name"`
	Entry              Entry  `json:"entry"`
	ExpectedGeneration int64  `json:"expectedGeneration,omitempty"`
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
	Phases   string                             `json:"phases,omitempty"`
	Service  string                             `json:"service,omitempty"`
	Image    string                             `json:"image,omitempty"`
	Revision string                             `json:"revision,omitempty"`
	Tasks    []swarmruntime.ServiceTaskEvidence `json:"tasks,omitempty"`
	Bake     *rollout.BakeVerdict               `json:"bake,omitempty"`
	// Regions is every region the replying node reaches, so a caller also
	// waits for regions that joined after its own node's seeds.
	Regions      []string                   `json:"regions,omitempty"`
	Attestations map[string]PeerAttestation `json:"attestations,omitempty"`
}

type stateReply struct {
	Region  string                  `json:"region"`
	Desired map[string]desiredState `json:"desired"`
	// Ready is the generation each local service runs with every replica ready.
	Ready map[string]int64 `json:"ready,omitempty"`
	// Failed is the generation of each service whose rollout here failed.
	Failed map[string]int64 `json:"failed,omitempty"`
}

// Applier changes this host's services.
type Applier interface {
	// Apply returns the original service snapshot for this operation; false when unchanged.
	Apply(ctx context.Context, spec swarmruntime.ServiceSpec) (bool, *api.Service, error)
	// Remove deletes name; false when it was absent.
	Remove(ctx context.Context, name string) (bool, error)
	// PrePull fetches image before Apply, outside the mesh lock, so a
	// replacement only creates and starts its container.
	PrePull(ctx context.Context, spec swarmruntime.ServiceSpec) error
	// Wait returns once every replica of spec runs it (and answers its ready
	// path when the spec names one), using the snapshot returned by Apply.
	Wait(ctx context.Context, spec swarmruntime.ServiceSpec, original *api.Service) (swarmruntime.ServiceRollout, error)
	Bake(context.Context, swarmruntime.ServiceSpec, swarmruntime.ServiceRollout) (rollout.BakeVerdict, error)
	// Ready returns the generation of each service whose up-to-date replicas all run.
	Ready(ctx context.Context) (map[string]int64, error)
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
	// work is every goroutine that writes the node's directory; Close waits for it.
	work sync.WaitGroup

	mu              sync.Mutex
	desired         map[string]desiredState
	failed          map[string]int64 // generation whose local rollout failed, per service
	baking          map[string]chan struct{}
	bakeUnsaved     map[string]bakeRecord
	peers           *peers
	peerReports     map[string]map[string]PeerAttestation
	peerReportMu    sync.Mutex
	topologyDesired atomic.Pointer[map[string]Entry]
}

func start(cfg config) (_ *Node, err error) {
	if cfg.peersEvery <= 0 {
		cfg.peersEvery = peersEvery
	}
	if err := os.MkdirAll(cfg.dir, 0o700); err != nil {
		return nil, err
	}
	desired, err := loadDesired(cfg.dir)
	if err != nil {
		return nil, err
	}
	peerFiles, err := newPeers(cfg)
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
		peers: peerFiles}
	node.publishTopologyDesired()
	handlers := map[string]nats.MsgHandler{
		PingSubject: func(m *nats.Msg) {
			var address string // a node without NetBird (or a worker) still answers; peers skip it
			if cfg.address != nil {
				address, _ = cfg.address()
			}
			node.respond(m, Reply{Region: cfg.region, Server: cfg.server, Regions: node.regions(), Address: address, Attestations: node.localAttestations()})
		},
		StateSubject: func(m *nats.Msg) {
			ready, err := cfg.applier.Ready(node.ctx)
			if err != nil {
				slog.Warn("mesh ready state unavailable", "error", err)
			}
			node.mu.Lock()
			state := stateReply{Region: cfg.region, Desired: maps.Clone(node.desired), Ready: ready, Failed: maps.Clone(node.failed)}
			node.bakeState(&state)
			node.mu.Unlock()
			node.respond(m, state)
		},
		// An apply waits for its tasks to run, so it must not hold up the next message.
		ApplySubject: func(m *nats.Msg) { node.work.Go(func() { node.handleApply(m) }) },
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
	node.work.Go(func() { node.watchPeers(ctx) })
	return node, nil
}

// Region is the region this node serves.
func (n *Node) Region() string { return n.cfg.region }

// TLS is the mesh mTLS config for both ends of a connection: it presents
// this node's leaf and accepts only peers the mesh CA signed.
func (n *Node) TLS() *tls.Config { return n.tls }

// AdmittedRegions includes durable admitted peers through outages and restarts,
// plus gateways discovered since the last admission round. Reachability never
// removes an admitted region from a cancellation ownership lookup.
func (n *Node) AdmittedRegions() []string {
	n.peers.mu.Lock()
	names := slices.Clone(n.peers.regions)
	n.peers.mu.Unlock()
	names = append(names, n.regions()...)
	slices.Sort(names)
	return slices.Compact(names)
}

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
	n.work.Wait()
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

// sync merges every replying peer's candidates and floor per name, then
// reconciles every entry so a missed or failed apply is retried.
func (n *Node) sync(ctx context.Context) {
	states := n.states(ctx)
	peers := map[string]map[string]desiredState{}
	for region, reply := range states {
		peers[region] = reply.Desired
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	before := maps.Clone(n.desired)
	changed := false
	for _, desired := range peers {
		for name, entry := range desired {
			if validState(name, entry) == nil {
				current := n.desired[name]
				merged, err := mergeState(current, entry)
				if err != nil {
					slog.WarnContext(ctx, "mesh desired state conflicts", "service", name, "error", err)
					continue
				}
				if !reflect.DeepEqual(merged, current) {
					n.desired[name] = merged
					changed = true
				}
			}
		}
	}
	if changed {
		if err := saveDesired(n.cfg.dir, n.desired); err != nil {
			slog.WarnContext(ctx, "mesh desired state save failed", "error", err)
			n.desired = before
			return
		}
	}
	n.publishTopologyDesired()
	for _, name := range slices.Sorted(maps.Keys(n.desired)) {
		// The peers file follows desired state even while the rollout waits (a
		// held canary or an earlier region's turn): a restart must re-render it.
		if entry := n.desired[name].entry(); entry.Spec != nil && (len(entry.Spec.Regions) == 0 || slices.Contains(entry.Spec.Regions, n.cfg.region)) {
			if err := n.peers.track(name, entry.Spec.Regions); err != nil {
				slog.WarnContext(ctx, "mesh peers file track failed", "service", name, "error", err)
			}
		}
		if key := n.bakePath(name, n.desired[name].entry().Generation); n.bakeUnsaved[key].Generation != 0 {
			if err := n.saveBake(key, n.bakeUnsaved[key]); err != nil {
				slog.WarnContext(ctx, "mesh bake evidence persistence failed", "service", name, "error", err)
			}
			continue
		}
		if entry := n.desired[name].entry(); n.held(entry) || entry.RollbackOf == 0 && n.turn(name, entry.Spec, entry.Generation, states) != nil {
			continue // an earlier region still rolls this generation out
		}
		if record, err := n.readBake(name, n.desired[name].entry().Generation); err == nil && record.Bake.Reason != "" {
			continue // failed bakes remain held even after restart
		}
		if applied, err := n.reconcile(ctx, name, n.desired[name]); err != nil {
			slog.WarnContext(ctx, "mesh reconcile failed", "service", name, "error", err)
		} else if applied.result == "applied" || applied.result == "unchanged" {
			n.work.Go(func() { _, _ = n.evaluate(n.ctx, applied) })
		}
	}
}

func (n *Node) handleApply(m *nats.Msg) {
	start := time.Now()
	var request ApplyRequest
	err := protocol.DecodeTolerant(m.Data, &request, maxWire)
	ctx, cancel := context.WithTimeout(n.ctx, n.applyWindow(request.Entry.Spec))
	defer cancel()
	reply := Reply{Region: n.cfg.region, Server: n.cfg.server, Regions: n.regions()}
	var applied applyResult
	var pulled time.Duration
	if spec := request.Entry.Spec; err == nil && spec != nil && (len(spec.Regions) == 0 || slices.Contains(spec.Regions, n.cfg.region)) {
		// The task's own Prepare still pulls, so a failed pre-pull only costs speed.
		if pullErr := n.cfg.applier.PrePull(ctx, *spec); pullErr != nil {
			slog.WarnContext(ctx, "mesh pre-pull failed; the task pulls instead", "service", request.Name, "error", pullErr)
		}
		pulled = time.Since(start)
	}
	if err == nil && n.held(request.Entry) {
		// A canary hold: this region keeps the previous generation and answers without applying.
		reply.Result, reply.ElapsedMS = "held after "+request.Entry.HoldAfter, time.Since(start).Milliseconds()
		n.respond(m, reply)
		return
	}
	// A rollback restores the serving release in every region at once.
	if err == nil {
		err = validEntry(request.Name, request.Entry)
	}
	if err == nil && request.ExpectedGeneration == 0 && request.Entry.RollbackOf == 0 {
		err = n.awaitTurn(ctx, request.Name, request.Entry.Spec, request.Entry.Generation)
	}
	if err == nil {
		err = n.awaitPeerAdmission(ctx, request.Entry.Spec)
	}
	if err == nil {
		applied, err = n.apply(ctx, request)
	}
	if err == nil && (applied.result == "applied" || applied.result == "unchanged") {
		submitted := time.Since(start)
		spec := applied.spec
		verdict, bakeErr := n.evaluate(ctx, applied)
		err = bakeErr
		reply.Service, reply.Image, reply.Tasks, reply.Revision = spec.Name, spec.Image, verdict.Rollout.Tasks, verdict.Rollout.Revision
		reply.Bake = &verdict.Bake
		reply.Phases = fmt.Sprintf("pulled %dms, submitted %dms, ready %dms", pulled.Milliseconds(), submitted.Milliseconds(), (submitted + time.Duration(verdict.Rollout.Ready)).Milliseconds())
		if !verdict.Bake.Started.IsZero() {
			reply.Phases += fmt.Sprintf(", bake %s (%d samples)", verdict.Bake.Finished.Sub(verdict.Bake.Started), verdict.Bake.Samples)
		}
	}
	reply.Result, reply.ElapsedMS = applied.result, time.Since(start).Milliseconds()
	if err != nil {
		reply.Error = err.Error()
	}
	if applied.result == "applied" || applied.result == "unchanged" {
		// Later regions stop waiting for a generation that failed here.
		n.mu.Lock()
		if n.failed == nil {
			n.failed = map[string]int64{}
		}
		if err != nil {
			n.failed[request.Name] = request.Entry.Generation
		} else {
			delete(n.failed, request.Name)
		}
		n.mu.Unlock()
	}
	n.respond(m, reply)
}

// states is every replying region's state.
func (n *Node) states(ctx context.Context) map[string]stateReply {
	return n.statesOf(ctx, nil, stateWait)
}

// statesOf collects replies until every region in want answered (nil: all
// known regions) or wait elapses.
func (n *Node) statesOf(ctx context.Context, want []string, wait time.Duration) map[string]stateReply {
	states := map[string]stateReply{}
	count := len(n.regions())
	if want != nil {
		count = math.MaxInt
	}
	_ = collect(ctx, n.conn, StateSubject, nil, count, wait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			states[reply.Region] = reply
		}
		return want == nil || slices.ContainsFunc(want, func(region string) bool { _, ok := states[region]; return !ok })
	})
	return states
}

// rolloutOrder is the order a rollout replaces regions in, one at a time, so
// the edge always has a serving region to hand off to (TerraBase is replaced
// stop-first: one writer per data dir). A spec's regions roll in the order it
// lists them; a spec for every region rolls the founded regions with the first
// (gru: ts-auth and the dashboard) last.
func rolloutOrder(spec *swarmruntime.ServiceSpec) []string {
	if len(spec.Regions) != 0 {
		return spec.Regions
	}
	founded := Regions()
	if len(founded) == 0 {
		return nil
	}
	return append(slices.Clone(founded[1:]), founded[0])
}

// earlier is the target regions of spec rolled before this one.
func (n *Node) earlier(spec *swarmruntime.ServiceSpec) []string {
	if spec == nil {
		return nil
	}
	order := rolloutOrder(spec)
	if i := slices.Index(order, n.cfg.region); i > 0 {
		return slices.Clone(order[:i])
	}
	return nil // first, untargeted or outside the order: waits for nobody
}

// regionWindow is one region's share of a rollout: its readiness timeout
// plus pull/submit, bounded dependency recovery and a full healthy bake.
func regionWindow(spec *swarmruntime.ServiceSpec) time.Duration {
	ready := swarmruntime.DefaultReadyTimeout
	if spec != nil && spec.ReadyTimeoutSeconds != 0 {
		ready = time.Duration(spec.ReadyTimeoutSeconds) * time.Second
	}
	return ready + 30*time.Second + rollout.MaxBakeWindow
}

// rolloutWait bounds a whole rollout of spec: every region in turn.
func rolloutWait(spec *swarmruntime.ServiceSpec) time.Duration {
	if spec == nil {
		return applyWait
	}
	return max(applyWait, time.Duration(max(len(rolloutOrder(spec)), 1))*regionWindow(spec))
}

// applyWindow bounds this region's part: waiting for the earlier regions, then
// its own rollout; it replies before the caller's rolloutWait ends.
func (n *Node) applyWindow(spec *swarmruntime.ServiceSpec) time.Duration {
	return max(applyWait, time.Duration(len(n.earlier(spec))+1)*regionWindow(spec)) - 10*time.Second
}

// held reports a region that comes after entry's canary hold.
func (n *Node) held(entry Entry) bool {
	return entry.HoldAfter != "" && slices.Contains(n.earlier(entry.Spec), entry.HoldAfter)
}

// errEarlierFailed stops a region from waiting for a generation an earlier
// region failed to roll out.
var errEarlierFailed = errors.New("an earlier region failed this rollout")

// turn allows this region to apply only after every earlier region reports
// the generation ready with a successful bake. Missing verdicts fail closed.
func (n *Node) turn(name string, spec *swarmruntime.ServiceSpec, generation int64, states map[string]stateReply) error {
	for _, region := range n.earlier(spec) {
		reply, answered := states[region]
		if !answered {
			return fmt.Errorf("%s has no bake verdict yet", region)
		}
		if reply.Failed[name] >= generation {
			return fmt.Errorf("%w: %s", errEarlierFailed, region)
		}
		if reply.Ready[name] < generation {
			return fmt.Errorf("%s does not run %s generation %d ready yet", region, name, generation)
		}
	}
	return nil
}

// awaitTurn waits until turn allows this region to apply.
func (n *Node) awaitTurn(ctx context.Context, name string, spec *swarmruntime.ServiceSpec, generation int64) error {
	earlier := n.earlier(spec)
	if len(earlier) == 0 {
		return nil
	}
	for {
		err := n.turn(name, spec, generation, n.statesOf(ctx, earlier, time.Second))
		if err == nil || errors.Is(err, errEarlierFailed) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for an earlier region: %w", err)
		case <-time.After(time.Second):
		}
	}
}

type applyResult struct {
	result  string
	spec    swarmruntime.ServiceSpec
	service *api.Service
	state   desiredState
}

func (n *Node) apply(ctx context.Context, request ApplyRequest) (applyResult, error) {
	if request.ExpectedGeneration != 0 {
		if request.Entry.RollbackOf != 0 && request.Entry.RollbackOf != request.ExpectedGeneration {
			return applyResult{}, errors.New("rollback ancestry differs from expected generation")
		}
		request.Entry.RollbackOf = request.ExpectedGeneration
	}
	if err := validEntry(request.Name, request.Entry); err != nil {
		return applyResult{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return applyResult{}, err
	}
	before, exists := n.desired[request.Name]
	current := before.entry()
	// An older generation here never took the failed rollout (an earlier region
	// stopped it): it takes the rollback entry too.
	if request.Entry.RollbackOf != 0 && current.Generation > request.Entry.RollbackOf {
		return applyResult{}, errors.New("rollback superseded by another apply")
	}
	if err := before.Floor.Accepts(request.Entry.Deployment); err != nil {
		return applyResult{}, err
	}
	merged, err := mergeState(before, stateFor(request.Entry))
	if err != nil {
		return applyResult{}, err
	}
	if !reflect.DeepEqual(merged.entry(), request.Entry) {
		return applyResult{}, fmt.Errorf("superseded by generation %d", current.Generation)
	}
	n.desired[request.Name] = merged
	// Persist before reconciliation, including retries of a persisted generation.
	if err := saveDesired(n.cfg.dir, n.desired); err != nil {
		if exists {
			n.desired[request.Name] = before
		} else {
			delete(n.desired, request.Name)
		}
		return applyResult{}, err
	}
	n.publishTopologyDesired()

	return n.reconcile(ctx, request.Name, n.desired[request.Name])
}

// reconcile makes the local service match entry; the caller holds n.mu.
func (n *Node) reconcile(ctx context.Context, name string, state desiredState) (applyResult, error) {
	entry := state.entry()
	if entry.Spec == nil || len(entry.Spec.Regions) != 0 && !slices.Contains(entry.Spec.Regions, n.cfg.region) {
		if _, err := n.cfg.applier.Remove(ctx, name); err != nil {
			return applyResult{}, err
		}
		if err := n.peers.untrack(name); err != nil {
			return applyResult{}, err
		}
		if entry.Spec == nil {
			return applyResult{result: "removed"}, nil
		}
		return applyResult{result: "skipped-not-targeted"}, nil
	}
	spec := *entry.Spec
	spec.Generation, spec.Region, spec.Node = entry.Generation, n.cfg.region, n.cfg.server
	spec.RollbackOf = entry.RollbackOf
	spec.Deployment, spec.DeploymentFloor = entry.Deployment, state.Floor
	if err := n.peers.track(name, spec.Regions); err != nil {
		return applyResult{}, err
	}
	changed, service, err := n.cfg.applier.Apply(ctx, spec)
	if err != nil {
		return applyResult{}, err
	}
	if changed {
		return applyResult{result: "applied", spec: spec, service: service, state: state}, nil
	}
	return applyResult{result: "unchanged", spec: spec, service: service, state: state}, nil
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
	if entry.RollbackOf < 0 || entry.RollbackOf >= entry.Generation {
		return errors.New("invalid rollback ancestry")
	}
	if err := entry.Deployment.Validate(); err != nil {
		return err
	}
	if entry.Deployment != nil && repository(entry.Deployment.Image) != "ghcr.io/terrascale/"+name {
		return errors.New("deployment image does not belong to the service")
	}
	if entry.Spec == nil {
		if entry.HoldAfter != "" {
			return errors.New("a removal cannot hold after a region")
		}
		return nil
	}
	if entry.HoldAfter != "" && !slices.Contains(rolloutOrder(entry.Spec), entry.HoldAfter) {
		return fmt.Errorf("holdAfter %q is not a region of the rollout %v", entry.HoldAfter, rolloutOrder(entry.Spec))
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

func loadDesired(dir string) (map[string]desiredState, error) {
	data, err := os.ReadFile(filepath.Join(dir, "desired.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]desiredState{}, nil
	}
	if err != nil {
		return nil, err
	}
	desired := map[string]desiredState{}
	if err := protocol.DecodeTolerant(data, &desired, maxWire); err != nil {
		return nil, fmt.Errorf("decode mesh desired state: %w", err)
	}
	if desired == nil {
		return nil, errors.New("mesh desired state must be an object")
	}
	for name, state := range desired {
		if err := validState(name, state); err != nil {
			return nil, fmt.Errorf("invalid desired state for %s: %w", name, err)
		}
	}
	return desired, nil
}

func saveDesired(dir string, desired map[string]desiredState) error {
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
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
