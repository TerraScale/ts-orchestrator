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
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const (
	ApplySubject = protocol.MeshApplySubject
	StateSubject = protocol.MeshStateSubject
	PingSubject  = protocol.MeshPingSubject

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
	// Workers is the replying founder's fully joined workers (ping only).
	Workers   []WorkerPeer `json:"workers,omitempty"`
	StartedAt time.Time    `json:"startedAt,omitzero"`
}

type stateReply struct {
	Nonce    string `json:"nonce,omitempty"`
	received time.Time
	Region   string                  `json:"region"`
	Desired  map[string]desiredState `json:"desired"`
	// Ready is the generation each local service runs with every replica ready.
	Ready        map[string]int64             `json:"ready,omitempty"`
	Serving      map[string]ServingResult     `json:"serving,omitempty"`
	BakeRequired map[string]bool              `json:"bakeRequired"`
	Admission    map[string]AdmissionDecision `json:"admission,omitempty"`
	Failed       map[string]int64             `json:"failed,omitempty"`
	Unsaved      map[string]int64             `json:"unsaved,omitempty"`
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
	Bake(context.Context, swarmruntime.ServiceSpec, swarmruntime.ServiceRollout, rollout.BakeVerdict, func(rollout.BakeVerdict) error) (rollout.BakeVerdict, error)
	Ready(ctx context.Context) (map[string]ServingResult, error)
}

type config struct {
	maintenance            *rolloutmaintenance.Store
	region, server, dir    string
	clusterHost            string
	clusterAdvertise       string
	clusterPort, localPort int
	seeds                  map[string]string
	routes                 []string
	ca                     *CA
	terrabaseToken         string  // TerraBase's client token, from Vault
	applier                Applier // nil on a worker, which serves no region requests
	every                  time.Duration
	peersDir               string // host root of every service's peers file
	peersEvery             time.Duration
	address                func() (string, error) // this node's NetBird IPv4
}

// Node is one region's running mesh server.
type Node struct {
	serving       atomic.Pointer[map[string]ServingResult]
	stateDesired  atomic.Pointer[map[string]desiredState]
	stateUnsaved  atomic.Pointer[map[string]bakeRecord]
	bootstrapHook atomic.Pointer[bootstrapHook]
	cfg           config
	tls           *tls.Config
	server        *server.Server
	conn          *nats.Conn
	fabric        *nats.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	// work is every goroutine that writes the node's directory; Close waits
	// for it, and closing (under workMu) refuses new ones.
	workMu  sync.Mutex
	closing bool
	work    sync.WaitGroup

	mu          sync.Mutex
	desired     map[string]desiredState
	specInvalid map[string]error
	baking      map[string]chan struct{}
	// starting is a ts-auth or ts-dashboard update reconcile submitted whose
	// evaluate has not yet registered its bake in baking.
	starting             map[string]bool
	bakeUnsaved          map[string]bakeRecord
	admissionMu          sync.Mutex
	admission            map[string]AdmissionDecision
	peers                *peers
	peerReports          map[string]map[string]PeerAttestation
	peerReportMu         sync.Mutex
	topologyDesired      atomic.Pointer[map[string]Entry]
	specInvalidPublished atomic.Pointer[map[string]error]

	regionalDrain atomic.Pointer[regionalDrainer]
	workerMu      sync.Mutex
	announced     map[string]announcement // founder: worker node -> its last announcement
	joined        []WorkerPeer            // founder: the fully joined workers, refreshed each peersEvery
	listening     time.Time
	settled       chan struct{}
}

func start(cfg config) (_ *Node, err error) {
	if cfg.peersEvery <= 0 {
		cfg.peersEvery = peersEvery
	}
	if err := os.MkdirAll(cfg.dir, 0o700); err != nil {
		return nil, err
	}
	desired, specInvalid, err := loadDesired(cfg.dir)
	if err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(specInvalid)) {
		slog.Error("stored service spec rejected; service not managed", "service", name,
			"error", fmt.Errorf("invalid desired state for %s: %w", name, specInvalid[name]))
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
	fabricSecret, err := randomHex()
	if err != nil {
		return nil, err
	}
	options, err := serverOptions(cfg, tlsConfig, secret, fabricSecret)
	if err != nil {
		return nil, err
	}
	embedded, err := server.NewServer(options)
	if err != nil {
		return nil, err
	}
	options.CustomClientAuthentication.(*clientAuth).server = embedded
	log := newContainedLog()
	embedded.SetLoggerV2(log, false, false, false)
	go embedded.Start()
	defer func() {
		if err != nil {
			embedded.Shutdown()
			embedded.WaitForShutdown()
		}
	}()
	if !embedded.ReadyForConnections(10 * time.Second) {
		return nil, log.failure()
	}
	conn, err := dialLocal(cfg.localPort, orchUser, secret)
	if err != nil {
		return nil, err
	}
	var fabric *nats.Conn
	if options.JetStream {
		if fabric, err = dialLocal(cfg.localPort, fabricUser, fabricSecret); err != nil {
			conn.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	node := &Node{cfg: cfg, tls: tlsConfig, server: embedded, conn: conn, fabric: fabric, ctx: ctx, cancel: cancel, desired: desired,
		specInvalid: specInvalid, peers: peerFiles, listening: time.Now(), settled: make(chan struct{})}
	if err := node.serveClockReports(); err != nil {
		node.closeConns()
		cancel()
		return nil, err
	}
	node.publishTopologyDesired()
	handlers := map[string]nats.MsgHandler{
		PingSubject: func(m *nats.Msg) {
			var address string // a node without NetBird (or a worker) still answers; peers skip it
			if cfg.address != nil {
				address, _ = cfg.address()
			}
			node.respond(m, Reply{Region: cfg.region, Server: cfg.server, Regions: node.regions(), Address: address, Attestations: node.localAttestations(),
				Workers: node.joinedWorkers(), StartedAt: node.listening})
		},
		StateSubject: func(m *nats.Msg) {
			var request struct {
				Nonce string `json:"nonce"`
			}
			_ = protocol.DecodeTolerant(m.Data, &request, maxWire)
			state := stateReply{Nonce: request.Nonce, Region: cfg.region, Desired: maps.Clone(*node.stateDesired.Load()), Ready: map[string]int64{}, Serving: node.servingSnapshot()}
			for name, result := range state.Serving {
				if result.fresh() {
					state.Ready[name] = result.Generation
				} else {
					delete(state.Serving, name)
				}
			}
			node.bakeState(&state)
			node.admissionMu.Lock()
			state.Admission = maps.Clone(node.admission)
			node.admissionMu.Unlock()
			node.respond(m, state)
		},
		// An apply waits for its tasks to run, so it must not hold up the next message.
		ApplySubject: func(m *nats.Msg) { node.goWork(func() { node.handleApply(m) }) },
	}
	handlers[protocol.MeshWorkerPrefix+cfg.region] = node.recordWorker
	handlers[protocol.MeshDrainPrefix+cfg.region] = func(m *nats.Msg) { node.goWork(func() { node.handleDrain(m) }) }
	if cfg.applier == nil {
		handlers = map[string]nats.MsgHandler{}
	}
	handlers[protocol.MeshDrainPrefix+cfg.region+"."+cfg.server+".fence"] = func(m *nats.Msg) { node.handleBootstrapFence(m) }
	handlers[protocol.MeshDrainPrefix+cfg.region+"."+cfg.server+".clear"] = func(m *nats.Msg) { node.handleBootstrapClear(m) }
	for subject, handler := range handlers {
		if _, err := conn.Subscribe(subject, handler); err != nil {
			node.closeConns()
			cancel()
			return nil, err
		}
	}
	if err := conn.Flush(); err != nil {
		node.closeConns()
		cancel()
		return nil, err
	}
	node.goWork(func() { node.watchPeers(ctx) })
	if cfg.applier == nil {
		node.goWork(func() { node.announce(ctx) })
	} else {
		node.goWork(func() { node.refreshJoined(ctx) })
	}
	return node, nil
}

// Region is the region this node serves.
func (n *Node) Region() string { return n.cfg.region }

// TLS is the mesh mTLS config for both ends of a connection: it presents
// this node's leaf and accepts only peers the mesh CA signed.
func (n *Node) TLS() *tls.Config { return n.tls }

func (n *Node) AdmittedRegions() []string {
	n.peers.mu.Lock()
	names := slices.Clone(n.peers.regions)
	n.peers.mu.Unlock()
	names = append(names, n.regions()...)
	slices.Sort(names)
	return slices.Compact(names)
}

func (n *Node) RTT() map[string]time.Duration {
	rtt := map[string]time.Duration{}
	for _, route := range n.routes() {
		region := serverRegion(route.RemoteName)
		if region == "" || region == n.cfg.region {
			continue
		}
		if d, err := time.ParseDuration(route.RTT); err == nil && d > 0 && (rtt[region] == 0 || d < rtt[region]) {
			rtt[region] = d
		}
	}
	return rtt
}

func dialLocal(port int, user, password string) (*nats.Conn, error) {
	return nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", port), nats.UserInfo(user, password),
		nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
}

// goWork runs f unless the node is closing.
func (n *Node) goWork(f func()) {
	n.workMu.Lock()
	defer n.workMu.Unlock()
	if !n.closing {
		n.work.Go(f)
	}
}

// Close stops the server; desired state stays on disk.
func (n *Node) Close() {
	n.workMu.Lock()
	n.closing = true
	n.workMu.Unlock()
	n.cancel()
	n.closeConns()
	n.server.Shutdown()
	n.server.WaitForShutdown()
	n.work.Wait()
}

func (n *Node) regions() []string {
	names := append([]string{n.cfg.region}, slices.Collect(maps.Keys(n.cfg.seeds))...)
	for _, route := range n.routes() {
		if region := serverRegion(route.RemoteName); region != "" {
			names = append(names, region)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func (n *Node) Run(ctx context.Context) {
	if n.cfg.applier != nil {
		n.goWork(func() { n.observeServing(n.ctx) })
	}
	tick := time.NewTicker(n.cfg.every)
	defer tick.Stop()
	var collected time.Time
	settled := n.settled
	for {
		if n.cfg.applier != nil {
			n.sync(ctx)
			if time.Since(collected) >= 10*time.Minute {
				n.mu.Lock()
				n.collectImages(ctx)
				n.pruneBakes()
				n.mu.Unlock()
				collected = time.Now()
			}
		} else {
			n.trackWorkerServices(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-n.ctx.Done():
			return
		case <-tick.C:
		case <-settled:
			settled = nil
		}
	}
}

// sync merges every replying peer's candidates and floor per name, then
// reconciles every entry so a missed or failed apply is retried.
func (n *Node) sync(ctx context.Context) {
	states := n.states(ctx)
	if n.ctx.Err() != nil {
		return
	}
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
					if err := n.acceptBakeReplacement(name, merged.entry()); err != nil {
						slog.WarnContext(ctx, "mesh held service refused", "service", name, "error", err)
						continue
					}
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
		if n.ctx.Err() != nil {
			return
		}
		if err, rejected := n.specInvalid[name]; rejected {
			slog.ErrorContext(ctx, "stored service spec rejected; service not managed", "service", name,
				"error", fmt.Errorf("invalid desired state for %s: %w", name, err))
			continue
		}
		if entry := n.desired[name].entry(); entry.Spec != nil && entry.Spec.NeedsPeers() && (len(entry.Spec.Regions) == 0 || slices.Contains(entry.Spec.Regions, n.cfg.region)) {
			if err := n.peers.track(name, entry.Spec.Regions, PerNode(entry.Spec)); err != nil {
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
		if n.dependentRolling(name) {
			continue // TerraBase waits for this region's ts-auth or ts-dashboard rollout
		}
		if applied, err := n.reconcile(ctx, name, n.desired[name]); errors.Is(err, errWorkersSettling) {
			slog.InfoContext(ctx, "mesh reconcile waits for worker announcements", "service", name, "reason", err)
		} else if err != nil {
			slog.WarnContext(ctx, "mesh reconcile failed", "service", name, "error", err)
		} else if applied.result == "applied" || applied.result == "unchanged" {
			n.goWork(func() { _, _ = n.evaluate(n.ctx, applied) })
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
	if err == nil {
		n.mu.Lock()
		err = n.checkBakeAdmission(request.Name, request.Entry)
		n.mu.Unlock()
	}
	var pulled time.Duration
	var pullErr error
	if spec := request.Entry.Spec; err == nil && spec != nil && (len(spec.Regions) == 0 || slices.Contains(spec.Regions, n.cfg.region)) {
		pullErr = prePull(ctx, n.cfg.applier, *spec)
		pulled = time.Since(start)
	}
	if err == nil && n.held(request.Entry) {
		// A canary hold: this region keeps the previous generation and answers without applying.
		reply.Result, reply.ElapsedMS = "held after "+request.Entry.HoldAfter, time.Since(start).Milliseconds()
		n.respond(m, reply)
		return
	}
	if err == nil && pullErr != nil {
		// Updates stop the serving task first: without the image on the host
		// the outage lasted the whole pull (gru TerraBase 2m50s, 2026-10-27).
		slog.WarnContext(ctx, "mesh pre-pull failed; the serving task keeps running", "service", request.Name, "error", pullErr)
		err = fmt.Errorf("pull %s before stopping the serving task: %w", request.Entry.Spec.Image, pullErr)
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
	for err == nil {
		var waited time.Duration
		if waited, err = n.awaitDependents(ctx, request.Name); err == nil && waited > 0 {
			// The wait is not TerraBase's own rollout time: extend its window.
			deadline, _ := ctx.Deadline()
			ctx, cancel = context.WithDeadline(n.ctx, deadline.Add(waited))
			defer cancel()
		}
		if err == nil {
			applied, err = n.apply(ctx, request)
		}
		if errors.Is(err, errWorkersSettling) {
			err = n.awaitWorkers(ctx)
			continue
		}
		if !errors.Is(err, errDependentRolling) {
			break
		}
		err = nil // a dependent started between the wait and the apply
	}
	if err == nil && (applied.result == "applied" || applied.result == "unchanged") {
		submitted := time.Since(start)
		spec := applied.spec
		verdict, bakeErr := n.evaluate(ctx, applied)
		err = bakeErr
		reply.Service, reply.Image, reply.Tasks, reply.Revision = spec.Name, spec.Image, verdict.Rollout.Tasks, verdict.Rollout.Revision
		reply.Bake = &verdict.Bake
		reply.Phases = fmt.Sprintf("pulled %dms, submitted %dms, ready %dms", pulled.Milliseconds(), submitted.Milliseconds(), (submitted + time.Duration(verdict.Rollout.Ready)).Milliseconds())
		if verdict.Rollout.StopFirst {
			reply.Phases += ", stop-first: candidate did not fit"
		}
		if !verdict.Bake.Started.IsZero() {
			reply.Phases += bakePhase(verdict.Bake)
		}
	}
	reply.Result, reply.ElapsedMS = applied.result, time.Since(start).Milliseconds()
	if err != nil {
		reply.Error = err.Error()
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
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		slog.ErrorContext(ctx, "mesh state nonce unavailable", "error", err)
		return states
	}
	challenge := hex.EncodeToString(nonce)
	payload, err := protocol.EncodeJSON(struct {
		Nonce string `json:"nonce"`
	}{challenge})
	if err != nil {
		return states
	}
	sent := time.Now()
	_ = collect(ctx, n.conn, StateSubject, payload, count, wait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil && time.Since(sent) <= servingMaxAge && (reply.Nonce == challenge || reply.Nonce == "" && reply.Serving == nil && reply.BakeRequired == nil && reply.Admission == nil && reply.Unsaved == nil) {
			reply.received = sent
			states[reply.Region] = reply
		}
		return want == nil || slices.ContainsFunc(want, func(region string) bool { _, ok := states[region]; return !ok })
	})
	return states
}

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

type AdmissionDecision struct {
	Generation int64     `json:"generation"`
	At         time.Time `json:"at"`
	Earlier    string    `json:"earlier,omitempty"`
	Evidence   string    `json:"evidence"`
}

func (n *Node) turn(name string, spec *swarmruntime.ServiceSpec, generation int64, states map[string]stateReply) (err error) {
	decision := AdmissionDecision{Generation: generation, At: time.Now(), Evidence: "admitted"}
	defer func() {
		n.admissionMu.Lock()
		defer n.admissionMu.Unlock()
		if n.admission == nil {
			n.admission = map[string]AdmissionDecision{}
		}
		n.admission[name] = decision
	}()
	for _, region := range n.earlier(spec) {
		decision.Earlier = region
		reply, answered := states[region]
		if !answered {
			decision.Evidence = "region reply missing"
			return fmt.Errorf("%s has no bake verdict yet", region)
		}
		if reply.Failed[name] == generation {
			decision.Evidence = "bake failed"
			return fmt.Errorf("%w: %s", errEarlierFailed, region)
		}
		if time.Since(reply.received) > servingMaxAge || reply.Nonce != "" && (!reply.Serving[name].Serving || reply.Serving[name].Generation != generation) {
			decision.Evidence = "fresh serving evidence missing"
			return fmt.Errorf("%s lacks fresh serving evidence for %s generation %d", region, name, generation)
		}
		if reply.Ready[name] != generation {
			decision.Evidence = "passed bake missing"
			return fmt.Errorf("%s does not run %s generation %d ready yet", region, name, generation)
		}
	}
	decision.Earlier = ""
	return nil
}

// errDependentRolling refuses a TerraBase apply while a dependent rolls out here.
var errDependentRolling = errors.New("a local ts-auth or ts-dashboard rollout is in progress")

// dependentRolling reports a TerraBase change that would restart TerraBase
// under a ts-auth or ts-dashboard rollout (readiness wait and bake) in this
// region: their readiness needs the local TerraBase, so the restart failed
// ts-dashboard's sjc rollback bake (E18). The caller holds n.mu.
func (n *Node) dependentRolling(name string) bool {
	if name != "terrabase" {
		return false
	}
	for _, dependent := range []string{"ts-auth", "ts-dashboard"} {
		if n.starting[dependent] {
			return true
		}
		for key := range n.baking {
			if strings.HasPrefix(filepath.Base(key), "bake-"+dependent+"-") {
				return true
			}
		}
	}
	return false
}

// awaitDependents waits until no dependent of name rolls out in this region
// and returns how long it waited; the caller extends TerraBase's window by it.
// An app's window would not absorb a TerraBase rollout, so apps never wait.
func (n *Node) awaitDependents(ctx context.Context, name string) (time.Duration, error) {
	start := time.Now()
	for {
		n.mu.Lock()
		rolling := n.dependentRolling(name)
		n.mu.Unlock()
		if !rolling {
			return time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			return time.Since(start), fmt.Errorf("waiting for a local ts-auth or ts-dashboard rollout: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
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
	if n.dependentRolling(request.Name) {
		return applyResult{}, errDependentRolling
	}
	before, exists := n.desired[request.Name]
	current := before.entry()
	// An older generation here never took the failed rollout (an earlier region
	// stopped it): it takes the rollback entry too.
	// A re-published rollback finds its own entry already applied: it is the same request.
	if request.Entry.RollbackOf != 0 && current.Generation > request.Entry.RollbackOf && !reflect.DeepEqual(current, request.Entry) {
		return applyResult{}, errors.New("rollback superseded by another apply")
	}
	if err := before.accepts(request.Entry.Deployment); err != nil {
		return applyResult{}, err
	}
	merged, err := mergeState(before, stateFor(request.Entry))
	if err != nil {
		return applyResult{}, err
	}
	if !reflect.DeepEqual(merged.entry(), request.Entry) {
		return applyResult{}, fmt.Errorf("superseded by generation %d", current.Generation)
	}
	if err := n.acceptBakeReplacement(request.Name, request.Entry); err != nil {
		return applyResult{}, err
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
	staged, _ := ctx.Value(bootstrapStageKey{}).(string)
	bootstrapStage := n.cfg.maintenance != nil && staged != "" && name == "terrabase" && state.entry().Spec != nil && state.entry().Spec.Image == staged
	if n.cfg.maintenance != nil {
		if !bootstrapStage {
			if err := n.cfg.maintenance.Publication(ctx, name); err != nil {
				return applyResult{}, err
			}
		}
	}
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
	spec.BootstrapStage = bootstrapStage
	perNode := PerNode(&spec)
	if perNode {
		// One task per fully joined node: a worker counts only once it announces
		// itself over the mesh and SwarmKit has it READY and ACTIVE, so a drained
		// or half-joined worker is never a release target.
		workers, settled := n.settledWorkers()
		spec.Replicas = min(regionalReplicas(&spec), uint64(1+len(workers)))
		if !settled {
			if err := n.keepReplicas(ctx, spec); err != nil {
				return applyResult{}, err
			}
		}
		spec.WorkerAddresses = make(map[string]string, len(workers))
		for _, worker := range workers {
			spec.WorkerAddresses[worker.Node] = worker.Address
		}
	}
	if spec.NeedsPeers() {
		if err := n.peers.track(name, spec.Regions, perNode); err != nil {
			return applyResult{}, err
		}
	}
	changed, service, err := n.cfg.applier.Apply(ctx, spec)
	if err != nil {
		return applyResult{}, err
	}
	if changed && (name == "ts-auth" || name == "ts-dashboard") {
		// Fence TerraBase from now until evaluate registers this bake.
		if n.starting == nil {
			n.starting = map[string]bool{}
		}
		n.starting[name] = true
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
	if entry.Deployment != nil && !swarmruntime.DeploymentImageBelongsToService(name, entry.Deployment.Image) {
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
	return collectAgain(ctx, conn, subject, payload, want, wait, 0, each)
}

// collectAgain is collect that re-publishes the request every again (when
// positive) until it is done, for receivers that may have restarted.
func collectAgain(ctx context.Context, conn *nats.Conn, subject string, payload []byte, want int, wait, again time.Duration, each func([]byte) bool) error {
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
	var republish <-chan time.Time
	if again > 0 {
		tick := time.NewTicker(again)
		defer tick.Stop()
		republish = tick.C
	}
	for got := 0; got < want; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-republish:
			if err := conn.PublishRequest(subject, inbox, payload); err != nil {
				return err
			}
		case m := <-replies:
			got++
			if !each(m.Data) {
				return nil
			}
		}
	}
	return nil
}

func loadDesired(dir string) (map[string]desiredState, map[string]error, error) {
	data, err := os.ReadFile(filepath.Join(dir, "desired.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]desiredState{}, map[string]error{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	desired := map[string]desiredState{}
	if err := protocol.DecodeTolerant(data, &desired, maxWire); err != nil {
		return nil, nil, fmt.Errorf("decode mesh desired state: %w", err)
	}
	if desired == nil {
		return nil, nil, errors.New("mesh desired state must be an object")
	}
	specInvalid := map[string]error{}
	for name, state := range desired {
		if err := validState(name, state); err != nil {
			specInvalid[name] = err
		}
	}
	return desired, specInvalid, nil
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

// Called with n.mu held so a new desired image cannot race collection.
func (n *Node) collectImages(ctx context.Context) {
	a, ok := n.cfg.applier.(swarmApplier)
	if !ok {
		return
	}
	// Digest matching conservatively retains both candidates and every floor.
	retained, err := protocol.EncodeJSON(n.desired)
	if err != nil {
		slog.WarnContext(ctx, "image retention unavailable", "error", err)
		return
	}
	client, close, err := a.control()
	if err == nil {
		defer close()
		var services *api.ListServicesResponse
		services, err = client.ListServices(ctx, &api.ListServicesRequest{})
		if err == nil {
			var executor *swarmruntime.Executor
			executor, err = swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, a.state)
			if err == nil {
				defer executor.Close()
				err = executor.CollectImages(ctx, services.Services, string(retained))
			}
		}
	}
	if err != nil {
		slog.WarnContext(ctx, "image collection deferred", "error", err)
	}
}

// prePullAttempts and prePullBackoff ride out a registry blip before a
// release fails rather than stopping a task whose image is not on the host.
const (
	prePullAttempts = 3
	prePullBackoff  = 2 * time.Second
)

// prePull fetches and unpacks spec's image (containerd verifies every digest)
// before the update stops the serving task.
func prePull(ctx context.Context, applier Applier, spec swarmruntime.ServiceSpec) error {
	var err error
	for attempt := range prePullAttempts {
		if attempt > 0 {
			slog.WarnContext(ctx, "mesh pre-pull failed; retrying", "service", spec.Name, "attempt", attempt, "error", err)
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(prePullBackoff << (attempt - 1)):
			}
		}
		if err = applier.PrePull(ctx, spec); err == nil {
			return nil
		}
	}
	return err
}
