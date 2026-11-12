package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

// WorkerPeer is one fully joined worker of a region, as its founder reports
// it in ping replies: the node name TerraBase sees as TS_NODE and its NetBird
// IPv4.
type WorkerPeer struct {
	Node    string `json:"node"`
	Address string `json:"address"`
}

// announcement is a worker's last word to its founder.
type announcement struct {
	address string
	at      time.Time
}

// workerFresh is how long an announcement counts: three missed rounds drop
// the worker from its region's peers files and per-node replica count.
const workerFresh = 3 * peersEvery

// workerNodes is the founder's view of its region's SwarmKit workers.
type workerNodes interface {
	// ReadyWorkers is every worker hostname that is READY and ACTIVE (not
	// drained or paused).
	ReadyWorkers(ctx context.Context) (map[string]bool, error)
	Replicas(ctx context.Context, service string) (uint64, error)
}

var errWorkersSettling = errors.New("the founder has not heard its workers for a full announcement window since it started")

// PerNode reports whether spec runs one task on every fully joined node of
// its region (a data owner such as TerraBase with replicas > 1) rather than
// once, on the founder.
func PerNode(spec *swarmruntime.ServiceSpec) bool {
	return spec != nil && len(spec.Mounts) != 0 && regionalReplicas(spec) > 1
}

// regionalReplicas upgrades existing TerraBase declarations in place. R10's
// founder needs one durable in-region holder; a drained worker still does not
// count toward the runtime replica count. Other services keep their declaration.
func regionalReplicas(spec *swarmruntime.ServiceSpec) uint64 {
	if spec.Name == "terrabase" {
		return 2
	}
	return spec.Replicas
}

// announce is a worker's loop: every peersEvery it tells its founder its node
// name and NetBird address.
func (n *Node) announce(ctx context.Context) {
	for {
		if address, err := n.cfg.address(); err == nil {
			data, err := protocol.EncodeJSON(WorkerPeer{Node: n.cfg.server, Address: address})
			if err == nil {
				err = n.conn.Publish(protocol.MeshWorkerPrefix+n.cfg.region, data)
			}
			if err != nil {
				slog.WarnContext(ctx, "mesh worker announcement failed", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-n.ctx.Done():
			return
		case <-time.After(n.cfg.peersEvery):
		}
	}
}

// recordWorker keeps a worker's announcement; only the founder subscribes.
func (n *Node) recordWorker(m *nats.Msg) {
	var at WorkerPeer
	if protocol.DecodeStrict(m.Data, &at, maxWire) != nil || at.Node == n.cfg.server || !validPeer(n.cfg.region, peer{at.Node, at.Address}) {
		return
	}
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	if n.announced == nil {
		n.announced = map[string]announcement{}
	}
	n.announced[at.Node] = announcement{address: at.Address, at: time.Now()}
}

// refreshJoined is the founder's loop: a worker is fully joined while it
// announces itself over the mesh (so NATS and its NetBird address work) and
// SwarmKit has it READY and ACTIVE in this region's cluster.
func (n *Node) refreshJoined(ctx context.Context) {
	for {
		n.setJoined(ctx)
		select {
		case <-ctx.Done():
			return
		case <-n.ctx.Done():
			return
		case <-time.After(n.cfg.peersEvery):
		}
	}
}

func (n *Node) setJoined(ctx context.Context) {
	var ready map[string]bool
	if lister, ok := n.cfg.applier.(workerNodes); ok {
		var err error
		if ready, err = lister.ReadyWorkers(ctx); err != nil {
			slog.WarnContext(ctx, "mesh worker membership unavailable", "error", err)
			return // keep the last joined set rather than shrink it on a control-socket error
		}
	}
	fresh := max(workerFresh, 3*n.cfg.peersEvery)
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	joined := []WorkerPeer{}
	for node, at := range n.announced {
		if time.Since(at.at) <= fresh && ready[node] {
			joined = append(joined, WorkerPeer{Node: node, Address: at.address})
		}
	}
	slices.SortFunc(joined, func(a, b WorkerPeer) int { return strings.Compare(a.Node, b.Node) })
	n.joined = joined
	if time.Since(n.listening) >= fresh {
		select {
		case <-n.settled:
		default:
			close(n.settled)
		}
	}
}

// joinedWorkers is the founder's fully joined workers, sorted; nil on a worker.
func (n *Node) joinedWorkers() []WorkerPeer {
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	return slices.Clone(n.joined)
}

func (n *Node) settledWorkers() ([]WorkerPeer, bool) {
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	select {
	case <-n.settled:
		return slices.Clone(n.joined), true
	default:
		return slices.Clone(n.joined), false
	}
}

func (n *Node) keepReplicas(ctx context.Context, spec swarmruntime.ServiceSpec) error {
	lister, ok := n.cfg.applier.(workerNodes)
	if !ok {
		return nil
	}
	current, err := lister.Replicas(ctx, spec.Name)
	if err != nil {
		return err
	}
	if spec.Replicas < current {
		return fmt.Errorf("%w: %s keeps its %d replicas, %d counted so far", errWorkersSettling, spec.Name, current, spec.Replicas)
	}
	return nil
}

func (n *Node) awaitWorkers(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting for worker announcements: %w", ctx.Err())
	case <-n.settled:
		return nil
	}
}

// trackWorkerServices keeps a worker's peers files for the per-node services
// its region's founder desires, so their task here finds its file (listing
// this worker once the founder counts it fully joined) before it starts.
func (n *Node) trackWorkerServices(ctx context.Context) {
	reply, ok := n.states(ctx)[n.cfg.region]
	if !ok {
		return // keep the files until the founder answers again
	}
	want := map[string]*swarmruntime.ServiceSpec{}
	for name, state := range reply.Desired {
		if spec := state.entry().Spec; PerNode(spec) && (len(spec.Regions) == 0 || slices.Contains(spec.Regions, n.cfg.region)) {
			want[name] = spec
		}
	}
	n.peers.mu.Lock()
	tracked := slices.Collect(maps.Keys(n.peers.targets))
	n.peers.mu.Unlock()
	for _, name := range tracked {
		if want[name] == nil {
			if err := n.peers.untrack(name); err != nil {
				slog.WarnContext(ctx, "mesh worker peers file untrack failed", "service", name, "error", err)
			}
		}
	}
	for name, spec := range want {
		if err := n.peers.track(name, spec.Regions, true); err != nil {
			slog.WarnContext(ctx, "mesh worker peers file track failed", "service", name, "error", err)
		}
	}
}

// ReadyWorkers lists this region's READY and ACTIVE SwarmKit workers.
func (a swarmApplier) ReadyWorkers(ctx context.Context) (map[string]bool, error) {
	client, done, err := a.control()
	if err != nil {
		return nil, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	ready := map[string]bool{}
	for _, node := range nodes.Nodes {
		if node.Spec.DesiredRole == api.NodeRoleWorker && node.Status.State == api.NodeStatus_READY &&
			node.Spec.Availability == api.NodeAvailabilityActive && node.Description != nil {
			ready[node.Description.Hostname] = true
		}
	}
	return ready, nil
}

func (a swarmApplier) Replicas(ctx context.Context, service string) (replicas uint64, err error) {
	err = a.rows(ctx, service, func(row swarmruntime.ServiceSpecStatus, _ bool, _ api.ControlClient) error {
		replicas = row.Replicas
		return nil
	})
	return replicas, err
}
