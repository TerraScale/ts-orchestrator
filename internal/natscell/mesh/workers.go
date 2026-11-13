package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
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
	Node          string   `json:"node"`
	Address       string   `json:"address"`
	ReadyServices []string `json:"ready_services,omitempty"`
}

// announcement is a worker's last word to its founder.
type announcement struct {
	address string
	at      time.Time
}

// workerFresh is how long an announcement counts: three missed rounds drop
// the worker from its region's peers files and per-node replica count.
const workerFresh = 3 * peersEvery

type workerNodes interface {
	WorkerStates(context.Context) (map[string]bool, map[string]bool, error)
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
	var ready, pending map[string]bool
	if lister, ok := n.cfg.applier.(workerNodes); ok {
		var err error
		if ready, pending, err = lister.WorkerStates(ctx); err != nil {
			slog.WarnContext(ctx, "mesh worker membership unavailable", "error", err)
			return
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
	if time.Since(n.listening) >= fresh && len(pending) == 0 {
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
		if spec := state.entry().Spec; PerNode(spec) && spec.NeedsPeers() && (len(spec.Regions) == 0 || slices.Contains(spec.Regions, n.cfg.region)) {
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

func (a swarmApplier) WorkerStates(ctx context.Context) (ready, pending map[string]bool, err error) {
	client, done, err := a.control()
	if err != nil {
		return nil, nil, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, nil, err
	}
	ready, pending = map[string]bool{}, map[string]bool{}
	for _, node := range nodes.Nodes {
		if node.Spec.DesiredRole != api.NodeRoleWorker || node.Spec.Availability != api.NodeAvailabilityActive || node.Description == nil {
			continue
		}
		switch node.Status.State {
		case api.NodeStatus_READY:
			ready[node.Description.Hostname] = true
		case api.NodeStatus_UNKNOWN:
			pending[node.Description.Hostname] = true
		}
	}
	return ready, pending, nil
}

func (a swarmApplier) Replicas(ctx context.Context, service string) (replicas uint64, err error) {
	err = a.rows(ctx, service, func(row swarmruntime.ServiceSpecStatus, _ bool, _ api.ControlClient) error {
		replicas = row.Replicas
		return nil
	})
	return replicas, err
}

func (n *Node) EdgePeers(ready func() []string) func() []WorkerPeer {
	type observed struct {
		peer WorkerPeer
		at   time.Time
	}
	var mu sync.Mutex
	peers := map[string]observed{}
	subject := protocol.MeshWorkerPrefix + n.cfg.region + ".edge"
	n.goWork(func() {
		var subscription *nats.Subscription
		backoff := time.Second
		for {
			var err error
			subscription, err = n.conn.Subscribe(subject, func(message *nats.Msg) {
				var at WorkerPeer
				if protocol.DecodeTolerant(message.Data, &at, maxWire) != nil || at.Node == n.cfg.server || !validPeer(n.cfg.region, peer{at.Node, at.Address}) {
					return
				}
				mu.Lock()
				peers[at.Node] = observed{peer: at, at: time.Now()}
				mu.Unlock()
			})
			if err == nil {
				break
			}
			slog.WarnContext(n.ctx, "edge announcements unavailable; retrying", "error", err)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
		}
		defer func() { _ = subscription.Unsubscribe() }()
		ticker := time.NewTicker(n.cfg.peersEvery)
		defer ticker.Stop()
		for {
			if address, err := n.cfg.address(); err == nil {
				data, err := protocol.EncodeJSON(WorkerPeer{Node: n.cfg.server, Address: address, ReadyServices: ready()})
				if err == nil {
					err = n.conn.Publish(subject, data)
				}
				if err != nil {
					slog.WarnContext(n.ctx, "mesh edge announcement failed", "error", err)
				}
			}
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	return func() []WorkerPeer {
		mu.Lock()
		defer mu.Unlock()
		fresh := max(workerFresh, 3*n.cfg.peersEvery)
		result := []WorkerPeer{}
		for node, item := range peers {
			if time.Since(item.at) > fresh {
				delete(peers, node)
				continue
			}
			result = append(result, item.peer)
		}
		slices.SortFunc(result, func(a, b WorkerPeer) int { return strings.Compare(a.Node, b.Node) })
		return result
	}
}
