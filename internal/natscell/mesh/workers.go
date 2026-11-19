package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

type WorkerPeer struct {
	Node          string   `json:"node"`
	Address       string   `json:"address"`
	ReadyServices []string `json:"ready_services,omitempty"`
}

type announcement struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	at      time.Time
}

type nodeAnnouncement struct {
	WorkerPeer
	NodeID string `json:"node_id"`
}

const workerSettleWindow = 3 * peersEvery

type workerNodes interface {
	WorkerStates(context.Context) (map[string]string, map[string]bool, map[string]bool, error)
	Replicas(ctx context.Context, service string) (uint64, error)
}

var errWorkersSettling = errors.New("this manager has not heard its workers for a full announcement window since it started")

func PerNode(spec *swarmruntime.ServiceSpec) bool {
	return spec != nil && (spec.EveryNode() || len(spec.Mounts) != 0 && regionalReplicas(spec) > 1)
}

func regionalReplicas(spec *swarmruntime.ServiceSpec) uint64 {
	if spec.Name == "terrabase" {
		return 2
	}
	return spec.Replicas
}

func (n *Node) announce(ctx context.Context) {
	for {
		if address, err := n.cfg.address(); err == nil {
			data, err := protocol.EncodeJSON(nodeAnnouncement{WorkerPeer: WorkerPeer{Node: n.cfg.server, Address: address}, NodeID: n.cfg.nodeID})
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

func (n *Node) recordWorker(m *nats.Msg) {
	var at nodeAnnouncement
	if protocol.DecodeStrict(m.Data, &at, maxWire) != nil || at.NodeID == "" || at.Node == n.cfg.server || !validPeer(n.cfg.region, peer{at.Node, at.Address}) {
		return
	}
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	lister, ok := n.cfg.applier.(workerNodes)
	if !ok {
		return
	}
	ready, _, _, err := lister.WorkerStates(n.ctx)
	if err != nil {
		slog.WarnContext(n.ctx, "mesh worker announcement membership unavailable", "error", err)
		return
	}
	if ready[at.NodeID] != at.Node {
		return
	}
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	if n.announced == nil {
		n.announced = map[string]announcement{}
	}
	known := announcement{NodeID: at.NodeID, Address: at.Address, at: time.Now()}
	previous := n.announced[at.Node]
	if previous.NodeID == known.NodeID && previous.Address == known.Address {
		n.announced[at.Node] = known
		return
	}
	next := maps.Clone(n.announced)
	next[at.Node] = known
	if err := n.saveWorkers(next); err != nil {
		slog.WarnContext(n.ctx, "mesh worker identity persistence failed", "error", err)
		return
	}
	n.announced = next
}

func (n *Node) saveWorkers(workers map[string]announcement) error {
	data, err := protocol.EncodeJSON(workers)
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(n.cfg.dir, "workers.json"), data)
}

func (n *Node) loadWorkers() error {
	data, err := os.ReadFile(filepath.Join(n.cfg.dir, "workers.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := protocol.DecodeStrict(data, &n.announced, maxWire); err != nil {
		return err
	}
	for node, at := range n.announced {
		if at.NodeID == "" || node == n.cfg.server || !validPeer(n.cfg.region, peer{node, at.Address}) {
			return errors.New("invalid persisted worker identity")
		}
	}
	return nil
}

func (n *Node) refreshJoined(ctx context.Context) {
	for {
		if err := n.setJoined(ctx); err != nil {
			slog.WarnContext(ctx, "mesh worker membership unavailable", "error", err)
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

func (n *Node) setJoined(ctx context.Context) error {
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	var ready map[string]string
	var pending, known map[string]bool
	if lister, ok := n.cfg.applier.(workerNodes); ok {
		var err error
		if ready, pending, known, err = lister.WorkerStates(ctx); err != nil {
			return err
		}
	}
	n.workerMu.Lock()
	defer n.workerMu.Unlock()
	window := max(workerSettleWindow, 3*n.cfg.peersEvery)
	joined := []WorkerPeer{}
	next := maps.Clone(n.announced)
	for node, at := range n.announced {
		if known != nil && !known[at.NodeID] {
			delete(next, node)
		}
		if ready[at.NodeID] == node {
			joined = append(joined, WorkerPeer{Node: node, Address: at.Address})
			last := at.at
			if last.IsZero() {
				last = n.listening
			}
			if age := time.Since(last); age >= window {
				slog.WarnContext(ctx, "ready regional worker has stopped announcing on the mesh", "worker", node, "node_id", at.NodeID, "last_announcement_age", age)
			}
		}
	}
	slices.SortFunc(joined, func(a, b WorkerPeer) int { return strings.Compare(a.Node, b.Node) })
	n.joined = joined
	if len(next) != len(n.announced) {
		if err := n.saveWorkers(next); err != nil {
			return err
		}
		n.announced = next
	}
	if time.Since(n.listening) >= window && len(pending) == 0 {
		select {
		case <-n.settled:
		default:
			close(n.settled)
		}
	}
	return nil
}

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

func (n *Node) trackWorkerServices(ctx context.Context) {
	reply, ok := n.states(ctx)[n.cfg.region]
	if !ok {
		return
	}
	want := map[string]*swarmruntime.ServiceSpec{}
	for name, state := range reply.Desired {
		if spec := state.entry().Spec; PerNode(spec) && spec.NeedsPeers() && spec.RunsIn(n.cfg.region) {
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

func (a swarmApplier) WorkerStates(ctx context.Context) (ready map[string]string, pending, known map[string]bool, err error) {
	client, done, err := a.control()
	if err != nil {
		return nil, nil, nil, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, nil, nil, err
	}
	ready, pending, known = map[string]string{}, map[string]bool{}, map[string]bool{}
	for _, node := range nodes.Nodes {
		known[node.ID] = true
		if node.Spec.Availability != api.NodeAvailabilityActive || node.Spec.Membership != api.NodeMembershipAccepted || node.Description == nil {
			continue
		}
		switch node.Status.State {
		case api.NodeStatus_READY:
			ready[node.ID] = node.Description.Hostname
		case api.NodeStatus_UNKNOWN:
			pending[node.ID] = true
			pending[node.Description.Hostname] = true
		}
	}
	return ready, pending, known, nil
}

func (a swarmApplier) Replicas(ctx context.Context, service string) (replicas uint64, err error) {
	err = a.rows(ctx, service, func(row swarmruntime.ServiceSpecStatus, _ bool, _ api.ControlClient) error {
		replicas = row.Replicas
		return nil
	})
	return replicas, err
}

func (n *Node) EdgePeers(ready func() []string, advertised func(WorkerPeer)) (func() []WorkerPeer, func()) {
	type observed struct {
		peer WorkerPeer
		at   time.Time
	}
	var mu sync.Mutex
	peers := map[string]observed{}
	changed := make(chan struct{}, 1)
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
				advertised(at)
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
			case <-changed:
			}
		}
	})
	listed := func() []WorkerPeer {
		mu.Lock()
		defer mu.Unlock()
		fresh := 2 * n.cfg.peersEvery
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
	return listed, func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
}
