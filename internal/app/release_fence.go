package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// A release fence (TS-610, the cell spec's release_fence) restarts a
// service release one node at a time. Before the leader submits a release
// it marks the release sequenced in the release channel bucket; every
// controller's host restart gate then holds a host's restart into it until
// the leader permits that node. The leader takes the nodes in turn: it
// fences the node's backends that are in rotation on the load balancer
// (drain, then offline after the grace), permits the node, waits until the
// node serves the release, returns the backends and waits for their health
// checks, then settles before the next node. A backend is fenced only
// while another backend of its set serves healthy. The fenced backends are
// recorded before the load balancer changes, so a new leader returns them.
const (
	defaultFenceGrace  = 15 * time.Second
	defaultFenceSettle = 10 * time.Second
	fencePoll          = 2 * time.Second
)

func sequencedKey(role string, release uint64) string {
	return "fence." + role + "." + strconv.FormatUint(release, 10)
}

func permitKey(role string, release uint64, node string) string {
	return sequencedKey(role, release) + "." + node
}

func fencedKey(node string) string { return "fenced." + node }

// releaseOf is the release a desired or report generation belongs to: a
// reconciled role's release-scoped generation, or the generation itself.
func releaseOf(generation uint64) uint64 {
	if release := workload.ReleaseOf(generation); release > 0 {
		return release
	}
	return generation
}

// releaseGate is the host restart gate of sequenced releases: a restart
// into one waits for its node's permit; every other restart passes.
func releaseGate(kv jetstream.KeyValue) func(context.Context, string, host.Desired) (bool, error) {
	return func(ctx context.Context, node string, desired host.Desired) (bool, error) {
		release := releaseOf(desired.Generation)
		if _, err := kv.Get(ctx, sequencedKey(desired.Role, release)); errors.Is(err, jetstream.ErrKeyNotFound) {
			return true, nil
		} else if err != nil {
			return false, err
		}
		_, err := kv.Get(ctx, permitKey(desired.Role, release, node))
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return false, nil
		}
		return err == nil, err
	}
}

// fencedBackend is one backend a fence takes out of rotation.
type fencedBackend struct {
	Set  string `json:"set"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// fenceRecord is a node's fence, recorded before the load balancer changes:
// the load balancer it was taken from, and whether every backend is out of
// rotation yet (fenced) or the fence may be part-way (fencing).
type fenceRecord struct {
	LoadBalancerID string          `json:"load_balancer_id"`
	Phase          string          `json:"phase"`
	Backends       []fencedBackend `json:"backends"`
}

// releaseFence is the leader's side of a release fence. Every change it
// makes is guarded by the authority epoch it started under, so a deposed
// leader stops.
type releaseFence struct {
	kv     jetstream.KeyValue
	hosts  seatrollout.Hosts
	fencer authority.Fencer
	// spec returns the cell spec's release fence, nil without one, and the
	// private address of each granted node.
	spec func() (*cellspec.ReleaseFence, map[string]string)
	// open returns the load balancer client; it is opened on first use.
	open func(context.Context) (lb.API, error)
	// sleep waits for a grace or a poll; tests shorten it.
	sleep func(context.Context, time.Duration) error

	mu  sync.Mutex
	api lb.API
}

func (f *releaseFence) client(ctx context.Context) (lb.API, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.api == nil {
		api, err := f.open(ctx)
		if err != nil {
			return nil, fmt.Errorf("open the load balancer client: %w", err)
		}
		f.api = api
	}
	return f.api, nil
}

// wait waits for d, and fails once the lease of epoch is lost.
func (f *releaseFence) wait(ctx context.Context, epoch uint64, d time.Duration) error {
	if f.sleep != nil {
		if err := f.sleep(ctx, d); err != nil {
			return err
		}
	} else {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return f.fencer.Guard(ctx, epoch)
}

// leading returns the epoch this leader acts under.
func (f *releaseFence) leading(ctx context.Context) (uint64, error) {
	snapshot := f.fencer.Current()
	if !snapshot.CanMutate() {
		return 0, errors.New("this controller does not hold the authority lease")
	}
	return snapshot.Epoch, f.fencer.Guard(ctx, snapshot.Epoch)
}

// prepare marks intent's release sequenced, before it is submitted, when
// the cell has a release fence.
func (f *releaseFence) prepare(ctx context.Context, intent delivery.Intent) error {
	if f == nil {
		return nil
	}
	if spec, _ := f.spec(); spec == nil {
		return nil
	}
	if _, err := f.leading(ctx); err != nil {
		return err
	}
	_, err := f.kv.Put(ctx, sequencedKey(intent.Role, intent.Generation), []byte("{}"))
	return err
}

// sequence restarts the nodes of an accepted, sequenced release one at a
// time and opens the release to every restart once each node serves it. A
// node that fails the release keeps its backends fenced.
func (f *releaseFence) sequence(ctx context.Context, intent delivery.Intent) error {
	role, release := intent.Role, intent.Generation
	if _, err := f.kv.Get(ctx, sequencedKey(role, release)); errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	epoch, err := f.leading(ctx)
	if err != nil {
		return err
	}
	api, err := f.client(ctx)
	if err != nil {
		return err
	}
	spec, addresses := f.spec()
	if spec == nil {
		// The cell dropped its fence: return every recorded backend, then
		// let every node restart at once.
		if err := f.restoreAll(ctx, api, epoch); err != nil {
			return err
		}
		return f.kv.Delete(ctx, sequencedKey(role, release))
	}
	grace, settle := durationOr(spec.DrainGraceSeconds, defaultFenceGrace), durationOr(spec.SettleSeconds, defaultFenceSettle)
	desired, err := f.hosts.ListDesired(ctx, role)
	if err != nil {
		return err
	}
	var nodes []string
	for _, d := range desired {
		if !d.Withdrawn && releaseOf(d.Generation) == release && !slices.Contains(nodes, d.Node) {
			nodes = append(nodes, d.Node)
		}
	}
	// Nodes already fenced go first: after a failed release the rollback
	// returns them before it takes a serving node out, so a set never waits
	// on a node that only later in the turn would serve again.
	fenced := map[string]bool{}
	for _, node := range nodes {
		if _, found, err := f.record(ctx, node); err != nil {
			return err
		} else if found {
			fenced[node] = true
		}
	}
	slices.SortFunc(nodes, func(a, b string) int {
		if fenced[a] != fenced[b] {
			if fenced[a] {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	for _, node := range nodes {
		state, err := f.nodeState(ctx, role, release, node)
		if err != nil {
			return err
		}
		if state != "running" {
			if err := f.fence(ctx, api, epoch, *spec, node, addresses[node], grace); err != nil {
				return err
			}
			if err := f.fencer.Guard(ctx, epoch); err != nil {
				return err
			}
			if _, err := f.kv.Put(ctx, permitKey(role, release, node), []byte("{}")); err != nil {
				return err
			}
			slog.Info("release fence permits a node", observability.ComponentKey, "rollout", "role", role,
				"release", release, "node", node)
			for state != "running" {
				if state == "failed" {
					return fmt.Errorf("%s replica %s failed release %d; its backends stay fenced", role, node, release)
				}
				if err := f.wait(ctx, epoch, fencePoll); err != nil {
					return fmt.Errorf("%s replica %s did not serve release %d: %w", role, node, release, err)
				}
				if state, err = f.nodeState(ctx, role, release, node); err != nil {
					return err
				}
			}
		}
		returned, err := f.restore(ctx, api, epoch, node)
		if err != nil {
			return err
		}
		if returned {
			if err := f.wait(ctx, epoch, settle); err != nil {
				return err
			}
		}
	}
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	for _, node := range nodes {
		if err := f.kv.Delete(ctx, permitKey(role, release, node)); err != nil {
			return err
		}
	}
	return f.kv.Delete(ctx, sequencedKey(role, release))
}

// nodeState is node's report of role at release: running, failed, or
// empty while it has none that is current.
func (f *releaseFence) nodeState(ctx context.Context, role string, release uint64, node string) (string, error) {
	statuses, err := f.hosts.ListHosts(ctx)
	if err != nil {
		return "", err
	}
	for _, status := range statuses {
		for _, report := range status.Reports {
			if report.Node != node || report.Role != role || releaseOf(report.Generation) != release ||
				time.Since(report.ObservedAt) >= host.ReportMaxAge {
				continue
			}
			if report.State == "running" || report.State == "failed" {
				return report.State, nil
			}
		}
	}
	return "", nil
}

// fence takes node's in-rotation backends out of every fenced set, each
// only while another backend of its set serves healthy. It records them
// first, as fencing, and marks the record fenced once every one is
// offline; a fence a deposed leader left part-way is finished from its
// record.
func (f *releaseFence) fence(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence, node,
	address string, grace time.Duration,
) error {
	record, found, err := f.record(ctx, node)
	if err != nil {
		return err
	}
	if found && record.Phase == "fenced" {
		return nil
	}
	if found {
		// A part-way fence resumes only while each backend it would still
		// take out has a healthy alternative on another node.
		for _, backend := range record.Backends {
			if _, err := f.guarded(ctx, api, epoch, record.LoadBalancerID,
				cellspec.FencedSet{Name: backend.Set, Port: backend.Port}, node, backend.IP); err != nil {
				return err
			}
		}
	} else {
		if address == "" {
			// No host grant names the node: its backends are unknown, so it
			// is never restarted unfenced.
			return fmt.Errorf("no host grant gives the address of %s; its restart stays held", node)
		}
		record = fenceRecord{LoadBalancerID: spec.LoadBalancerID, Phase: "fencing"}
		for _, set := range spec.BackendSets {
			backend, err := f.guarded(ctx, api, epoch, spec.LoadBalancerID, set, node, address)
			if err != nil {
				return err
			}
			if backend != nil {
				record.Backends = append(record.Backends, *backend)
			}
		}
		if len(record.Backends) == 0 {
			return nil
		}
		if err := f.save(ctx, epoch, node, record); err != nil {
			return err
		}
	}
	for _, offline := range []bool{false, true} {
		for _, backend := range record.Backends {
			if err := f.update(ctx, api, epoch, record.LoadBalancerID, backend, true, offline); err != nil {
				return err
			}
		}
		if !offline {
			// In-flight requests finish on the drained backends.
			if err := f.wait(ctx, epoch, grace); err != nil {
				return err
			}
		}
	}
	record.Phase = "fenced"
	if err := f.save(ctx, epoch, node, record); err != nil {
		return err
	}
	slog.Info("release fence took a node out of rotation", observability.ComponentKey, "rollout", "node", node,
		"backends", len(record.Backends))
	return nil
}

// guarded returns node's backend in set when it is in rotation, once a
// backend of another node serves healthy in the set; nil when it is not in
// rotation.
func (f *releaseFence) guarded(ctx context.Context, api lb.API, epoch uint64, id string, set cellspec.FencedSet,
	node, address string,
) (*fencedBackend, error) {
	for {
		observed, err := api.ListBackends(ctx, id, set.Name)
		if err != nil {
			return nil, err
		}
		unhealthy, err := api.UnhealthyBackends(ctx, id, set.Name)
		if err != nil {
			return nil, err
		}
		mine, others := false, 0
		for _, backend := range observed {
			switch {
			case backend.IP == address && backend.Port == set.Port:
				mine = backend.Serving()
			case backend.IP != address && backend.Serving() && !unhealthy[backend.Name()]:
				// Only another node's backend keeps the set serving.
				others++
			}
		}
		if !mine {
			return nil, nil
		}
		if others > 0 {
			return &fencedBackend{Set: set.Name, IP: address, Port: set.Port}, nil
		}
		// The node's backend is the set's last healthy one: wait for
		// another rather than drop the set.
		if err := f.wait(ctx, epoch, fencePoll); err != nil {
			return nil, fmt.Errorf("%s backend of %s is the last healthy one: %w", set.Name, node, err)
		}
	}
}

// update sets one backend's drain and offline flags under the epoch.
func (f *releaseFence) update(ctx context.Context, api lb.API, epoch uint64, id string, backend fencedBackend,
	drain, offline bool,
) error {
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	request, err := api.UpdateBackend(ctx, id, backend.Set, lb.Backend{IP: backend.IP, Port: backend.Port}.Fenced(drain, offline))
	if err != nil {
		return err
	}
	return api.WaitWorkRequest(ctx, request)
}

func (f *releaseFence) record(ctx context.Context, node string) (fenceRecord, bool, error) {
	entry, err := f.kv.Get(ctx, fencedKey(node))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return fenceRecord{}, false, nil
	}
	if err != nil {
		return fenceRecord{}, false, err
	}
	var record fenceRecord
	if err := json.Unmarshal(entry.Value(), &record); err != nil {
		return fenceRecord{}, false, fmt.Errorf("decode the fence of %s: %w", node, err)
	}
	return record, true, nil
}

func (f *releaseFence) save(ctx context.Context, epoch uint64, node string, record fenceRecord) error {
	wire, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = f.kv.Put(ctx, fencedKey(node), wire)
	return err
}

// restore returns the backends recorded for node to rotation on the load
// balancer they were taken from, and waits until their health checks
// pass; it reports whether any were returned.
func (f *releaseFence) restore(ctx context.Context, api lb.API, epoch uint64, node string) (bool, error) {
	record, found, err := f.record(ctx, node)
	if err != nil || !found {
		return false, err
	}
	for _, backend := range record.Backends {
		if err := f.update(ctx, api, epoch, record.LoadBalancerID, backend, false, false); err != nil {
			return false, err
		}
	}
	for _, backend := range record.Backends {
		name := lb.Backend{IP: backend.IP, Port: backend.Port}.Name()
		for {
			unhealthy, err := api.UnhealthyBackends(ctx, record.LoadBalancerID, backend.Set)
			if err != nil {
				return false, err
			}
			if !unhealthy[name] {
				break
			}
			if err := f.wait(ctx, epoch, fencePoll); err != nil {
				return false, fmt.Errorf("%s backend %s did not pass its health check: %w", backend.Set, name, err)
			}
		}
	}
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return false, err
	}
	slog.Info("release fence returned a node to rotation", observability.ComponentKey, "rollout", "node", node)
	return true, f.kv.Delete(ctx, fencedKey(node))
}

// restoreAll returns every recorded fence.
func (f *releaseFence) restoreAll(ctx context.Context, api lb.API, epoch uint64) error {
	keys, err := f.kv.ListKeysFiltered(ctx, fencedKey("*"))
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for key := range keys.Keys() {
		if _, err := f.restore(ctx, api, epoch, strings.TrimPrefix(key, fencedKey(""))); err != nil {
			return err
		}
	}
	return nil
}

func durationOr(seconds int, fallback time.Duration) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
