package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
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
// while the set's quorum guard (min_serving backends of other nodes) serves
// healthy. The fenced backends are recorded before the load balancer
// changes, so a new leader returns them.
//
// Node operations and controller rollouts take nodes out the same way. A
// node's record names its holders: release, rollout and maintenance. Its
// backends return only when the last holder lets go.
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

// Holders of a node's fence.
const (
	holdRelease     = "release"
	holdRollout     = "rollout"
	holdMaintenance = "maintenance"
)

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
	// LoadBalancerID is the load balancer the backend was taken from; it
	// returns there whatever the cell spec names since.
	LoadBalancerID string `json:"load_balancer_id"`
	Set            string `json:"set"`
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	// Weight and Backup are the backend's own, restored with it.
	Weight int  `json:"weight,omitzero"`
	Backup bool `json:"backup,omitzero"`
	// Offline is set once the backend is out of rotation.
	Offline bool `json:"offline,omitzero"`
	// Keep the admitted quorum when the live spec is changed or removed.
	Minimum int `json:"min_serving,omitempty"`
}

// fenceRecord is a node's fence, recorded before the load balancer
// changes: every backend taken, or being taken, out of rotation, and who
// holds it out.
type fenceRecord struct {
	Backends []fencedBackend `json:"backends"`
	Holders  []string        `json:"holders,omitempty"`
}

// holders are the record's holders; a record written before holders
// existed belongs to a release fence.
func (r fenceRecord) holders() []string {
	if len(r.Holders) == 0 {
		return []string{holdRelease}
	}
	return r.Holders
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
	// seats reports TerraBase seats (controller.terrabase_seats), which
	// sequence TerraBase themselves.
	seats bool
	// sleep waits for a grace or a poll; tests shorten it.
	sleep func(context.Context, time.Duration) error

	mu  sync.Mutex
	api lb.API
	// nodes serializes the fences and restores of each node; quorum
	// serializes taking any backend out, so two nodes never pass the
	// quorum guard on the same observation.
	nodes  sync.Map
	quorum sync.Mutex
}

// lockNode serializes changes to node's fence in this leader.
func (f *releaseFence) lockNode(node string) func() {
	lock, _ := f.nodes.LoadOrStore(node, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	return lock.(*sync.Mutex).Unlock
}

func (f *releaseFence) lockNodeContext(ctx context.Context, node string) (func(), error) {
	lock, _ := f.nodes.LoadOrStore(node, &sync.Mutex{})
	if err := lockFenceContext(ctx, lock.(*sync.Mutex)); err != nil {
		return nil, err
	}
	return lock.(*sync.Mutex).Unlock, nil
}

// Keep bounded operations cancellable while legacy operations hold the lock.
func lockFenceContext(ctx context.Context, lock *sync.Mutex) error {
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if lock.TryLock() {
			if err := ctx.Err(); err != nil {
				lock.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-retry.C:
		}
	}
}

// minServing is set's quorum guard in the current fence.
func (f *releaseFence) minServing(set string) int {
	if spec, _ := f.spec(); spec != nil {
		for _, fenced := range spec.BackendSets {
			if fenced.Name == set {
				return fenced.Min()
			}
		}
	}
	return cellspec.DefaultMinServing
}

func (f *releaseFence) client(ctx context.Context) (lb.API, error) {
	if err := lockFenceContext(ctx, &f.mu); err != nil {
		return nil, err
	}
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
	if spec, _ := f.spec(); spec == nil || f.seats && intent.Role == terrabase.Role {
		// With TerraBase seats the seat controller orders TerraBase
		// restarts and drains; one sequencer gates a role.
		return nil
	}
	if _, err := f.leading(ctx); err != nil {
		return err
	}
	// A release issued again keeps its mark, and with it its canary.
	_, err := f.kv.Create(ctx, sequencedKey(intent.Role, intent.Generation), []byte("{}"))
	if errors.Is(err, jetstream.ErrKeyExists) {
		return nil
	}
	return err
}

// sequence restarts the nodes of an accepted, sequenced release one at a
// time and opens the release to every restart once each node serves it. A
// node that fails the release keeps its backends fenced. With gate and the
// fence's canary, the first node must pass gate before the next restarts
// (TS-623); a rollback passes a nil gate.
func (f *releaseFence) sequence(ctx context.Context, intent delivery.Intent, gate canaryGate) error {
	role, release := intent.Role, intent.Generation
	// Without a fence every recorded backend returns first, whether or not
	// this release was marked.
	if err := f.reconcile(ctx); err != nil {
		return err
	}
	if _, err := f.kv.Get(ctx, sequencedKey(role, release)); errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	epoch, err := f.leading(ctx)
	if err != nil {
		return err
	}
	spec, addresses := f.spec()
	if spec == nil {
		// The cell dropped its fence: every node of the release restarts
		// at once.
		if err := f.fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		return f.kv.Delete(ctx, sequencedKey(role, release))
	}
	api, err := f.client(ctx)
	if err != nil {
		return err
	}
	// A node fenced by an earlier release and no longer allocated, its
	// replica withdrawn or moved, keeps no backend out of rotation. Without
	// a replica to wait for, its backends return without waiting for their
	// health checks: the load balancer routes nothing to a failing one, and
	// every fence still needs a healthy alternative.
	left, err := f.keys(ctx, fencedKey("*"))
	if err != nil {
		return err
	}
	for _, key := range left {
		node := strings.TrimPrefix(key, fencedKey(""))
		if allocated, err := f.allocated(ctx, role, release, node); err != nil {
			return err
		} else if !allocated {
			if _, err := f.restore(ctx, api, epoch, node, holdRelease, false); err != nil {
				return err
			}
		}
	}
	grace, settle := durationOr(spec.DrainGraceSeconds, defaultFenceGrace), durationOr(spec.SettleSeconds, defaultFenceSettle)
	var canary *canaryRecord
	if gate != nil && spec.Canary != nil {
		if canary, err = f.canary(ctx, role, release); err != nil {
			return err
		}
	}
	// The workload reconciler may move the release's replicas while it
	// rolls, so the allocations are read again after every node: a node it
	// adds is fenced and permitted before the release opens.
	done := map[string]bool{}
	var nodes []string
nodes:
	for {
		node, found, err := f.nextNode(ctx, role, release, done)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if canary != nil && canary.Node != "" && !canary.Passed && node != canary.Node && !done[canary.Node] {
			// A new leader resumes with the canary, whichever node another
			// fence holds out.
			if allocated, err := f.allocated(ctx, role, release, canary.Node); err != nil {
				return err
			} else if allocated {
				node = canary.Node
			} else {
				*canary = canaryRecord{}
			}
		}
		done[node], nodes = true, append(nodes, node)
		state, err := f.nodeState(ctx, role, release, node)
		if err != nil {
			return err
		}
		target := canaryTarget{Role: role, Node: node, Address: addresses[node]}
		if spec.Canary != nil {
			target.Canary = *spec.Canary
		}
		if canary != nil && canary.Node == "" {
			// The first node is the canary. Its baseline is taken before it
			// changes; one that already serves the release has none, so
			// every check must pass.
			canary.Node = node
			if state != "running" {
				canary.Baseline = slices.Sorted(maps.Keys(gate(ctx, target)))
				slog.Info("release canary baseline", observability.ComponentKey, "rollout", "role", role,
					"release", release, "node", node, "failing", canary.Baseline)
			}
			if err := f.saveCanary(ctx, epoch, role, release, *canary); err != nil {
				return err
			}
		}
		if state != "running" {
			if err := f.fence(ctx, api, epoch, *spec, node, addresses[node], grace, holdRelease); err != nil {
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
					return fmt.Errorf("%w: %s replica %s failed release %d; its backends stay fenced", errBadRelease, role, node, release)
				}
				if err := f.wait(ctx, epoch, fencePoll); err != nil {
					return fmt.Errorf("%s replica %s did not serve release %d: %w", role, node, release, err)
				}
				if allocated, err := f.allocated(ctx, role, release, node); err != nil {
					return err
				} else if !allocated {
					// The reconciler withdrew the replica: its node's other
					// workloads return to rotation, and the next node may be
					// its replacement.
					slog.Info("release fence returns a withdrawn node", observability.ComponentKey, "rollout", "role", role,
						"release", release, "node", node)
					if _, err := f.restore(ctx, api, epoch, node, holdRelease, false); err != nil {
						return err
					}
					if canary != nil && canary.Node == node && !canary.Passed {
						// The next node is the canary.
						*canary = canaryRecord{}
						if err := f.saveCanary(ctx, epoch, role, release, *canary); err != nil {
							return err
						}
					}
					continue nodes
				}
				if state, err = f.nodeState(ctx, role, release, node); err != nil {
					return err
				}
			}
		}
		if canary != nil && canary.Node == node && !canary.Passed {
			// Still out of rotation: the release reaches no other node
			// unless the canary passes.
			if err := f.gateCanary(ctx, epoch, gate, target, release, canary); err != nil {
				return err
			}
		}
		returned, err := f.restore(ctx, api, epoch, node, holdRelease, true)
		if err != nil {
			return err
		}
		if returned {
			if err := f.wait(ctx, epoch, settle); err != nil {
				return err
			}
		}
	}
	keys := []string{sequencedKey(role, release)}
	for _, node := range nodes {
		keys = append(keys, permitKey(role, release, node))
	}
	// The mark goes last, so an interrupted cleanup leaves the release held,
	// never open.
	slices.Reverse(keys)
	for _, key := range keys {
		if err := f.deleteGuarded(ctx, epoch, key); err != nil {
			return err
		}
	}
	return f.sweep(ctx, epoch, role, release)
}

// nextNode is the next node with an active allocation of role at release
// that done does not hold yet: nodes already fenced first, since after a
// failed release the rollback returns them before it takes a serving node
// out, then by name.
func (f *releaseFence) nextNode(ctx context.Context, role string, release uint64, done map[string]bool) (string, bool, error) {
	desired, err := f.hosts.ListDesired(ctx, role)
	if err != nil {
		return "", false, err
	}
	best, bestFenced, found := "", false, false
	for _, d := range desired {
		if d.Withdrawn || releaseOf(d.Generation) != release || done[d.Node] {
			continue
		}
		_, fenced, err := f.record(ctx, d.Node)
		if err != nil {
			return "", false, err
		}
		if !found || fenced && !bestFenced || fenced == bestFenced && d.Node < best {
			best, bestFenced, found = d.Node, fenced, true
		}
	}
	return best, found, nil
}

// canary reads release's canary from its mark.
func (f *releaseFence) canary(ctx context.Context, role string, release uint64) (*canaryRecord, error) {
	entry, err := f.kv.Get(ctx, sequencedKey(role, release))
	if err != nil {
		return nil, err
	}
	var record canaryRecord
	if err := json.Unmarshal(entry.Value(), &record); err != nil {
		return nil, fmt.Errorf("decode the canary of %s release %d: %w", role, release, err)
	}
	return &record, nil
}

func (f *releaseFence) saveCanary(ctx context.Context, epoch uint64, role string, release uint64, record canaryRecord) error {
	wire, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = f.kv.Put(ctx, sequencedKey(role, release), wire)
	return err
}

// gateCanary runs gate against the canary, which serves the release, until
// no check that passed in its baseline fails, at most canaryAttempts times;
// it fails the release otherwise.
func (f *releaseFence) gateCanary(ctx context.Context, epoch uint64, gate canaryGate, target canaryTarget, release uint64,
	canary *canaryRecord,
) error {
	started := time.Now()
	failed := gate(ctx, target)
	regressions := canary.regressions(failed)
	for attempt := 1; len(regressions) > 0 && attempt < canaryAttempts; attempt++ {
		slog.Warn("release canary failed a check; retrying", observability.ComponentKey, "rollout", "role", target.Role,
			"release", release, "node", target.Node, "failed", regressions)
		if err := f.wait(ctx, epoch, canaryRetry); err != nil {
			return err
		}
		failed = gate(ctx, target)
		regressions = canary.regressions(failed)
	}
	if len(regressions) > 0 {
		return fmt.Errorf("%w: %s canary %s failed release %d's gate (%s); its backends stay fenced", errBadRelease,
			target.Role, target.Node, release, strings.Join(regressions, "; "))
	}
	canary.Passed = true
	slog.Info("release canary passed", observability.ComponentKey, "rollout", "role", target.Role, "release", release,
		"node", target.Node, "took", time.Since(started).Round(time.Second), "failing_before", canary.Baseline,
		"failing", slices.Sorted(maps.Keys(failed)))
	return f.saveCanary(ctx, epoch, target.Role, release, *canary)
}

// allocated reports whether node has an active allocation of role at
// release.
func (f *releaseFence) allocated(ctx context.Context, role string, release uint64, node string) (bool, error) {
	desired, err := f.hosts.ListDesired(ctx, role)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(desired, func(d host.Desired) bool {
		return d.Node == node && !d.Withdrawn && releaseOf(d.Generation) == release
	}), nil
}

func (f *releaseFence) loadJSON(ctx context.Context, key string, value any) error {
	entry, err := f.kv.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(entry.Value(), value, json.RejectUnknownMembers(true))
}

// keys lists the bucket's keys that match filter.
func (f *releaseFence) keys(ctx context.Context, filter string) ([]string, error) {
	lister, err := f.kv.ListKeysFiltered(ctx, filter)
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer lister.Stop()
	var keys []string
	for key := range lister.Keys() {
		keys = append(keys, key)
	}
	// The lister closes early, without an error, when ctx ends.
	return keys, ctx.Err()
}

// deleteGuarded deletes key while this leader still holds epoch: the
// bucket enforces no epoch, and a new leader may be writing the same keys.
func (f *releaseFence) deleteGuarded(ctx context.Context, epoch uint64, key string) error {
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	return f.kv.Delete(ctx, key)
}

// sweep deletes the marks and permits of role's releases before release,
// which a failed or superseded sequence left. Only now that every node
// serves release may they go: while desired still named an older release,
// its mark held the restarts into it.
func (f *releaseFence) sweep(ctx context.Context, epoch uint64, role string, release uint64) error {
	keys, err := f.keys(ctx, "fence."+role+".>")
	if err != nil {
		return err
	}
	for _, key := range keys {
		number, _, _ := strings.Cut(strings.TrimPrefix(key, "fence."+role+"."), ".")
		if older, err := strconv.ParseUint(number, 10, 64); err == nil && older < release {
			if err := f.deleteGuarded(ctx, epoch, key); err != nil {
				return err
			}
		}
	}
	return nil
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

// fence takes node's in-rotation backends out of every fenced set for
// holder. Each backend is recorded before the load balancer changes and
// marked offline once it is out, so a fence a deposed leader left part-way
// is finished from its record. A record that an earlier fence left, under
// another fence configuration, gains every backend the current one takes
// out, so the node never restarts while one of them serves. Right before
// each backend is drained, and again before it is set offline, the set's
// quorum guard must hold without it.
func (f *releaseFence) fence(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence, node,
	address string, grace time.Duration, holder string,
) error {
	if address == "" {
		// No host grant names the node: its backends are unknown, so it is
		// never restarted unfenced.
		return fmt.Errorf("no host grant gives the address of %s; its restart stays held", node)
	}
	unlock, err := f.lockNodeContext(ctx, node)
	if err != nil {
		return err
	}
	defer unlock()
	return f.fenceLocked(ctx, api, epoch, spec, node, address, grace, holder)
}

// fenceLocked is fence with node's lock held.
func (f *releaseFence) fenceLocked(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence, node,
	address string, grace time.Duration, holder string,
) error {
	record, found, err := f.record(ctx, node)
	if err != nil {
		return err
	}
	added := !slices.Contains(record.holders(), holder)
	if added {
		record.Holders = append(slices.Clone(record.holders()), holder)
		if !found {
			record.Holders = []string{holder}
		}
		slices.Sort(record.Holders)
	}
	for _, set := range spec.BackendSets {
		observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return err
		}
		for _, backend := range observed {
			if backend.IP != address || backend.Port != set.Port || !backend.Serving() ||
				slices.ContainsFunc(record.Backends, func(recorded fencedBackend) bool {
					return recorded.LoadBalancerID == spec.LoadBalancerID && recorded.Set == set.Name &&
						recorded.IP == address && recorded.Port == set.Port
				}) {
				continue
			}
			weight, backup := backend.Shape()
			record.Backends = append(record.Backends, fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name,
				IP: address, Port: set.Port, Weight: weight, Backup: backup, Minimum: set.Min()})
			added = true
		}
	}
	if added || !found {
		if err := f.save(ctx, epoch, node, record); err != nil {
			return err
		}
	}
	return f.takeOutRecord(ctx, api, epoch, node, record, grace)
}

// takeOutRecord takes the recorded backends that are not offline yet out
// of rotation, each under the quorum guard, and records them offline.
func (f *releaseFence) takeOutRecord(ctx context.Context, api lb.API, epoch uint64, node string, record fenceRecord,
	grace time.Duration,
) error {
	if !slices.ContainsFunc(record.Backends, func(backend fencedBackend) bool { return !backend.Offline }) {
		return nil
	}
	for _, offline := range []bool{false, true} {
		for _, backend := range record.Backends {
			if backend.Offline {
				continue
			}
			if err := f.takeOut(ctx, api, epoch, backend, node, offline); err != nil {
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
	for i := range record.Backends {
		record.Backends[i].Offline = true
	}
	if err := f.save(ctx, epoch, node, record); err != nil {
		return err
	}
	slog.Info("release fence took a node out of rotation", observability.ComponentKey, "rollout", "node", node,
		"backends", len(record.Backends))
	return nil
}

// takeOut drains backend, or sets it offline, once the quorum guard holds
// without it: at least the set's min_serving backends of other nodes serve
// healthy. Until then it waits, so an operation that would break the
// quorum queues behind the one that holds it.
func (f *releaseFence) takeOut(ctx context.Context, api lb.API, epoch uint64, backend fencedBackend, node string,
	offline bool,
) error {
	minimum := f.minServing(backend.Set)
	if backend.Minimum > 0 {
		minimum = backend.Minimum
		if spec, _ := f.spec(); spec != nil {
			for _, set := range spec.BackendSets {
				if set.Name == backend.Set {
					minimum = max(minimum, set.Min())
				}
			}
		}
	}
	for {
		if err := lockFenceContext(ctx, &f.quorum); err != nil {
			return err
		}
		serving, err := servingOthers(ctx, api, backend)
		if err == nil && serving >= minimum {
			err = f.update(ctx, api, epoch, backend, true, offline)
		}
		f.quorum.Unlock()
		if err != nil || serving >= minimum {
			return err
		}
		if err := f.wait(ctx, epoch, fencePoll); err != nil {
			return fmt.Errorf("%s backend of %s: %d other backends serve healthy, the set keeps at least %d (the last healthy ones stay): %w",
				backend.Set, node, serving, minimum, err)
		}
	}
}

// servingOthers counts the backends of other nodes that serve healthy in
// backend's set.
func servingOthers(ctx context.Context, api lb.API, backend fencedBackend) (int, error) {
	observed, err := api.ListBackends(ctx, backend.LoadBalancerID, backend.Set)
	if err != nil {
		return 0, err
	}
	unhealthy, err := api.UnhealthyBackends(ctx, backend.LoadBalancerID, backend.Set)
	if err != nil {
		return 0, err
	}
	serving := 0
	for _, other := range observed {
		if other.IP != backend.IP && other.Serving() && !unhealthy[other.Name()] {
			serving++
		}
	}
	return serving, nil
}

// update sets one backend's drain and offline flags under the epoch.
func (f *releaseFence) update(ctx context.Context, api lb.API, epoch uint64, backend fencedBackend, drain, offline bool) error {
	id := backend.LoadBalancerID
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	request, err := api.UpdateBackend(ctx, id, backend.Set,
		lb.Backend{IP: backend.IP, Port: backend.Port}.Shaped(backend.Weight, backend.Backup).Fenced(drain, offline))
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

// restore lets holder go of node's fence. When no other holder keeps the
// node out, it returns the recorded backends to rotation on the load
// balancer they were taken from and, with healthy, waits until their
// health checks pass; it reports whether any were returned.
func (f *releaseFence) restore(ctx context.Context, api lb.API, epoch uint64, node, holder string, healthy bool) (bool, error) {
	unlock, err := f.lockNodeContext(ctx, node)
	if err != nil {
		return false, err
	}
	defer unlock()
	return f.restoreLocked(ctx, api, epoch, node, holder, healthy)
}

// restoreLocked is restore with node's lock held.
func (f *releaseFence) restoreLocked(ctx context.Context, api lb.API, epoch uint64, node, holder string, healthy bool,
) (bool, error) {
	record, found, err := f.record(ctx, node)
	if err != nil || !found {
		return false, err
	}
	if others := slices.DeleteFunc(slices.Clone(record.holders()), func(h string) bool { return h == holder }); len(others) > 0 {
		if len(others) == len(record.holders()) {
			return false, nil
		}
		record.Holders = others
		return false, f.save(ctx, epoch, node, record)
	}
	// Recorded as back in rotation before the load balancer changes, so a
	// restore cut short leaves a record the next fence drains again; the
	// holder stays on it until it is gone, so the holder finishes it.
	record.Holders = []string{holder}
	for i := range record.Backends {
		record.Backends[i].Offline = false
	}
	if err := f.save(ctx, epoch, node, record); err != nil {
		return false, err
	}
	for _, backend := range record.Backends {
		if err := f.update(ctx, api, epoch, backend, false, false); err != nil {
			return false, err
		}
	}
	for _, backend := range record.Backends {
		name := lb.Backend{IP: backend.IP, Port: backend.Port}.Name()
		for healthy {
			unhealthy, err := api.UnhealthyBackends(ctx, backend.LoadBalancerID, backend.Set)
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
	return len(record.Backends) > 0, f.kv.Delete(ctx, fencedKey(node))
}

// reconcile undoes every release's fence once the cell has no release
// fence: a dropped fence leaves no backend out of rotation for a release,
// even one a failed release left and no later release marks, and no
// restart held; other holders keep their nodes out. It returns
// recorded backends without waiting for their health checks, which a
// failed node may never pass, and clears every mark and permit, so every
// node may restart at once. The leader runs it on every pass, bounded.
func (f *releaseFence) reconcile(ctx context.Context) error {
	if f == nil {
		return nil
	}
	if spec, _ := f.spec(); spec != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	fenced, err := f.keys(ctx, fencedKey("*"))
	if err != nil {
		return err
	}
	marks, err := f.keys(ctx, "fence.>")
	if err != nil {
		return err
	}
	if len(fenced) == 0 && len(marks) == 0 {
		return nil
	}
	epoch, err := f.leading(ctx)
	if err != nil {
		return err
	}
	if len(fenced) > 0 {
		api, err := f.client(ctx)
		if err != nil {
			return err
		}
		for _, key := range fenced {
			if _, err := f.restore(ctx, api, epoch, strings.TrimPrefix(key, fencedKey("")), holdRelease, false); err != nil {
				return err
			}
		}
	}
	for _, key := range marks {
		if err := f.deleteGuarded(ctx, epoch, key); err != nil {
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
