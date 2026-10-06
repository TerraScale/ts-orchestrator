package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

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

// fencedBackend is one backend a fence took out of rotation.
type fencedBackend struct {
	Set  string `json:"set"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// releaseFence is the leader's side of a release fence.
type releaseFence struct {
	kv    jetstream.KeyValue
	hosts seatrollout.Hosts
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

func (f *releaseFence) wait(ctx context.Context, d time.Duration) error {
	if f.sleep != nil {
		return f.sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
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
	spec, addresses := f.spec()
	if spec == nil {
		// The cell dropped its fence: every node may restart at once.
		return f.kv.Delete(ctx, sequencedKey(role, release))
	}
	api, err := f.client(ctx)
	if err != nil {
		return err
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
	slices.Sort(nodes)
	for _, node := range nodes {
		state, err := f.nodeState(ctx, role, release, node)
		if err != nil {
			return err
		}
		if state != "running" {
			if err := f.fence(ctx, api, *spec, node, addresses[node], grace); err != nil {
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
				if err := f.wait(ctx, fencePoll); err != nil {
					return fmt.Errorf("%s replica %s did not serve release %d: %w", role, node, release, err)
				}
				if state, err = f.nodeState(ctx, role, release, node); err != nil {
					return err
				}
			}
		}
		returned, err := f.restore(ctx, api, *spec, node)
		if err != nil {
			return err
		}
		if returned {
			if err := f.wait(ctx, settle); err != nil {
				return err
			}
		}
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
// only while another backend of its set serves healthy, and records them
// first. A node already fenced keeps its record.
func (f *releaseFence) fence(ctx context.Context, api lb.API, spec cellspec.ReleaseFence, node, address string,
	grace time.Duration,
) error {
	if _, err := f.kv.Get(ctx, fencedKey(node)); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	if address == "" {
		slog.Warn("release fence has no address for a node; it restarts unfenced", observability.ComponentKey, "rollout",
			"node", node)
		return nil
	}
	var fenced []fencedBackend
	var backends []lb.Backend
	for _, set := range spec.BackendSets {
		for {
			observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
			if err != nil {
				return err
			}
			unhealthy, err := api.UnhealthyBackends(ctx, spec.LoadBalancerID, set.Name)
			if err != nil {
				return err
			}
			mine, others := -1, 0
			for i, backend := range observed {
				switch {
				case backend.IP == address && backend.Port == set.Port:
					mine = i
				case backend.Serving() && !unhealthy[backend.Name()]:
					others++
				}
			}
			if mine < 0 || !observed[mine].Serving() {
				break
			}
			if others > 0 {
				fenced = append(fenced, fencedBackend{Set: set.Name, IP: address, Port: set.Port})
				backends = append(backends, observed[mine])
				break
			}
			// The node's backend is the set's last healthy one: wait for
			// another rather than drop the set.
			if err := f.wait(ctx, fencePoll); err != nil {
				return fmt.Errorf("%s backend of %s is the last healthy one: %w", set.Name, node, err)
			}
		}
	}
	if len(fenced) == 0 {
		return nil
	}
	record, err := json.Marshal(fenced)
	if err != nil {
		return err
	}
	if _, err := f.kv.Put(ctx, fencedKey(node), record); err != nil {
		return err
	}
	for _, offline := range []bool{false, true} {
		for i, backend := range backends {
			request, err := api.UpdateBackend(ctx, spec.LoadBalancerID, fenced[i].Set, backend.Fenced(true, offline))
			if err != nil {
				return err
			}
			if err := api.WaitWorkRequest(ctx, request); err != nil {
				return err
			}
		}
		if !offline {
			// In-flight requests finish on the drained backends.
			if err := f.wait(ctx, grace); err != nil {
				return err
			}
		}
	}
	slog.Info("release fence took a node out of rotation", observability.ComponentKey, "rollout", "node", node,
		"backends", len(fenced))
	return nil
}

// restore returns the backends recorded for node to rotation and waits
// until their health checks pass; it reports whether any were returned.
func (f *releaseFence) restore(ctx context.Context, api lb.API, spec cellspec.ReleaseFence, node string) (bool, error) {
	entry, err := f.kv.Get(ctx, fencedKey(node))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var fenced []fencedBackend
	if err := json.Unmarshal(entry.Value(), &fenced); err != nil {
		return false, fmt.Errorf("decode the fence of %s: %w", node, err)
	}
	for _, backend := range fenced {
		request, err := api.UpdateBackend(ctx, spec.LoadBalancerID, backend.Set,
			lb.Backend{IP: backend.IP, Port: backend.Port}.Fenced(false, false))
		if err != nil {
			return false, err
		}
		if err := api.WaitWorkRequest(ctx, request); err != nil {
			return false, err
		}
	}
	for _, backend := range fenced {
		name := lb.Backend{IP: backend.IP, Port: backend.Port}.Name()
		for {
			unhealthy, err := api.UnhealthyBackends(ctx, spec.LoadBalancerID, backend.Set)
			if err != nil {
				return false, err
			}
			if !unhealthy[name] {
				break
			}
			if err := f.wait(ctx, fencePoll); err != nil {
				return false, fmt.Errorf("%s backend %s did not pass its health check: %w", backend.Set, name, err)
			}
		}
	}
	slog.Info("release fence returned a node to rotation", observability.ComponentKey, "rollout", "node", node)
	return true, f.kv.Delete(ctx, fencedKey(node))
}

func durationOr(seconds int, fallback time.Duration) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
