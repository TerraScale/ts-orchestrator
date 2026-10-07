package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// The edge reconciler (TS-632) owns every release_fence set that names a
// role: on the authority leader it keeps the set equal to the role's
// replicas, and in rotation only the ones that serve. Each pass it
//
//   - adds a backend for a replica that has none, out of rotation and held
//     for health, so it joins only once its node serves;
//   - takes a replica out whose host has reported it starting, stopped or
//     failed for edgeDownFor, held for health under the quorum guard;
//   - returns a node held for health once every role on it runs at its
//     desired generation and the load balancer's health checks pass;
//   - undoes hand edits: a backend that serves while its node's record keeps
//     it out is taken out again, a backend out of rotation that no record
//     explains is held for health (it returns once its node serves), and a
//     backup or weighted backend becomes a plain one;
//   - removes the backend of a node without a replica once it serves
//     nothing, and leaves alone, with a held decision, a backend that is no
//     node of the cell or still serves without a replica: a human decides;
//   - records a held decision for a granted node whose instance is missing,
//     renamed, or not running outside a node operation.
//
// Every change runs under the node's fence lock, after the backend set is
// read again, so it never races a fence, a restore or another pass.
const (
	holdHealth = "health"

	edgeInterval   = 30 * time.Second
	edgeDownFor    = 20 * time.Second
	edgeActTimeout = 3 * time.Minute
)

type edgeReconciler struct {
	cell  string
	fence *releaseFence
	// ops reads the nodes' instances and operations; nil checks none.
	ops      *nodeOps
	interval time.Duration
	// downFor overrides edgeDownFor in tests.
	downFor time.Duration

	mu sync.Mutex
	// down is when a node's role was first seen not serving.
	down map[string]time.Time
	// alerted is the held conditions already recorded.
	alerted map[string]bool
}

func newEdgeReconciler(cell string, fence *releaseFence) *edgeReconciler {
	return &edgeReconciler{cell: cell, fence: fence, interval: edgeInterval, downFor: edgeDownFor,
		down: map[string]time.Time{}, alerted: map[string]bool{}}
}

func (e *edgeReconciler) run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		if e.fence.fencer.Current().CanMutate() {
			if err := e.pass(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("edge reconcile", observability.ComponentKey, "edge", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pass reconciles every owned set once.
func (e *edgeReconciler) pass(ctx context.Context) error {
	spec, addresses := e.fence.spec()
	if spec == nil {
		return nil
	}
	epoch, err := e.fence.leading(ctx)
	if err != nil {
		return err
	}
	api, err := e.fence.client(ctx)
	if err != nil {
		return err
	}
	statuses, err := e.fence.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	nodeOf := map[string]string{}
	for node, address := range addresses {
		nodeOf[address] = node
	}
	held := map[string]bool{}
	var errs []error
	act := func(f func(context.Context) error) {
		actCtx, cancel := context.WithTimeout(ctx, edgeActTimeout)
		defer cancel()
		errs = append(errs, f(actCtx))
	}
	for _, set := range spec.BackendSets {
		if set.Role == "" {
			continue
		}
		desired, err := e.fence.hosts.ListDesired(ctx, set.Role)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		members := map[string]bool{}
		for _, d := range desired {
			if !d.Withdrawn && addresses[d.Node] != "" {
				members[d.Node] = true
			}
		}
		if len(members) == 0 {
			// Never empty a set on a desired state that reads empty.
			held[set.Name+": no "+set.Role+" replica has a host grant"] = true
			continue
		}
		observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		have := map[string]bool{}
		for _, backend := range observed {
			node, granted := nodeOf[backend.IP]
			switch {
			case !granted || backend.Port != set.Port:
				held[set.Name+": backend "+backend.Name()+" is no node of the cell"] = true
			case !members[node]:
				act(func(ctx context.Context) error {
					reason, err := e.unallocated(ctx, api, epoch, *spec, set, node)
					if reason != "" {
						held[set.Name+": "+reason] = true
					}
					return err
				})
			default:
				have[node] = true
				act(func(ctx context.Context) error {
					return e.member(ctx, api, epoch, *spec, set, node, statuses)
				})
			}
		}
		for _, node := range slices.Sorted(maps.Keys(members)) {
			if !have[node] {
				act(func(ctx context.Context) error { return e.add(ctx, api, epoch, *spec, set, node) })
			}
		}
	}
	if e.ops != nil {
		errs = append(errs, e.instances(ctx, addresses, held))
	}
	e.alert(ctx, epoch, held)
	return errors.Join(errs...)
}

// instances holds every granted node whose instance is not the one
// running instance named after it, outside a node operation.
func (e *edgeReconciler) instances(ctx context.Context, addresses map[string]string, held map[string]bool) error {
	api, err := e.ops.instances(ctx)
	if err != nil {
		return err
	}
	instances, err := api.Instances(ctx)
	if err != nil {
		return err
	}
	for _, node := range slices.Sorted(maps.Keys(addresses)) {
		instance, err := findNode(instances, node)
		if err != nil {
			held["instance: "+err.Error()+"; renamed or terminated outside ts-orch"] = true
			continue
		}
		if instance.State == "RUNNING" {
			continue
		}
		if op, found, err := e.ops.load(ctx, node); err != nil {
			return err
		} else if !found || !op.active() {
			held["instance: "+node+" is "+instance.State+" outside a node operation"] = true
		}
	}
	return nil
}

// alert records each newly held condition once, as a held decision, and
// forgets the ones that cleared.
func (e *edgeReconciler) alert(ctx context.Context, epoch uint64, held map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, condition := range slices.Sorted(maps.Keys(held)) {
		if e.alerted[condition] {
			continue
		}
		slog.Warn("edge reconcile leaves a backend to an operator", observability.ComponentKey, "edge", "condition", condition)
		decisionlog.Record(ctx, decisionlog.Decision{Region: e.cell, Actor: decisionlog.Actor{Slice: "edge"},
			Kind: decisionlog.KindHeld, Subject: decisionlog.Subject{Kind: "load-balancer", ID: condition},
			Summary: "Left a load balancer backend for an operator", Reason: "The change is ambiguous: " + condition,
			Status: decisionlog.StatusFailed, Epoch: epoch})
	}
	e.alerted = held
}

func (e *edgeReconciler) corrected(ctx context.Context, epoch uint64, node, summary string) {
	slog.Info("edge reconcile", observability.ComponentKey, "edge", "node", node, "change", summary)
	decisionlog.Record(ctx, decisionlog.Decision{Region: e.cell, Actor: decisionlog.Actor{Slice: "edge"},
		Kind: decisionlog.KindOCIDriftCorrected, Subject: decisionlog.Subject{Kind: "node", ID: node},
		Summary: summary, Status: decisionlog.StatusSucceeded, Epoch: epoch})
}

// backend finds node's backend in set, read again now.
func (e *edgeReconciler) backend(ctx context.Context, api lb.API, spec cellspec.ReleaseFence, set cellspec.FencedSet,
	node string,
) (lb.Backend, bool, error) {
	_, addresses := e.fence.spec()
	observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
	if err != nil {
		return lb.Backend{}, false, err
	}
	index := slices.IndexFunc(observed, func(b lb.Backend) bool { return b.IP == addresses[node] && b.Port == set.Port })
	if index < 0 {
		return lb.Backend{}, false, nil
	}
	return observed[index], true, nil
}

// member reconciles one replica's backend.
func (e *edgeReconciler) member(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence,
	set cellspec.FencedSet, node string, statuses []host.HostStatus,
) error {
	defer e.fence.lockNode(node)()
	record, found, err := e.fence.record(ctx, node)
	if err != nil {
		return err
	}
	backend, exists, err := e.backend(ctx, api, spec, set, node)
	if err != nil || !exists {
		return err
	}
	grace := durationOr(spec.DrainGraceSeconds, defaultFenceGrace)
	if found {
		holders := record.holders()
		pending := slices.ContainsFunc(record.Backends, func(b fencedBackend) bool { return !b.Offline })
		if slices.Contains(holders, holdHealth) {
			if reason, err := nodeRolesServing(ctx, e.fence.hosts, node, time.Time{}); err != nil || reason == "" {
				if err != nil {
					return err
				}
				if returned, err := e.fence.restoreLocked(ctx, api, epoch, node, holdHealth, true); err != nil || !returned {
					return err
				}
				e.corrected(ctx, epoch, node, "Returned a node that serves again")
				return nil
			}
			if pending && slices.Equal(holders, []string{holdHealth}) {
				return e.fence.takeOutRecord(ctx, api, epoch, node, record, grace)
			}
		}
		if pending || !backend.Serving() {
			// A fence or restore in progress owns it, or it is out.
			return nil
		}
		// A hand edit returned a backend its node's holders keep out, or
		// the set joined the fence after the node was taken out.
		index := slices.IndexFunc(record.Backends, func(b fencedBackend) bool {
			return b.LoadBalancerID == spec.LoadBalancerID && b.Set == set.Name && b.IP == backend.IP && b.Port == set.Port
		})
		if index < 0 {
			record.Backends = append(record.Backends, fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name,
				IP: backend.IP, Port: set.Port, Weight: 1})
		} else {
			record.Backends[index].Offline = false
		}
		if err := e.fence.save(ctx, epoch, node, record); err != nil {
			return err
		}
		if err := e.fence.takeOutRecord(ctx, api, epoch, node, record, grace); err != nil {
			return err
		}
		e.corrected(ctx, epoch, node, "Took a held node's backend out of rotation again")
		return nil
	}
	weight, backup := backend.Shape()
	switch {
	case !backend.Serving():
		// Out of rotation with no record: a hand edit or a lost record.
		// Held for health, it returns once the node serves.
		record := fenceRecord{Holders: []string{holdHealth}, Backends: []fencedBackend{{LoadBalancerID: spec.LoadBalancerID,
			Set: set.Name, IP: backend.IP, Port: set.Port, Weight: 1, Offline: true}}}
		if err := e.fence.save(ctx, epoch, node, record); err != nil {
			return err
		}
		e.corrected(ctx, epoch, node, "Held an unexplained out-of-rotation backend until its node serves")
		return nil
	case weight > 1 || backup:
		if err := e.fence.update(ctx, api, epoch, fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name,
			IP: backend.IP, Port: set.Port, Weight: 1}, false, false); err != nil {
			return err
		}
		e.corrected(ctx, epoch, node, "Made a backup or weighted backend a plain one")
		return nil
	}
	if !e.notServing(node, set.Role, statuses) {
		return nil
	}
	record = fenceRecord{Holders: []string{holdHealth}, Backends: []fencedBackend{{LoadBalancerID: spec.LoadBalancerID,
		Set: set.Name, IP: backend.IP, Port: set.Port, Weight: weight, Backup: backup}}}
	if err := e.fence.save(ctx, epoch, node, record); err != nil {
		return err
	}
	if err := e.fence.takeOutRecord(ctx, api, epoch, node, record, grace); err != nil {
		return err
	}
	e.corrected(ctx, epoch, node, "Took a replica that does not serve out of rotation")
	return nil
}

// notServing reports a role whose host has reported it starting, stopped
// or failed for downFor. A late or missing report is no evidence: the load
// balancer's own health check covers it, and a NATS hiccup must not make
// the set flap.
func (e *edgeReconciler) notServing(node, role string, statuses []host.HostStatus) bool {
	var newest host.Report
	for _, status := range statuses {
		for _, report := range status.Reports {
			if report.Node == node && report.Role == role && report.ObservedAt.After(newest.ObservedAt) {
				newest = report
			}
		}
	}
	key := node + "/" + role
	e.mu.Lock()
	defer e.mu.Unlock()
	if newest.ObservedAt.IsZero() || time.Since(newest.ObservedAt) >= host.ReportMaxAge ||
		newest.State == "running" || newest.State == "waiting" {
		delete(e.down, key)
		return false
	}
	since, seen := e.down[key]
	if !seen {
		e.down[key] = time.Now()
		return false
	}
	return time.Since(since) >= e.downFor
}

// add creates a replica's missing backend out of rotation, held for health.
func (e *edgeReconciler) add(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence,
	set cellspec.FencedSet, node string,
) error {
	defer e.fence.lockNode(node)()
	if _, exists, err := e.backend(ctx, api, spec, set, node); err != nil || exists {
		return err
	}
	_, addresses := e.fence.spec()
	record, found, err := e.fence.record(ctx, node)
	if err != nil {
		return err
	}
	if !found {
		record.Holders = []string{holdHealth}
	} else if !slices.Contains(record.holders(), holdHealth) {
		record.Holders = append(slices.Clone(record.holders()), holdHealth)
		slices.Sort(record.Holders)
	}
	created := fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name, IP: addresses[node], Port: set.Port,
		Weight: 1, Offline: true}
	record.Backends = append(slices.DeleteFunc(record.Backends, func(b fencedBackend) bool {
		return b.LoadBalancerID == created.LoadBalancerID && b.Set == created.Set && b.IP == created.IP && b.Port == created.Port
	}), created)
	// Recorded first, so the backend never exists unexplained.
	if err := e.fence.save(ctx, epoch, node, record); err != nil {
		return err
	}
	if err := e.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	request, err := api.CreateBackend(ctx, spec.LoadBalancerID, set.Name,
		lb.Backend{IP: created.IP, Port: created.Port}.Fenced(true, true))
	if err != nil {
		return err
	}
	if err := api.WaitWorkRequest(ctx, request); err != nil {
		return err
	}
	e.corrected(ctx, epoch, node, fmt.Sprintf("Added %s's backend to %s out of rotation", node, set.Name))
	return nil
}

// unallocated removes the backend of a node without a replica once it
// serves nothing; a serving, healthy one is left to an operator.
func (e *edgeReconciler) unallocated(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence,
	set cellspec.FencedSet, node string,
) (string, error) {
	defer e.fence.lockNode(node)()
	backend, exists, err := e.backend(ctx, api, spec, set, node)
	if err != nil || !exists {
		return "", err
	}
	if backend.Serving() {
		unhealthy, err := api.UnhealthyBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return "", err
		}
		if !unhealthy[backend.Name()] {
			return fmt.Sprintf("%s serves without a %s replica", node, set.Role), nil
		}
	}
	if err := e.fence.fencer.Guard(ctx, epoch); err != nil {
		return "", err
	}
	request, err := api.DeleteBackend(ctx, spec.LoadBalancerID, set.Name, backend.Name())
	if err != nil {
		return "", err
	}
	if err := api.WaitWorkRequest(ctx, request); err != nil {
		return "", err
	}
	if record, found, err := e.fence.record(ctx, node); err != nil {
		return "", err
	} else if found {
		record.Backends = slices.DeleteFunc(record.Backends, func(b fencedBackend) bool {
			return b.LoadBalancerID == spec.LoadBalancerID && b.Set == set.Name && b.IP == backend.IP && b.Port == set.Port
		})
		if err := e.fence.save(ctx, epoch, node, record); err != nil {
			return "", err
		}
	}
	e.corrected(ctx, epoch, node, fmt.Sprintf("Removed %s's backend from %s: it has no %s replica", node, set.Name, set.Role))
	return "", nil
}
