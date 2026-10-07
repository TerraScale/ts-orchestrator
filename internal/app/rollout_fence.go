package app

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
)

// rolloutFence drains a node before an orchestrator self-update restarts
// it (TS-632): the executor's gate holds a controller or host step until
// the unit's node is out of every fenced load balancer set (holder
// rollout), one node at a time, and the leader returns the node once the
// unit serves its release again and every role on the node reports running
// at its desired generation since. Restarting a controller restarts its
// node's host agent and workloads, so the same flow as a node operation.
type rolloutFence struct {
	// ctx bounds the background fences: the controller's run.
	ctx   context.Context
	fence *releaseFence
	// nodeOf names the node a unit runs on.
	nodeOf func(unit string) string
	// unitOf is its inverse.
	unitOf func(node string) string
	// timeout bounds one background fence.
	timeout time.Duration

	mu sync.Mutex
	// fencing names the nodes a background fence is taking out, and last
	// the error each one's last fence ended with.
	fencing map[string]bool
	last    map[string]error
	// restarted is the incarnation a fenced unit first proved its release
	// in, and when this leader saw it; reports must be newer.
	restarted map[string]incarnation
}

type incarnation struct {
	nonce string
	at    time.Time
}

func newRolloutFence(ctx context.Context, fence *releaseFence, nodeOf, unitOf func(string) string) *rolloutFence {
	return &rolloutFence{ctx: ctx, fence: fence, nodeOf: nodeOf, unitOf: unitOf, timeout: 15 * time.Minute,
		fencing: map[string]bool{}, last: map[string]error{}, restarted: map[string]incarnation{}}
}

// check is the gate: nil once unit's node is out of rotation for the
// rollout, or has nothing behind the load balancer. It never waits: it
// starts the fence in the background and holds the step until it is done.
func (r *rolloutFence) check(ctx context.Context, unit string) error {
	node := r.nodeOf(unit)
	spec, addresses := r.fence.spec()
	if spec == nil || addresses[node] == "" {
		return nil
	}
	record, found, err := r.fence.record(ctx, node)
	if err != nil {
		return fmt.Errorf("%w: read the fence of %s: %v", rolloutexec.ErrGateHeld, node, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fencing[node] {
		return fmt.Errorf("%w: taking %s out of rotation on the load balancer", rolloutexec.ErrGateHeld, node)
	}
	if found && slices.Contains(record.holders(), holdRollout) &&
		!slices.ContainsFunc(record.Backends, func(b fencedBackend) bool { return !b.Offline }) {
		return nil
	}
	// One node at a time: the previous one returns first.
	if other, err := r.otherHeld(ctx, node); err != nil || other != "" {
		return fmt.Errorf("%w: %s is still out of rotation for the rollout%v", rolloutexec.ErrGateHeld, other,
			errSuffix(err))
	}
	r.fencing[node] = true
	last := r.last[node]
	go r.run(node)
	return fmt.Errorf("%w: taking %s out of rotation on the load balancer%v", rolloutexec.ErrGateHeld, node, errSuffix(last))
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return " (last attempt: " + err.Error() + ")"
}

// run fences node for the rollout under the current lease.
func (r *rolloutFence) run(node string) {
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()
	err := func() error {
		epoch, err := r.fence.leading(ctx)
		if err != nil {
			return err
		}
		spec, addresses := r.fence.spec()
		if spec == nil {
			return nil
		}
		api, err := r.fence.client(ctx)
		if err != nil {
			return err
		}
		return r.fence.fence(ctx, api, epoch, *spec, node, addresses[node],
			durationOr(spec.DrainGraceSeconds, defaultFenceGrace), holdRollout)
	}()
	if err != nil {
		slog.Warn("rollout fence", observability.ComponentKey, "rollout", "node", node, "error", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fencing[node], r.last[node] = false, err
}

// otherHeld names another node a rollout holds out of rotation.
func (r *rolloutFence) otherHeld(ctx context.Context, node string) (string, error) {
	nodes, err := r.heldNodes(ctx)
	if err != nil {
		return "", err
	}
	for _, held := range nodes {
		if held != node {
			return held, nil
		}
	}
	return "", nil
}

func (r *rolloutFence) heldNodes(ctx context.Context) ([]string, error) {
	keys, err := r.fence.keys(ctx, fencedKey("*"))
	if err != nil {
		return nil, err
	}
	var nodes []string
	for _, key := range keys {
		node := strings.TrimPrefix(key, fencedKey(""))
		record, found, err := r.fence.record(ctx, node)
		if err != nil {
			return nil, err
		}
		if found && slices.Contains(record.holders(), holdRollout) {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// returnLoop returns served nodes every few seconds on the leader.
func (r *rolloutFence) returnLoop(ctx context.Context, store *rollout.Store, proofs rolloutexec.ProofSource,
	fencer authority.Fencer,
) {
	ticker := time.NewTicker(fencePoll)
	defer ticker.Stop()
	for {
		if fencer.Current().CanMutate() {
			if err := r.returnNodes(ctx, store, proofs); err != nil && ctx.Err() == nil {
				slog.Warn("rollout fence", observability.ComponentKey, "rollout", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// returnNodes returns the nodes the rollout holds whose unit serves again.
func (r *rolloutFence) returnNodes(ctx context.Context, store *rollout.Store, proofs rolloutexec.ProofSource) error {
	nodes, err := r.heldNodes(ctx)
	if err != nil || len(nodes) == 0 {
		return err
	}
	active, _, ok, err := store.Active(ctx)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		r.mu.Lock()
		fencing := r.fencing[node]
		r.mu.Unlock()
		if fencing {
			continue
		}
		since, ready := r.unitServes(node, active, ok, proofs)
		if !ready {
			continue
		}
		if reason, err := nodeRolesServing(ctx, r.fence.hosts, node, since); err != nil || reason != "" {
			if err != nil {
				return err
			}
			continue
		}
		epoch, err := r.fence.leading(ctx)
		if err != nil {
			return err
		}
		api, err := r.fence.client(ctx)
		if err != nil {
			return err
		}
		// Bounded: a backend that never passes its health check must not
		// stop the loop from returning the others.
		restoreCtx, cancel := context.WithTimeout(ctx, r.timeout)
		_, err = r.fence.restore(restoreCtx, api, epoch, node, holdRollout, true)
		cancel()
		if err != nil {
			return err
		}
		r.mu.Lock()
		delete(r.restarted, node)
		r.mu.Unlock()
		slog.Info("rollout fence returned a node", observability.ComponentKey, "rollout", "node", node)
	}
	return nil
}

// unitServes reports whether node's unit is done with its step and proves
// the release it should run, and since when this leader has seen that
// incarnation. A unit that waits for its step, or is being stepped, keeps
// its node out.
func (r *rolloutFence) unitServes(node string, record rollout.Record, active bool, proofs rolloutexec.ProofSource,
) (time.Time, bool) {
	unit := r.unitOf(node)
	want := ""
	if progress, in := record.Units[unit]; active && in {
		switch progress.State {
		case rollout.UnitPending, rollout.UnitPreparing, rollout.UnitRollingBack:
			return time.Time{}, false
		case rollout.UnitSoaking, rollout.UnitPromoted:
			want = record.ToDigest
		case rollout.UnitRolledBack:
			want = record.FromDigest
		}
	}
	proof, ok := proofs.Latest(unit)
	if !ok || time.Since(proof.ReceivedAt) > rolloutexec.DefaultProofFreshness || want != "" && proof.BinarySHA256 != want {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seen, known := r.restarted[node]
	if !known || seen.nonce != proof.StartNonce {
		seen = incarnation{nonce: proof.StartNonce, at: time.Now()}
		r.restarted[node] = seen
	}
	return seen.at, true
}
