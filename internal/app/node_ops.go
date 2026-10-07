package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
)

// Node operations (TS-632) are the one way a cell's servers change: ts-orch
// node drain|undrain|reboot|resize. The authority leader runs them one at a
// time, each the same way: take the node's backends out of every fenced
// load balancer set (drain, the grace for in-flight requests, offline, each
// only while the set's quorum guard holds without it), act, check that the
// node serves again, and return its backends once their health checks
// pass. The check is the cell's own: the node's controller is back in the
// JetStream cluster and every role desired on the node reports running at
// its desired generation, which needs the member's /readyz (TerraBase
// answers it only once caught up with its peers) since the action.
//
// An operation is a record in the release channel bucket, written before
// anything changes, so a new leader resumes it. drain keeps the node out
// (holder maintenance) until undrain; the other operations hold it out
// (holder operation) while they run, and after they fail until undrain.
const (
	nodeOpDrain   = "drain"
	nodeOpUndrain = "undrain"
	nodeOpReboot  = "reboot"
	nodeOpResize  = "resize"

	nodeOpQueued  = "queued"
	nodeOpRunning = "running"
	nodeOpDone    = "done"
	nodeOpFailed  = "failed"

	// holdOperation holds a node out while one operation runs on it.
	holdOperation = "operation"

	nodeOpSubmitKind = "node.submit"
	nodeOpStatusKind = "node.status"

	nodeOpPoll    = 5 * time.Second
	nodeOpTimeout = 30 * time.Minute
)

func nodeOpKey(node string) string { return "nodeop." + node }

// nodeOp is one operation and its progress.
type nodeOp struct {
	ID       string  `json:"id"`
	Node     string  `json:"node"`
	Op       string  `json:"op"`
	OCPUs    float32 `json:"ocpus,omitzero"`
	MemoryGB float32 `json:"memory_gb,omitzero"`
	Actor    string  `json:"actor"`
	State    string  `json:"state"`
	// Step is the running operation's step: fence, act, check or return.
	Step        string    `json:"step,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// ActedAt is when the node's instance was changed; the check waits for
	// reports newer than it.
	ActedAt time.Time `json:"acted_at,omitzero"`
	// Session is the node's host agent session before the change. A report
	// from another session proves the node restarted; empty when nothing
	// restarts it.
	Session string `json:"session,omitempty"`
}

func (op nodeOp) active() bool { return op.State == nodeOpQueued || op.State == nodeOpRunning }

// nodeOpRequest is the operator's request.
type nodeOpRequest struct {
	Node     string  `json:"node,omitempty"`
	Op       string  `json:"op,omitempty"`
	OCPUs    float32 `json:"ocpus,omitzero"`
	MemoryGB float32 `json:"memory_gb,omitzero"`
}

// nodeFenceStatus is one node's fence: who holds it out and its backends.
type nodeFenceStatus struct {
	Node     string          `json:"node"`
	Holders  []string        `json:"holders"`
	Backends []fencedBackend `json:"backends"`
}

type nodeOpReply struct {
	Operation  *nodeOp           `json:"operation,omitempty"`
	Operations []nodeOp          `json:"operations,omitempty"`
	Fences     []nodeFenceStatus `json:"fences,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// nodeInstance is a node's OCI instance as observed.
type nodeInstance struct {
	ID       string
	Name     string
	State    string
	OCPUs    float32
	MemoryGB float32
}

// nodeCompute changes a node's instance. Find locates it by its display
// name, the node's name; Instances lists every one the nodes may be.
type nodeCompute interface {
	Find(ctx context.Context, node string) (nodeInstance, error)
	Instances(ctx context.Context) ([]nodeInstance, error)
	Reboot(ctx context.Context, id string) error
	Resize(ctx context.Context, id string, ocpus, memoryGB float32) error
}

// nodeOps runs node operations on the authority leader.
type nodeOps struct {
	fence *releaseFence
	// compute opens the instance client on first use.
	compute func(context.Context) (nodeCompute, error)
	// cluster returns nil once node's controller, if it runs one, is back
	// in a whole JetStream cluster; nil checks nothing.
	cluster func(ctx context.Context, node string) error
	// poll overrides nodeOpPoll in tests.
	poll time.Duration
	wake chan struct{}
	now  func() time.Time

	mu  sync.Mutex
	api nodeCompute
}

func newNodeOps(fence *releaseFence, compute func(context.Context) (nodeCompute, error),
	cluster func(context.Context, string) error,
) *nodeOps {
	return &nodeOps{fence: fence, compute: compute, cluster: cluster, wake: make(chan struct{}, 1), now: time.Now}
}

// findNode is the one instance named node.
func findNode(instances []nodeInstance, node string) (nodeInstance, error) {
	var found []nodeInstance
	for _, instance := range instances {
		if instance.Name == node {
			found = append(found, instance)
		}
	}
	if len(found) != 1 {
		return nodeInstance{}, fmt.Errorf("%d instances are named %s", len(found), node)
	}
	return found[0], nil
}

func (o *nodeOps) instances(ctx context.Context) (nodeCompute, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.api == nil {
		api, err := o.compute(ctx)
		if err != nil {
			return nil, fmt.Errorf("open the compute client: %w", err)
		}
		o.api = api
	}
	return o.api, nil
}

// serve answers one signed node request. Any trusted signer may read the
// status; changing a node needs can_register_hosts.
func (o *nodeOps) serve(ctx context.Context, wire []byte, cell string, policy signerPolicy, fencer authority.Fencer,
) (nodeOpReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return nodeOpReply{}, err
	}
	trusted, ok := policy.trusted(envelope.KeyID)
	if !ok || trusted.Actor != envelope.Actor {
		return nodeOpReply{}, errors.New("node request signer is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: cell, Kind: envelope.Kind,
		Actor: trusted.Actor, OperationID: envelope.OperationID, Generation: envelope.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return nodeOpReply{}, err
	}
	if envelope.Epoch == 0 || fencer.Current().Epoch != envelope.Epoch {
		return nodeOpReply{}, authority.ErrFenced
	}
	if envelope.Kind == nodeOpStatusKind {
		return o.status(ctx)
	}
	if grant, _ := policy.grant(trusted.Actor); !grant.CanRegisterHosts {
		return nodeOpReply{}, fmt.Errorf("trusted signer %s may not change nodes (can_register_hosts)", trusted.Actor)
	}
	var request nodeOpRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return nodeOpReply{}, err
	}
	op, err := o.submit(ctx, envelope.Epoch, trusted.Actor, envelope.OperationID, request)
	if err != nil {
		return nodeOpReply{}, err
	}
	return nodeOpReply{Operation: &op}, nil
}

// submit validates request and queues it. It refuses an operation that
// would break a set's quorum guard now, rather than queue it behind a
// failure nobody is fixing; one that waits for another operation queues.
func (o *nodeOps) submit(ctx context.Context, epoch uint64, actor, id string, request nodeOpRequest) (nodeOp, error) {
	switch request.Op {
	case nodeOpDrain, nodeOpUndrain, nodeOpReboot:
		if request.OCPUs != 0 || request.MemoryGB != 0 {
			return nodeOp{}, fmt.Errorf("node %s takes no shape", request.Op)
		}
	case nodeOpResize:
		if request.OCPUs <= 0 || request.OCPUs > 64 || request.MemoryGB <= 0 || request.MemoryGB > 1024 {
			return nodeOp{}, errors.New("node resize needs --ocpus and --memory-gb")
		}
	default:
		return nodeOp{}, fmt.Errorf("unknown node operation %q", request.Op)
	}
	spec, addresses := o.fence.spec()
	if spec == nil {
		return nodeOp{}, errors.New("the cell spec has no release_fence, so no load balancer set to take nodes out of")
	}
	if addresses[request.Node] == "" {
		return nodeOp{}, fmt.Errorf("no host grant names node %q", request.Node)
	}
	current, found, err := o.load(ctx, request.Node)
	if err != nil {
		return nodeOp{}, err
	}
	if found && current.active() {
		return nodeOp{}, fmt.Errorf("node %s already has a %s operation %s (%s)", request.Node, current.Op, current.ID, current.State)
	}
	record, held, err := o.fence.record(ctx, request.Node)
	if err != nil {
		return nodeOp{}, err
	}
	switch {
	case request.Op == nodeOpUndrain && (!held || !slices.ContainsFunc(record.holders(), func(h string) bool {
		return h == holdMaintenance || h == holdOperation
	})):
		return nodeOp{}, fmt.Errorf("node %s is not drained", request.Node)
	case request.Op != nodeOpUndrain && !held:
		if err := o.quorum(ctx, request.Node); err != nil {
			return nodeOp{}, err
		}
	}
	now := o.now().UTC()
	op := nodeOp{ID: id, Node: request.Node, Op: request.Op, OCPUs: request.OCPUs, MemoryGB: request.MemoryGB,
		Actor: actor, State: nodeOpQueued, RequestedAt: now, UpdatedAt: now}
	if err := o.save(ctx, epoch, op); err != nil {
		return nodeOp{}, err
	}
	slog.Info("node operation queued", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op, "actor", actor)
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return op, nil
}

// quorum refuses to take node out while a set it serves in would keep
// fewer than its min_serving healthy backends of other nodes.
func (o *nodeOps) quorum(ctx context.Context, node string) error {
	spec, addresses := o.fence.spec()
	api, err := o.fence.client(ctx)
	if err != nil {
		return err
	}
	for _, set := range spec.BackendSets {
		observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return err
		}
		backend := fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name, IP: addresses[node], Port: set.Port}
		if !slices.ContainsFunc(observed, func(b lb.Backend) bool { return b.IP == backend.IP && b.Port == set.Port && b.Serving() }) {
			continue
		}
		serving, err := servingOthers(ctx, api, backend)
		if err != nil {
			return err
		}
		if serving < set.Min() {
			return fmt.Errorf("refused: taking %s out of %s would leave %d healthy backends serving; the set keeps at least %d",
				node, set.Name, serving, set.Min())
		}
	}
	return nil
}

// status lists every node's latest operation and every fenced node.
func (o *nodeOps) status(ctx context.Context) (nodeOpReply, error) {
	var reply nodeOpReply
	keys, err := o.fence.keys(ctx, nodeOpKey("*"))
	if err != nil {
		return reply, err
	}
	for _, key := range keys {
		op, found, err := o.load(ctx, strings.TrimPrefix(key, nodeOpKey("")))
		if err != nil {
			return reply, err
		}
		if found {
			reply.Operations = append(reply.Operations, op)
		}
	}
	fenced, err := o.fence.keys(ctx, fencedKey("*"))
	if err != nil {
		return reply, err
	}
	for _, key := range fenced {
		node := strings.TrimPrefix(key, fencedKey(""))
		record, found, err := o.fence.record(ctx, node)
		if err != nil {
			return reply, err
		}
		if found {
			reply.Fences = append(reply.Fences, nodeFenceStatus{Node: node, Holders: record.holders(), Backends: record.Backends})
		}
	}
	return reply, nil
}

func (o *nodeOps) load(ctx context.Context, node string) (nodeOp, bool, error) {
	entry, err := o.fence.kv.Get(ctx, nodeOpKey(node))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nodeOp{}, false, nil
	}
	if err != nil {
		return nodeOp{}, false, err
	}
	var op nodeOp
	if err := json.Unmarshal(entry.Value(), &op); err != nil {
		return nodeOp{}, false, fmt.Errorf("decode the operation of %s: %w", node, err)
	}
	return op, true, nil
}

func (o *nodeOps) save(ctx context.Context, epoch uint64, op nodeOp) error {
	op.UpdatedAt = o.now().UTC()
	wire, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if err := o.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = o.fence.kv.Put(ctx, nodeOpKey(op.Node), wire)
	return err
}

// run executes queued operations on the leader, one at a time, oldest
// first; a running one, which a deposed leader left, goes first.
func (o *nodeOps) run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if o.fence.fencer.Current().CanMutate() {
			if err := o.pass(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("node operation", observability.ComponentKey, "nodes", "error", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		case <-o.wake:
		}
	}
}

// pass runs every pending operation in turn.
func (o *nodeOps) pass(ctx context.Context) error {
	for {
		op, found, err := o.next(ctx)
		if err != nil || !found {
			return err
		}
		epoch, err := o.fence.leading(ctx)
		if err != nil {
			return err
		}
		runCtx, cancel := context.WithTimeout(ctx, nodeOpTimeout)
		err = o.execute(runCtx, epoch, &op)
		cancel()
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || ctx.Err() != nil {
			// The next leader resumes it.
			return err
		}
		op.State, op.Step = nodeOpDone, ""
		if err != nil {
			op.State, op.Reason = nodeOpFailed, err.Error()
			slog.Error("node operation failed", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op, "error", err)
		} else {
			slog.Info("node operation done", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op)
		}
		if err := o.save(ctx, epoch, op); err != nil {
			return err
		}
	}
}

func (o *nodeOps) next(ctx context.Context) (nodeOp, bool, error) {
	status, err := o.status(ctx)
	if err != nil {
		return nodeOp{}, false, err
	}
	var best nodeOp
	found := false
	for _, op := range status.Operations {
		if !op.active() {
			continue
		}
		if !found || op.State == nodeOpRunning && best.State != nodeOpRunning ||
			op.State == best.State && op.RequestedAt.Before(best.RequestedAt) {
			best, found = op, true
		}
	}
	return best, found, nil
}

// execute runs op from its recorded step. Each step is recorded before it
// starts, and the instance change is recorded only after OCI accepted it,
// so a resumed operation may repeat a reboot but never skips one.
func (o *nodeOps) execute(ctx context.Context, epoch uint64, op *nodeOp) error {
	step := func(name string) error {
		op.State, op.Step = nodeOpRunning, name
		return o.save(ctx, epoch, *op)
	}
	spec, addresses := o.fence.spec()
	if spec == nil {
		return errors.New("the cell spec dropped its release_fence")
	}
	api, err := o.fence.client(ctx)
	if err != nil {
		return err
	}
	grace := durationOr(spec.DrainGraceSeconds, defaultFenceGrace)
	switch op.Op {
	case nodeOpDrain:
		if err := step("fence"); err != nil {
			return err
		}
		return o.fence.fence(ctx, api, epoch, *spec, op.Node, addresses[op.Node], grace, holdMaintenance)
	case nodeOpUndrain:
		if err := step("check"); err != nil {
			return err
		}
		if err := o.serving(ctx, epoch, *op); err != nil {
			return err
		}
		if err := step("return"); err != nil {
			return err
		}
		// A failed operation's hold goes too.
		for _, holder := range []string{holdOperation, holdMaintenance} {
			if _, err := o.fence.restore(ctx, api, epoch, op.Node, holder, true); err != nil {
				return err
			}
		}
		return nil
	}
	if op.Step == "" || op.Step == "fence" {
		if err := step("fence"); err != nil {
			return err
		}
		if err := o.fence.fence(ctx, api, epoch, *spec, op.Node, addresses[op.Node], grace, holdOperation); err != nil {
			return err
		}
	}
	if op.ActedAt.IsZero() {
		if err := step("act"); err != nil {
			return err
		}
		if err := o.act(ctx, op); err != nil {
			return err
		}
		op.ActedAt = o.now().UTC()
	}
	if err := step("check"); err != nil {
		return err
	}
	if err := o.serving(ctx, epoch, *op); err != nil {
		return err
	}
	if err := step("return"); err != nil {
		return err
	}
	_, err = o.fence.restore(ctx, api, epoch, op.Node, holdOperation, true)
	return err
}

// act changes the node's instance. The node's controller, if it runs one,
// must be in a whole JetStream cluster first: a reboot must not take the
// cluster below its quorum.
func (o *nodeOps) act(ctx context.Context, op *nodeOp) error {
	if o.cluster != nil {
		if err := o.cluster(ctx, op.Node); err != nil {
			return err
		}
	}
	api, err := o.instances(ctx)
	if err != nil {
		return err
	}
	instance, err := api.Find(ctx, op.Node)
	if err != nil {
		return err
	}
	if op.Op == nodeOpResize && instance.OCPUs == op.OCPUs && instance.MemoryGB == op.MemoryGB {
		op.Session = ""
		return nil
	}
	if op.Session, err = nodeSession(ctx, o.fence.hosts, op.Node); err != nil {
		return err
	}
	slog.Info("node operation changes the instance", observability.ComponentKey, "nodes", "node", op.Node,
		"op", op.Op, "instance", instance.ID)
	if op.Op == nodeOpResize {
		return api.Resize(ctx, instance.ID, op.OCPUs, op.MemoryGB)
	}
	return api.Reboot(ctx, instance.ID)
}

// nodeSession is the session of node's host agent in its newest report.
func nodeSession(ctx context.Context, hosts seatrollout.Hosts, node string) (string, error) {
	statuses, err := hosts.ListHosts(ctx)
	if err != nil {
		return "", err
	}
	session, newest := "", time.Time{}
	for _, status := range statuses {
		for _, report := range status.Reports {
			if report.Node == node && report.ObservedAt.After(newest) {
				session, newest = report.SessionID, report.ObservedAt
			}
		}
	}
	return session, nil
}

// serving waits until op's node serves again: its instance runs (with the
// requested shape), its host agent restarted, its controller is back in a
// whole cluster, and every role desired on it reports running at its
// desired generation since the change.
func (o *nodeOps) serving(ctx context.Context, epoch uint64, op nodeOp) error {
	for {
		reason, err := o.notServing(ctx, op)
		if err != nil {
			return err
		}
		if reason == "" {
			return nil
		}
		if err := o.wait(ctx, epoch); err != nil {
			return fmt.Errorf("%s does not serve: %s: %w", op.Node, reason, err)
		}
	}
}

func (o *nodeOps) wait(ctx context.Context, epoch uint64) error {
	poll := o.poll
	if poll <= 0 {
		poll = nodeOpPoll
	}
	return o.fence.wait(ctx, epoch, poll)
}

// notServing says why op's node does not serve yet, or "" once it does.
func (o *nodeOps) notServing(ctx context.Context, op nodeOp) (string, error) {
	if !op.ActedAt.IsZero() {
		api, err := o.instances(ctx)
		if err != nil {
			return "", err
		}
		instance, err := api.Find(ctx, op.Node)
		if err != nil {
			return "", err
		}
		if instance.State != "RUNNING" {
			return "its instance is " + instance.State, nil
		}
		if op.Op == nodeOpResize && (instance.OCPUs != op.OCPUs || instance.MemoryGB != op.MemoryGB) {
			return fmt.Sprintf("its instance has %g OCPUs and %g GB", instance.OCPUs, instance.MemoryGB), nil
		}
		if op.Session != "" {
			session, err := nodeSession(ctx, o.fence.hosts, op.Node)
			if err != nil {
				return "", err
			}
			if session == op.Session {
				return "its host agent has not restarted", nil
			}
		}
	}
	if o.cluster != nil {
		if err := o.cluster(ctx, op.Node); err != nil {
			return err.Error(), nil
		}
	}
	return nodeRolesServing(ctx, o.fence.hosts, op.Node, op.ActedAt)
}

// nodeRolesServing says which role desired on node does not report running
// at its desired generation after since, or "" when every one does.
func nodeRolesServing(ctx context.Context, hosts seatrollout.Hosts, node string, since time.Time) (string, error) {
	statuses, err := hosts.ListHosts(ctx)
	if err != nil {
		return "", err
	}
	for _, status := range statuses {
		if status.Registration.Node != node {
			continue
		}
		for _, role := range status.Registration.Roles {
			desired, err := hosts.ListDesired(ctx, role)
			if err != nil {
				return "", err
			}
			index := slices.IndexFunc(desired, func(d host.Desired) bool { return d.Node == node && !d.Withdrawn })
			if index < 0 {
				continue
			}
			if !slices.ContainsFunc(status.Reports, func(report host.Report) bool {
				return report.Node == node && report.Role == role && report.State == "running" &&
					report.Generation == desired[index].Generation && report.ObservedAt.After(since) &&
					time.Since(report.ObservedAt) < host.ReportMaxAge
			}) {
				return role + " does not report running at its desired generation", nil
			}
		}
	}
	return "", nil
}
