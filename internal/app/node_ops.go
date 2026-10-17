package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
)

// Node operations (TS-632) are the one way a cell's servers change: ts-orch
// node drain|undrain|reboot|resize|add|retire. The authority leader runs
// them one at a time, each the same way: take the node's backends out of every fenced
// load balancer set (drain, the grace for in-flight requests, offline, each
// only while the set's quorum guard holds without it), act, check that the
// node serves again, and return its backends once their health checks
// pass. The check is the cell's own: the node's controller is back in the
// JetStream cluster and every role desired on the node reports running at
// its desired generation, which needs the member's /readyz (TerraBase
// answers it only once caught up with its peers) since the action.
//
// rename gives a node its new name (TS-609 renames gru-1-ctl-1 to ts-gru-1)
// once the cell spec grants the new name at its address: the instance, boot
// volume and hostname take it, the host re-enrolls under it at the reboot,
// and the roles desired on the old name move to it.
//
// add brings a granted, enrolled node in: its missing backends in the sets
// that name a role it runs are created out of rotation, then checked and
// returned. retire takes a node without replicas or a controller out for
// good: its backends are removed, its boot volume backed up (FULL, tagged
// delete-after a week) and its instance terminated.
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
	nodeOpAdd     = "add"
	nodeOpRetire  = "retire"
	nodeOpRename  = "rename"

	// retiredBackupDays is how long a retired node's boot volume backup is
	// kept (its delete-after tag).
	retiredBackupDays = 7

	nodeOpQueued  = "queued"
	nodeOpRunning = "running"
	nodeOpDone    = "done"
	nodeOpFailed  = "failed"

	// holdOperation holds a node out while one operation runs on it.
	holdOperation = "operation"

	nodeOpSubmitKind = "node.submit"
	nodeOpStatusKind = "node.status"

	nodeOpPoll = 5 * time.Second
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
	// Backup is a retired node's boot volume backup.
	Backup string `json:"backup,omitempty"`
	// From is a renamed node's old name and Instance its instance, which
	// keeps its ID across the rename.
	From     string `json:"from,omitempty"`
	Instance string `json:"instance,omitempty"`
	// The immutable journal entry retains the original signed authority.
	RequestSHA256   string `json:"request_sha256,omitempty"`
	RequestRevision uint64 `json:"request_revision,omitzero"`
}

func (op nodeOp) active() bool { return op.State == nodeOpQueued || op.State == nodeOpRunning }

// nodeOpRequest is the operator's request.
type nodeOpRequest struct {
	Node              string    `json:"node,omitempty"`
	To                string    `json:"to,omitempty"`
	Op                string    `json:"op,omitempty"`
	OCPUs             float32   `json:"ocpus,omitzero"`
	MemoryGB          float32   `json:"memory_gb,omitzero"`
	ExecutionDeadline time.Time `json:"execution_deadline,omitzero"`
}

// nodeFenceStatus is one node's fence: who holds it out and its backends.
type nodeFenceStatus struct {
	Node     string          `json:"node"`
	Holders  []string        `json:"holders"`
	Backends []fencedBackend `json:"backends"`
}

type nodeOpReply struct {
	NetBird      *network.Record           `json:"netbird,omitempty"`
	NetBirdNodes map[string]network.Status `json:"netbird_nodes,omitempty"`
	Operation    *nodeOp                   `json:"operation,omitempty"`
	Operations   []nodeOp                  `json:"operations,omitempty"`
	Fences       []nodeFenceStatus         `json:"fences,omitempty"`
	Error        string                    `json:"error,omitempty"`
}

// nodeInstance is a node's OCI instance as observed.
type nodeInstance struct {
	ID       string
	Name     string
	State    string
	OCPUs    float32
	MemoryGB float32
}

// nodeCompute reads ROOT observations and narrows a retained signed operation.
type nodeCompute interface {
	Prepare(ctx context.Context, request rootoci.NodeMaintenanceRequest) error
	Find(ctx context.Context, node string) (nodeInstance, error)
	Instances(ctx context.Context) ([]nodeInstance, error)
	Reboot(ctx context.Context, id string) error
	Resize(ctx context.Context, id string, ocpus, memoryGB float32) error
	// Backup takes a FULL, available backup of the instance's boot volume;
	// token makes a repeated request return the same one.
	Backup(ctx context.Context, id, name string, tags map[string]string, token string) (string, error)
	Terminate(ctx context.Context, id string) error
	// Rename gives the instance and its boot volume the node's new name.
	Rename(ctx context.Context, id, name string) error
}

// nodeDesired writes host desired state: host.Controller.
type nodeDesired interface {
	ApplyDesired(ctx context.Context, d host.Desired) (host.Receipt, error)
	RetireIdle(ctx context.Context, node string) (bool, error)
}

// nodeOps runs node operations on the authority leader.
type nodeOps struct {
	fence *releaseFence
	cfg   Config
	js    jetstream.JetStream
	// compute opens the instance client on first use.
	compute func(context.Context) (nodeCompute, error)
	// cluster returns nil once node's controller, if it runs one, is back
	// in a whole JetStream cluster; nil checks nothing.
	cluster func(ctx context.Context, node string) error
	// controllers reports a node that runs a controller, which retire
	// refuses: a controller leaves the cell through its membership. Nil
	// reports none.
	controllers func(node string) bool
	// pool reports a node the node scaler owns, which every operation
	// refuses: the scaler names, drains and removes it. Nil reports none.
	pool func(node string) bool
	// desired moves a renamed node's roles to its new name.
	desired nodeDesired
	// forget deletes an instance's host enrollment grant, so a renamed host
	// enrolls afresh under its new name.
	forget func(ctx context.Context, instanceID string) error
	// poll overrides nodeOpPoll in tests.
	poll time.Duration
	wake chan struct{}
	now  func() time.Time

	mu  sync.Mutex
	api nodeCompute
}

func newNodeOps(fence *releaseFence, compute func(context.Context) (nodeCompute, error),
	cluster func(context.Context, string) error, cfg Config, js jetstream.JetStream,
) *nodeOps {
	return &nodeOps{fence: fence, cfg: cfg, js: js, compute: compute, cluster: cluster, wake: make(chan struct{}, 1), now: time.Now}
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
	if envelope.Kind != nodeOpSubmitKind || envelope.Generation != 1 {
		return nodeOpReply{}, errors.New("node mutation requires its exact submit kind and generation")
	}
	if grant, _ := policy.grant(trusted.Actor); !grant.CanRegisterHosts {
		return nodeOpReply{}, fmt.Errorf("trusted signer %s may not change nodes (can_register_hosts)", trusted.Actor)
	}
	var request nodeOpRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return nodeOpReply{}, err
	}
	reference, err := o.retainRequest(ctx, wire, envelope)
	if err != nil {
		return nodeOpReply{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, envelope.ExpiresAt)
	defer cancel()
	api, err := o.instances(ctx)
	if err != nil {
		return nodeOpReply{}, err
	}
	if err := api.Prepare(ctx, rootoci.NodeMaintenanceRequest{OperationID: envelope.OperationID,
		RequestSHA256: reference.SHA256, RequestRevision: reference.Revision}); err != nil {
		return nodeOpReply{}, err
	}
	op, err := o.submit(ctx, envelope.Epoch, trusted.Actor, envelope.OperationID, request, reference)
	if err != nil {
		return nodeOpReply{}, err
	}
	return nodeOpReply{Operation: &op}, nil
}

// submit validates request and queues it. It refuses an operation that
// would break a set's quorum guard now, rather than queue it behind a
// failure nobody is fixing; one that waits for another operation queues.
func (o *nodeOps) submit(ctx context.Context, epoch uint64, actor, id string, request nodeOpRequest, original nodeOperationRequestReference) (nodeOp, error) {
	if !entityid.Valid(id) || !nodeOperationDigestValid(original.SHA256) || original.Revision == 0 {
		return nodeOp{}, errors.New("node operation needs its original signed request and canonical ULID")
	}
	from := ""
	switch request.Op {
	case nodeOpDrain, nodeOpUndrain, nodeOpReboot, nodeOpAdd, nodeOpRetire, nodeOpRename:
		if request.OCPUs != 0 || request.MemoryGB != 0 {
			return nodeOp{}, fmt.Errorf("node %s takes no shape", request.Op)
		}
		if (request.Op == nodeOpRename) != (request.To != "") {
			return nodeOp{}, errors.New("--new-name names a renamed node's new name, for node rename only")
		}
		if request.Op == nodeOpRename {
			if err := naming.Validate(request.To); err != nil || request.To == request.Node {
				return nodeOp{}, fmt.Errorf("node rename needs a new node name: %q", request.To)
			}
			// The operation, its fence and the node's grant go by the new name.
			from, request.Node = request.Node, request.To
		}
	case nodeOpResize:
		if request.OCPUs <= 0 || request.OCPUs > 64 || request.MemoryGB <= 0 || request.MemoryGB > 1024 {
			return nodeOp{}, errors.New("node resize needs --ocpus and --memory-gb")
		}
	default:
		return nodeOp{}, fmt.Errorf("unknown node operation %q", request.Op)
	}
	for _, node := range []string{from, request.Node} {
		if node != "" && o.pool != nil && o.pool(node) {
			return nodeOp{}, fmt.Errorf("%s is a pool node; the node scaler owns it", node)
		}
	}
	spec, addresses := o.fence.spec()
	if spec == nil {
		return nodeOp{}, errors.New("the cell spec has no release_fence, so no load balancer set to take nodes out of")
	}
	if addresses[request.Node] == "" {
		return nodeOp{}, fmt.Errorf("no host grant names node %q", request.Node)
	}
	if from != "" {
		if addresses[from] != "" {
			return nodeOp{}, fmt.Errorf("the cell spec still grants %s; grant %s at its address first (ts-orch service grant-host)",
				from, request.Node)
		}
		if o.controllers != nil && o.controllers(from) && !o.controllers(request.Node) {
			return nodeOp{}, fmt.Errorf("%s runs a controller: %s's host grant must name its controller slot (--controller)",
				from, request.Node)
		}
		if old, found, err := o.load(ctx, from); err != nil {
			return nodeOp{}, err
		} else if found && old.active() {
			return nodeOp{}, fmt.Errorf("node %s has a %s operation %s (%s)", from, old.Op, old.ID, old.State)
		}
	}
	current, found, err := o.load(ctx, request.Node)
	if err != nil {
		return nodeOp{}, err
	}
	if found && current.ID == id {
		if current.RequestSHA256 != original.SHA256 || current.RequestRevision != original.Revision || current.Op != request.Op || current.From != from || current.OCPUs != request.OCPUs || current.MemoryGB != request.MemoryGB || current.Actor != actor {
			return nodeOp{}, errors.New("node operation retry differs from its original request")
		}
		if _, err := o.originalRequest(ctx, current); err != nil {
			return nodeOp{}, err
		}
		return current, nil
	}
	if found && current.active() {
		return nodeOp{}, fmt.Errorf("node %s already has a %s operation %s (%s)", request.Node, current.Op, current.ID, current.State)
	}
	record, held, err := o.fence.record(ctx, request.Node)
	if err != nil {
		return nodeOp{}, err
	}
	if request.Op == nodeOpUndrain {
		// A fence a failed rename left at the node's address, under a name
		// no grant holds any more, is the node's to undrain.
		strays, err := o.strayFences(ctx, request.Node, addresses)
		if err != nil {
			return nodeOp{}, err
		}
		for _, stray := range strays {
			if !held {
				record.Holders = nil
			}
			record.Holders, held = append(record.Holders, stray.holders()...), true
		}
	}
	if request.Op == nodeOpRetire {
		if o.controllers != nil && o.controllers(request.Node) {
			return nodeOp{}, fmt.Errorf("node %s runs a controller; ts-orch node retire takes only hosts without one", request.Node)
		}
		if role, err := nodeReplica(ctx, o.fence.hosts, request.Node); err != nil {
			return nodeOp{}, err
		} else if role != "" {
			return nodeOp{}, fmt.Errorf("node %s still has a %s replica; move it first", request.Node, role)
		}
	}
	switch {
	case request.Op == nodeOpAdd:
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
		From: from, Actor: actor, State: nodeOpQueued, RequestedAt: now, UpdatedAt: now,
		RequestSHA256: original.SHA256, RequestRevision: original.Revision}
	if err := o.save(ctx, epoch, op); err != nil {
		return nodeOp{}, err
	}
	slog.InfoContext(ctx, "node operation queued", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op, "actor", actor)
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
	if reader, ok := o.fence.fencer.(netbirdStateReader); ok {
		state, err := readNetBirdState(ctx, reader)
		if err != nil {
			return reply, err
		}
		if state.Revision != 0 {
			reply.NetBird = &state.Record
		}
	}
	networkKeys, err := o.fence.keys(ctx, "netbird.status.*")
	if err != nil {
		return reply, err
	}
	if len(networkKeys) > 0 {
		reply.NetBirdNodes = make(map[string]network.Status, len(networkKeys))
	}
	for _, key := range networkKeys {
		var status network.Status
		if err := o.fence.loadJSON(ctx, key, &status); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return reply, err
			}
			continue
		}
		reply.NetBirdNodes[strings.TrimPrefix(key, "netbird.status.")] = status
	}
	keys, err := o.fence.keys(ctx, nodeOpKey("*"))
	if err != nil {
		return reply, err
	}
	for _, key := range keys {
		if strings.HasPrefix(key, nodeOperationRequestKey("")) {
			continue
		}
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
	if !entityid.Valid(op.ID) || op.Node != node || !nodeOperationDigestValid(op.RequestSHA256) || op.RequestRevision == 0 {
		return nodeOp{}, false, errors.New("stored node operation identity is invalid")
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
	if _, err := o.originalRequest(ctx, op); err != nil {
		return err
	}
	entry, err := o.fence.kv.Get(ctx, nodeOpKey(op.Node))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		_, err = o.fence.kv.Create(ctx, nodeOpKey(op.Node), wire)
		return err
	}
	if err != nil {
		return err
	}
	var current nodeOp
	if err := json.Unmarshal(entry.Value(), &current, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if current.ID == op.ID {
		if current.RequestSHA256 != op.RequestSHA256 || current.RequestRevision != op.RequestRevision || !current.RequestedAt.Equal(op.RequestedAt) ||
			!current.ActedAt.IsZero() && !current.ActedAt.Equal(op.ActedAt) || current.Backup != "" && current.Backup != op.Backup || current.Instance != "" && current.Instance != op.Instance || current.Session != "" && current.Session != op.Session {
			return errors.New("node operation original request, first attempt or accepted receipts cannot change")
		}
	} else if current.active() {
		return errors.New("another active node operation owns this node")
	}
	if err := o.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = o.fence.kv.Update(ctx, nodeOpKey(op.Node), wire, entry.Revision())
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
				slog.WarnContext(ctx, "node operation", observability.ComponentKey, "nodes", "error", err)
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
		original, err := o.originalRequest(ctx, op)
		if err != nil {
			return err
		}
		runCtx, cancel := context.WithDeadline(ctx, original.ExpiresAt)
		if original.Epoch != epoch || !time.Now().Before(original.ExpiresAt) {
			err = errors.New("original node operation authority expired or changed epoch")
		} else {
			err = o.execute(runCtx, epoch, &op)
		}
		cancel()
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || ctx.Err() != nil {
			// The next leader resumes it.
			return err
		}
		op.State, op.Step = nodeOpDone, ""
		if err != nil {
			op.State, op.Reason = nodeOpFailed, err.Error()
			slog.ErrorContext(runCtx, "node operation failed", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op, "error", err)
		} else {
			slog.InfoContext(runCtx, "node operation done", observability.ComponentKey, "nodes", "node", op.Node, "op", op.Op)
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
	ctx = withNodeMaintenanceRequest(ctx, *op)
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
	case nodeOpAdd:
		if err := step("act"); err != nil {
			return err
		}
		if err := o.addBackends(ctx, api, epoch, *spec, op.Node, addresses[op.Node]); err != nil {
			return err
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
		_, err := o.fence.restore(ctx, api, epoch, op.Node, holdOperation, true)
		return err
	case nodeOpRetire:
		return o.retire(ctx, epoch, api, *spec, addresses[op.Node], op, step)
	case nodeOpRename:
		return o.rename(ctx, epoch, api, *spec, addresses[op.Node], op, step)
	case nodeOpDrain:
		if err := step("fence"); err != nil {
			return err
		}
		return o.fence.fence(ctx, api, epoch, *spec, op.Node, addresses[op.Node], grace, holdMaintenance)
	case nodeOpUndrain:
		if err := step("check"); err != nil {
			return err
		}
		strays, err := o.strayFences(ctx, op.Node, addresses)
		if err != nil {
			return err
		}
		for name := range strays {
			if err := o.adoptFence(ctx, epoch, name, op.Node); err != nil {
				return err
			}
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
	slog.InfoContext(ctx, "node operation changes the instance", observability.ComponentKey, "nodes", "node", op.Node,
		"op", op.Op, "instance", instance.ID)
	if op.Op == nodeOpResize {
		return api.Resize(ctx, instance.ID, op.OCPUs, op.MemoryGB)
	}
	return api.Reboot(ctx, instance.ID)
}

// addBackends creates node's missing backends, out of rotation and held by
// the operation, in every set that names a role the node has a replica of.
func (o *nodeOps) addBackends(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence, node,
	address string,
) error {
	defer o.fence.lockNode(node)()
	record, found, err := o.fence.record(ctx, node)
	if err != nil {
		return err
	}
	if !found {
		record.Holders = []string{holdOperation}
	} else if !slices.Contains(record.holders(), holdOperation) {
		record.Holders = append(slices.Clone(record.holders()), holdOperation)
		slices.Sort(record.Holders)
	}
	var missing []fencedBackend
	for _, set := range spec.BackendSets {
		if set.Role == "" {
			continue
		}
		desired, err := o.fence.hosts.ListDesired(ctx, set.Role)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(desired, func(d host.Desired) bool { return d.Node == node && !d.Withdrawn }) {
			continue
		}
		observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(observed, func(b lb.Backend) bool { return b.IP == address && b.Port == set.Port }) {
			continue
		}
		created := fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: set.Name, IP: address, Port: set.Port, Weight: 1,
			Offline: true}
		record.Backends = append(record.Backends, created)
		missing = append(missing, created)
	}
	// Recorded first, so a backend never exists unexplained.
	if err := o.fence.save(ctx, epoch, node, record); err != nil {
		return err
	}
	for _, backend := range missing {
		if err := o.fence.fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		request, err := api.CreateBackend(ctx, backend.LoadBalancerID, backend.Set,
			lb.Backend{IP: backend.IP, Port: backend.Port}.Fenced(true, true))
		if err != nil {
			return err
		}
		if err := api.WaitWorkRequest(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

// retire fences the node, removes its backends, backs its boot volume up
// and terminates its instance; it ends once the instance is gone.
func (o *nodeOps) retire(ctx context.Context, epoch uint64, api lb.API, spec cellspec.ReleaseFence, address string,
	op *nodeOp, step func(string) error,
) error {
	if op.ActedAt.IsZero() {
		if op.Step == "" || op.Step == "fence" {
			if err := step("fence"); err != nil {
				return err
			}
			if err := o.fence.fence(ctx, api, epoch, spec, op.Node, address, durationOr(spec.DrainGraceSeconds,
				defaultFenceGrace), holdOperation); err != nil {
				return err
			}
		}
		if err := step("act"); err != nil {
			return err
		}
		if err := o.removeBackends(ctx, api, epoch, spec, op.Node, address); err != nil {
			return err
		}
		instances, err := o.instances(ctx)
		if err != nil {
			return err
		}
		instance, err := instances.Find(ctx, op.Node)
		if err != nil {
			return err
		}
		now := o.now().UTC()
		if op.Backup == "" {
			if op.Backup, err = instances.Backup(ctx, instance.ID, op.Node+"-retired-"+now.Format("20060102"),
				map[string]string{"terrascale-host-node": op.Node, "ts-node-operation": op.ID,
					"delete-after": now.AddDate(0, 0, retiredBackupDays).Format(time.DateOnly)}, op.ID); err != nil {
				return err
			}
			if err := o.save(ctx, epoch, *op); err != nil {
				return err
			}
		}
		slog.InfoContext(ctx, "node operation terminates an instance", observability.ComponentKey, "nodes", "node", op.Node,
			"instance", instance.ID, "backup", op.Backup)
		if err := instances.Terminate(ctx, instance.ID); err != nil {
			return err
		}
		op.ActedAt = o.now().UTC()
	}
	if err := step("check"); err != nil {
		return err
	}
	for {
		instances, err := o.instances(ctx)
		if err != nil {
			return err
		}
		listed, err := instances.Instances(ctx)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(listed, func(instance nodeInstance) bool { return instance.Name == op.Node }) {
			break
		}
		if err := o.wait(ctx, epoch); err != nil {
			return fmt.Errorf("the instance of %s is not terminated: %w", op.Node, err)
		}
	}
	// The record holds no backend now; letting go of it deletes it.
	_, err := o.fence.restore(ctx, api, epoch, op.Node, holdOperation, false)
	return err
}

// rename fences the node at its granted address, renames its instance,
// forgets its host enrollment and reboots it; the host enrolls under the new
// name, the roles desired on the old name move to it, and the node returns
// once they serve.
func (o *nodeOps) rename(ctx context.Context, epoch uint64, api lb.API, spec cellspec.ReleaseFence, address string,
	op *nodeOp, step func(string) error,
) error {
	if op.ActedAt.IsZero() {
		if op.Step == "" || op.Step == "fence" {
			if err := step("fence"); err != nil {
				return err
			}
			if err := o.adoptFence(ctx, epoch, op.From, op.Node); err != nil {
				return err
			}
			if err := o.fence.fence(ctx, api, epoch, spec, op.Node, address, durationOr(spec.DrainGraceSeconds,
				defaultFenceGrace), holdOperation); err != nil {
				return err
			}
		}
		if err := step("act"); err != nil {
			return err
		}
		if o.cluster != nil {
			if err := o.cluster(ctx, op.Node); err != nil {
				return err
			}
		}
		instances, err := o.instances(ctx)
		if err != nil {
			return err
		}
		if op.Instance == "" {
			instance, err := instances.Find(ctx, op.From)
			if err != nil {
				return err
			}
			if op.Session, err = nodeSession(ctx, o.fence.hosts, op.From); err != nil {
				return err
			}
			op.Instance = instance.ID
			if err := o.save(ctx, epoch, *op); err != nil {
				return err
			}
		}
		if o.forget == nil || o.desired == nil {
			return errors.New("this leader cannot re-enroll a renamed host")
		}
		slog.InfoContext(ctx, "node operation renames an instance", observability.ComponentKey, "nodes", "node", op.From,
			"to", op.Node, "instance", op.Instance)
		if err := instances.Rename(ctx, op.Instance, op.Node); err != nil {
			return err
		}
		if err := o.forget(ctx, op.Instance); err != nil {
			return err
		}
		if err := instances.Reboot(ctx, op.Instance); err != nil {
			return err
		}
		op.ActedAt = o.now().UTC()
	}
	if err := step("check"); err != nil {
		return err
	}
	for {
		moved, err := o.moveDesired(ctx, epoch, op.From, op.Node)
		if err != nil {
			return err
		}
		if moved {
			break
		}
		if err := o.wait(ctx, epoch); err != nil {
			return fmt.Errorf("%s has not enrolled as %s: %w", op.From, op.Node, err)
		}
	}
	if err := o.serving(ctx, epoch, *op); err != nil {
		return err
	}
	if err := step("return"); err != nil {
		return err
	}
	_, err := o.fence.restore(ctx, api, epoch, op.Node, holdOperation, true)
	return err
}

// moveDesired gives node to every role desired on from, once to has
// enrolled, withdraws them from from and retires from. It reports false
// while to has no live host session: a registration an earlier rename left
// under to is not the renamed host.
func (o *nodeOps) moveDesired(ctx context.Context, epoch uint64, from, to string) (bool, error) {
	statuses, err := o.fence.hosts.ListHosts(ctx)
	if err != nil {
		return false, err
	}
	if !slices.ContainsFunc(statuses, func(status host.HostStatus) bool {
		return status.Registration.Node == to && !status.SessionExpiresAt.IsZero()
	}) {
		return false, nil
	}
	desired, err := o.fence.hosts.ListDesired(ctx, "")
	if err != nil {
		return false, err
	}
	for _, d := range desired {
		if d.Node != from || d.Withdrawn {
			continue
		}
		// The workload reconciler may have placed the replica already.
		if !slices.ContainsFunc(desired, func(e host.Desired) bool { return e.Node == to && e.Role == d.Role && !e.Withdrawn }) {
			if err := o.carryPermit(ctx, epoch, d, from, to); err != nil {
				return false, err
			}
			moved := d
			moved.Node, moved.AuthorityEpoch = to, epoch
			if _, err := o.desired.ApplyDesired(ctx, moved); err != nil {
				return false, fmt.Errorf("move %s to %s: %w", d.Role, to, err)
			}
		}
		// A withdrawal carries no execution data and moves the generation on.
		withdrawn := host.Desired{Cell: d.Cell, Node: d.Node, Environment: d.Environment, Role: d.Role,
			Generation: d.Generation + 1, AuthorityEpoch: epoch, Withdrawn: true}
		if _, err := o.desired.ApplyDesired(ctx, withdrawn); err != nil {
			return false, fmt.Errorf("withdraw %s from %s: %w", d.Role, from, err)
		}
	}
	// ponytail: the old name's registration stays, retired; delete it once
	// a host plane API removes registrations.
	_, err = o.desired.RetireIdle(ctx, from)
	return err == nil, err
}

// carryPermit gives to the permit from holds for d's release: a release the
// fence sequences starts a host only on its node's permit, and the renamed
// node already ran this one.
func (o *nodeOps) carryPermit(ctx context.Context, epoch uint64, d host.Desired, from, to string) error {
	release := releaseOf(d.Generation)
	if _, err := o.fence.kv.Get(ctx, permitKey(d.Role, release, from)); errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if err := o.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err := o.fence.kv.Put(ctx, permitKey(d.Role, release, to), []byte("{}"))
	return err
}

// strayFences are the fence records at node's granted address under names
// no host grant holds, which a failed rename leaves behind (TS-632).
func (o *nodeOps) strayFences(ctx context.Context, node string, addresses map[string]string) (map[string]fenceRecord, error) {
	keys, err := o.fence.keys(ctx, fencedKey("*"))
	if err != nil {
		return nil, err
	}
	strays := map[string]fenceRecord{}
	for _, key := range keys {
		name := strings.TrimPrefix(key, fencedKey(""))
		if name == node || addresses[name] != "" {
			continue
		}
		record, found, err := o.fence.record(ctx, name)
		if err != nil {
			return nil, err
		}
		if found && slices.ContainsFunc(record.Backends, func(b fencedBackend) bool { return b.IP == addresses[node] }) {
			strays[name] = record
		}
	}
	return strays, nil
}

// adoptFence moves the old name's fence record, its holders and backends,
// to the new name, so they return with the renamed node.
func (o *nodeOps) adoptFence(ctx context.Context, epoch uint64, from, to string) error {
	defer o.fence.lockNode(from)()
	defer o.fence.lockNode(to)()
	old, found, err := o.fence.record(ctx, from)
	if err != nil || !found {
		return err
	}
	record, _, err := o.fence.record(ctx, to)
	if err != nil {
		return err
	}
	for _, backend := range old.Backends {
		if !slices.Contains(record.Backends, backend) {
			record.Backends = append(record.Backends, backend)
		}
	}
	for _, holder := range old.holders() {
		if !slices.Contains(record.Holders, holder) {
			record.Holders = append(record.Holders, holder)
		}
	}
	slices.Sort(record.Holders)
	if err := o.fence.save(ctx, epoch, to, record); err != nil {
		return err
	}
	return o.fence.deleteGuarded(ctx, epoch, fencedKey(from))
}

// removeBackends deletes node's backends from every fenced set and from
// its record. The fence took them out first.
func (o *nodeOps) removeBackends(ctx context.Context, api lb.API, epoch uint64, spec cellspec.ReleaseFence, node,
	address string,
) error {
	defer o.fence.lockNode(node)()
	for _, set := range spec.BackendSets {
		observed, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return err
		}
		for _, backend := range observed {
			if backend.IP != address || backend.Port != set.Port {
				continue
			}
			if backend.Serving() {
				return fmt.Errorf("%s backend %s still serves; it is not removed", set.Name, backend.Name())
			}
			if err := o.fence.fencer.Guard(ctx, epoch); err != nil {
				return err
			}
			request, err := api.DeleteBackend(ctx, spec.LoadBalancerID, set.Name, backend.Name())
			if err != nil {
				return err
			}
			if err := api.WaitWorkRequest(ctx, request); err != nil {
				return err
			}
		}
	}
	record, found, err := o.fence.record(ctx, node)
	if err != nil || !found {
		return err
	}
	record.Backends = nil
	return o.fence.save(ctx, epoch, node, record)
}

// nodeReplica names a role node still has an active replica of, or "".
func nodeReplica(ctx context.Context, hosts seatrollout.Hosts, node string) (string, error) {
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
			if slices.ContainsFunc(desired, func(d host.Desired) bool { return d.Node == node && !d.Withdrawn }) {
				return role, nil
			}
		}
	}
	return "", nil
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
