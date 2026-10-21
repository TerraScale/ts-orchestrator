package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// nodeHosts runs terrabase and ts-auth on every node. A node reports both
// running from its current host agent session; a reboot gives it a new one.
type nodeHosts struct {
	mu       sync.Mutex
	sessions map[string]string
	down     map[string]bool
	// states overrides a node/role report's state.
	states map[string]string
	// withdrawn nodes have no replica.
	withdrawn map[string]bool
}

func (h *nodeHosts) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	var desired []host.Desired
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, node := range []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"} {
		desired = append(desired, host.Desired{Node: node, Role: role, Generation: 7, Withdrawn: h.withdrawn[node]})
	}
	return desired, nil
}

func (h *nodeHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"} {
		status := host.HostStatus{Registration: host.Registration{Node: node, Roles: []string{"terrabase", "ts-auth"}}}
		if !h.down[node] {
			for _, role := range status.Registration.Roles {
				state := h.states[node+"/"+role]
				if state == "" {
					state = "running"
				}
				status.Reports = append(status.Reports, host.Report{Node: node, Role: role, Generation: 7, State: state,
					SessionID: h.sessions[node], ObservedAt: time.Now()})
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// nodeInstances reboots instantly: a node goes down and comes back with a
// new host agent session. It records every call with the node's backends'
// state at that moment.
type nodeInstances struct {
	hosts *nodeHosts
	lb    *fenceLB
	t     *testing.T
	shape map[string][2]float32
	calls []string
	// names renames a node's instance; an empty name removes it.
	names map[string]string
	// rebooted, when set, runs after a node's reboot.
	rebooted func(node string)
}

func (c *nodeInstances) Prepare(context.Context, rootoci.NodeMaintenanceRequest) error { return nil }

func (c *nodeInstances) Rename(_ context.Context, id, name string) error {
	node := strings.TrimPrefix(id, "ocid1.instance.")
	c.calls = append(c.calls, "rename "+node+" "+name)
	if c.names == nil {
		c.names = map[string]string{}
	}
	c.names[node] = name
	return nil
}

func (c *nodeInstances) Backup(_ context.Context, id, name string, tags map[string]string, token string) (string, error) {
	node := strings.TrimPrefix(id, "ocid1.instance.")
	if tags["terrascale-host-node"] != node || !strings.HasPrefix(name, node+"-retired-") || token == "" {
		c.t.Errorf("backup %s %q %v %q", id, name, tags, token)
	}
	c.calls = append(c.calls, "backup "+node)
	return "ocid1.bootvolumebackup." + node, nil
}

func (c *nodeInstances) Terminate(_ context.Context, id string) error {
	node := strings.TrimPrefix(id, "ocid1.instance.")
	c.lb.mu.Lock()
	for set, backends := range c.lb.sets {
		if slices.ContainsFunc(backends, func(b lb.Backend) bool { return b.IP == fenceAddresses[node] }) {
			c.t.Errorf("terminated %s while it has a %s backend", node, set)
		}
	}
	c.lb.mu.Unlock()
	c.calls = append(c.calls, "terminate "+node)
	if c.names == nil {
		c.names = map[string]string{}
	}
	c.names[node] = ""
	return nil
}

func (c *nodeInstances) Instances(context.Context) ([]nodeInstance, error) {
	var instances []nodeInstance
	for _, node := range []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"} {
		name, renamed := c.names[node]
		if !renamed {
			name = node
		}
		if name != "" {
			shape := c.shape[node]
			instances = append(instances, nodeInstance{ID: "ocid1.instance." + node, Name: name, State: "RUNNING",
				OCPUs: shape[0], MemoryGB: shape[1]})
		}
	}
	return instances, nil
}

func (c *nodeInstances) Find(ctx context.Context, node string) (nodeInstance, error) {
	instances, _ := c.Instances(ctx)
	return findNode(instances, node)
}

func (c *nodeInstances) restart(node string) {
	c.lb.mu.Lock()
	for set, backends := range c.lb.sets {
		for _, backend := range backends {
			if backend.IP == fenceAddresses[node] && backend.Serving() {
				c.t.Errorf("%s restarted while its %s backend serves", node, set)
			}
		}
	}
	c.lb.mu.Unlock()
	c.hosts.mu.Lock()
	c.hosts.sessions[node] += "+"
	c.hosts.mu.Unlock()
}

func (c *nodeInstances) Reboot(_ context.Context, id string) error {
	node := strings.TrimPrefix(id, "ocid1.instance.")
	c.calls = append(c.calls, "reboot "+node)
	c.restart(node)
	if c.rebooted != nil {
		c.rebooted(node)
	}
	return nil
}

func (c *nodeInstances) Resize(_ context.Context, id string, ocpus, memoryGB float32) error {
	node := strings.TrimPrefix(id, "ocid1.instance.")
	c.calls = append(c.calls, "resize "+node)
	c.shape[node] = [2]float32{ocpus, memoryGB}
	c.restart(node)
	return nil
}

func newNodeOpsTest(t *testing.T) (*nodeOps, *fenceLB, *nodeInstances) {
	t.Helper()
	fence, _, balancer, _, _ := newFenceTest(t)
	// Every node serves in both sets; the default quorum guard keeps two.
	balancer.sets["ts-auth"][0] = lb.Backend{IP: fenceAddresses["gru-1-ctl-1"], Port: 8080}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x",
		BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465}, {Name: "ts-auth", Port: 8080}}}
	fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, fenceAddresses }
	hosts := &nodeHosts{sessions: map[string]string{"gru-1-ctl-1": "s1", "gru-1-ctl-2": "s2", "gru-1-ctl-3": "s3"}, down: map[string]bool{},
		states: map[string]string{}, withdrawn: map[string]bool{}}
	fence.hosts = hosts
	instances := &nodeInstances{hosts: hosts, lb: balancer, t: t, shape: map[string][2]float32{}}
	ops := newNodeOps(fence, func(context.Context) (nodeCompute, error) { return instances, nil }, nil, Config{}, nil)
	ops.poll = time.Millisecond
	return ops, balancer, instances
}

func (o *nodeOps) operation(t *testing.T, node string) nodeOp {
	t.Helper()
	op, found, err := o.load(t.Context(), node)
	if err != nil || !found {
		t.Fatalf("operation of %s: %v %v", node, found, err)
	}
	return op
}

// A reboot drains the node, reboots it only while none of its backends
// serves, waits for its new host agent to report every role running and
// returns it; the record is gone afterwards.
func TestNodeRebootDrainsActsChecksAndReturns(t *testing.T) {
	ops, balancer, instances := newNodeOpsTest(t)
	ctx := t.Context()
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-2", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "gru-1-ctl-2"); op.State != nodeOpDone || op.ActedAt.IsZero() || op.Session != "s2" {
		t.Fatalf("operation %+v", op)
	}
	want := []string{
		"terrabase 10.0.0.12:9465 drain", "ts-auth 10.0.0.12:8080 drain",
		"terrabase 10.0.0.12:9465 offline", "ts-auth 10.0.0.12:8080 offline",
		"terrabase 10.0.0.12:9465 active", "ts-auth 10.0.0.12:8080 active",
	}
	if !slices.Equal(balancer.log, want) || !slices.Equal(instances.calls, []string{"reboot gru-1-ctl-2"}) {
		t.Fatalf("load balancer\n%s\ninstances %q", strings.Join(balancer.log, "\n"), instances.calls)
	}
	if _, found, _ := ops.fence.record(ctx, "gru-1-ctl-2"); found {
		t.Fatal("the fence record was left")
	}
}

// A rebooted node whose roles do not serve again keeps its backends out,
// and the operation fails.
func TestNodeRebootKeepsANodeThatDoesNotServeOut(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ops.fence.hosts.(*nodeHosts).down["gru-1-ctl-3"] = true
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	op := nodeOp{ID: entityid.New(), Node: "gru-1-ctl-3", Op: nodeOpReboot, State: nodeOpQueued}
	ops.seedOriginalTest(t, ctx, 3, &op)
	err := ops.execute(ctx, 3, &op)
	if err == nil || !strings.Contains(err.Error(), "does not serve") {
		t.Fatalf("execute: %v", err)
	}
	if balancer.sets["terrabase"][2].Serving() || balancer.sets["ts-auth"][2].Serving() {
		t.Fatal("a node that does not serve was returned")
	}
	// Once it serves, undrain releases the failed operation's hold.
	op.State = nodeOpFailed
	if err := ops.save(t.Context(), 3, op); err != nil {
		t.Fatal(err)
	}
	ops.fence.hosts.(*nodeHosts).down["gru-1-ctl-3"] = false
	if _, err := ops.submitTest(t, t.Context(), 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-3", Op: nodeOpUndrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !balancer.sets["terrabase"][2].Serving() || !balancer.sets["ts-auth"][2].Serving() {
		t.Fatal("undrain did not return the node")
	}
}

// A resize changes the shape and checks the new one; a node already at the
// shape is not restarted.
func TestNodeResizeChangesTheShapeOnce(t *testing.T) {
	ops, _, instances := newNodeOpsTest(t)
	ctx := t.Context()
	instances.shape["gru-1-ctl-3"] = [2]float32{1, 4}
	for _, node := range []string{"gru-1-ctl-1", "gru-1-ctl-3"} {
		if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: node, Op: nodeOpResize, OCPUs: 1, MemoryGB: 4}); err != nil {
			t.Fatal(err)
		}
		if err := ops.pass(ctx); err != nil {
			t.Fatal(err)
		}
		if op := ops.operation(t, node); op.State != nodeOpDone {
			t.Fatalf("%s: %+v", node, op)
		}
	}
	if !slices.Equal(instances.calls, []string{"resize gru-1-ctl-1"}) || instances.shape["gru-1-ctl-1"] != [2]float32{1, 4} {
		t.Fatalf("instances %q %v", instances.calls, instances.shape)
	}
}

// A drained node stays out across a release that restarts it and across a
// reboot; undrain returns it. Another node is refused while the quorum
// guard (two serving) would break.
func TestNodeDrainHoldsAcrossOtherFencesAndGuardsTheQuorum(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ctx := t.Context()
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpDrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-2", Op: nodeOpReboot}); err == nil ||
		!strings.Contains(err.Error(), "keeps at least 2") {
		t.Fatalf("broke the quorum: %v", err)
	}
	// A release and a reboot fence and return gru-1-ctl-1; it stays out.
	api, _ := ops.fence.client(ctx)
	spec, _ := ops.fence.spec()
	if err := ops.fence.fence(ctx, api, 3, *spec, "gru-1-ctl-1", fenceAddresses["gru-1-ctl-1"], 0, holdRelease); err != nil {
		t.Fatal(err)
	}
	if returned, err := ops.fence.restore(ctx, api, 3, "gru-1-ctl-1", holdRelease, true); err != nil || returned {
		t.Fatalf("a release returned a drained node: %v %v", returned, err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if balancer.sets["terrabase"][0].Serving() {
		t.Fatal("a reboot returned a drained node")
	}
	record, _, _ := ops.fence.record(ctx, "gru-1-ctl-1")
	if !slices.Equal(record.holders(), []string{holdMaintenance}) {
		t.Fatalf("holders %q", record.holders())
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpUndrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if !balancer.sets["terrabase"][0].Serving() || !balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("undrain did not return the node")
	}
}

func TestNodeSubmitRefusals(t *testing.T) {
	ops, _, _ := newNodeOpsTest(t)
	ctx := t.Context()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	policy, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{{
		Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Roles: []string{"ts-auth"}, Environments: []string{"production"}, CanRegisterHosts: true,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for name, deadline := range map[string]time.Time{
		"bounded":  now.Add(30 * time.Minute),
		"missing":  {},
		"extended": now.Add(30*time.Minute + time.Second),
		"expired":  now.Add(-time.Second),
	} {
		payload, err := protocol.EncodeJSON(nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot, ExecutionDeadline: deadline})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: nodeOpSubmitKind,
			Actor: "ops", OperationID: entityid.NewAt(now), Generation: 1, Epoch: 3},
			now, now.Add(time.Minute), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyNodeOperationRequest(wire, "gru", 3, policy, now); (err == nil) != (name == "bounded") {
			t.Fatalf("signed deadline %s: %v", name, err)
		}
	}
	for name, id := range map[string]string{
		"derived":           entityid.Derive("node-legacy", "request"),
		"earlier millis":    entityid.NewAt(now.Add(-time.Millisecond)),
		"later millis":      entityid.NewAt(now.Add(time.Millisecond)),
		"resigned newer ID": entityid.NewAt(now.Add(-time.Second)),
	} {
		payload, err := protocol.EncodeJSON(nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot, ExecutionDeadline: now.Add(nodeOperationExecutionLifetime)})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: nodeOpSubmitKind,
			Actor: "ops", OperationID: id, Generation: 1, Epoch: 3}, now, now.Add(time.Minute), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyNodeOperationRequest(wire, "gru", 3, policy, now); err == nil || !strings.Contains(err.Error(), "signed issue millisecond") {
			t.Fatalf("signed operation identity %s: %v", name, err)
		}
	}
	for name, request := range map[string]nodeOpRequest{
		"unknown node":    {Node: "gru-1-ctl-9", Op: nodeOpDrain},
		"unknown op":      {Node: "gru-1-ctl-1", Op: "rename"},
		"resize no shape": {Node: "gru-1-ctl-1", Op: nodeOpResize},
		"reboot shape":    {Node: "gru-1-ctl-1", Op: nodeOpReboot, OCPUs: 1},
		"not drained":     {Node: "gru-1-ctl-1", Op: nodeOpUndrain},
	} {
		if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot}); err == nil ||
		!strings.Contains(err.Error(), "already has") {
		t.Fatalf("a second operation on one node: %v", err)
	}
}

// Pool nodes belong to the node scaler: no operation takes one, by its name
// or as a rename's new name.
func TestNodeSubmitRefusesPoolNodes(t *testing.T) {
	ops, _, _ := newNodeOpsTest(t)
	ops.pool = func(node string) bool { return node == "gru-1-ctl-2" || node == "ts-gru-4" }
	for name, request := range map[string]nodeOpRequest{
		"reboot": {Node: "gru-1-ctl-2", Op: nodeOpReboot},
		"resize": {Node: "gru-1-ctl-2", Op: nodeOpResize, OCPUs: 2, MemoryGB: 8},
		"rename": {Node: "gru-1-ctl-1", To: "ts-gru-4", Op: nodeOpRename},
	} {
		if _, err := ops.submitTest(t, t.Context(), 3, "mariogk", entityid.New(), request); err == nil ||
			!strings.Contains(err.Error(), "pool node") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ops.submitTest(t, t.Context(), 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
}

// Without the quorum, a fence waits instead of taking a backend out.
func TestFenceWaitsForTheQuorumGuard(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	balancer.down["10.0.0.13:9465"] = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Cancel at the quorum wait so fixture I/O cannot consume the observation window.
	ops.fence.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	api, err := ops.fence.client(ctx)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := ops.fence.spec()
	err = ops.fence.fence(ctx, api, 3, *spec, "gru-1-ctl-1", fenceAddresses["gru-1-ctl-1"], 0, holdMaintenance)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "keeps at least 2") || len(balancer.log) != 0 {
		t.Fatalf("fence: %v, load balancer %q", err, balancer.log)
	}
}

// proofs is a fixed health proof per unit.
type proofs map[string]rolloutexec.HealthProof

func (p proofs) Latest(unit string) (rolloutexec.HealthProof, bool) {
	proof, ok := p[unit]
	return proof, ok
}

// The deploy gate holds a unit's step until its node is out of rotation,
// one node at a time; the node returns once its unit proves the target and
// its roles serve.
func TestRolloutFenceDrainsBeforeTheStepAndReturnsAfter(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ctx := t.Context()
	fences := newRolloutFence(ctx, ops.fence, func(unit string) string { return strings.Replace(unit, "controller-", "gru-1-ctl-", 1) },
		func(node string) string { return strings.Replace(node, "gru-1-ctl-", "controller-", 1) })
	gate := func(unit string) error {
		for range 200 {
			err := fences.check(ctx, unit)
			if !errors.Is(err, rolloutexec.ErrGateHeld) || !strings.Contains(err.Error(), "taking") {
				return err
			}
			time.Sleep(5 * time.Millisecond)
		}
		return errors.New("the fence never finished")
	}
	if err := gate("controller-1"); err != nil {
		t.Fatal(err)
	}
	if balancer.sets["terrabase"][0].Serving() || balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("the gate passed a serving node")
	}
	if err := fences.check(ctx, "controller-2"); err == nil || !strings.Contains(err.Error(), "gru-1-ctl-1 is still out") {
		t.Fatalf("a second node: %v", err)
	}
	record := rollout.Record{ToDigest: "new", FromDigest: "old", Units: map[string]rollout.UnitProgress{
		"controller-1": {State: rollout.UnitPreparing}}}
	sources := proofs{"controller-1": {BinarySHA256: "old", StartNonce: "000000000000ae0e535d50ddd92a6c00", ReceivedAt: time.Now()}}
	since, ready := fences.unitServes("gru-1-ctl-1", record, true, sources)
	if ready {
		t.Fatal("a unit being stepped is ready")
	}
	record.Units["controller-1"] = rollout.UnitProgress{State: rollout.UnitSoaking}
	if _, ready = fences.unitServes("gru-1-ctl-1", record, true, sources); ready {
		t.Fatal("a unit on the old release is ready")
	}
	sources["controller-1"] = rolloutexec.HealthProof{BinarySHA256: "new", StartNonce: "000000000000133bf48ddeb8844f9ef8", ReceivedAt: time.Now()}
	if since, ready = fences.unitServes("gru-1-ctl-1", record, true, sources); !ready || since.IsZero() {
		t.Fatal("a unit that proves the target is not ready")
	}
	record.Phase, record.Units["controller-1"] = rollout.PhaseFrozen, rollout.UnitProgress{State: rollout.UnitRollingBack}
	sources["controller-1"] = rolloutexec.HealthProof{BinarySHA256: "0000000000V4MRM46HP1SNGDYW", StartNonce: "000000000000133bf48ddeb8844f9ef8", ReceivedAt: time.Now()}
	if _, ready = fences.unitServes("gru-1-ctl-1", record, true, sources); !ready {
		t.Fatal("a frozen rollout held its node although the node serves")
	}
	record.Phase = rollout.PhaseRollingBack
	if _, ready = fences.unitServes("gru-1-ctl-1", record, true, sources); ready {
		t.Fatal("a unit rolling back is ready")
	}
	record.Phase, record.Units["controller-1"] = "", rollout.UnitProgress{State: rollout.UnitSoaking}
	sources["controller-1"] = rolloutexec.HealthProof{BinarySHA256: "new", StartNonce: "000000000000133bf48ddeb8844f9ef8", ReceivedAt: time.Now()}
	if reason, err := nodeRolesServing(ctx, ops.fence.hosts, "gru-1-ctl-1", since.Add(-time.Second)); err != nil || reason != "" {
		t.Fatalf("roles: %q %v", reason, err)
	}
	api, _ := ops.fence.client(ctx)
	if _, err := ops.fence.restore(ctx, api, 3, "gru-1-ctl-1", holdRollout, true); err != nil {
		t.Fatal(err)
	}
	if !balancer.sets["terrabase"][0].Serving() {
		t.Fatal("the node did not return")
	}
	if err := gate("controller-2"); err != nil {
		t.Fatal(err)
	}
}

// retire takes only a node without replicas or a controller, and leaves it
// with no backend, a backup and no instance.
func TestNodeRetireRemovesBacksUpAndTerminates(t *testing.T) {
	ops, balancer, instances := newNodeOpsTest(t)
	ctx := t.Context()
	ops.controllers = func(node string) bool { return node == "gru-1-ctl-1" }
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpRetire}); err == nil ||
		!strings.Contains(err.Error(), "controller") {
		t.Fatalf("retired a controller: %v", err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-3", Op: nodeOpRetire}); err == nil ||
		!strings.Contains(err.Error(), "replica") {
		t.Fatalf("retired a node with replicas: %v", err)
	}
	ops.fence.hosts.(*nodeHosts).withdrawn["gru-1-ctl-3"] = true
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-3", Op: nodeOpRetire}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "gru-1-ctl-3"); op.State != nodeOpDone || op.Backup != "ocid1.bootvolumebackup.gru-1-ctl-3" {
		t.Fatalf("operation %+v", op)
	}
	if !slices.Equal(instances.calls, []string{"backup gru-1-ctl-3", "terminate gru-1-ctl-3"}) {
		t.Fatalf("instances %q", instances.calls)
	}
	for set := range balancer.sets {
		if _, ok := backendOf(balancer, set, "10.0.0.13:9465"); ok {
			t.Fatalf("%s kept a backend", set)
		}
	}
	if _, found, _ := ops.fence.record(ctx, "gru-1-ctl-3"); found {
		t.Fatal("the fence record was left")
	}
}

// add creates a replica's missing backend out of rotation and returns it
// once the node serves.
func TestNodeAddJoinsAMissingBackend(t *testing.T) {
	_, ops, balancer, _ := newEdgeTest(t)
	ctx := t.Context()
	balancer.sets["ts-auth"] = balancer.sets["ts-auth"][:2]
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-3", Op: nodeOpAdd}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "gru-1-ctl-3"); op.State != nodeOpDone {
		t.Fatalf("operation %+v", op)
	}
	if backend, ok := backendOf(balancer, "ts-auth", "10.0.0.13:8080"); !ok || !backend.Serving() {
		t.Fatalf("gru-1-ctl-3's ts-auth backend %+v %v: %q", backend, ok, balancer.log)
	}
	if !slices.Contains(balancer.log, "ts-auth 10.0.0.13:8080 created") {
		t.Fatalf("load balancer %q", balancer.log)
	}
}

// renameHosts is a host plane whose nodes run terrabase and ts-auth as
// desired; a node that enrolls under a new name reports from a new session
// and its old name stops reporting.
type renameHosts struct {
	mu       sync.Mutex
	nodes    []string
	down     map[string]bool
	sessions map[string]string
	desired  map[string]host.Desired
	retired  []string
}

func newRenameHosts() *renameHosts {
	h := &renameHosts{nodes: []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}, down: map[string]bool{},
		sessions: map[string]string{"gru-1-ctl-1": "s1", "gru-1-ctl-2": "s2", "gru-1-ctl-3": "s3"}, desired: map[string]host.Desired{}}
	for _, node := range h.nodes {
		for _, role := range []string{"terrabase", "ts-auth"} {
			h.desired[node+"/"+role] = host.Desired{Node: node, Role: role, Generation: 15,
				Digest: strings.Repeat("a", 64), Env: map[string]string{"ROLE": role}}
		}
	}
	return h
}

func (h *renameHosts) enroll(from, to string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.Contains(h.nodes, to) {
		h.nodes = append(h.nodes, to)
	}
	h.down[from], h.sessions[to] = true, "n1"
}

func (h *renameHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range h.nodes {
		status := host.HostStatus{Registration: host.Registration{Node: node, Roles: []string{"terrabase", "ts-auth"}}}
		if h.sessions[node] != "" && !h.down[node] {
			status.SessionExpiresAt = time.Now().Add(30 * time.Second)
		}
		for _, role := range status.Registration.Roles {
			if d, ok := h.desired[node+"/"+role]; ok && !d.Withdrawn && !h.down[node] {
				status.Reports = append(status.Reports, host.Report{Node: node, Role: role, Generation: d.Generation,
					State: "running", SessionID: h.sessions[node], ObservedAt: time.Now()})
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (h *renameHosts) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var desired []host.Desired
	for _, d := range h.desired {
		if role == "" || d.Role == role {
			desired = append(desired, d)
		}
	}
	return desired, nil
}

// ApplyDesired refuses what the host controller refuses: a withdrawal with
// execution data, and a generation that moves back or changes in place.
func (h *renameHosts) ApplyDesired(_ context.Context, d host.Desired) (host.Receipt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if d.Withdrawn && (d.Digest != "" || len(d.Args) != 0 || len(d.Env) != 0 || len(d.Secrets) != 0) {
		return host.Receipt{}, errors.New("withdrawn desired contains execution data")
	}
	if current, ok := h.desired[d.Node+"/"+d.Role]; ok && (d.Generation < current.Generation ||
		d.Generation == current.Generation && current.Withdrawn != d.Withdrawn) {
		return host.Receipt{}, errors.New("generation moved backward or changed within a generation")
	}
	h.desired[d.Node+"/"+d.Role] = d
	return host.Receipt{}, nil
}

func (h *renameHosts) RetireIdle(_ context.Context, node string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retired = append(h.retired, node)
	return true, nil
}

// A rename needs the new name granted at the node's address. It fences the
// node there, renames the instance, forgets its enrollment and reboots it;
// once the host enrolled under the new name, the old name's roles move to
// it, the old name retires, and the node returns once they serve (TS-609).
func TestNodeRenameReenrollsTheHostAndMovesItsRoles(t *testing.T) {
	ops, balancer, instances := newNodeOpsTest(t)
	ctx := t.Context()
	hosts := newRenameHosts()
	ops.fence.hosts, ops.desired = hosts, hosts
	ops.forget = func(_ context.Context, id string) error {
		instances.calls = append(instances.calls, "forget "+id)
		return nil
	}
	instances.rebooted = func(node string) { hosts.enroll(node, "ts-gru-1") }
	request := nodeOpRequest{Node: "gru-1-ctl-1", To: "ts-gru-1", Op: nodeOpRename}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), request); err == nil || !strings.Contains(err.Error(), "no host grant") {
		t.Fatalf("renamed to an ungranted name: %v", err)
	}
	spec, _ := ops.fence.spec()
	both := map[string]string{"gru-1-ctl-1": "10.0.0.11", "ts-gru-1": "10.0.0.11", "gru-1-ctl-2": "10.0.0.12", "gru-1-ctl-3": "10.0.0.13"}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, both }
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), request); err == nil || !strings.Contains(err.Error(), "still grants gru-1-ctl-1") {
		t.Fatalf("renamed while the old name keeps its grant: %v", err)
	}
	ops.controllers = func(node string) bool { return node == "gru-1-ctl-1" }
	renamed := map[string]string{"ts-gru-1": "10.0.0.11", "gru-1-ctl-2": "10.0.0.12", "gru-1-ctl-3": "10.0.0.13"}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, renamed }
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), request); err == nil || !strings.Contains(err.Error(), "controller slot") {
		t.Fatalf("renamed a controller node without its slot: %v", err)
	}
	ops.controllers = func(node string) bool { return node == "ts-gru-1" }
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpRename}); err == nil {
		t.Fatal("a rename without --new-name was queued")
	}
	// gru-1-ctl-1 ran TerraBase release 15 on its permit, and a failed operation
	// left it held out under its old name.
	for _, key := range []string{sequencedKey("terrabase", 15), permitKey("terrabase", 15, "gru-1-ctl-1")} {
		if _, err := ops.fence.kv.Put(ctx, key, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	api, _ := ops.fence.client(ctx)
	if err := ops.fence.fence(ctx, api, 3, *spec, "gru-1-ctl-1", "10.0.0.11", time.Millisecond, holdOperation); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), request); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.fence.kv.Get(ctx, permitKey("terrabase", 15, "ts-gru-1")); err != nil {
		t.Fatalf("the renamed node has no permit for the release it runs: %v", err)
	}
	if _, found, _ := ops.fence.record(ctx, "gru-1-ctl-1"); found {
		t.Fatal("the old name's fence record was left")
	}
	if op := ops.operation(t, "ts-gru-1"); op.State != nodeOpDone || op.From != "gru-1-ctl-1" || op.Instance != "ocid1.instance.gru-1-ctl-1" ||
		op.Session != "s1" {
		t.Fatalf("operation %+v", op)
	}
	if want := []string{"rename gru-1-ctl-1 ts-gru-1", "forget ocid1.instance.gru-1-ctl-1", "reboot gru-1-ctl-1"}; !slices.Equal(instances.calls, want) {
		t.Fatalf("instances %q, want %q", instances.calls, want)
	}
	for _, role := range []string{"terrabase", "ts-auth"} {
		if moved, old := hosts.desired["ts-gru-1/"+role], hosts.desired["gru-1-ctl-1/"+role]; moved.Withdrawn || moved.Generation != 15 ||
			moved.AuthorityEpoch != 3 || moved.Digest == "" || !old.Withdrawn || old.Generation != 16 || old.Digest != "" {
			t.Fatalf("%s desired: new %+v, old %+v", role, moved, old)
		}
	}
	if !slices.Equal(hosts.retired, []string{"gru-1-ctl-1"}) {
		t.Fatalf("retired %v", hosts.retired)
	}
	if !balancer.sets["terrabase"][0].Serving() || !balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("the renamed node was not returned")
	}
	if _, found, _ := ops.fence.record(ctx, "ts-gru-1"); found {
		t.Fatal("the fence record was left")
	}
}

// A registration a failed rename left under the new name has no session:
// the roles move only once the renamed host enrolled there (TS-632, gru-1
// 2026-10-07).
func TestNodeRenameMovesRolesOnlyToALiveSession(t *testing.T) {
	ops, _, _ := newNodeOpsTest(t)
	ctx := t.Context()
	hosts := newRenameHosts()
	ops.fence.hosts, ops.desired = hosts, hosts
	hosts.nodes = append(hosts.nodes, "ts-gru-1")
	if moved, err := ops.moveDesired(ctx, 3, "gru-1-ctl-1", "ts-gru-1"); err != nil || moved {
		t.Fatalf("moved %t (%v) to a stale registration", moved, err)
	}
	if _, found := hosts.desired["ts-gru-1/terrabase"]; found || hosts.desired["gru-1-ctl-1/terrabase"].Withdrawn {
		t.Fatalf("desired %+v", hosts.desired)
	}
	hosts.enroll("gru-1-ctl-1", "ts-gru-1")
	if moved, err := ops.moveDesired(ctx, 3, "gru-1-ctl-1", "ts-gru-1"); err != nil || !moved {
		t.Fatalf("moved %t (%v) after the host enrolled", moved, err)
	}
	if d := hosts.desired["ts-gru-1/terrabase"]; d.Withdrawn || d.Digest == "" {
		t.Fatalf("terrabase desired %+v", d)
	}
}

// A failed rename whose grant went back left its fence under the new name,
// which no grant holds: undrain of the node at that address releases it
// (TS-632, gru-1 2026-10-07), and undrain of the stray name stays refused.
func TestNodeUndrainReleasesAFenceAFailedRenameLeftAtItsAddress(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ctx := t.Context()
	spec, addresses := ops.fence.spec()
	api, _ := ops.fence.client(ctx)
	if err := ops.fence.fence(ctx, api, 3, *spec, "ts-gru-1", addresses["gru-1-ctl-1"], time.Millisecond, holdOperation); err != nil {
		t.Fatal(err)
	}
	if balancer.sets["terrabase"][0].Serving() {
		t.Fatal("the stray fence did not take gru-1-ctl-1's address out")
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "ts-gru-1", Op: nodeOpUndrain}); err == nil ||
		!strings.Contains(err.Error(), "no host grant") {
		t.Fatalf("undrain of the ungranted name: %v", err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-2", Op: nodeOpUndrain}); err == nil ||
		!strings.Contains(err.Error(), "not drained") {
		t.Fatalf("undrain of a node with no fence at its address: %v", err)
	}
	if _, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.New(), nodeOpRequest{Node: "gru-1-ctl-1", Op: nodeOpUndrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "gru-1-ctl-1"); op.State != nodeOpDone {
		t.Fatalf("operation %+v", op)
	}
	if !balancer.sets["terrabase"][0].Serving() || !balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("undrain did not return the address the stray fence held")
	}
	for _, node := range []string{"ts-gru-1", "gru-1-ctl-1"} {
		if _, found, _ := ops.fence.record(ctx, node); found {
			t.Fatalf("the fence record of %s was left", node)
		}
	}
}

// These signed fixtures preserve orchestration coverage; they do not substitute
// for the concrete root credential, policy and manager admission sources.
func (o *nodeOps) seedOriginalTest(t *testing.T, ctx context.Context, epoch uint64, op *nodeOp) {
	t.Helper()
	id, err := entityid.Parse(op.ID)
	if err != nil || id.Time() == 0 {
		t.Fatal("node fixture needs a timestamped operation ID")
	}
	now := time.UnixMilli(int64(id.Time())).UTC()
	request := nodeOpRequest{Node: op.Node, Op: op.Op, OCPUs: op.OCPUs, MemoryGB: op.MemoryGB,
		ExecutionDeadline: now.Add(nodeOperationExecutionLifetime)}
	if op.From != "" {
		request.Node, request.To = op.From, op.Node
	}
	if op.Actor == "" {
		op.Actor = "mariogk"
	}
	if entry, err := o.fence.kv.Get(ctx, nodeOperationRequestKey(op.ID)); err == nil {
		var record nodeOperationRequestRecord
		var original protocol.Envelope
		if err := json.Unmarshal(entry.Value(), &record); err != nil {
			t.Fatal(err)
		}
		if err := protocol.DecodeStrict(record.Wire, &original, maxRegistrationWireBytes); err != nil {
			t.Fatal(err)
		}
		var saved nodeOpRequest
		if err := protocol.DecodeStrict(original.Payload, &saved, maxRegistrationBytes); err != nil {
			t.Fatal(err)
		}
		request.ExecutionDeadline = saved.ExecutionDeadline
		payload, err := protocol.EncodeJSON(request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original.Payload, payload) || original.Epoch != epoch || original.Actor != op.Actor {
			t.Fatal("test reused a node operation ID for another request")
		}
		op.RequestSHA256, op.RequestRevision = controllerSHA256(record.Wire), entry.Revision()
		return
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: nodeOpSubmitKind, Actor: op.Actor, OperationID: op.ID, Generation: 1, Epoch: epoch}, now, now.Add(time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("0", 64)
	reference, err := retainNodeOperationRequest(ctx, o.fence.kv, op.ID, nodeOperationRequestRecord{Wire: wire,
		Policy: nodeOperationPolicyPins{ControllerSHA256: digest, RootSHA256: digest, SpecSHA256: digest, RootRevision: 1, SpecRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	op.RequestSHA256, op.RequestRevision = reference.SHA256, reference.Revision
}

func (o *nodeOps) submitTest(t *testing.T, ctx context.Context, epoch uint64, actor, id string, request nodeOpRequest) (nodeOp, error) {
	t.Helper()
	if !entityid.Valid(id) {
		return o.submit(ctx, epoch, actor, id, request, nodeOperationRequestReference{})
	}
	op := nodeOp{ID: id, Node: request.Node, Op: request.Op, Actor: actor, OCPUs: request.OCPUs, MemoryGB: request.MemoryGB}
	if request.Op == nodeOpRename {
		op.Node, op.From = request.To, request.Node
	}
	o.seedOriginalTest(t, ctx, epoch, &op)
	return o.submit(ctx, epoch, actor, id, request, nodeOperationRequestReference{SHA256: op.RequestSHA256, Revision: op.RequestRevision})
}
