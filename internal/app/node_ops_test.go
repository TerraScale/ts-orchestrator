package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
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
	for _, node := range []string{"ctl-1", "ctl-2", "ctl-3"} {
		desired = append(desired, host.Desired{Node: node, Role: role, Generation: 7, Withdrawn: h.withdrawn[node]})
	}
	return desired, nil
}

func (h *nodeHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range []string{"ctl-1", "ctl-2", "ctl-3"} {
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
	for _, node := range []string{"ctl-1", "ctl-2", "ctl-3"} {
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
	balancer.sets["ts-auth"][0] = lb.Backend{IP: fenceAddresses["ctl-1"], Port: 8080}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x",
		BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465}, {Name: "ts-auth", Port: 8080}}}
	fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, fenceAddresses }
	hosts := &nodeHosts{sessions: map[string]string{"ctl-1": "s1", "ctl-2": "s2", "ctl-3": "s3"}, down: map[string]bool{},
		states: map[string]string{}, withdrawn: map[string]bool{}}
	fence.hosts = hosts
	instances := &nodeInstances{hosts: hosts, lb: balancer, t: t, shape: map[string][2]float32{}}
	ops := newNodeOps(fence, func(context.Context) (nodeCompute, error) { return instances, nil }, nil)
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
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-2", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "ctl-2"); op.State != nodeOpDone || op.ActedAt.IsZero() || op.Session != "s2" {
		t.Fatalf("operation %+v", op)
	}
	want := []string{
		"terrabase 10.0.0.12:9465 drain", "ts-auth 10.0.0.12:8080 drain",
		"terrabase 10.0.0.12:9465 offline", "ts-auth 10.0.0.12:8080 offline",
		"terrabase 10.0.0.12:9465 active", "ts-auth 10.0.0.12:8080 active",
	}
	if !slices.Equal(balancer.log, want) || !slices.Equal(instances.calls, []string{"reboot ctl-2"}) {
		t.Fatalf("load balancer\n%s\ninstances %q", strings.Join(balancer.log, "\n"), instances.calls)
	}
	if _, found, _ := ops.fence.record(ctx, "ctl-2"); found {
		t.Fatal("the fence record was left")
	}
}

// A rebooted node whose roles do not serve again keeps its backends out,
// and the operation fails.
func TestNodeRebootKeepsANodeThatDoesNotServeOut(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ops.fence.hosts.(*nodeHosts).down["ctl-3"] = true
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	op := nodeOp{ID: "op-1", Node: "ctl-3", Op: nodeOpReboot, State: nodeOpQueued}
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
	ops.fence.hosts.(*nodeHosts).down["ctl-3"] = false
	if _, err := ops.submit(t.Context(), 3, "mariogk", "op-2", nodeOpRequest{Node: "ctl-3", Op: nodeOpUndrain}); err != nil {
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
	instances.shape["ctl-3"] = [2]float32{1, 4}
	for _, node := range []string{"ctl-1", "ctl-3"} {
		if _, err := ops.submit(ctx, 3, "mariogk", "op-"+node, nodeOpRequest{Node: node, Op: nodeOpResize, OCPUs: 1, MemoryGB: 4}); err != nil {
			t.Fatal(err)
		}
		if err := ops.pass(ctx); err != nil {
			t.Fatal(err)
		}
		if op := ops.operation(t, node); op.State != nodeOpDone {
			t.Fatalf("%s: %+v", node, op)
		}
	}
	if !slices.Equal(instances.calls, []string{"resize ctl-1"}) || instances.shape["ctl-1"] != [2]float32{1, 4} {
		t.Fatalf("instances %q %v", instances.calls, instances.shape)
	}
}

// A drained node stays out across a release that restarts it and across a
// reboot; undrain returns it. Another node is refused while the quorum
// guard (two serving) would break.
func TestNodeDrainHoldsAcrossOtherFencesAndGuardsTheQuorum(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	ctx := t.Context()
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-1", Op: nodeOpDrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-2", nodeOpRequest{Node: "ctl-2", Op: nodeOpReboot}); err == nil ||
		!strings.Contains(err.Error(), "keeps at least 2") {
		t.Fatalf("broke the quorum: %v", err)
	}
	// A release and a reboot fence and return ctl-1; it stays out.
	api, _ := ops.fence.client(ctx)
	spec, _ := ops.fence.spec()
	if err := ops.fence.fence(ctx, api, 3, *spec, "ctl-1", fenceAddresses["ctl-1"], 0, holdRelease); err != nil {
		t.Fatal(err)
	}
	if returned, err := ops.fence.restore(ctx, api, 3, "ctl-1", holdRelease, true); err != nil || returned {
		t.Fatalf("a release returned a drained node: %v %v", returned, err)
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-3", nodeOpRequest{Node: "ctl-1", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if balancer.sets["terrabase"][0].Serving() {
		t.Fatal("a reboot returned a drained node")
	}
	record, _, _ := ops.fence.record(ctx, "ctl-1")
	if !slices.Equal(record.holders(), []string{holdMaintenance}) {
		t.Fatalf("holders %q", record.holders())
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-4", nodeOpRequest{Node: "ctl-1", Op: nodeOpUndrain}); err != nil {
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
	for name, request := range map[string]nodeOpRequest{
		"unknown node":    {Node: "ctl-9", Op: nodeOpDrain},
		"unknown op":      {Node: "ctl-1", Op: "rename"},
		"resize no shape": {Node: "ctl-1", Op: nodeOpResize},
		"reboot shape":    {Node: "ctl-1", Op: nodeOpReboot, OCPUs: 1},
		"not drained":     {Node: "ctl-1", Op: nodeOpUndrain},
	} {
		if _, err := ops.submit(ctx, 3, "mariogk", "op", request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-1", Op: nodeOpReboot}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-2", nodeOpRequest{Node: "ctl-1", Op: nodeOpReboot}); err == nil ||
		!strings.Contains(err.Error(), "already has") {
		t.Fatalf("a second operation on one node: %v", err)
	}
}

// Without the quorum, a fence waits instead of taking a backend out.
func TestFenceWaitsForTheQuorumGuard(t *testing.T) {
	ops, balancer, _ := newNodeOpsTest(t)
	balancer.down["10.0.0.13:9465"] = true
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	api, _ := ops.fence.client(ctx)
	spec, _ := ops.fence.spec()
	err := ops.fence.fence(ctx, api, 3, *spec, "ctl-1", fenceAddresses["ctl-1"], 0, holdMaintenance)
	if err == nil || !strings.Contains(err.Error(), "keeps at least 2") || slices.Contains(balancer.log, "terrabase 10.0.0.11:9465 drain") {
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
	fences := newRolloutFence(ctx, ops.fence, func(unit string) string { return strings.Replace(unit, "controller-", "ctl-", 1) },
		func(node string) string { return strings.Replace(node, "ctl-", "controller-", 1) })
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
	if err := fences.check(ctx, "controller-2"); err == nil || !strings.Contains(err.Error(), "ctl-1 is still out") {
		t.Fatalf("a second node: %v", err)
	}
	record := rollout.Record{ToDigest: "new", FromDigest: "old", Units: map[string]rollout.UnitProgress{
		"controller-1": {State: rollout.UnitPreparing}}}
	sources := proofs{"controller-1": {BinarySHA256: "old", StartNonce: "a", ReceivedAt: time.Now()}}
	since, ready := fences.unitServes("ctl-1", record, true, sources)
	if ready {
		t.Fatal("a unit being stepped is ready")
	}
	record.Units["controller-1"] = rollout.UnitProgress{State: rollout.UnitSoaking}
	if _, ready = fences.unitServes("ctl-1", record, true, sources); ready {
		t.Fatal("a unit on the old release is ready")
	}
	sources["controller-1"] = rolloutexec.HealthProof{BinarySHA256: "new", StartNonce: "b", ReceivedAt: time.Now()}
	if since, ready = fences.unitServes("ctl-1", record, true, sources); !ready || since.IsZero() {
		t.Fatal("a unit that proves the target is not ready")
	}
	if reason, err := nodeRolesServing(ctx, ops.fence.hosts, "ctl-1", since.Add(-time.Second)); err != nil || reason != "" {
		t.Fatalf("roles: %q %v", reason, err)
	}
	api, _ := ops.fence.client(ctx)
	if _, err := ops.fence.restore(ctx, api, 3, "ctl-1", holdRollout, true); err != nil {
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
	ops.controllers = func(node string) bool { return node == "ctl-1" }
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-1", Op: nodeOpRetire}); err == nil ||
		!strings.Contains(err.Error(), "controller") {
		t.Fatalf("retired a controller: %v", err)
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-2", nodeOpRequest{Node: "ctl-3", Op: nodeOpRetire}); err == nil ||
		!strings.Contains(err.Error(), "replica") {
		t.Fatalf("retired a node with replicas: %v", err)
	}
	ops.fence.hosts.(*nodeHosts).withdrawn["ctl-3"] = true
	if _, err := ops.submit(ctx, 3, "mariogk", "op-3", nodeOpRequest{Node: "ctl-3", Op: nodeOpRetire}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "ctl-3"); op.State != nodeOpDone || op.Backup != "ocid1.bootvolumebackup.ctl-3" {
		t.Fatalf("operation %+v", op)
	}
	if !slices.Equal(instances.calls, []string{"backup ctl-3", "terminate ctl-3"}) {
		t.Fatalf("instances %q", instances.calls)
	}
	for set := range balancer.sets {
		if _, ok := backendOf(balancer, set, "10.0.0.13:9465"); ok {
			t.Fatalf("%s kept a backend", set)
		}
	}
	if _, found, _ := ops.fence.record(ctx, "ctl-3"); found {
		t.Fatal("the fence record was left")
	}
}

// add creates a replica's missing backend out of rotation and returns it
// once the node serves.
func TestNodeAddJoinsAMissingBackend(t *testing.T) {
	_, ops, balancer, _ := newEdgeTest(t)
	ctx := t.Context()
	balancer.sets["ts-auth"] = balancer.sets["ts-auth"][:2]
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-3", Op: nodeOpAdd}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "ctl-3"); op.State != nodeOpDone {
		t.Fatalf("operation %+v", op)
	}
	if backend, ok := backendOf(balancer, "ts-auth", "10.0.0.13:8080"); !ok || !backend.Serving() {
		t.Fatalf("ctl-3's ts-auth backend %+v %v: %q", backend, ok, balancer.log)
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
	h := &renameHosts{nodes: []string{"ctl-1", "ctl-2", "ctl-3"}, down: map[string]bool{},
		sessions: map[string]string{"ctl-1": "s1", "ctl-2": "s2", "ctl-3": "s3"}, desired: map[string]host.Desired{}}
	for _, node := range h.nodes {
		for _, role := range []string{"terrabase", "ts-auth"} {
			h.desired[node+"/"+role] = host.Desired{Node: node, Role: role, Generation: 7}
		}
	}
	return h
}

func (h *renameHosts) enroll(from, to string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nodes, h.down[from], h.sessions[to] = append(h.nodes, to), true, "n1"
}

func (h *renameHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range h.nodes {
		status := host.HostStatus{Registration: host.Registration{Node: node, Roles: []string{"terrabase", "ts-auth"}}}
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

func (h *renameHosts) ApplyDesired(_ context.Context, d host.Desired) (host.Receipt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
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
	request := nodeOpRequest{Node: "ctl-1", To: "ts-gru-1", Op: nodeOpRename}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-0", request); err == nil || !strings.Contains(err.Error(), "no host grant") {
		t.Fatalf("renamed to an ungranted name: %v", err)
	}
	spec, _ := ops.fence.spec()
	both := map[string]string{"ctl-1": "10.0.0.11", "ts-gru-1": "10.0.0.11", "ctl-2": "10.0.0.12", "ctl-3": "10.0.0.13"}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, both }
	if _, err := ops.submit(ctx, 3, "mariogk", "op-0", request); err == nil || !strings.Contains(err.Error(), "still grants ctl-1") {
		t.Fatalf("renamed while the old name keeps its grant: %v", err)
	}
	ops.controllers = func(node string) bool { return node == "ctl-1" }
	renamed := map[string]string{"ts-gru-1": "10.0.0.11", "ctl-2": "10.0.0.12", "ctl-3": "10.0.0.13"}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, renamed }
	if _, err := ops.submit(ctx, 3, "mariogk", "op-0", request); err == nil || !strings.Contains(err.Error(), "controller slot") {
		t.Fatalf("renamed a controller node without its slot: %v", err)
	}
	ops.controllers = func(node string) bool { return node == "ts-gru-1" }
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", nodeOpRequest{Node: "ctl-1", Op: nodeOpRename}); err == nil {
		t.Fatal("a rename without --new-name was queued")
	}
	if _, err := ops.submit(ctx, 3, "mariogk", "op-1", request); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if op := ops.operation(t, "ts-gru-1"); op.State != nodeOpDone || op.From != "ctl-1" || op.Instance != "ocid1.instance.ctl-1" ||
		op.Session != "s1" {
		t.Fatalf("operation %+v", op)
	}
	if want := []string{"rename ctl-1 ts-gru-1", "forget ocid1.instance.ctl-1", "reboot ctl-1"}; !slices.Equal(instances.calls, want) {
		t.Fatalf("instances %q, want %q", instances.calls, want)
	}
	for _, role := range []string{"terrabase", "ts-auth"} {
		if moved, old := hosts.desired["ts-gru-1/"+role], hosts.desired["ctl-1/"+role]; moved.Withdrawn || moved.Generation != 7 ||
			moved.AuthorityEpoch != 3 || !old.Withdrawn {
			t.Fatalf("%s desired: new %+v, old %+v", role, moved, old)
		}
	}
	if !slices.Equal(hosts.retired, []string{"ctl-1"}) {
		t.Fatalf("retired %v", hosts.retired)
	}
	if !balancer.sets["terrabase"][0].Serving() || !balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("the renamed node was not returned")
	}
	if _, found, _ := ops.fence.record(ctx, "ts-gru-1"); found {
		t.Fatal("the fence record was left")
	}
}
