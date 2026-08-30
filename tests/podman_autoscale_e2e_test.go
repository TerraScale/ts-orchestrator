// Package tests holds the cross-package integration proofs of the repo. This
// file is the deterministic end-to-end proof of the rootless-hosting and
// autoscaling lane: a real embedded NATS server, a real host agent wired to
// the real rootless podman adapter (over an injected fake podman client and a
// controlled metrics source), and the real autoscaler engine driving the full
// provision -> converge -> heartbeat -> cordon -> drain -> retire sequence.
// No network leaves the process and no real container is ever created.
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

// The node envelope of the provisioned node's heartbeat metric source: the
// exact envelope the autoscaler provisions for the seeded demand.
const (
	e2eNodeMemoryTotalBytes = int64(1 << 30)
	e2eNodeCpuQuotaPercent  = 200
	e2eNodeTasksMax         = 128
	e2eNodeMemoryUsedBytes  = int64(100 << 20)
	e2eNodeCpuUsedPercent   = 5
	e2eBaselineMemoryTotal  = int64(4 << 30)
	e2eBaselineCpuQuota     = 400
	e2eBaselineTasksMax     = 512
	e2eBaselineMemoryUsed   = int64(1 << 30)
	e2eBaselineCpuUsed      = 100
	e2eBaselineTasksRunning = 128
	e2eRequestTimeout       = 2 * time.Second
	e2ePollTimeout          = 2 * time.Second
	e2eHeartbeatInterval    = 5 * time.Millisecond
)

var e2ePlanDigest = mustE2EDigest()

func mustE2EDigest() runtime.ArtifactDigest {
	digest, err := runtime.NewArtifactDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return digest
}

// fakeE2EContainer is the fake client's tracked container.
type fakeE2EContainer struct {
	image    string
	platform string
	labels   map[string]string
	running  bool
}

// fakeE2EPodmanClient implements runtime.PodmanClient with an in-memory
// container table: Inspect answers Absent until Create ran, Create stores the
// exact run request it was given, Start and Stop flip the running flag, and
// Delete forgets the container. Every call is recorded in order.
type fakeE2EPodmanClient struct {
	mutex           sync.Mutex
	containers      map[string]*fakeE2EContainer
	calls           []string
	createdRequests []runtime.PodmanRunRequest
}

func newFakeE2EPodmanClient() *fakeE2EPodmanClient {
	return &fakeE2EPodmanClient{containers: make(map[string]*fakeE2EContainer)}
}

func (c *fakeE2EPodmanClient) record(call string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.calls = append(c.calls, call)
}

// Preflight proves nothing, because the fake needs no host.
func (c *fakeE2EPodmanClient) Preflight(ctx context.Context) error {
	c.record("preflight")
	return nil
}

// Pull records the pull without resolving anything.
func (c *fakeE2EPodmanClient) Pull(ctx context.Context, imageReference string, platform string) error {
	c.record("pull:" + imageReference + "|" + platform)
	return nil
}

// Create stores the container with its fencing labels, not yet running.
func (c *fakeE2EPodmanClient) Create(ctx context.Context, request runtime.PodmanRunRequest) error {
	c.record("create:" + request.ContainerId)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	labels := make(map[string]string, len(request.Labels))
	for key, value := range request.Labels {
		labels[key] = value
	}
	c.containers[request.ContainerId] = &fakeE2EContainer{
		image:    request.ImageReference,
		platform: request.Platform,
		labels:   labels,
		running:  false,
	}
	c.createdRequests = append(c.createdRequests, request)
	return nil
}

// Start marks one container running.
func (c *fakeE2EPodmanClient) Start(ctx context.Context, containerId string) error {
	c.record("start:" + containerId)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if container, present := c.containers[containerId]; present {
		container.running = true
	}
	return nil
}

// Stop marks one container stopped.
func (c *fakeE2EPodmanClient) Stop(ctx context.Context, containerId string) error {
	c.record("stop:" + containerId)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if container, present := c.containers[containerId]; present {
		container.running = false
	}
	return nil
}

// Delete forgets one container entirely.
func (c *fakeE2EPodmanClient) Delete(ctx context.Context, containerId string) error {
	c.record("delete:" + containerId)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.containers, containerId)
	return nil
}

// Inspect answers the fenced observation of the tracked container state.
func (c *fakeE2EPodmanClient) Inspect(ctx context.Context, containerId string) (runtime.PodmanAllocationObservation, error) {
	c.record("inspect:" + containerId)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	container, present := c.containers[containerId]
	if !present {
		return runtime.NewPodmanAllocationObservation(runtime.PodmanAllocationStateAbsent, "", nil, false)
	}
	if container.running {
		return runtime.NewPodmanAllocationObservation(
			runtime.PodmanAllocationStateRunning, container.image, container.labels, true, container.platform)
	}
	return runtime.NewPodmanAllocationObservation(
		runtime.PodmanAllocationStateStopped, container.image, container.labels, false, container.platform)
}

// EnsureVolume records the named volume without creating anything.
func (c *fakeE2EPodmanClient) EnsureVolume(ctx context.Context, name string) error {
	c.record("volume:" + name)
	return nil
}

// runningCount reports how many tracked containers are running; it is the
// metric source's task gauge.
func (c *fakeE2EPodmanClient) runningCount() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	count := 0
	for _, container := range c.containers {
		if container.running {
			count++
		}
	}
	return count
}

// recordedCalls snapshots the call log in order.
func (c *fakeE2EPodmanClient) recordedCalls() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]string{}, c.calls...)
}

// createdRequest returns the exact run request of the nth Create.
func (c *fakeE2EPodmanClient) createdRequest(index int) runtime.PodmanRunRequest {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.createdRequests[index]
}

// e2eMetricsSource is the controlled heartbeat metrics source of the node
// agent: memory and CPU stay low (the workload runs idle) while the running
// task gauge mirrors the fake podman container table exactly, so the
// autoscaler's retire gate observes the allocation count.
type e2eMetricsSource struct {
	podman *fakeE2EPodmanClient
}

// Sample maps the fake container table into one validated metric sample.
func (s *e2eMetricsSource) Sample(ctx context.Context) (hostagent.NodeMetricsSample, error) {
	return hostagent.NewNodeMetricsSample(
		e2eNodeMemoryTotalBytes,
		e2eNodeMemoryUsedBytes,
		e2eNodeCpuQuotaPercent,
		e2eNodeCpuUsedPercent,
		e2eNodeTasksMax,
		s.podman.runningCount(),
		0)
}

// e2eUnusedNativeAdapter records every call: the native systemd driver is
// never exercised by this proof, so any call fails the test at the end.
type e2eUnusedNativeAdapter struct {
	calls int
}

// Converge refuses: the native driver must not be driven here.
func (a *e2eUnusedNativeAdapter) Converge(ctx context.Context, plan runtime.HostRuntimePlan) error {
	a.calls++
	return fmt.Errorf("e2e: the native driver must not be converged by this test")
}

// Observe refuses: the native driver must not be observed here.
func (a *e2eUnusedNativeAdapter) Observe(ctx context.Context, plan runtime.HostRuntimePlan) (runtime.SystemdAllocationObservation, error) {
	a.calls++
	return runtime.SystemdAllocationObservation{}, fmt.Errorf("e2e: the native driver must not be observed by this test")
}

// Stop refuses: the native driver must not be stopped here.
func (a *e2eUnusedNativeAdapter) Stop(ctx context.Context, plan runtime.HostRuntimePlan) error {
	a.calls++
	return fmt.Errorf("e2e: the native driver must not be stopped by this test")
}

// e2eHeartbeatLog keeps the latest heartbeat per node from the wildcard
// heartbeat subscription of the control connection.
type e2eHeartbeatLog struct {
	mutex  sync.Mutex
	latest map[string]hostagent.NodeHeartbeat
}

func newE2EHeartbeatLog() *e2eHeartbeatLog {
	return &e2eHeartbeatLog{latest: make(map[string]hostagent.NodeHeartbeat)}
}

func (l *e2eHeartbeatLog) store(heartbeat hostagent.NodeHeartbeat) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.latest[heartbeat.NodeId.Value] = heartbeat
}

func (l *e2eHeartbeatLog) load(nodeId string) (hostagent.NodeHeartbeat, bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	heartbeat, present := l.latest[nodeId]
	return heartbeat, present
}

// e2eModelNode is one node of the test's cluster model: its lifecycle state,
// its stateful replicas, and (for nodes without a live agent) its synthetic
// metric sample.
type e2eModelNode struct {
	nodeId    string
	state     autoscaling.NodeState
	replicas  []stateful.ReplicaHealth
	synthetic *hostagent.NodeMetricsSample
}

// e2eDrainSafety adapts the stateful replica evaluator onto the autoscaler
// engine's drain seam: the peers of a candidate are the model's other nodes.
type e2eDrainSafety struct {
	evaluator *stateful.ReplicaDrainSafetyEvaluator
	peers     func(candidateNodeId string) []stateful.NodeDrainCandidate
}

// EvaluateDrainSafety answers the engine's drain gate for one candidate.
func (d *e2eDrainSafety) EvaluateDrainSafety(
	ctx context.Context,
	candidate stateful.NodeDrainCandidate,
) (stateful.DrainDecision, error) {
	return d.evaluator.EvaluateDrainSafety(candidate, d.peers(candidate.NodeId))
}

// TestPodmanAutoscaleLaneEndToEnd proves the composed lane: an embedded NATS
// server carries the real node transport, the real podman adapter converges a
// canonical OCI plan over a request-reply, the heartbeat reports the running
// allocation, and the real autoscaler engine provisions the node for seeded
// demand and later cordons, drains, and retires it through the stateful
// drain gate. The full action sequence and the final node set are asserted.
func TestPodmanAutoscaleLaneEndToEnd(t *testing.T) {
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	instance.Start()
	t.Cleanup(func() {
		instance.Shutdown()
		instance.WaitForShutdown()
	})
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded nats server did not become ready")
	}

	controlConnection, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatalf("control connection: %v", err)
	}
	t.Cleanup(controlConnection.Close)

	heartbeats := newE2EHeartbeatLog()
	subscription, err := controlConnection.Subscribe(
		hostagent.NatsSubjectNodePrefix+".*."+hostagent.NatsSubjectLeafHeartbeat,
		func(message *nats.Msg) {
			var heartbeat hostagent.NodeHeartbeat
			if err := json.Unmarshal(message.Data, &heartbeat); err != nil {
				return
			}
			heartbeats.store(heartbeat)
		})
	if err != nil {
		t.Fatalf("heartbeat subscription: %v", err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := controlConnection.Flush(); err != nil {
		t.Fatalf("control flush: %v", err)
	}

	// The plan under test: a canonical OCI plan of an OCI-only admitted role.
	allocationId, err := runtime.NewRuntimeAllocationId("dashboard-a")
	if err != nil {
		t.Fatalf("allocation id: %v", err)
	}
	plan, err := runtime.NewHostRuntimePlan(
		runtime.AdmittedRoleCustomerDashboard,
		runtime.RuntimeDriverOciContainer,
		allocationId,
		e2ePlanDigest,
		runtime.HostArchitectureX64,
		nil)
	if err != nil {
		t.Fatalf("canonical plan: %v", err)
	}
	planJson, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	fingerprint, err := runtime.CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	// The autoscaler, its drain gate, its provisioner, and the model.
	drainPolicy, err := stateful.NewDrainPolicy(1 << 20)
	if err != nil {
		t.Fatalf("drain policy: %v", err)
	}
	replicaEvaluator, err := stateful.NewReplicaDrainSafetyEvaluator(drainPolicy)
	if err != nil {
		t.Fatalf("replica evaluator: %v", err)
	}
	baselinePeerUp := false
	model := []e2eModelNode{
		{
			nodeId: "node-baseline",
			state:  autoscaling.NodeStateReady,
			replicas: []stateful.ReplicaHealth{
				mustE2EReplica(t, "terrabase-member", "terrabase-b", baselinePeerUp),
			},
			synthetic: mustE2ESyntheticSample(t, e2eBaselineMemoryTotal, e2eBaselineMemoryUsed,
				e2eBaselineCpuQuota, e2eBaselineCpuUsed, e2eBaselineTasksMax, e2eBaselineTasksRunning),
		},
	}
	drainSafety := &e2eDrainSafety{
		evaluator: replicaEvaluator,
		peers: func(candidateNodeId string) []stateful.NodeDrainCandidate {
			peers := make([]stateful.NodeDrainCandidate, 0, len(model))
			for _, node := range model {
				if node.nodeId == candidateNodeId {
					continue
				}
				candidate, err := stateful.NewNodeDrainCandidate(node.nodeId, node.replicas)
				if err != nil {
					t.Fatalf("peer candidate %s: %v", node.nodeId, err)
				}
				peers = append(peers, candidate)
			}
			return peers
		},
	}
	policy, err := autoscaling.NewAutoscalerConfig(
		1, 3, 30, 40, 1, 2, 2, 3)
	if err != nil {
		t.Fatalf("autoscaler config: %v", err)
	}
	engine, err := autoscaling.NewAutoscaler(policy, drainSafety)
	if err != nil {
		t.Fatalf("autoscaler: %v", err)
	}
	provisioner := autoscaling.NewStaticNodeProvisioner()

	buildSnapshot := func(t *testing.T, demand []autoscaling.AllocationDemand) autoscaling.AutoscalerSnapshot {
		t.Helper()
		nodes := make([]autoscaling.NodeObservation, 0, len(model))
		for _, node := range model {
			sample := node.synthetic
			if sample == nil {
				heartbeat, present := heartbeats.load(node.nodeId)
				if !present {
					t.Fatalf("no heartbeat observed for node %s", node.nodeId)
				}
				sample = &heartbeat.Metrics
			}
			capacity, err := autoscaling.NewNodeResources(
				sample.MemoryTotalBytes, sample.CpuQuotaPercent, sample.TasksMax)
			if err != nil {
				t.Fatalf("capacity of %s: %v", node.nodeId, err)
			}
			usage, err := autoscaling.NewNodeResources(
				sample.MemoryUsedBytes, sample.CpuUsedPercent, sample.TasksRunning)
			if err != nil {
				t.Fatalf("usage of %s: %v", node.nodeId, err)
			}
			observation, err := autoscaling.NewNodeObservation(
				node.nodeId, node.state, capacity, usage, sample.PendingAllocations, node.replicas)
			if err != nil {
				t.Fatalf("observation of %s: %v", node.nodeId, err)
			}
			nodes = append(nodes, observation)
		}
		snapshot, err := autoscaling.NewAutoscalerSnapshot(nodes, demand)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		return snapshot
	}

	var actionKinds []string
	runTick := func(t *testing.T, demand []autoscaling.AllocationDemand) []autoscaling.AutoscalerAction {
		t.Helper()
		actions, err := engine.Tick(context.Background(), buildSnapshot(t, demand))
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
		for _, action := range actions {
			actionKinds = append(actionKinds, action.Kind().String())
		}
		return actions
	}

	seededDemand := []autoscaling.AllocationDemand{
		mustE2EDemand(t, "dashboard-main", "customer-dashboard",
			e2eNodeMemoryTotalBytes, e2eNodeCpuQuotaPercent, e2eNodeTasksMax),
	}

	// Phase 1, tick 1: an empty fleet with seeded demand beyond capacity must
	// provision exactly one node sized to the demand.
	actions := runTick(t, seededDemand)
	if len(actions) != 1 || actions[0].Kind() != autoscaling.AutoscalerActionProvisionNode {
		t.Fatalf("tick 1 actions = %v; want exactly one provision", actionKinds)
	}
	provisionRequest := actions[0].ProvisionRequest()
	if provisionRequest.NodeId != "as-node-1" ||
		provisionRequest.NodeClass != autoscaling.AutoscalerNodeClass ||
		provisionRequest.Resources.MemoryBytes != e2eNodeMemoryTotalBytes ||
		provisionRequest.Resources.CpuPercent != e2eNodeCpuQuotaPercent ||
		provisionRequest.Resources.Tasks != e2eNodeTasksMax ||
		provisionRequest.Reason == "" {
		t.Fatalf("provision request = %#v", provisionRequest)
	}
	if err := provisioner.Provision(context.Background(), provisionRequest); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// The provisioned node comes up: a real host agent on its own connection,
	// the real rootless podman adapter over the fake client, controlled
	// metrics, and a fast heartbeat.
	fakePodman := newFakeE2EPodmanClient()
	podmanAdapter, err := runtime.NewPodmanRootlessHostRuntimeAdapter(fakePodman, nil)
	if err != nil {
		t.Fatalf("podman adapter: %v", err)
	}
	nativeAdapter := &e2eUnusedNativeAdapter{}
	nodeId, err := hostagent.NewNodeId("as-node-1")
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	agentConnection, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatalf("agent connection: %v", err)
	}
	t.Cleanup(agentConnection.Close)
	wiredConnection, err := hostagent.NewLiveNatsConnection(agentConnection)
	if err != nil {
		t.Fatalf("agent connection seam: %v", err)
	}
	metrics := &e2eMetricsSource{podman: fakePodman}
	agent, err := hostagent.NewHostAgent(hostagent.HostAgentConfig{
		NodeId:            nodeId,
		Connection:        wiredConnection,
		Systemd:           nativeAdapter,
		Container:         podmanAdapter,
		Metrics:           metrics,
		HeartbeatInterval: e2eHeartbeatInterval,
		Now:               time.Now,
	})
	if err != nil {
		t.Fatalf("host agent: %v", err)
	}
	agentContext, cancelAgent := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelAgent()
		if err := agent.Close(); err != nil {
			t.Fatalf("agent close: %v", err)
		}
	})
	if err := agent.Start(agentContext); err != nil {
		t.Fatalf("agent start: %v", err)
	}

	// Phase 1, converge: the control plane drives the canonical plan to the
	// node over a real NATS request-reply and the agent accepts it.
	convergeReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		command := mustE2ECommand(t, planJson, "e2e-converge-1")
		subject, err := hostagent.NodeConvergeSubject(nodeId)
		if err != nil {
			t.Fatalf("converge subject: %v", err)
		}
		return subject, mustE2EJSON(t, command)
	})
	var convergeReceipt hostagent.ConvergeReceipt
	e2eDecode(t, convergeReply, &convergeReceipt)
	if !convergeReceipt.Accepted || convergeReceipt.CommandId != "e2e-converge-1" ||
		convergeReceipt.PlanFingerprint != fingerprint {
		t.Fatalf("converge receipt = %#v", convergeReceipt)
	}

	// The fake podman client observed the exact converge sequence and the
	// fencing labels of the created container.
	calls := fakePodman.recordedCalls()
	if !slices.Contains(calls, "pull:"+plan.Oci.ImageReference+"|"+plan.Oci.Platform) ||
		!slices.Contains(calls, "create:terrascale-dashboard-a") ||
		!slices.Contains(calls, "start:terrascale-dashboard-a") {
		t.Fatalf("podman calls after converge = %v", calls)
	}
	if calls[0] != "preflight" {
		t.Fatalf("first podman call = %q; want the preflight", calls[0])
	}
	created := fakePodman.createdRequest(0)
	if created.ImageReference != plan.Oci.ImageReference ||
		created.Labels[runtime.PodmanLabelAllocation] != "dashboard-a" ||
		created.Labels[runtime.PodmanLabelFingerprint] != fingerprint ||
		created.RunAsUser != plan.Oci.Security.RunAsUser ||
		!created.ReadOnlyRootfs || !created.NoNewPrivileges {
		t.Fatalf("created run request = %#v", created)
	}

	// Observe over the real request-reply: the fenced observation is Running.
	observeReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		command := mustE2ECommand(t, planJson, "e2e-observe-1")
		subject, err := hostagent.NodeObserveSubject(nodeId)
		if err != nil {
			t.Fatalf("observe subject: %v", err)
		}
		return subject, mustE2EJSON(t, command)
	})
	var observeReceipt hostagent.ObserveReceipt
	e2eDecode(t, observeReply, &observeReceipt)
	if !observeReceipt.Accepted || observeReceipt.PlanFingerprint != fingerprint {
		t.Fatalf("observe receipt = %#v", observeReceipt)
	}
	if !strings.Contains(observeReceipt.Detail, "Running") {
		t.Fatalf("observe detail = %q; want Running", observeReceipt.Detail)
	}

	// The node model now tracks the provisioned node, fed by real heartbeats.
	model = append(model, e2eModelNode{
		nodeId: "as-node-1",
		state:  autoscaling.NodeStateReady,
		replicas: []stateful.ReplicaHealth{
			mustE2EReplica(t, "terrabase-member", "terrabase-a", true),
		},
	})
	heartbeat := waitForE2EHeartbeatTasks(t, heartbeats, "as-node-1", 1)
	if heartbeat.Metrics.TasksRunning != 1 {
		t.Fatalf("heartbeat tasks = %d; want the running allocation reported", heartbeat.Metrics.TasksRunning)
	}

	// Phase 2, tick 2: demand is dropped; the workload keeps running while
	// the fleet reports sustained headroom.
	actions = runTick(t, nil)
	if len(actions) != 0 {
		t.Fatalf("tick 2 actions = %v; want none before the scale-down confirms", actionKinds)
	}

	// Tick 3: the counter has confirmed, but the stateful drain gate is NOT
	// satisfied (the only peer replica elsewhere is down), so the drain is
	// deferred fail-closed.
	actions = runTick(t, nil)
	if len(actions) != 0 {
		t.Fatalf("tick 3 actions = %v; want the drain deferred while no healthy peer exists", actionKinds)
	}

	// The peer replica elsewhere comes up; the drain gate now allows.
	baselinePeerUp = true
	model[0].replicas = []stateful.ReplicaHealth{
		mustE2EReplica(t, "terrabase-member", "terrabase-b", baselinePeerUp),
	}

	// Tick 4: cordon then drain the lowest-utilization node, as-node-1.
	actions = runTick(t, nil)
	if len(actions) != 2 ||
		actions[0].Kind() != autoscaling.AutoscalerActionCordonNode ||
		actions[1].Kind() != autoscaling.AutoscalerActionDrainNode ||
		actions[0].NodeId() != "as-node-1" || actions[1].NodeId() != "as-node-1" {
		t.Fatalf("tick 4 actions = %v; want cordon+drain of as-node-1", actionKinds)
	}

	// The cordon is delivered over the real cordon subject and acknowledged.
	cordonReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		command, err := hostagent.NewCordonCommand("e2e-cordon-1", true)
		if err != nil {
			t.Fatalf("cordon command: %v", err)
		}
		subject, err := hostagent.NodeCordonSubject(nodeId)
		if err != nil {
			t.Fatalf("cordon subject: %v", err)
		}
		return subject, mustE2EJSON(t, command)
	})
	var acknowledgment hostagent.CordonAcknowledgment
	e2eDecode(t, cordonReply, &acknowledgment)
	if !acknowledgment.Cordoned || acknowledgment.NodeId != "as-node-1" {
		t.Fatalf("cordon acknowledgment = %#v", acknowledgment)
	}
	model[len(model)-1].state = autoscaling.NodeStateDraining

	// A cordoned node refuses new work fail-closed, with the fingerprint.
	refusedReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		command := mustE2ECommand(t, planJson, "e2e-converge-cordoned")
		subject, err := hostagent.NodeConvergeSubject(nodeId)
		if err != nil {
			t.Fatalf("converge subject: %v", err)
		}
		return subject, mustE2EJSON(t, command)
	})
	var refusedReceipt hostagent.ConvergeReceipt
	e2eDecode(t, refusedReply, &refusedReceipt)
	if refusedReceipt.Accepted || refusedReceipt.PlanFingerprint != fingerprint {
		t.Fatalf("cordoned converge receipt = %#v; want refused with the fingerprint", refusedReceipt)
	}

	// The drain status reports one running allocation and not drained.
	statusReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		request, err := hostagent.NewNodeStatusRequest("e2e-drain-status-1")
		if err != nil {
			t.Fatalf("status request: %v", err)
		}
		subject, err := hostagent.NodeDrainStatusSubject(nodeId)
		if err != nil {
			t.Fatalf("drain-status subject: %v", err)
		}
		return subject, mustE2EJSON(t, request)
	})
	var statusReport hostagent.DrainStatusReport
	e2eDecode(t, statusReply, &statusReport)
	if !statusReport.Cordoned || statusReport.Drained || len(statusReport.Allocations) != 1 ||
		statusReport.Allocations[0].AllocationId != "dashboard-a" ||
		!statusReport.Allocations[0].Running ||
		statusReport.Allocations[0].PlanFingerprint != fingerprint {
		t.Fatalf("drain status report = %#v", statusReport)
	}

	// The drain stops the allocation over the real stop subject.
	stopReply := e2eRequest(t, controlConnection, func() (string, []byte) {
		command := mustE2ECommand(t, planJson, "e2e-stop-1")
		subject, err := hostagent.NodeStopSubject(nodeId)
		if err != nil {
			t.Fatalf("stop subject: %v", err)
		}
		return subject, mustE2EJSON(t, command)
	})
	var stopReceipt hostagent.StopReceipt
	e2eDecode(t, stopReply, &stopReceipt)
	if !stopReceipt.Accepted || stopReceipt.PlanFingerprint != fingerprint {
		t.Fatalf("stop receipt = %#v", stopReceipt)
	}
	calls = fakePodman.recordedCalls()
	if !slices.Contains(calls, "stop:terrascale-dashboard-a") {
		t.Fatalf("podman calls after stop = %v", calls)
	}

	// The heartbeat quiets to zero running tasks.
	_ = waitForE2EHeartbeatTasks(t, heartbeats, "as-node-1", 0)

	// Tick 5: the drained, quiet node is retired.
	actions = runTick(t, nil)
	if len(actions) != 1 || actions[0].Kind() != autoscaling.AutoscalerActionRetireNode ||
		actions[0].NodeId() != "as-node-1" {
		t.Fatalf("tick 5 actions = %v; want the retire of as-node-1", actionKinds)
	}
	if err := provisioner.Retire(context.Background(), "as-node-1"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	model[len(model)-1].state = autoscaling.NodeStateRetired

	// Ticks 6 and 7: the fleet is steady at MinNodes; no further actions.
	for tick := 6; tick <= 7; tick++ {
		actions = runTick(t, nil)
		if len(actions) != 0 {
			t.Fatalf("tick %d actions = %v; want a steady fleet", tick, actionKinds)
		}
	}

	// The full action sequence and the final node set.
	if !slices.Equal(actionKinds, []string{
		"ProvisionNode", "CordonNode", "DrainNode", "RetireNode",
	}) {
		t.Fatalf("action sequence = %v", actionKinds)
	}
	if len(provisioner.Provisions) != 1 || provisioner.Provisions[0].NodeId != "as-node-1" {
		t.Fatalf("provisions = %#v", provisioner.Provisions)
	}
	if len(provisioner.Retires) != 1 || provisioner.Retires[0] != "as-node-1" {
		t.Fatalf("retires = %#v", provisioner.Retires)
	}
	if model[0].nodeId != "node-baseline" || model[0].state != autoscaling.NodeStateReady ||
		model[1].nodeId != "as-node-1" || model[1].state != autoscaling.NodeStateRetired {
		t.Fatalf("final node set = %#v", model)
	}
	if nativeAdapter.calls != 0 {
		t.Fatalf("the native systemd adapter was driven %d times by an OCI plan", nativeAdapter.calls)
	}
}

// e2eRequest sends one request-reply built by the subject-and-payload
// constructor and returns the raw reply.
func e2eRequest(t *testing.T, connection *nats.Conn, build func() (string, []byte)) []byte {
	t.Helper()
	subject, payload := build()
	reply, err := connection.Request(subject, payload, e2eRequestTimeout)
	if err != nil {
		t.Fatalf("request on %s: %v", subject, err)
	}
	return reply.Data
}

// e2eDecode decodes one strict reply payload into the target receipt.
func e2eDecode(t *testing.T, data []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("reply decode: %v; payload %s", err, data)
	}
}

// mustE2ECommand builds one validated workload command from the plan payload.
func mustE2ECommand(t *testing.T, planJson []byte, commandId string) hostagent.WorkloadCommandRequest {
	t.Helper()
	command, err := hostagent.NewWorkloadCommandRequest(planJson, commandId)
	if err != nil {
		t.Fatalf("command %s: %v", commandId, err)
	}
	return command
}

// mustE2EJSON marshals one wire value, failing on the impossible error.
func mustE2EJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return payload
}

// mustE2EReplica builds one validated replica health observation.
func mustE2EReplica(t *testing.T, roleKind string, allocationId string, up bool) stateful.ReplicaHealth {
	t.Helper()
	replica, err := stateful.NewReplicaHealth(roleKind, allocationId, up, 0, 1, 0)
	if err != nil {
		t.Fatalf("replica %s: %v", allocationId, err)
	}
	return replica
}

// mustE2ESyntheticSample builds the validated metric sample of a model node
// without a live agent.
func mustE2ESyntheticSample(
	t *testing.T,
	memoryTotal int64,
	memoryUsed int64,
	cpuQuota int,
	cpuUsed int,
	tasksMax int,
	tasksRunning int,
) *hostagent.NodeMetricsSample {
	t.Helper()
	sample, err := hostagent.NewNodeMetricsSample(
		memoryTotal, memoryUsed, cpuQuota, cpuUsed, tasksMax, tasksRunning, 0)
	if err != nil {
		t.Fatalf("synthetic sample: %v", err)
	}
	return &sample
}

// mustE2EDemand builds one validated unsatisfied allocation demand unit.
func mustE2EDemand(
	t *testing.T,
	roleId string,
	roleKind string,
	memoryBytes int64,
	cpuPercent int,
	tasks int,
) autoscaling.AllocationDemand {
	t.Helper()
	resources, err := autoscaling.NewNodeResources(memoryBytes, cpuPercent, tasks)
	if err != nil {
		t.Fatalf("demand resources: %v", err)
	}
	demand, err := autoscaling.NewAllocationDemand(roleId, roleKind, false, resources)
	if err != nil {
		t.Fatalf("demand %s: %v", roleId, err)
	}
	return demand
}

// waitForE2EHeartbeatTasks polls the heartbeat log until the node reports the
// wanted running-task count, with a bounded deadline.
func waitForE2EHeartbeatTasks(
	t *testing.T,
	log *e2eHeartbeatLog,
	nodeId string,
	want int,
) hostagent.NodeHeartbeat {
	t.Helper()
	deadline := time.Now().Add(e2ePollTimeout)
	for {
		heartbeat, present := log.load(nodeId)
		if present && heartbeat.Metrics.TasksRunning == want {
			return heartbeat
		}
		if time.Now().After(deadline) {
			t.Fatalf("node %s never reported %d running tasks", nodeId, want)
		}
		time.Sleep(e2eHeartbeatInterval)
	}
}
