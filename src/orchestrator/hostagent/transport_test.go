// This file tests the node transport with a fake NATS connection and a
// manually ticked heartbeat clock: full request-reply round trips, cordon
// behavior, heartbeat content, and graceful close.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// fakePublication is one recorded publication.
type fakePublication struct {
	Subject string
	Payload []byte
}

// fakeNatsConnection records subscriptions and publications and never touches
// the network.
type fakeNatsConnection struct {
	mutex         sync.Mutex
	handlers      map[string]func(*nats.Msg)
	subscriptions []string
	published     []fakePublication
	flushes       int
	drains        int
	closes        int
}

func newFakeNatsConnection() *fakeNatsConnection {
	return &fakeNatsConnection{handlers: map[string]func(*nats.Msg){}}
}

func (f *fakeNatsConnection) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.handlers[subject] = handler
	f.subscriptions = append(f.subscriptions, subject)
	return nil, nil
}

func (f *fakeNatsConnection) Publish(subject string, payload []byte) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.published = append(f.published, fakePublication{Subject: subject, Payload: append([]byte(nil), payload...)})
	return nil
}

func (f *fakeNatsConnection) Request(subject string, payload []byte, timeout time.Duration) (*nats.Msg, error) {
	return nil, errors.New("the node transport never issues requests")
}

func (f *fakeNatsConnection) Flush() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.flushes++
	return nil
}

func (f *fakeNatsConnection) Drain() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.drains++
	return nil
}

func (f *fakeNatsConnection) Close() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.closes++
}

func (f *fakeNatsConnection) request(subject string, payload []byte) []byte {
	f.mutex.Lock()
	handler := f.handlers[subject]
	f.mutex.Unlock()
	if handler == nil {
		panic("no handler subscribed on " + subject)
	}
	message := &nats.Msg{Subject: subject, Reply: "_INBOX.test", Data: payload}
	handler(message)
	return f.lastReply()
}

func (f *fakeNatsConnection) lastReply() []byte {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for index := len(f.published) - 1; index >= 0; index-- {
		if f.published[index].Subject == "_INBOX.test" {
			return f.published[index].Payload
		}
	}
	return nil
}

func (f *fakeNatsConnection) publicationsOn(subject string) []fakePublication {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var matched []fakePublication
	for _, publication := range f.published {
		if publication.Subject == subject {
			matched = append(matched, publication)
		}
	}
	return matched
}

func (f *fakeNatsConnection) counts() (flushes int, drains int, closes int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.flushes, f.drains, f.closes
}

// fakeHeartbeatTicker is a manually ticked heartbeat clock.
type fakeHeartbeatTicker struct {
	ticks   chan time.Time
	stopped bool
}

func newFakeHeartbeatTicker() *fakeHeartbeatTicker {
	return &fakeHeartbeatTicker{ticks: make(chan time.Time, 8)}
}

func (f *fakeHeartbeatTicker) C() <-chan time.Time { return f.ticks }

func (f *fakeHeartbeatTicker) Stop() { f.stopped = true }

func (f *fakeHeartbeatTicker) tick() {
	select {
	case f.ticks <- time.Unix(0, 0):
	default:
		panic("fake ticker tick channel is full")
	}
}

// fakeMetricsSource serves one fixed valid sample.
type fakeMetricsSource struct {
	sample NodeMetricsSample
	err    error
}

func (f *fakeMetricsSource) Sample(ctx context.Context) (NodeMetricsSample, error) {
	return f.sample, f.err
}

// fixedTestClock serves one fixed positive timestamp.
func fixedTestClock() time.Time { return time.Unix(1750000000, 0).UTC() }

func newTransportForTest(t *testing.T, connection NatsConnection, executor *WorkloadExecutor,
	ticker HeartbeatTicker, metrics MetricsSource, closeConnection bool) *NatsTransport {
	t.Helper()
	transport, err := NewNatsTransport(NatsTransportConfig{
		NodeId:          executorTestNodeId(t),
		Connection:      connection,
		Executor:        executor,
		Metrics:         metrics,
		Ticker:          ticker,
		Now:             fixedTestClock,
		CloseConnection: closeConnection,
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if err := transport.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func defaultTransportForTest(t *testing.T) (*NatsTransport, *fakeNatsConnection, *fakeNativeAdapter, *fakeContainerAdapter) {
	t.Helper()
	connection := newFakeNatsConnection()
	systemd := &fakeNativeAdapter{observation: runningSystemdObservation()}
	container := &fakeContainerAdapter{observation: runningPodmanObservation(t)}
	executor := newExecutorForTest(t, systemd, container)
	transport := newTransportForTest(t, connection, executor, newFakeHeartbeatTicker(), defaultMetricsForTest(), false)
	return transport, connection, systemd, container
}

func defaultMetricsForTest() *fakeMetricsSource {
	sample, err := NewNodeMetricsSample(16<<30, 8<<30, 800, 200, 4096, 512, 0)
	if err != nil {
		panic(err)
	}
	return &fakeMetricsSource{sample: sample}
}

func TestNatsTransportSubscribesToEveryRequestSubject(t *testing.T) {
	_, connection, _, _ := defaultTransportForTest(t)

	expected := []string{
		"terrascale.node.v1.gru-node-1.converge",
		"terrascale.node.v1.gru-node-1.observe",
		"terrascale.node.v1.gru-node-1.stop",
		"terrascale.node.v1.gru-node-1.delete",
		"terrascale.node.v1.gru-node-1.cordon",
		"terrascale.node.v1.gru-node-1.drain-status",
	}
	if len(connection.subscriptions) != len(expected) {
		t.Fatalf("subscriptions = %v", connection.subscriptions)
	}
	for _, subject := range expected {
		if _, present := connection.handlers[subject]; !present {
			t.Fatalf("subject %s not subscribed: %v", subject, connection.subscriptions)
		}
	}
	if _, present := connection.handlers["terrascale.node.v1.gru-node-1.heartbeat"]; present {
		t.Fatal("the heartbeat leaf is publish-only and must not be subscribed")
	}
	flushes, _, _ := connection.counts()
	if flushes != 1 {
		t.Fatalf("start must flush once, got %d", flushes)
	}
}

func TestNatsTransportRejectsStartAfterClose(t *testing.T) {
	connection := newFakeNatsConnection()
	executor := newExecutorForTest(t, &fakeNativeAdapter{observation: runningSystemdObservation()},
		&fakeContainerAdapter{observation: runningPodmanObservation(t)})
	ticker := newFakeHeartbeatTicker()
	transport, err := NewNatsTransport(NatsTransportConfig{
		NodeId: executorTestNodeId(t), Connection: connection, Executor: executor,
		Metrics: defaultMetricsForTest(), Ticker: ticker, Now: fixedTestClock,
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var operationError *InvalidOperationError
	if err := transport.Start(context.Background()); !errors.As(err, &operationError) {
		t.Fatalf("start after close must be rejected, got %v", err)
	}
	if flushes, _, _ := connection.counts(); flushes != 0 {
		t.Fatalf("closed transport must not subscribe or flush: %d", flushes)
	}
}

func TestNatsTransportAnswersEveryWorkloadLeaf(t *testing.T) {
	tests := []struct {
		leaf    string
		plan    runtime.HostRuntimePlan
		decoder func([]byte) (commandId string, accepted bool, fingerprint string)
	}{
		{
			leaf: "converge",
			plan: executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1"),
			decoder: func(payload []byte) (string, bool, string) {
				var receipt ConvergeReceipt
				if err := json.Unmarshal(payload, &receipt); err != nil {
					t.Fatalf("receipt: %v", err)
				}
				return receipt.CommandId, receipt.Accepted, receipt.PlanFingerprint
			},
		},
		{
			leaf: "observe",
			plan: executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1"),
			decoder: func(payload []byte) (string, bool, string) {
				var receipt ObserveReceipt
				if err := json.Unmarshal(payload, &receipt); err != nil {
					t.Fatalf("receipt: %v", err)
				}
				return receipt.CommandId, receipt.Accepted, receipt.PlanFingerprint
			},
		},
		{
			leaf: "stop",
			plan: executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1"),
			decoder: func(payload []byte) (string, bool, string) {
				var receipt StopReceipt
				if err := json.Unmarshal(payload, &receipt); err != nil {
					t.Fatalf("receipt: %v", err)
				}
				return receipt.CommandId, receipt.Accepted, receipt.PlanFingerprint
			},
		},
		{
			leaf: "delete",
			plan: executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "grafana-1"),
			decoder: func(payload []byte) (string, bool, string) {
				var receipt DeleteReceipt
				if err := json.Unmarshal(payload, &receipt); err != nil {
					t.Fatalf("receipt: %v", err)
				}
				return receipt.CommandId, receipt.Accepted, receipt.PlanFingerprint
			},
		},
	}
	for _, test := range tests {
		t.Run(test.leaf, func(t *testing.T) {
			_, connection, _, _ := defaultTransportForTest(t)
			command := executorTestCommand(t, test.plan, "cmd-"+test.leaf)
			payload, err := json.Marshal(command)
			if err != nil {
				t.Fatalf("command wire: %v", err)
			}

			reply := connection.request("terrascale.node.v1.gru-node-1."+test.leaf, payload)

			commandId, accepted, fingerprint := test.decoder(reply)
			if commandId != "cmd-"+test.leaf {
				t.Fatalf("command id = %q", commandId)
			}
			if !accepted {
				t.Fatalf("reply not accepted: %s", reply)
			}
			expectedFingerprint, err := runtime.CanonicalPlanFingerprint.Compute(test.plan)
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
			if fingerprint != expectedFingerprint {
				t.Fatalf("fingerprint = %q, want %q", fingerprint, expectedFingerprint)
			}
		})
	}
}

func TestNatsTransportWorkloadCommandWireRoundTrips(t *testing.T) {
	plan := executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "grafana-1")
	command := executorTestCommand(t, plan, "cmd-wire-1")

	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(payload), `"planJson":"`) || !strings.Contains(string(payload), `"commandId":"cmd-wire-1"`) {
		t.Fatalf("wire payload = %s", payload)
	}

	var decoded WorkloadCommandRequest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.CommandId != command.CommandId || string(decoded.PlanJson) != string(command.PlanJson) {
		t.Fatal("the command wire round trip must be lossless")
	}

	var rejected WorkloadCommandRequest
	if err := json.Unmarshal([]byte(`{"planJson":"e30=","commandId":"cmd-x","injected":1}`), &rejected); err == nil {
		t.Fatal("unknown wire fields must be rejected")
	}
	if err := json.Unmarshal([]byte(`{"commandId":"cmd-x"}`), &rejected); err == nil {
		t.Fatal("a command without a plan payload must be rejected")
	}
}

func TestNatsTransportCordonRejectsConvergeWhileObserving(t *testing.T) {
	_, connection, systemd, _ := defaultTransportForTest(t)
	cordonPayload, err := json.Marshal(mustCordonCommand(t, "cmd-cordon-1", true))
	if err != nil {
		t.Fatalf("cordon wire: %v", err)
	}

	ackReply := connection.request("terrascale.node.v1.gru-node-1.cordon", cordonPayload)

	var acknowledgment CordonAcknowledgment
	if err := json.Unmarshal(ackReply, &acknowledgment); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if !acknowledgment.Cordoned || acknowledgment.NodeId != "gru-node-1" || acknowledgment.CommandId != "cmd-cordon-1" {
		t.Fatalf("acknowledgment = %+v", acknowledgment)
	}

	plan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	convergePayload, err := json.Marshal(executorTestCommand(t, plan, "cmd-after-cordon"))
	if err != nil {
		t.Fatalf("command wire: %v", err)
	}
	convergeReply := connection.request("terrascale.node.v1.gru-node-1.converge", convergePayload)
	var convergeReceipt ConvergeReceipt
	if err := json.Unmarshal(convergeReply, &convergeReceipt); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if convergeReceipt.Accepted {
		t.Fatal("a cordoned node must refuse new work")
	}
	if systemd.convergeCalls != 0 {
		t.Fatal("a cordoned node must not reach the adapter")
	}

	observeReply := connection.request("terrascale.node.v1.gru-node-1.observe", convergePayload)
	var observeReceipt ObserveReceipt
	if err := json.Unmarshal(observeReply, &observeReceipt); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if !observeReceipt.Accepted {
		t.Fatal("observe must keep answering while cordoned")
	}
}

func TestNatsTransportDrainStatusReportsCordonAndObservations(t *testing.T) {
	_, connection, systemd, container := defaultTransportForTest(t)
	nativePlan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	ociPlan := executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "grafana-1")
	for _, plan := range []runtime.HostRuntimePlan{nativePlan, ociPlan} {
		payload, err := json.Marshal(executorTestCommand(t, plan, "cmd-"+plan.AllocationId.Value))
		if err != nil {
			t.Fatalf("command wire: %v", err)
		}
		connection.request("terrascale.node.v1.gru-node-1.converge", payload)
	}

	statusPayload, err := json.Marshal(mustNodeStatusRequest(t, "cmd-drain-1"))
	if err != nil {
		t.Fatalf("status wire: %v", err)
	}
	reply := connection.request("terrascale.node.v1.gru-node-1.drain-status", statusPayload)

	var report DrainStatusReport
	if err := json.Unmarshal(reply, &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.CommandId != "cmd-drain-1" || report.NodeId != "gru-node-1" {
		t.Fatalf("report = %+v", report)
	}
	if report.Cordoned || report.Drained {
		t.Fatalf("an uncordoned node is not drained: %+v", report)
	}
	if len(report.Allocations) != 2 {
		t.Fatalf("allocations = %+v", report.Allocations)
	}
	if report.Allocations[0].AllocationId != "grafana-1" || report.Allocations[1].AllocationId != "gru-orchestrator-1" {
		t.Fatalf("allocations must be ordered: %+v", report.Allocations)
	}
	for _, allocation := range report.Allocations {
		if !allocation.Running {
			t.Fatalf("converged allocations report running: %+v", allocation)
		}
	}

	// Stop everything, cordon, and require a drained report.
	systemd.observation = runtime.SystemdAllocationObservation{
		UnitName: "terrascale-unit.service",
		State:    runtime.SystemdAllocationStateStopped,
		Result:   "success",
	}
	container.observation = mustStoppedPodmanObservation(t)
	cordonPayload, err := json.Marshal(mustCordonCommand(t, "cmd-cordon-2", true))
	if err != nil {
		t.Fatalf("cordon wire: %v", err)
	}
	connection.request("terrascale.node.v1.gru-node-1.cordon", cordonPayload)

	reply = connection.request("terrascale.node.v1.gru-node-1.drain-status", statusPayload)
	if err := json.Unmarshal(reply, &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	if !report.Cordoned || !report.Drained {
		t.Fatalf("a cordoned node with stopped allocations is drained: %+v", report)
	}
}

func TestNatsTransportPublishesHeartbeatsOnInjectedTicks(t *testing.T) {
	connection := newFakeNatsConnection()
	systemd := &fakeNativeAdapter{}
	executor := newExecutorForTest(t, systemd, &fakeContainerAdapter{})
	ticker := newFakeHeartbeatTicker()
	newTransportForTest(t, connection, executor, ticker, defaultMetricsForTest(), false)

	subject := "terrascale.node.v1.gru-node-1.heartbeat"
	if published := connection.publicationsOn(subject); len(published) != 1 {
		t.Fatalf("start must publish the first heartbeat, got %d", len(published))
	}
	assertHeartbeatPayload(t, connection.publicationsOn(subject)[0].Payload)

	ticker.tick()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(connection.publicationsOn(subject)) >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if published := connection.publicationsOn(subject); len(published) != 2 {
		t.Fatalf("each tick must publish one heartbeat, got %d", len(published))
	}
	assertHeartbeatPayload(t, connection.publicationsOn(subject)[1].Payload)
}

func assertHeartbeatPayload(t *testing.T, payload []byte) {
	t.Helper()
	var heartbeat NodeHeartbeat
	if err := json.Unmarshal(payload, &heartbeat); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if heartbeat.NodeId.Value != "gru-node-1" {
		t.Fatalf("node id = %q", heartbeat.NodeId.Value)
	}
	if heartbeat.UnixSeconds != fixedTestClock().Unix() {
		t.Fatalf("unix seconds = %d", heartbeat.UnixSeconds)
	}
	if heartbeat.Metrics.CpuQuotaPercent != 800 || heartbeat.Metrics.TasksMax != 4096 {
		t.Fatalf("metrics = %+v", heartbeat.Metrics)
	}
}

func TestNatsTransportRepliesEnvelopeErrorOnUndecodableCommand(t *testing.T) {
	_, connection, systemd, _ := defaultTransportForTest(t)

	reply := connection.request("terrascale.node.v1.gru-node-1.converge", []byte(`{"planJson":42}`))

	var envelopeError CommandEnvelopeError
	if err := json.Unmarshal(reply, &envelopeError); err != nil {
		t.Fatalf("envelope error: %v", err)
	}
	if envelopeError.Detail == "" {
		t.Fatal("the envelope error must carry a bounded detail")
	}
	if systemd.convergeCalls != 0 {
		t.Fatal("an undecodable command must not reach the adapter")
	}
}

func TestNatsTransportCloseDrainsGracefully(t *testing.T) {
	connection := newFakeNatsConnection()
	executor := newExecutorForTest(t, &fakeNativeAdapter{}, &fakeContainerAdapter{})
	ticker := newFakeHeartbeatTicker()
	transport := newTransportForTest(t, connection, executor, ticker, defaultMetricsForTest(), false)

	if err := transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
	flushes, drains, closes := connection.counts()
	if flushes != 1 || drains != 1 {
		t.Fatalf("flushes = %d, drains = %d", flushes, drains)
	}
	if closes != 0 {
		t.Fatalf("a caller-owned connection must not be closed, got %d closes", closes)
	}
	if !ticker.stopped {
		t.Fatal("close must stop the ticker")
	}

	ownedConnection := newFakeNatsConnection()
	ownedTransport := newTransportForTest(t, ownedConnection, executor, newFakeHeartbeatTicker(), defaultMetricsForTest(), true)
	if err := ownedTransport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, drains, closes := ownedConnection.counts(); drains != 1 || closes != 1 {
		t.Fatalf("an owned connection must be drained and closed: drains = %d, closes = %d", drains, closes)
	}
}

func TestNatsTransportRejectsInvalidConfiguration(t *testing.T) {
	valid := NatsTransportConfig{
		NodeId:     executorTestNodeId(t),
		Connection: newFakeNatsConnection(),
		Executor:   newExecutorForTest(t, &fakeNativeAdapter{}, &fakeContainerAdapter{}),
		Metrics:    defaultMetricsForTest(),
		Ticker:     newFakeHeartbeatTicker(),
		Now:        fixedTestClock,
	}
	tests := []struct {
		name      string
		mutate    func(config *NatsTransportConfig)
		wantParam string
	}{
		{name: "missing connection", mutate: func(c *NatsTransportConfig) { c.Connection = nil }, wantParam: "Connection"},
		{name: "missing executor", mutate: func(c *NatsTransportConfig) { c.Executor = nil }, wantParam: "Executor"},
		{name: "missing metrics", mutate: func(c *NatsTransportConfig) { c.Metrics = nil }, wantParam: "Metrics"},
		{name: "missing ticker", mutate: func(c *NatsTransportConfig) { c.Ticker = nil }, wantParam: "Ticker"},
		{name: "missing clock", mutate: func(c *NatsTransportConfig) { c.Now = nil }, wantParam: "Now"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewNatsTransport(config); err == nil {
				t.Fatal("expected a configuration error")
			} else if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %s", err, test.wantParam)
			}
		})
	}
}

func mustCordonCommand(t *testing.T, commandId string, cordoned bool) CordonCommand {
	t.Helper()
	command, err := NewCordonCommand(commandId, cordoned)
	if err != nil {
		t.Fatalf("cordon command: %v", err)
	}
	return command
}

func mustNodeStatusRequest(t *testing.T, commandId string) NodeStatusRequest {
	t.Helper()
	request, err := NewNodeStatusRequest(commandId)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	return request
}
