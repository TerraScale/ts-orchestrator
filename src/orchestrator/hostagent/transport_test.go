package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// fakeNatsConnection is the in-memory NatsConnection seam: it captures
// publications and answers request-reply pairs synchronously.
type fakeNatsConnection struct {
	mutex         sync.Mutex
	subscriptions map[string]func(*nats.Msg)
	published     []struct {
		subject string
		payload []byte
	}
	failPublishSubject string
	failPublishCount   int
	drainCalls         int
	closeCalls         int
}

func newFakeNatsConnection() *fakeNatsConnection {
	return &fakeNatsConnection{subscriptions: map[string]func(*nats.Msg){}}
}

func (f *fakeNatsConnection) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.subscriptions[subject] = handler
	return &nats.Subscription{}, nil
}

func (f *fakeNatsConnection) Publish(subject string, payload []byte) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if subject == f.failPublishSubject && f.failPublishCount > 0 {
		f.failPublishCount--
		return errors.New("injected publish failure")
	}
	f.published = append(f.published, struct {
		subject string
		payload []byte
	}{subject, payload})
	return nil
}

// request delivers one request-reply message to the handler subscribed on
// subject and returns the reply payload published to the inbox.
func (f *fakeNatsConnection) request(subject string, payload []byte) ([]byte, error) {
	f.mutex.Lock()
	handler, present := f.subscriptions[subject]
	published := len(f.published)
	f.mutex.Unlock()
	if !present {
		return nil, &InvalidOperationError{Message: "no subscription on " + subject}
	}
	handler(&nats.Msg{Subject: subject, Data: payload, Reply: "_INBOX.test"})
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, publication := range f.published[published:] {
		if publication.subject == "_INBOX.test" {
			return publication.payload, nil
		}
	}
	return nil, &InvalidOperationError{Message: "no reply was published"}
}

func (f *fakeNatsConnection) Flush() error { return nil }

func (f *fakeNatsConnection) Drain() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.drainCalls++
	return nil
}

func (f *fakeNatsConnection) Close() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.closeCalls++
}

func (f *fakeNatsConnection) heartbeatPayloads(t *testing.T) []HostHeartbeat {
	t.Helper()
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var heartbeats []HostHeartbeat
	for _, publication := range f.published {
		if publication.subject != "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.observation.heartbeat" {
			continue
		}
		var heartbeat HostHeartbeat
		if err := json.Unmarshal(publication.payload, &heartbeat); err != nil {
			t.Fatalf("heartbeat payload does not decode: %v", err)
		}
		heartbeats = append(heartbeats, heartbeat)
	}
	return heartbeats
}

// manualTicker is the injectable heartbeat clock.
type manualTicker struct {
	channel chan time.Time
	stopped bool
}

func newManualTicker() *manualTicker { return &manualTicker{channel: make(chan time.Time, 1)} }

func (t *manualTicker) C() <-chan time.Time { return t.channel }

func (t *manualTicker) Stop() { t.stopped = true }

func (t *manualTicker) tick() {
	select {
	case t.channel <- time.Now():
	default:
	}
}

// newTestTransport builds one transport over the lifecycle harness.
func newTestTransport(t *testing.T, harness *testHarness) (*NatsTransport, *fakeNatsConnection, *manualTicker) {
	t.Helper()
	connection := newFakeNatsConnection()
	ticker := newManualTicker()
	transport, err := NewNatsTransport(NatsTransportConfig{
		NodeId:     NodeId{Value: "gru-1"},
		Connection: connection,
		Lifecycle:  harness.lifecycle,
		Facts:      harness.factsSource(t),
		Ticker:     ticker,
		Now:        func() time.Time { return time.Unix(1756900000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport, connection, ticker
}

// factsSource builds one facts source with a healthy clock for transport
// tests.
func (h *testHarness) factsSource(t *testing.T) *HostFactsSource {
	t.Helper()
	source, err := NewHostFactsSource(HostFactsSourceConfig{
		Clock:          fakeClock{offset: 10 * time.Millisecond},
		Statfs:         fakeStatfs(1<<40, 1<<39),
		DataVolumeRoot: h.dataVolume,
		Systemd:        h.systemd,
		InstallRoot:    h.root,
		Installer:      h.lifecycle.installer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// TestTransportServesTheDrainDeployRollbackSurface walks the RPC
// choreography the delivery lane drives: drain, drain-status to the quiesce
// gate, deploy, release — plus the rollback path.
func TestTransportServesTheDrainDeployRollbackSurface(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	v2 := harness.publish(t, "terrabase", "1.1.0")
	harness.applyDesired(t, v1)
	harness.applyDesired(t, v2)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	_, connection, _ := newTestTransport(t, harness)

	// Drain through the RPC surface.
	reply, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain",
		mustJSON(t, DrainCommand{CommandId: "cmd-drain", Drain: true}))
	if err != nil {
		t.Fatal(err)
	}
	var drainReceipt DrainReceipt
	if err := json.Unmarshal(reply, &drainReceipt); err != nil {
		t.Fatal(err)
	}
	if !drainReceipt.Draining || !drainReceipt.Quiesced || drainReceipt.NodeId != "gru-1" {
		t.Fatalf("drain receipt is %+v", drainReceipt)
	}

	// The drain-status gate reports the same state with facts.
	reply, err = connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status",
		mustJSON(t, NodeStatusRequest{CommandId: "cmd-status"}))
	if err != nil {
		t.Fatal(err)
	}
	var status NodeStatusReport
	if err := json.Unmarshal(reply, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != NodeStateDraining || !status.Quiesced {
		t.Fatalf("status report is %+v", status)
	}
	if status.Facts.ClockOffsetMillis != 10 || status.Facts.ClockUnhealthy {
		t.Fatalf("status facts are %+v", status.Facts)
	}

	// Deploy v2 under the drain.
	reply, err = connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.deploy",
		mustJSON(t, DeployCommand{CommandId: "cmd-deploy", Component: "terrabase", Version: "1.1.0"}))
	if err != nil {
		t.Fatal(err)
	}
	var deployReceipt DeployReceipt
	if err := json.Unmarshal(reply, &deployReceipt); err != nil {
		t.Fatal(err)
	}
	if !deployReceipt.Accepted || deployReceipt.Current != "1.1.0" {
		t.Fatalf("deploy receipt is %+v", deployReceipt)
	}

	// Release back to serving.
	reply, err = connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain",
		mustJSON(t, DrainCommand{CommandId: "cmd-release"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reply, &drainReceipt); err != nil {
		t.Fatal(err)
	}
	if drainReceipt.Draining {
		t.Fatalf("release receipt is %+v", drainReceipt)
	}

	// Rollback from serving: accepted, current back at 1.0.0.
	reply, err = connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback",
		mustJSON(t, RollbackCommand{CommandId: "cmd-rollback", Component: "terrabase"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reply, &deployReceipt); err != nil {
		t.Fatal(err)
	}
	if !deployReceipt.Accepted || deployReceipt.Current != "1.0.0" {
		t.Fatalf("rollback receipt is %+v", deployReceipt)
	}
}

// TestTransportRefusesDeployWithoutDrain asserts the fail-closed gate
// surfaces as an unaccepted receipt with the reason, not a timeout.
func TestTransportRefusesDeployWithoutDrain(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, v1)
	_, connection, _ := newTestTransport(t, harness)
	reply, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.deploy",
		mustJSON(t, DeployCommand{CommandId: "cmd-deploy", Component: "terrabase", Version: "1.0.0"}))
	if err != nil {
		t.Fatal(err)
	}
	var receipt DeployReceipt
	if err := json.Unmarshal(reply, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Accepted {
		t.Fatalf("undrained deploy accepted: %+v", receipt)
	}
	if receipt.Detail == "" {
		t.Fatal("refused receipt carries no reason")
	}
}

// TestTransportPublishesHeartbeatsOnTheTicker asserts the heartbeat cadence
// and payload over the publish-only subject.
func TestTransportPublishesHeartbeatsOnTheTicker(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, v1)
	_, connection, ticker := newTestTransport(t, harness)
	ticker.tick()
	var heartbeats []HostHeartbeat
	for deadline := time.Now().Add(5 * time.Second); ; {
		heartbeats = connection.heartbeatPayloads(t)
		if len(heartbeats) >= 2 || time.Now().After(deadline) { // Start heartbeat plus the tick
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(heartbeats) < 2 {
		t.Fatalf("heartbeats published: %d", len(heartbeats))
	}
	heartbeat := heartbeats[len(heartbeats)-1]
	if heartbeat.NodeId != "gru-1" || heartbeat.UnixSeconds != 1756900000 {
		t.Fatalf("heartbeat envelope is %+v", heartbeat)
	}
	if heartbeat.Facts.State != NodeStateServing || heartbeat.Facts.TsNodeVersion != TsNodeVersion {
		t.Fatalf("heartbeat facts are %+v", heartbeat.Facts)
	}
}

// TestTransportRejectsUnknownFields asserts the closed wire vocabulary.
func TestTransportRejectsUnknownFields(t *testing.T) {
	harness := newTestHarness(t)
	harness.applyDesired(t, harness.publish(t, "terrabase", "1.0.0"))
	_, connection, _ := newTestTransport(t, harness)
	reply, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain",
		[]byte(`{"commandId":"cmd-bad","drain":true,"extra":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope CommandEnvelopeError
	if err := json.Unmarshal(reply, &envelope); err != nil || envelope.Detail == "" {
		t.Fatalf("unknown field not answered with an envelope error: %s %v", reply, err)
	}
}

// TestTransportRollbackReplayIsStable proves a lost reply and a later
// redelivery cannot toggle rollback back to the failed release.
func TestTransportRollbackReplayIsStable(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	v2 := harness.publish(t, "terrabase", "1.1.0")
	harness.applyDesired(t, v1)
	harness.applyDesired(t, v2)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := FlipCurrent(harness.root, "terrabase", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	transport, connection, _ := newTestTransport(t, harness)
	command := mustJSON(t, RollbackCommand{CommandId: "cmd-lost", Component: "terrabase"})
	connection.failPublishSubject = "_INBOX.test"
	connection.failPublishCount = 1
	if _, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback", command); err == nil {
		t.Fatal("lost reply was unexpectedly delivered")
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.0.0" {
		t.Fatalf("current after first rollback = %q", current)
	}
	restarts := countOperation(harness.systemd.ops(), "restart:"+UnitName("terrabase"))
	reply, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback", command)
	if err != nil {
		t.Fatal(err)
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.0.0" {
		t.Fatalf("duplicate rollback toggled current to %q", current)
	}
	if got := countOperation(harness.systemd.ops(), "restart:"+UnitName("terrabase")); got != restarts {
		t.Fatalf("duplicate rollback restarted again: before=%d after=%d", restarts, got)
	}
	var receipt DeployReceipt
	if err := json.Unmarshal(reply, &receipt); err != nil || !receipt.Accepted || receipt.Current != "1.0.0" {
		t.Fatalf("replayed receipt = %+v, %v", receipt, err)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	// A new transport over the same data root replays the durable receipt.
	secondConnection := newFakeNatsConnection()
	secondTicker := newManualTicker()
	second, err := NewNatsTransport(NatsTransportConfig{
		NodeId: NodeId{Value: "gru-1"}, Connection: secondConnection,
		Lifecycle: harness.lifecycle, Facts: harness.factsSource(t), Ticker: secondTicker,
		Now: func() time.Time { return time.Unix(1756900000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	secondReply, err := secondConnection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback", command)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, secondReply) {
		t.Fatalf("restart replay changed response: %s != %s", reply, secondReply)
	}
	if got := countOperation(harness.systemd.ops(), "restart:"+UnitName("terrabase")); got != restarts {
		t.Fatalf("restart replay executed rollback again: before=%d after=%d", restarts, got)
	}
}

// TestTransportRecoversPendingRollbackAtPinnedTarget covers both crash
// windows: after intent but before mutation, and after mutation but before
// the terminal receipt commit.
func TestTransportRecoversPendingRollbackAtPinnedTarget(t *testing.T) {
	for _, mutateBeforeRestart := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-mutation", true: "after-mutation"}[mutateBeforeRestart], func(t *testing.T) {
			harness := newTestHarness(t)
			v1 := harness.publish(t, "terrabase", "1.0.0")
			v2 := harness.publish(t, "terrabase", "1.1.0")
			harness.applyDesired(t, v1)
			harness.applyDesired(t, v2)
			if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
				t.Fatal(err)
			}
			if err := FlipCurrent(harness.root, "terrabase", "1.1.0"); err != nil {
				t.Fatal(err)
			}
			journal, err := newCommandJournal(filepath.Join(harness.dataVolume, TsNodeComponentName, "command-journal"))
			if err != nil || journal.initialize() != nil {
				t.Fatalf("initialize journal: %v", err)
			}
			command := RollbackCommand{CommandId: "cmd-crash", Component: "terrabase"}
			request := mustJSON(t, command)
			plan, err := harness.lifecycle.prepareRollback(command.Component)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.begin(commandKindRollback, command.CommandId, request, &plan); err != nil {
				t.Fatal(err)
			}
			if mutateBeforeRestart {
				if err := harness.lifecycle.applyTransition(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
			}
			_, connection, _ := newTestTransport(t, harness)
			if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.0.0" {
				t.Fatalf("recovery current = %q", current)
			}
			restarts := countOperation(harness.systemd.ops(), "restart:"+UnitName("terrabase"))
			if _, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback", request); err != nil {
				t.Fatal(err)
			}
			if got := countOperation(harness.systemd.ops(), "restart:"+UnitName("terrabase")); got != restarts {
				t.Fatalf("completed recovery replayed mutation: before=%d after=%d", restarts, got)
			}
		})
	}
}

// TestTransportRejectsCommandIdReuse proves an ID cannot cross command
// payloads or subjects after its first durable use.
func TestTransportRejectsCommandIdReuse(t *testing.T) {
	harness := newTestHarness(t)
	harness.applyDesired(t, harness.publish(t, "terrabase", "1.0.0"))
	_, connection, _ := newTestTransport(t, harness)
	subject := "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain"
	if _, err := connection.request(subject, []byte(`{"commandId":"cmd-reuse","drain":true}`)); err != nil {
		t.Fatal(err)
	}
	reply, err := connection.request(subject, []byte(`{"commandId":"cmd-reuse","drain":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope CommandEnvelopeError
	if err := json.Unmarshal(reply, &envelope); err != nil || envelope.Detail == "" {
		t.Fatalf("conflicting command ID reply = %s, %v", reply, err)
	}
	if harness.lifecycle.State() != NodeStateDraining {
		t.Fatal("conflicting command ID changed lifecycle state")
	}
}

// TestTransportClosePreservesBorrowedConnection checks ownership: transport
// drains only its subscriptions when the caller owns the connection.
func TestTransportClosePreservesBorrowedConnection(t *testing.T) {
	harness := newTestHarness(t)
	transport, connection, _ := newTestTransport(t, harness)
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.drainCalls != 0 || connection.closeCalls != 0 {
		t.Fatalf("borrowed connection drained=%d closed=%d", connection.drainCalls, connection.closeCalls)
	}
}

func countOperation(operations []string, wanted string) int {
	count := 0
	for _, operation := range operations {
		if operation == wanted {
			count++
		}
	}
	return count
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
