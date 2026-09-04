package hostagent

import (
	"context"
	"encoding/json"
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

func (f *fakeNatsConnection) Drain() error { return nil }

func (f *fakeNatsConnection) Close() {}

func (f *fakeNatsConnection) heartbeatPayloads(t *testing.T) []HostHeartbeat {
	t.Helper()
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var heartbeats []HostHeartbeat
	for _, publication := range f.published {
		if publication.subject != "terrascale.node.v1.gru-1.heartbeat" {
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
	harness.applyDesired(t, v1, v2)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	_, connection, _ := newTestTransport(t, harness)

	// Drain through the RPC surface.
	reply, err := connection.request("terrascale.node.v1.gru-1.drain",
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
	reply, err = connection.request("terrascale.node.v1.gru-1.drain-status",
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
	reply, err = connection.request("terrascale.node.v1.gru-1.deploy",
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
	reply, err = connection.request("terrascale.node.v1.gru-1.drain",
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
	reply, err = connection.request("terrascale.node.v1.gru-1.rollback",
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
	reply, err := connection.request("terrascale.node.v1.gru-1.deploy",
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
	reply, err := connection.request("terrascale.node.v1.gru-1.drain",
		[]byte(`{"commandId":"cmd-bad","drain":true,"extra":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope CommandEnvelopeError
	if err := json.Unmarshal(reply, &envelope); err != nil || envelope.Detail == "" {
		t.Fatalf("unknown field not answered with an envelope error: %s %v", reply, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
