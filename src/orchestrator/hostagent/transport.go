// This file implements the node transport of the host agent: the injectable
// NATS connection and heartbeat clock seams, the strict JSON wire codecs of
// the contract payloads, and the transport that answers the drain,
// drain-status, deploy, and rollback request-reply subjects of contracts.go
// through the lifecycle and facts source, and publishes periodic
// heartbeats.
package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// NatsConnection is the injectable NATS connection seam of the node
// transport. The live spelling wraps one *nats.Conn; tests inject a fake
// conn.
type NatsConnection interface {
	// Subscribe registers one message handler on a subject.
	Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error)
	// Publish sends one payload on a subject.
	Publish(subject string, payload []byte) error
	// Flush pushes buffered publications to the server.
	Flush() error
	// Drain gracefully drains subscriptions and publications.
	Drain() error
	// Close closes the connection.
	Close()
}

// LiveNatsConnection adapts one *nats.Conn to the transport seam.
type LiveNatsConnection struct {
	// Connection is the wrapped live connection.
	Connection *nats.Conn
}

// NewLiveNatsConnection validates that the wrapped connection exists.
func NewLiveNatsConnection(connection *nats.Conn) (LiveNatsConnection, error) {
	if connection == nil {
		return LiveNatsConnection{}, &errs.Argument{
			Param:   "connection",
			Message: "A live NATS connection is required.",
		}
	}
	return LiveNatsConnection{Connection: connection}, nil
}

// Subscribe registers one message handler on the live connection.
func (c LiveNatsConnection) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	return c.Connection.Subscribe(subject, handler)
}

// Publish sends one payload on the live connection.
func (c LiveNatsConnection) Publish(subject string, payload []byte) error {
	return c.Connection.Publish(subject, payload)
}

// Flush pushes buffered publications to the server.
func (c LiveNatsConnection) Flush() error { return c.Connection.Flush() }

// Drain gracefully drains the live connection.
func (c LiveNatsConnection) Drain() error { return c.Connection.Drain() }

// Close closes the live connection.
func (c LiveNatsConnection) Close() { c.Connection.Close() }

// HeartbeatTicker is the injectable heartbeat clock seam: C yields
// heartbeat instants and Stop releases the clock. Tests inject a manually
// ticked clock.
type HeartbeatTicker interface {
	// C yields one channel that receives on every heartbeat instant.
	C() <-chan time.Time
	// Stop releases the clock's resources.
	Stop()
}

// IntervalHeartbeatTicker is the live spelling over one time.Ticker.
type IntervalHeartbeatTicker struct {
	ticker *time.Ticker
}

// NewIntervalHeartbeatTicker validates the interval and starts the ticker.
func NewIntervalHeartbeatTicker(interval time.Duration) (*IntervalHeartbeatTicker, error) {
	if interval <= 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "interval",
			Message: "The heartbeat interval must be positive.",
		}
	}
	return &IntervalHeartbeatTicker{ticker: time.NewTicker(interval)}, nil
}

// C yields the ticker's heartbeat channel.
func (t *IntervalHeartbeatTicker) C() <-chan time.Time { return t.ticker.C }

// Stop stops the ticker.
func (t *IntervalHeartbeatTicker) Stop() { t.ticker.Stop() }

// decodeStrictJSON decodes one canonical JSON document, rejecting unknown
// fields and trailing data so the transport wire vocabulary stays closed.
func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The payload is not the canonical JSON shape: %s.", err.Error())}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return &InvalidDataError{Message: "The payload must be exactly one JSON document."}
	}
	return nil
}

// NatsTransportConfig is the fully explicit transport configuration.
type NatsTransportConfig struct {
	// NodeId identifies the node whose subjects the transport serves.
	NodeId NodeId
	// Connection is the NATS connection seam the transport uses.
	Connection NatsConnection
	// Lifecycle executes host mutations.
	Lifecycle *Lifecycle
	// Facts samples the heartbeat dimensions.
	Facts *HostFactsSource
	// Ticker drives the heartbeat cadence.
	Ticker HeartbeatTicker
	// Now provides heartbeat timestamps; it must return positive Unix time.
	Now func() time.Time
	// CloseConnection closes the connection in Close; the caller sets it
	// when the transport owns the connection.
	CloseConnection bool
}

// NatsTransport serves the node subjects of contracts.go: it answers the
// drain, drain-status, deploy, and rollback requests through the lifecycle
// and publishes heartbeats on the injected clock's cadence.
type NatsTransport struct {
	nodeId          NodeId
	connection      NatsConnection
	lifecycle       *Lifecycle
	facts           *HostFactsSource
	ticker          HeartbeatTicker
	now             func() time.Time
	closeConnection bool

	commandContext context.Context
	subscriptions  []*nats.Subscription
	closing        chan struct{}
	heartbeatDone  chan struct{}
	mutex          sync.Mutex
	closeOnce      sync.Once
	closeErr       error
	started        bool
	closed         bool
}

// NewNatsTransport validates the configuration and composes the transport.
func NewNatsTransport(config NatsTransportConfig) (*NatsTransport, error) {
	nodeId, err := NewNodeId(config.NodeId.Value)
	if err != nil {
		return nil, err
	}
	if config.Connection == nil {
		return nil, &errs.Argument{Param: "Connection", Message: "A NATS connection is required."}
	}
	if config.Lifecycle == nil {
		return nil, &errs.Argument{Param: "Lifecycle", Message: "A lifecycle is required."}
	}
	if config.Facts == nil {
		return nil, &errs.Argument{Param: "Facts", Message: "A facts source is required."}
	}
	if config.Ticker == nil {
		return nil, &errs.Argument{Param: "Ticker", Message: "A heartbeat ticker is required."}
	}
	if config.Now == nil {
		return nil, &errs.Argument{Param: "Now", Message: "A heartbeat clock is required."}
	}
	return &NatsTransport{
		nodeId:          nodeId,
		connection:      config.Connection,
		lifecycle:       config.Lifecycle,
		facts:           config.Facts,
		ticker:          config.Ticker,
		now:             config.Now,
		closeConnection: config.CloseConnection,
		closing:         make(chan struct{}),
		heartbeatDone:   make(chan struct{}),
	}, nil
}

// Start subscribes to the node's request subjects, flushes them, publishes
// the first heartbeat, and runs the heartbeat loop until ctx is cancelled
// or Close is called. It returns once the transport is serving.
func (t *NatsTransport) Start(ctx context.Context) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The transport context must not be nil."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.closed {
		return &InvalidOperationError{Message: "The transport was already closed."}
	}
	if t.started {
		return &InvalidOperationError{Message: "The transport was already started."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	subscriptions := []struct {
		subject func(NodeId) (string, error)
		handler func(*nats.Msg)
	}{
		{NodeDrainSubject, t.handleDrain},
		{NodeDrainStatusSubject, t.handleDrainStatus},
		{NodeDeploySubject, t.handleDeploy},
		{NodeRollbackSubject, t.handleRollback},
	}
	for _, entry := range subscriptions {
		subject, err := entry.subject(t.nodeId)
		if err != nil {
			t.unsubscribeAll()
			return err
		}
		subscription, err := t.connection.Subscribe(subject, entry.handler)
		if err != nil {
			t.unsubscribeAll()
			return err
		}
		t.subscriptions = append(t.subscriptions, subscription)
	}
	if err := t.connection.Flush(); err != nil {
		t.unsubscribeAll()
		return err
	}
	if err := ctx.Err(); err != nil {
		t.unsubscribeAll()
		return err
	}
	t.commandContext = ctx
	if err := t.HeartbeatOnce(ctx); err != nil {
		t.unsubscribeAll()
		return err
	}
	t.started = true
	go t.heartbeatLoop(ctx)
	return nil
}

// HeartbeatOnce samples the facts source and publishes one heartbeat.
func (t *NatsTransport) HeartbeatOnce(ctx context.Context) error {
	facts, err := t.facts.Sample(ctx, t.lifecycle.State(), t.lifecycle.Desired())
	if err != nil {
		return err
	}
	heartbeat, err := NewHostHeartbeat(t.nodeId.Value, t.now().Unix(), facts)
	if err != nil {
		return err
	}
	subject, err := NodeHeartbeatSubject(t.nodeId)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	return t.connection.Publish(subject, payload)
}

// Close gracefully stops the heartbeat loop and ticker, drains every
// subscription and the connection, and closes the connection when the
// transport owns it. Close is idempotent.
func (t *NatsTransport) Close() error {
	t.closeOnce.Do(func() {
		t.mutex.Lock()
		defer t.mutex.Unlock()
		t.closed = true
		close(t.closing)
		if t.started {
			<-t.heartbeatDone
		}
		t.ticker.Stop()
		for _, subscription := range t.subscriptions {
			if subscription != nil {
				_ = subscription.Drain()
			}
		}
		if err := t.connection.Drain(); err != nil {
			t.closeErr = err
		}
		if t.closeConnection {
			t.connection.Close()
		}
	})
	return t.closeErr
}

func (t *NatsTransport) unsubscribeAll() {
	for _, subscription := range t.subscriptions {
		if subscription != nil {
			_ = subscription.Unsubscribe()
		}
	}
	t.subscriptions = nil
}

func (t *NatsTransport) heartbeatLoop(ctx context.Context) {
	defer close(t.heartbeatDone)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.closing:
			return
		case _, ok := <-t.ticker.C():
			if !ok {
				return
			}
			// A failed heartbeat must not stop the loop; the next tick
			// retries and the control plane acts on silence.
			_ = t.HeartbeatOnce(ctx)
		}
	}
}

func (t *NatsTransport) handleDrain(message *nats.Msg) {
	var command DrainCommand
	if err := decodeStrictJSON(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	var cause error
	detail := "drain released"
	if command.Drain {
		detail = "drain begun"
		cause = t.lifecycle.BeginDrain(t.context())
	} else {
		cause = t.lifecycle.ReleaseDrain(t.context())
	}
	receipt, err := NewDrainReceipt(command.CommandId, t.nodeId.Value,
		t.lifecycle.State() == NodeStateDraining,
		t.lifecycle.Quiesced(t.context()),
		detailOf(cause, detail))
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleDrainStatus(message *nats.Msg) {
	var request NodeStatusRequest
	if err := decodeStrictJSON(message.Data, &request); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	facts, err := t.facts.Sample(t.context(), t.lifecycle.State(), t.lifecycle.Desired())
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	report, err := NewNodeStatusReport(request.CommandId, t.nodeId.Value,
		t.lifecycle.State(), t.lifecycle.Quiesced(t.context()), facts)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, report)
}

func (t *NatsTransport) handleDeploy(message *nats.Msg) {
	var command DeployCommand
	if err := decodeStrictJSON(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	cause := t.lifecycle.Deploy(t.context(), command.Component, command.Version)
	current, _ := CurrentVersion(t.lifecycle.installRoot, command.Component)
	receipt, err := NewDeployReceipt(command.CommandId, t.nodeId.Value,
		cause == nil, current, detailOf(cause, "deployed"))
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleRollback(message *nats.Msg) {
	var command RollbackCommand
	if err := decodeStrictJSON(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	cause := t.lifecycle.Rollback(t.context(), command.Component)
	current, _ := CurrentVersion(t.lifecycle.installRoot, command.Component)
	receipt, err := NewDeployReceipt(command.CommandId, t.nodeId.Value,
		cause == nil, current, detailOf(cause, "rolled back"))
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, receipt)
}

// context returns the context commands run under; before Start it is the
// background context so handlers never see a nil context.
func (t *NatsTransport) context() context.Context {
	if t.commandContext == nil {
		return context.Background()
	}
	return t.commandContext
}

// replyJSON marshals one reply and publishes it on the request's reply
// subject. A message with no reply subject is a plain publish and gets no
// reply.
func (t *NatsTransport) replyJSON(message *nats.Msg, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.respond(message, payload)
}

// replyEnvelopeError answers one undecodable command with the bounded
// envelope error so the requester never waits for a timeout.
func (t *NatsTransport) replyEnvelopeError(message *nats.Msg, err error) {
	payload, marshalErr := json.Marshal(NewCommandEnvelopeError(err.Error()))
	if marshalErr != nil {
		return
	}
	t.respond(message, payload)
}

func (t *NatsTransport) respond(message *nats.Msg, payload []byte) {
	if message.Reply == "" {
		return
	}
	_ = t.connection.Publish(message.Reply, payload)
}
