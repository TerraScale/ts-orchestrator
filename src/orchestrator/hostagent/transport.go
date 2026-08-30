// This file implements the node transport of the host agent: the injectable
// NATS connection and heartbeat clock seams, the camelCase wire codecs of the
// contract payloads, and the transport that answers the request-reply subjects
// of contracts.go with typed receipts and publishes periodic heartbeats.
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
)

// NatsConnection is the injectable NATS connection seam of the node transport.
// The live spelling wraps one *nats.Conn; tests inject a fake conn.
type NatsConnection interface {
	// Subscribe registers one message handler on a subject.
	Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error)
	// Publish sends one payload on a subject.
	Publish(subject string, payload []byte) error
	// Request sends one request-reply message and waits for its reply.
	Request(subject string, payload []byte, timeout time.Duration) (*nats.Msg, error)
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

// Subscribe registers one message handler on the live connection.
func (c LiveNatsConnection) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	return c.Connection.Subscribe(subject, handler)
}

// Publish sends one payload on the live connection.
func (c LiveNatsConnection) Publish(subject string, payload []byte) error {
	return c.Connection.Publish(subject, payload)
}

// Request sends one request-reply message on the live connection.
func (c LiveNatsConnection) Request(subject string, payload []byte, timeout time.Duration) (*nats.Msg, error) {
	return c.Connection.Request(subject, payload, timeout)
}

// Flush pushes buffered publications to the server.
func (c LiveNatsConnection) Flush() error { return c.Connection.Flush() }

// Drain gracefully drains the live connection.
func (c LiveNatsConnection) Drain() error { return c.Connection.Drain() }

// Close closes the live connection.
func (c LiveNatsConnection) Close() { c.Connection.Close() }

// HeartbeatTicker is the injectable heartbeat clock seam: C yields heartbeat
// instants and Stop releases the clock. Tests inject a manually ticked clock.
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
		return nil, &ArgumentOutOfRangeError{
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

// MarshalJSON encodes one command request as the canonical camelCase wire
// shape, revalidating it first so an unvalidated struct can never reach the
// wire. The plan payload is standard base64, matching byte[] serialization.
func (r WorkloadCommandRequest) MarshalJSON() ([]byte, error) {
	validated, err := NewWorkloadCommandRequest(r.PlanJson, r.CommandId)
	if err != nil {
		return nil, err
	}
	return json.Marshal(workloadCommandRequestWire{
		PlanJson:  validated.PlanJson,
		CommandId: validated.CommandId,
	})
}

// UnmarshalJSON decodes one command request from the canonical camelCase wire
// shape, rejecting unknown fields and revalidating through the constructor.
func (r *WorkloadCommandRequest) UnmarshalJSON(data []byte) error {
	var wire workloadCommandRequestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	validated, err := NewWorkloadCommandRequest(wire.PlanJson, wire.CommandId)
	if err != nil {
		return err
	}
	*r = validated
	return nil
}

type workloadCommandRequestWire struct {
	PlanJson  []byte `json:"planJson"`
	CommandId string `json:"commandId"`
}

// MarshalJSON encodes one heartbeat as the canonical camelCase wire shape,
// revalidating it first so an unvalidated heartbeat can never reach the wire.
func (h NodeHeartbeat) MarshalJSON() ([]byte, error) {
	validated, err := NewNodeHeartbeat(h.NodeId, h.UnixSeconds, h.Metrics)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nodeHeartbeatWire{
		NodeId:      validated.NodeId.Value,
		UnixSeconds: validated.UnixSeconds,
		Metrics: nodeMetricsSampleWire{
			MemoryTotalBytes:   validated.Metrics.MemoryTotalBytes,
			MemoryUsedBytes:    validated.Metrics.MemoryUsedBytes,
			CpuQuotaPercent:    validated.Metrics.CpuQuotaPercent,
			CpuUsedPercent:     validated.Metrics.CpuUsedPercent,
			TasksMax:           validated.Metrics.TasksMax,
			TasksRunning:       validated.Metrics.TasksRunning,
			PendingAllocations: validated.Metrics.PendingAllocations,
		},
	})
}

// UnmarshalJSON decodes one heartbeat from the canonical camelCase wire shape,
// rejecting unknown fields and revalidating through the constructor.
func (h *NodeHeartbeat) UnmarshalJSON(data []byte) error {
	var wire nodeHeartbeatWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	metrics, err := NewNodeMetricsSample(
		wire.Metrics.MemoryTotalBytes, wire.Metrics.MemoryUsedBytes, wire.Metrics.CpuQuotaPercent,
		wire.Metrics.CpuUsedPercent, wire.Metrics.TasksMax, wire.Metrics.TasksRunning,
		wire.Metrics.PendingAllocations)
	if err != nil {
		return err
	}
	validated, err := NewNodeHeartbeat(NodeId{Value: wire.NodeId}, wire.UnixSeconds, metrics)
	if err != nil {
		return err
	}
	*h = validated
	return nil
}

type nodeHeartbeatWire struct {
	NodeId      string                `json:"nodeId"`
	UnixSeconds int64                 `json:"unixSeconds"`
	Metrics     nodeMetricsSampleWire `json:"metrics"`
}

type nodeMetricsSampleWire struct {
	MemoryTotalBytes   int64 `json:"memoryTotalBytes"`
	MemoryUsedBytes    int64 `json:"memoryUsedBytes"`
	CpuQuotaPercent    int   `json:"cpuQuotaPercent"`
	CpuUsedPercent     int   `json:"cpuUsedPercent"`
	TasksMax           int   `json:"tasksMax"`
	TasksRunning       int   `json:"tasksRunning"`
	PendingAllocations int   `json:"pendingAllocations"`
}

// CordonCommand is the payload of the cordon subject: one bounded command
// token and the target cordon state, so cordon can also release a node.
type CordonCommand struct {
	CommandId string
	Cordoned  bool
}

// NewCordonCommand validates one cordon command.
func NewCordonCommand(commandId string, cordoned bool) (CordonCommand, error) {
	validated, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return CordonCommand{}, err
	}
	return CordonCommand{CommandId: validated, Cordoned: cordoned}, nil
}

// MarshalJSON encodes one cordon command as the canonical camelCase wire shape.
func (c CordonCommand) MarshalJSON() ([]byte, error) {
	validated, err := NewCordonCommand(c.CommandId, c.Cordoned)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cordonCommandWire{CommandId: validated.CommandId, Cordoned: validated.Cordoned})
}

// UnmarshalJSON decodes one cordon command, rejecting unknown fields.
func (c *CordonCommand) UnmarshalJSON(data []byte) error {
	var wire cordonCommandWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	validated, err := NewCordonCommand(wire.CommandId, wire.Cordoned)
	if err != nil {
		return err
	}
	*c = validated
	return nil
}

type cordonCommandWire struct {
	CommandId string `json:"commandId"`
	Cordoned  bool   `json:"cordoned"`
}

// NodeStatusRequest is the payload of the drain-status subject.
type NodeStatusRequest struct {
	CommandId string
}

// NewNodeStatusRequest validates one status request.
func NewNodeStatusRequest(commandId string) (NodeStatusRequest, error) {
	validated, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeStatusRequest{}, err
	}
	return NodeStatusRequest{CommandId: validated}, nil
}

// MarshalJSON encodes one status request as the canonical camelCase wire shape.
func (r NodeStatusRequest) MarshalJSON() ([]byte, error) {
	validated, err := NewNodeStatusRequest(r.CommandId)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nodeStatusRequestWire{CommandId: validated.CommandId})
}

// UnmarshalJSON decodes one status request, rejecting unknown fields.
func (r *NodeStatusRequest) UnmarshalJSON(data []byte) error {
	var wire nodeStatusRequestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	validated, err := NewNodeStatusRequest(wire.CommandId)
	if err != nil {
		return err
	}
	*r = validated
	return nil
}

type nodeStatusRequestWire struct {
	CommandId string `json:"commandId"`
}

// CordonAcknowledgment is the reply to one cordon command.
type CordonAcknowledgment struct {
	CommandId string
	NodeId    string
	Cordoned  bool
}

// NewCordonAcknowledgment validates one cordon acknowledgment.
func NewCordonAcknowledgment(commandId string, nodeId string, cordoned bool) (CordonAcknowledgment, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return CordonAcknowledgment{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return CordonAcknowledgment{}, err
	}
	return CordonAcknowledgment{
		CommandId: validatedCommand,
		NodeId:    validatedNode.Value,
		Cordoned:  cordoned,
	}, nil
}

// MarshalJSON encodes one cordon acknowledgment as the canonical camelCase
// wire shape.
func (a CordonAcknowledgment) MarshalJSON() ([]byte, error) {
	validated, err := NewCordonAcknowledgment(a.CommandId, a.NodeId, a.Cordoned)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cordonAcknowledgmentWire{
		CommandId: validated.CommandId,
		NodeId:    validated.NodeId,
		Cordoned:  validated.Cordoned,
	})
}

// UnmarshalJSON decodes one cordon acknowledgment, rejecting unknown fields.
func (a *CordonAcknowledgment) UnmarshalJSON(data []byte) error {
	var wire cordonAcknowledgmentWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	validated, err := NewCordonAcknowledgment(wire.CommandId, wire.NodeId, wire.Cordoned)
	if err != nil {
		return err
	}
	*a = validated
	return nil
}

type cordonAcknowledgmentWire struct {
	CommandId string `json:"commandId"`
	NodeId    string `json:"nodeId"`
	Cordoned  bool   `json:"cordoned"`
}

// DrainStatusReport is the reply to one drain-status request: the cordon
// flag, whether the node is fully drained, and one normalized observation per
// served allocation, ordered by allocation id.
type DrainStatusReport struct {
	CommandId   string
	NodeId      string
	Cordoned    bool
	Drained     bool
	Allocations []AllocationObservation
}

// NewDrainStatusReport validates one drain-status report and orders its
// allocations by allocation id for deterministic replies.
func NewDrainStatusReport(
	commandId string,
	nodeId string,
	cordoned bool,
	drained bool,
	allocations []AllocationObservation,
) (DrainStatusReport, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return DrainStatusReport{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return DrainStatusReport{}, err
	}
	snapshot := make([]AllocationObservation, 0, len(allocations))
	for _, allocation := range allocations {
		validatedAllocation, err := NewNodeId(allocation.AllocationId)
		if err != nil {
			return DrainStatusReport{}, &InvalidDataError{Message: fmt.Sprintf(
				"The allocation %q is not a canonical token.", allocation.AllocationId)}
		}
		if allocation.State == "" {
			return DrainStatusReport{}, &InvalidDataError{
				Message: "Every reported allocation must carry a state.",
			}
		}
		if _, err := requireHostAgentFingerprint(allocation.PlanFingerprint, "planFingerprint"); err != nil {
			return DrainStatusReport{}, err
		}
		if allocation.Driver == "" {
			return DrainStatusReport{}, &InvalidDataError{
				Message: "Every reported allocation must carry a driver.",
			}
		}
		snapshot = append(snapshot, AllocationObservation{
			AllocationId:    validatedAllocation.Value,
			Driver:          allocation.Driver,
			State:           allocation.State,
			Running:         allocation.Running,
			PlanFingerprint: allocation.PlanFingerprint,
		})
	}
	for index := 1; index < len(snapshot); index++ {
		if snapshot[index-1].AllocationId > snapshot[index].AllocationId {
			return DrainStatusReport{}, &InvalidDataError{
				Message: "Drain-status allocations must be ordered by allocation id.",
			}
		}
	}
	return DrainStatusReport{
		CommandId:   validatedCommand,
		NodeId:      validatedNode.Value,
		Cordoned:    cordoned,
		Drained:     drained,
		Allocations: snapshot,
	}, nil
}

// drainStatusReportWire is the wire shape of one drain-status report.
type drainStatusReportWire struct {
	CommandId   string                  `json:"commandId"`
	NodeId      string                  `json:"nodeId"`
	Cordoned    bool                    `json:"cordoned"`
	Drained     bool                    `json:"drained"`
	Allocations []AllocationObservation `json:"allocations"`
}

// MarshalJSON encodes one drain-status report as the canonical camelCase wire
// shape.
func (r DrainStatusReport) MarshalJSON() ([]byte, error) {
	validated, err := NewDrainStatusReport(r.CommandId, r.NodeId, r.Cordoned, r.Drained, r.Allocations)
	if err != nil {
		return nil, err
	}
	return json.Marshal(drainStatusReportWire{
		CommandId:   validated.CommandId,
		NodeId:      validated.NodeId,
		Cordoned:    validated.Cordoned,
		Drained:     validated.Drained,
		Allocations: validated.Allocations,
	})
}

// UnmarshalJSON decodes one drain-status report, rejecting unknown fields.
func (r *DrainStatusReport) UnmarshalJSON(data []byte) error {
	var wire drainStatusReportWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return err
	}
	validated, err := NewDrainStatusReport(wire.CommandId, wire.NodeId, wire.Cordoned, wire.Drained, wire.Allocations)
	if err != nil {
		return err
	}
	*r = validated
	return nil
}

// CommandEnvelopeError is the reply the transport sends when a command
// envelope itself cannot be validated, because no typed receipt carrying a
// bounded command identifier can be built for it.
type CommandEnvelopeError struct {
	Detail string `json:"detail"`
}

// NewCommandEnvelopeError builds one bounded, log-safe envelope error.
func NewCommandEnvelopeError(detail string) CommandEnvelopeError {
	return CommandEnvelopeError{Detail: boundedReceiptDetail(detail)}
}

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
	// Executor answers the workload command subjects.
	Executor *WorkloadExecutor
	// Metrics samples the heartbeat dimensions.
	Metrics MetricsSource
	// Ticker drives the heartbeat cadence.
	Ticker HeartbeatTicker
	// Now provides heartbeat timestamps; it must return positive Unix time.
	Now func() time.Time
	// CloseConnection closes the connection in Close; the caller sets it when
	// the transport owns the connection.
	CloseConnection bool
}

// NatsTransport serves the node subjects of contracts.go: it answers the
// converge, observe, stop, delete, cordon, and drain-status requests with
// typed replies and publishes heartbeats on the injected clock's cadence.
type NatsTransport struct {
	nodeId          NodeId
	connection      NatsConnection
	executor        *WorkloadExecutor
	metrics         MetricsSource
	ticker          HeartbeatTicker
	now             func() time.Time
	closeConnection bool

	commandContext context.Context
	subscriptions  []*nats.Subscription
	closing        chan struct{}
	heartbeatDone  chan struct{}
	closeOnce      sync.Once
	closeErr       error
	started        bool
}

// NewNatsTransport validates the configuration and composes the transport.
func NewNatsTransport(config NatsTransportConfig) (*NatsTransport, error) {
	nodeId, err := NewNodeId(config.NodeId.Value)
	if err != nil {
		return nil, err
	}
	if config.Connection == nil {
		return nil, &ArgumentError{Param: "Connection", Message: "A NATS connection is required."}
	}
	if config.Executor == nil {
		return nil, &ArgumentError{Param: "Executor", Message: "A workload executor is required."}
	}
	if config.Metrics == nil {
		return nil, &ArgumentError{Param: "Metrics", Message: "A metrics source is required."}
	}
	if config.Ticker == nil {
		return nil, &ArgumentError{Param: "Ticker", Message: "A heartbeat ticker is required."}
	}
	if config.Now == nil {
		return nil, &ArgumentError{Param: "Now", Message: "A heartbeat clock is required."}
	}
	return &NatsTransport{
		nodeId:          nodeId,
		connection:      config.Connection,
		executor:        config.Executor,
		metrics:         config.Metrics,
		ticker:          config.Ticker,
		now:             config.Now,
		closeConnection: config.CloseConnection,
		closing:         make(chan struct{}),
		heartbeatDone:   make(chan struct{}),
	}, nil
}

// Start subscribes to the node's request subjects, flushes them, publishes
// the first heartbeat, and runs the heartbeat loop until ctx is cancelled or
// Close is called. It returns once the transport is serving.
func (t *NatsTransport) Start(ctx context.Context) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The transport context must not be nil."}
	}
	if t.started {
		return &InvalidOperationError{Message: "The transport was already started."}
	}
	subscriptions := []struct {
		subject func(NodeId) (string, error)
		handler func(*nats.Msg)
	}{
		{NodeConvergeSubject, t.handleConverge},
		{NodeObserveSubject, t.handleObserve},
		{NodeStopSubject, t.handleStop},
		{NodeDeleteSubject, t.handleDelete},
		{NodeCordonSubject, t.handleCordon},
		{NodeDrainStatusSubject, t.handleDrainStatus},
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
	t.commandContext = ctx
	if err := t.HeartbeatOnce(ctx); err != nil {
		t.unsubscribeAll()
		return err
	}
	t.started = true
	go t.heartbeatLoop(ctx)
	return nil
}

// HeartbeatOnce samples the metrics source and publishes one heartbeat.
func (t *NatsTransport) HeartbeatOnce(ctx context.Context) error {
	sample, err := t.metrics.Sample(ctx)
	if err != nil {
		return err
	}
	heartbeat, err := NewNodeHeartbeat(t.nodeId, t.now().Unix(), sample)
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
			// retries and the autoscaler acts on silence.
			_ = t.HeartbeatOnce(ctx)
		}
	}
}

func (t *NatsTransport) handleConverge(message *nats.Msg) {
	var command WorkloadCommandRequest
	if err := json.Unmarshal(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	receipt, _ := t.executor.Converge(t.context(), command)
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleObserve(message *nats.Msg) {
	var command WorkloadCommandRequest
	if err := json.Unmarshal(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	receipt, _ := t.executor.Observe(t.context(), command)
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleStop(message *nats.Msg) {
	var command WorkloadCommandRequest
	if err := json.Unmarshal(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	receipt, _ := t.executor.Stop(t.context(), command)
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleDelete(message *nats.Msg) {
	var command WorkloadCommandRequest
	if err := json.Unmarshal(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	receipt, _ := t.executor.Delete(t.context(), command)
	t.replyJSON(message, receipt)
}

func (t *NatsTransport) handleCordon(message *nats.Msg) {
	var command CordonCommand
	if err := json.Unmarshal(message.Data, &command); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.executor.SetCordoned(command.Cordoned)
	acknowledgment, err := NewCordonAcknowledgment(command.CommandId, t.nodeId.Value, t.executor.Cordoned())
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, acknowledgment)
}

func (t *NatsTransport) handleDrainStatus(message *nats.Msg) {
	var request NodeStatusRequest
	if err := json.Unmarshal(message.Data, &request); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	observations, _ := t.executor.ObserveAllocations(t.context())
	report, err := NewDrainStatusReport(
		request.CommandId,
		t.nodeId.Value,
		t.executor.Cordoned(),
		t.executor.Drained(observations),
		observations)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.replyJSON(message, report)
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
