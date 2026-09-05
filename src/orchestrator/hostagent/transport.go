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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

const (
	commandKindDrain             = "drain"
	commandKindStatus            = "status"
	commandKindDeploy            = "deploy"
	commandKindRollback          = "rollback"
	commandKindManifest          = "apply-manifest"
	hostAgentMaximumCommandBytes = 64 << 10
	hostAgentStatusTimeout       = 5 * time.Second
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

// decodeCommandObject admits one bounded flat object with the exact key set
// of a command. It rejects duplicates, case variants, null values, unknown
// keys, missing keys, and trailing data before a typed constructor runs.
func decodeCommandObject(data []byte, required ...string) (map[string]json.RawMessage, error) {
	return decodeCommandObjectBounded(data, hostAgentMaximumCommandBytes, required...)
}

func decodeCommandObjectBounded(data []byte, maximum int, required ...string) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > maximum {
		return nil, &InvalidDataError{Message: "The command payload exceeds its size bound."}
	}
	allowed := make(map[string]struct{}, len(required))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, &InvalidDataError{Message: "The command payload is not a JSON object."}
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, &InvalidDataError{Message: "The command payload must be a JSON object."}
	}
	fields := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, &InvalidDataError{Message: "The command payload contains an invalid field name."}
		}
		field, ok := token.(string)
		if !ok {
			return nil, &InvalidDataError{Message: "The command payload contains an invalid field name."}
		}
		if _, known := allowed[field]; !known {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command payload contains unknown field %q.", field)}
		}
		if _, duplicate := fields[field]; duplicate {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command payload contains duplicate field %q.", field)}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command field %q is invalid.", field)}
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command field %q must not be null.", field)}
		}
		fields[field] = raw
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, &InvalidDataError{Message: "The command payload is not a complete JSON object."}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, &InvalidDataError{Message: "The command payload must be exactly one JSON document."}
	}
	for _, field := range required {
		if _, present := fields[field]; !present {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command payload is missing field %q.", field)}
		}
	}
	return fields, nil
}

func decodeApplyManifestCommand(data []byte) (ApplyManifestCommand, error) {
	fields, err := decodeCommandObjectBounded(data, hostAgentMaximumManifestBytes+4096,
		"commandId", "expectedManifestSha256", "manifest")
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	var commandId, expected string
	if json.Unmarshal(fields["commandId"], &commandId) != nil ||
		json.Unmarshal(fields["expectedManifestSha256"], &expected) != nil {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The apply-manifest command has invalid field types."}
	}
	manifest, err := ParseHostManifest(fields["manifest"])
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	canonical, err := CanonicalHostManifestJSON(manifest)
	if err != nil || !bytes.Equal(canonical, fields["manifest"]) {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The embedded manifest must use canonical compact JSON."}
	}
	return NewApplyManifestCommand(commandId, expected, manifest)
}

func decodeDrainCommand(data []byte) (DrainCommand, error) {
	fields, err := decodeCommandObject(data, "commandId", "drain")
	if err != nil {
		return DrainCommand{}, err
	}
	var commandId string
	var drain bool
	if json.Unmarshal(fields["commandId"], &commandId) != nil || json.Unmarshal(fields["drain"], &drain) != nil {
		return DrainCommand{}, &InvalidDataError{Message: "The drain command has invalid field types."}
	}
	return NewDrainCommand(commandId, drain)
}

func decodeStatusCommand(data []byte) (NodeStatusRequest, error) {
	fields, err := decodeCommandObject(data, "commandId")
	if err != nil {
		return NodeStatusRequest{}, err
	}
	var commandId string
	if json.Unmarshal(fields["commandId"], &commandId) != nil {
		return NodeStatusRequest{}, &InvalidDataError{Message: "The status command has an invalid commandId."}
	}
	return NewNodeStatusRequest(commandId)
}

func decodeDeployCommand(data []byte) (DeployCommand, error) {
	fields, err := decodeCommandObject(data, "commandId", "component", "version")
	if err != nil {
		return DeployCommand{}, err
	}
	var commandId, component, version string
	if json.Unmarshal(fields["commandId"], &commandId) != nil ||
		json.Unmarshal(fields["component"], &component) != nil ||
		json.Unmarshal(fields["version"], &version) != nil {
		return DeployCommand{}, &InvalidDataError{Message: "The deploy command has invalid field types."}
	}
	return NewDeployCommand(commandId, component, version)
}

func decodeRollbackCommand(data []byte) (RollbackCommand, error) {
	fields, err := decodeCommandObject(data, "commandId", "component")
	if err != nil {
		return RollbackCommand{}, err
	}
	var commandId, component string
	if json.Unmarshal(fields["commandId"], &commandId) != nil ||
		json.Unmarshal(fields["component"], &component) != nil {
		return RollbackCommand{}, &InvalidDataError{Message: "The rollback command has invalid field types."}
	}
	return NewRollbackCommand(commandId, component)
}

// NatsTransportConfig is the fully explicit transport configuration.
type NatsTransportConfig struct {
	CommandAuthority nodeauthority.CommandAuthorizer
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
	// CommandJournalDir stores durable idempotency intent and receipts. Empty
	// derives the canonical ts-node directory under the lifecycle data root.
	CommandJournalDir string
	// ManifestPath is the root-owned durable desired manifest. Empty derives
	// the canonical path under the reserved ts-node state root.
	ManifestPath string
}

// NatsTransport serves the node subjects of contracts.go: it answers the
// drain, drain-status, deploy, and rollback requests through the lifecycle
// and publishes heartbeats on the injected clock's cadence.
type NatsTransport struct {
	authorizer      nodeauthority.CommandAuthorizer
	epochs          *nodeauthority.EpochStore
	nodeId          NodeId
	connection      NatsConnection
	lifecycle       *Lifecycle
	facts           *HostFactsSource
	ticker          HeartbeatTicker
	now             func() time.Time
	closeConnection bool
	journal         *commandJournal
	manifestPath    string

	commandContext      context.Context
	commandContextMutex sync.RWMutex
	commandMutex        sync.Mutex
	subscriptions       []*nats.Subscription
	closing             chan struct{}
	heartbeatDone       chan struct{}
	mutex               sync.Mutex
	closeOnce           sync.Once
	closeErr            error
	started             bool
	closed              bool
}

// NewNatsTransport validates the configuration and composes the transport.
func NewNatsTransport(config NatsTransportConfig) (*NatsTransport, error) {
	if config.CommandAuthority == nil {
		return nil, errors.New("hostagent: receiver command authority is required")
	}
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
	journalDir := config.CommandJournalDir
	canonicalJournalDir := filepath.Join(config.Lifecycle.dataRoot, TsNodeComponentName, "command-journal")
	if journalDir == "" {
		journalDir = canonicalJournalDir
	}
	if journalDir != canonicalJournalDir {
		return nil, &InvalidOperationError{Message: "The command journal must use the reserved ts-node state directory."}
	}
	manifestPath := config.ManifestPath
	canonicalManifestPath := filepath.Join(config.Lifecycle.dataRoot, TsNodeComponentName, "manifest.json")
	if manifestPath == "" {
		manifestPath = canonicalManifestPath
	}
	if manifestPath != canonicalManifestPath {
		return nil, &InvalidOperationError{Message: "The desired manifest must use the reserved ts-node state directory."}
	}
	journal, err := newCommandJournal(journalDir)
	if err != nil {
		return nil, err
	}
	return &NatsTransport{
		authorizer:      config.CommandAuthority,
		nodeId:          nodeId,
		connection:      config.Connection,
		lifecycle:       config.Lifecycle,
		facts:           config.Facts,
		ticker:          config.Ticker,
		now:             config.Now,
		closeConnection: config.CloseConnection,
		journal:         journal,
		manifestPath:    manifestPath,
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
	t.commandContextMutex.Lock()
	t.commandContext = ctx
	t.commandContextMutex.Unlock()
	if err := t.journal.initialize(); err != nil {
		return err
	}
	var epochErr error
	t.epochs, epochErr = nodeauthority.NewEpochStore(t.journal.dir, t.nodeId.Value)
	if epochErr != nil {
		return epochErr
	}
	// Pending mutations require a fresh signed reissue after restart; they
	// cannot be resumed from an expired or superseded controller's intent.
	acquired := true
	defer func() {
		if acquired {
			_ = t.epochs.Close()
		}
	}()
	if err := t.prepareLifecycleForStartup(); err != nil {
		return err
	}
	if err := t.restoreDurableDrain(ctx); err != nil {
		return err
	}
	subscriptions := []struct {
		subject func(NodeId) (string, error)
		handler func(*nats.Msg)
	}{
		{NodeDrainSubject, t.authorizedHandler(t.handleDrain)},
		{NodeDrainStatusSubject, t.handleDrainStatus},
		{NodeDeploySubject, t.authorizedHandler(t.handleDeploy)},
		{NodeRollbackSubject, t.authorizedHandler(t.handleRollback)},
		{NodeApplyManifestSubject, t.authorizedHandler(t.handleApplyManifest)},
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
	if err := t.HeartbeatOnce(ctx); err != nil {
		t.unsubscribeAll()
		return err
	}
	acquired = false
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
		t.commandMutex.Lock()
		if t.epochs != nil {
			t.closeErr = errors.Join(t.closeErr, t.epochs.Close())
		}
		t.commandMutex.Unlock()
		if t.closeConnection {
			if err := t.connection.Drain(); err != nil {
				t.closeErr = err
			}
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
	command, err := decodeDrainCommand(message.Data)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.handleRecordedCommand(message, commandKindDrain, command.CommandId, command, nil)
}

func (t *NatsTransport) handleDrainStatus(message *nats.Msg) {
	request, err := decodeStatusCommand(message.Data)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if !t.commandMutex.TryLock() {
		t.replyEnvelopeError(message, t.lifecycle.observationBusyError())
		return
	}
	defer t.commandMutex.Unlock()
	record, found, err := t.journal.find(commandKindStatus, request.CommandId, canonical)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if found {
		if record.State == commandJournalDone {
			t.respond(message, record.Response)
			return
		}
		t.finishJournalRecord(t.context(), message, record)
		return
	}
	response, err := t.statusResponse(request)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.respond(message, response)
}

func (t *NatsTransport) handleDeploy(message *nats.Msg) {
	command, err := decodeDeployCommand(message.Data)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.handleTransitionCommand(message, commandKindDeploy, command.CommandId, command, func(ctx context.Context) (transitionPlan, error) {
		return t.lifecycle.prepareDeploy(ctx, command.Component, command.Version)
	})
}

func (t *NatsTransport) handleRollback(message *nats.Msg) {
	command, err := decodeRollbackCommand(message.Data)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.handleTransitionCommand(message, commandKindRollback, command.CommandId, command, func(context.Context) (transitionPlan, error) {
		return t.lifecycle.prepareRollback(command.Component)
	})
}

func (t *NatsTransport) handleApplyManifest(message *nats.Msg) {
	command, err := decodeApplyManifestCommand(message.Data)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.handleRecordedCommand(message, commandKindManifest, command.CommandId, command, nil)
}

func (t *NatsTransport) handleRecordedCommand(message *nats.Msg, kind, commandId string, command any, plan *transitionPlan) {
	request, err := json.Marshal(command)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.commandMutex.Lock()
	defer t.commandMutex.Unlock()
	commandContext, cancel, authorityErr := t.authorizeLocked(message)
	if authorityErr != nil {
		t.replyEnvelopeError(message, authorityErr)
		return
	}
	defer cancel()
	record, found, err := t.journal.find(kind, commandId, request)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if found && record.State == commandJournalDone {
		t.respond(message, record.Response)
		return
	}
	if !found {
		record, err = t.journal.begin(kind, commandId, request, plan)
		if err != nil {
			t.replyEnvelopeError(message, err)
			return
		}
	}
	response, err := t.executeJournalRecord(commandContext, record)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if err := t.journal.complete(record, response); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.respond(message, response)
}

func (t *NatsTransport) handleTransitionCommand(message *nats.Msg, kind, commandId string, command any, prepare func(context.Context) (transitionPlan, error)) {
	request, err := json.Marshal(command)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.commandMutex.Lock()
	defer t.commandMutex.Unlock()
	commandContext, cancel, authorityErr := t.authorizeLocked(message)
	if authorityErr != nil {
		t.replyEnvelopeError(message, authorityErr)
		return
	}
	defer cancel()
	record, found, err := t.journal.find(kind, commandId, request)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if found {
		if record.State == commandJournalDone {
			t.respond(message, record.Response)
			return
		}
		t.finishJournalRecord(commandContext, message, record)
		return
	}
	ctx := commandContext
	if ctx == nil {
		t.replyEnvelopeError(message, &InvalidOperationError{Message: "The transport is not serving commands."})
		return
	}
	plan, cause := prepare(ctx)
	if cause != nil {
		response, responseErr := t.transitionResponse(kind, commandId, transitionCommandComponent(command), cause)
		if responseErr != nil {
			t.replyEnvelopeError(message, responseErr)
			return
		}
		record, err := t.journal.storeDone(kind, commandId, request, response)
		if err != nil {
			t.replyEnvelopeError(message, err)
			return
		}
		t.respond(message, record.Response)
		return
	}
	record, err = t.journal.begin(kind, commandId, request, &plan)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.finishJournalRecord(commandContext, message, record)
}

func (t *NatsTransport) finishJournalRecord(ctx context.Context, message *nats.Msg, record commandJournalRecord) {
	response, err := t.executeJournalRecord(ctx, record)
	if err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	if err := t.journal.complete(record, response); err != nil {
		t.replyEnvelopeError(message, err)
		return
	}
	t.respond(message, response)
}

func (t *NatsTransport) executeJournalRecord(ctx context.Context, record commandJournalRecord) ([]byte, error) {
	if ctx == nil {
		return nil, &InvalidOperationError{Message: "The transport is not serving commands."}
	}
	switch record.Kind {
	case commandKindDrain:
		var command DrainCommand
		if err := json.Unmarshal(record.Request, &command); err != nil {
			return nil, err
		}
		var cause error
		detail := "drain released"
		if command.Drain {
			detail = "drain begun"
			cause = t.lifecycle.BeginDrain(ctx)
		} else {
			cause = t.lifecycle.ReleaseDrain(ctx)
		}
		receipt, err := NewDrainReceipt(command.CommandId, t.nodeId.Value,
			t.lifecycle.State() == NodeStateDraining, t.lifecycle.Quiesced(ctx), detailOf(cause, detail))
		if err != nil {
			return nil, err
		}
		return json.Marshal(receipt)
	case commandKindStatus:
		var request NodeStatusRequest
		if err := json.Unmarshal(record.Request, &request); err != nil {
			return nil, err
		}
		return t.statusResponse(request)
	case commandKindDeploy, commandKindRollback:
		if record.Plan == nil {
			return nil, &InvalidDataError{Message: "The transition command has no durable plan."}
		}
		cause := t.lifecycle.applyTransition(ctx, *record.Plan)
		return t.transitionResponse(record.Kind, record.CommandId, record.Plan.Spec.Name, cause)
	case commandKindManifest:
		var command ApplyManifestCommand
		if err := json.Unmarshal(record.Request, &command); err != nil {
			return nil, err
		}
		return t.applyManifest(ctx, command)
	default:
		return nil, &InvalidDataError{Message: "The command journal contains an unknown command kind."}
	}
}

func (t *NatsTransport) statusResponse(request NodeStatusRequest) ([]byte, error) {
	ctx := t.context()
	if ctx == nil {
		return nil, &InvalidOperationError{Message: "The transport is not serving commands."}
	}
	ctx, cancel := context.WithTimeout(ctx, hostAgentStatusTimeout)
	defer cancel()
	before, err := t.lifecycle.tryObservation(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := t.facts.Sample(ctx, before.state, before.desired)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	after, err := t.lifecycle.tryObservation(ctx)
	if err != nil {
		return nil, err
	}
	if before.state != after.state || before.quiesced != after.quiesced || !slices.Equal(before.desired, after.desired) {
		return nil, errHostObservationBusy
	}
	report, err := NewNodeStatusReport(request.CommandId, t.nodeId.Value,
		after.state, after.quiesced, facts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func transitionCommandComponent(command any) string {
	switch typed := command.(type) {
	case DeployCommand:
		return typed.Component
	case RollbackCommand:
		return typed.Component
	}
	return ""
}

func (t *NatsTransport) transitionResponse(kind, commandId, component string, cause error) ([]byte, error) {
	if component == "" {
		return nil, &InvalidDataError{Message: "The transition component is missing."}
	}
	current, _ := CurrentVersion(t.lifecycle.installRoot, component)
	detail := "deployed"
	if kind == commandKindRollback {
		detail = "rolled back"
	}
	receipt, err := NewDeployReceipt(commandId, t.nodeId.Value, cause == nil, current, detailOf(cause, detail))
	if err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func (t *NatsTransport) applyManifest(ctx context.Context, command ApplyManifestCommand) ([]byte, error) {
	canonical, err := CanonicalHostManifestJSON(command.Manifest)
	if err != nil {
		return nil, err
	}
	wantedSha256, err := HostManifestSha256(command.Manifest)
	if err != nil {
		return nil, err
	}
	current, err := readRegularFileBounded(t.manifestPath, hostAgentMaximumManifestBytes)
	if err != nil {
		return nil, err
	}
	currentManifest, err := ParseHostManifest(current)
	if err != nil {
		return nil, err
	}
	currentCanonical, err := CanonicalHostManifestJSON(currentManifest)
	if err != nil || !bytes.Equal(current, currentCanonical) {
		return nil, &InvalidDataError{Message: "The durable host manifest is not canonical."}
	}
	currentSha256, err := HostManifestSha256(currentManifest)
	if err != nil {
		return nil, err
	}
	accepted := true
	detail := "manifest committed"
	if currentSha256 != wantedSha256 {
		if currentSha256 != command.ExpectedManifestSha256 {
			accepted = false
			detail = "manifest compare-and-swap rejected"
		} else if err := writeDurableManifest(t.manifestPath, canonical); err != nil {
			return nil, err
		}
	}
	if accepted {
		if convergeErr := t.lifecycle.ApplyDesired(ctx, command.Manifest.Components); convergeErr != nil {
			detail = "manifest committed; convergence pending: " + convergeErr.Error()
		}
		currentSha256 = wantedSha256
	}
	receipt, err := NewManifestReceipt(command.CommandId, t.nodeId.Value, accepted, currentSha256, boundedReceiptDetail(detail))
	if err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func writeDurableManifest(path string, data []byte) error {
	if len(data) == 0 || len(data) > hostAgentMaximumManifestBytes {
		return &InvalidDataError{Message: "The durable host manifest exceeds its size bound."}
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(info, "ts-node state directory"); err != nil {
		return err
	}
	staged := filepath.Join(dir, ".manifest.staging")
	if stageInfo, statErr := os.Lstat(staged); statErr == nil {
		if err := requireOwnedRegular(stageInfo, false, "manifest stage"); err != nil {
			return err
		}
		if err := os.Remove(staged); err != nil {
			return err
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	file, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		_ = file.Close()
		_ = os.Remove(staged)
		return cause
	}
	if _, err := file.Write(data); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, path); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(dir)
}

// prepareLifecycleForStartup restores the durable mode flag before manifest
// reconciliation. This prevents a fresh Lifecycle from starting units while
// the last accepted command still says the node is drained.
func (t *NatsTransport) prepareLifecycleForStartup() error {
	command, found, err := t.journal.latestDrain()
	if err != nil {
		return err
	}
	if found {
		t.lifecycle.restoreDrainMode(command.Drain)
	}
	return nil
}

func (t *NatsTransport) restoreDurableDrain(ctx context.Context) error {
	command, found, err := t.journal.latestDrain()
	if err != nil || !found {
		return err
	}
	if command.Drain {
		return t.lifecycle.BeginDrain(ctx)
	}
	return t.lifecycle.ReleaseDrain(ctx)
}

// context returns the context commands run under. Handlers are not exposed
// until Start has stored it, so there is no background-context fallback.
func (t *NatsTransport) context() context.Context {
	t.commandContextMutex.RLock()
	defer t.commandContextMutex.RUnlock()
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
