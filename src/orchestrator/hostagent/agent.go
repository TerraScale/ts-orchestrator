// This file composes the per-node host agent of the rootless-hosting and
// autoscaling lane: one workload executor, one NATS transport, and the
// heartbeat metrics source, wired together from one fully explicit
// configuration with no ambient environment reads.
package hostagent

import (
	"context"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// HostAgentConfig is the fully explicit configuration of one node host agent.
// Either Connection or NatsURL must be set, never both: the caller wires an
// in-process or pre-dialed connection, or lets the agent dial one explicit
// nats:// URL itself.
type HostAgentConfig struct {
	// NodeId is the validated node identity the agent serves.
	NodeId NodeId
	// Connection is a pre-wired transport connection owned by the caller.
	Connection NatsConnection
	// NatsURL is the explicit nats:// URL the agent dials in Start.
	NatsURL string
	// NatsOptions carries the already validated authentication and TLS options
	// for a dialed production connection. It must be empty with a pre-wired
	// Connection; local plaintext test lanes leave it empty.
	NatsOptions []nats.Option
	// ConnectTimeout bounds the dial when NatsURL is used.
	ConnectTimeout time.Duration
	// Systemd executes native systemd plans; wire it in user-manager mode so
	// units run under the unprivileged node account.
	Systemd NativePlanAdapter
	// Container executes OCI container plans through rootless podman.
	Container ContainerPlanAdapter
	// Metrics samples the node metric dimensions for heartbeats.
	Metrics MetricsSource
	// HeartbeatInterval is the fixed heartbeat period.
	HeartbeatInterval time.Duration
	// Now provides heartbeat timestamps; it must return positive Unix time.
	Now func() time.Time
}

// HostAgent is the node-side composition: it receives canonical plans on the
// node subjects, executes them through the rootless adapters, and publishes
// heartbeats until its context is cancelled or Close is called.
type HostAgent struct {
	nodeId            NodeId
	connection        NatsConnection
	natsURL           string
	natsOptions       []nats.Option
	connectTimeout    time.Duration
	ownsConnection    bool
	heartbeatInterval time.Duration
	metricsSource     MetricsSource
	nowFunc           func() time.Time
	executor          *WorkloadExecutor
	transport         *NatsTransport
	completion        chan struct{}
	completionOnce    sync.Once
	mutex             sync.Mutex
	closeOnce         sync.Once
	closeErr          error
	closed            bool
}

// NewHostAgent validates the configuration and composes the agent. Nothing is
// dialed or started here; Start does that.
func NewHostAgent(config HostAgentConfig) (*HostAgent, error) {
	nodeId, err := NewNodeId(config.NodeId.Value)
	if err != nil {
		return nil, err
	}
	if (config.Connection == nil) == (config.NatsURL == "") {
		return nil, &ArgumentError{
			Param:   "Connection",
			Message: "Exactly one of a wired connection or a NATS URL is required.",
		}
	}
	if config.Connection != nil && len(config.NatsOptions) != 0 {
		return nil, &ArgumentError{
			Param:   "NatsOptions",
			Message: "NATS dial options cannot accompany a pre-wired connection.",
		}
	}
	if config.Connection == nil && config.ConnectTimeout <= 0 {
		return nil, &ArgumentOutOfRangeError{
			Param:   "ConnectTimeout",
			Message: "A positive connect timeout is required when dialing a NATS URL.",
		}
	}
	if config.Systemd == nil {
		return nil, &ArgumentError{
			Param:   "Systemd",
			Message: "A native systemd adapter wired in user-manager mode is required.",
		}
	}
	if config.Container == nil {
		return nil, &ArgumentError{
			Param:   "Container",
			Message: "A rootless OCI container adapter is required.",
		}
	}
	if config.Metrics == nil {
		return nil, &ArgumentError{
			Param:   "Metrics",
			Message: "A metrics source is required.",
		}
	}
	if config.HeartbeatInterval <= 0 {
		return nil, &ArgumentOutOfRangeError{
			Param:   "HeartbeatInterval",
			Message: "The heartbeat interval must be positive.",
		}
	}
	if config.Now == nil {
		return nil, &ArgumentError{
			Param:   "Now",
			Message: "A heartbeat clock is required.",
		}
	}
	executor, err := NewWorkloadExecutor(WorkloadExecutorConfig{
		NodeId:    nodeId,
		Systemd:   config.Systemd,
		Container: config.Container,
	})
	if err != nil {
		return nil, err
	}
	return &HostAgent{
		nodeId:            nodeId,
		connection:        config.Connection,
		natsURL:           config.NatsURL,
		natsOptions:       append([]nats.Option(nil), config.NatsOptions...),
		connectTimeout:    config.ConnectTimeout,
		ownsConnection:    config.Connection == nil,
		heartbeatInterval: config.HeartbeatInterval,
		metricsSource:     config.Metrics,
		nowFunc:           config.Now,
		executor:          executor,
		completion:        make(chan struct{}),
	}, nil
}

// Start wires the connection and transport and begins serving the node
// subjects. It returns once serving is up; the agent then runs until ctx is
// cancelled or Close is called, whichever happens first. Calling Start twice
// is an invalid operation.
func (a *HostAgent) Start(ctx context.Context) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The agent context must not be nil."}
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.closed {
		return &InvalidOperationError{Message: "The agent was already closed."}
	}
	if a.transport != nil {
		return &InvalidOperationError{Message: "The agent was already started."}
	}
	connection := a.connection
	if connection == nil {
		options := []nats.Option{
			nats.Timeout(a.connectTimeout),
			nats.MaxReconnects(0),
			nats.RetryOnFailedConnect(false),
		}
		options = append(options, a.natsOptions...)
		dialed, err := nats.Connect(a.natsURL, options...)
		if err != nil {
			return err
		}
		wrapped, err := NewLiveNatsConnection(dialed)
		if err != nil {
			dialed.Close()
			return err
		}
		connection = wrapped
	}
	ticker, err := NewIntervalHeartbeatTicker(a.heartbeatInterval)
	if err != nil {
		a.releaseDialed(connection)
		return err
	}
	transport, err := NewNatsTransport(NatsTransportConfig{
		NodeId:          a.nodeId,
		Connection:      connection,
		Executor:        a.executor,
		Metrics:         a.metricsSource,
		Ticker:          ticker,
		Now:             a.nowFunc,
		CloseConnection: a.ownsConnection,
	})
	if err != nil {
		ticker.Stop()
		a.releaseDialed(connection)
		return err
	}
	if err := transport.Start(ctx); err != nil {
		ticker.Stop()
		_ = transport.Close()
		return err
	}
	a.transport = transport
	go func() {
		<-ctx.Done()
		// Context cancellation is the agent's lifecycle signal. Drain the
		// transport as part of that shutdown; merely closing Completion would
		// leave the NATS subscriptions serving commands after the caller has
		// observed the agent stop.
		_ = a.Close()
	}()
	return nil
}

// Close gracefully drains the transport's subscriptions and closes the
// resources the agent owns. Close is idempotent and safe to call from any
// goroutine.
func (a *HostAgent) Close() error {
	a.closeOnce.Do(func() {
		a.mutex.Lock()
		defer a.mutex.Unlock()
		a.closed = true
		if a.transport != nil {
			a.closeErr = a.transport.Close()
		}
		a.complete()
	})
	return a.closeErr
}

// Completion closes when the agent's start context is cancelled, so callers
// can wait for a context-driven shutdown to finish its Close.
func (a *HostAgent) Completion() <-chan struct{} {
	return a.completion
}

// Executor exposes the agent's workload executor for drain wiring and tests.
func (a *HostAgent) Executor() *WorkloadExecutor {
	return a.executor
}

// NodeId reports the node identity the agent serves.
func (a *HostAgent) NodeId() NodeId {
	return a.nodeId
}

// Cordoned reports the executor's cordon flag.
func (a *HostAgent) Cordoned() bool {
	return a.executor.Cordoned()
}

func (a *HostAgent) complete() {
	a.completionOnce.Do(func() { close(a.completion) })
}

func (a *HostAgent) releaseDialed(connection NatsConnection) {
	if a.ownsConnection {
		connection.Close()
	}
}
