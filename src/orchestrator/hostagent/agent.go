// This file composes the D-69 host agent: one lifecycle (the host
// mutations), one manifest watcher (desired components), one facts source
// (heartbeats), and one NATS transport (the RPC surface), wired together
// from one fully explicit configuration with no ambient environment reads.
package hostagent

import (
	"context"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const (
	hostAgentReconnectWait = 250 * time.Millisecond
	hostAgentMaxReconnects = 480
)

// HostAgentConfig is the fully explicit configuration of one host agent.
// Either Connection or NatsURL must be set, never both: the caller wires an
// in-process or pre-dialed connection, or lets the agent dial one explicit
// URL itself.
type HostAgentConfig struct {
	// NodeId is the validated node identity the agent serves.
	NodeId NodeId
	// Connection is a pre-wired transport connection owned by the caller.
	Connection NatsConnection
	// NatsURL is the explicit URL the agent dials in Start.
	NatsURL string
	// NatsOptions carries the already validated authentication and TLS
	// options for a dialed production connection. It must be empty with a
	// pre-wired Connection; local plaintext lanes leave it empty.
	NatsOptions []nats.Option
	// ConnectTimeout bounds the dial when NatsURL is used.
	ConnectTimeout time.Duration
	// Lifecycle executes every host mutation.
	Lifecycle *Lifecycle
	// Facts samples the heartbeat dimensions.
	Facts *HostFactsSource
	// ManifestPath is the local desired-state file the agent watches.
	ManifestPath string
	// ReconcileInterval is the manifest watch cadence.
	ReconcileInterval time.Duration
	// HeartbeatInterval is the fixed heartbeat period.
	HeartbeatInterval time.Duration
	// Now provides heartbeat timestamps; it must return positive Unix time.
	Now func() time.Time
}

// HostAgent is the node-side composition: it reconciles the host toward the
// manifest, answers the ts.orch.v2 host-agent subjects of contracts.go, and
// publishes heartbeats until its context is cancelled or Close is called.
type HostAgent struct {
	nodeId            NodeId
	connection        NatsConnection
	natsURL           string
	natsOptions       []nats.Option
	connectTimeout    time.Duration
	ownsConnection    bool
	lifecycle         *Lifecycle
	facts             *HostFactsSource
	manifestPath      string
	reconcileInterval time.Duration
	heartbeatInterval time.Duration
	nowFunc           func() time.Time
	transport         *NatsTransport
	watcher           *ManifestWatcher
	completion        chan struct{}
	completionOnce    sync.Once
	runCancel         context.CancelFunc
	watcherDone       chan struct{}
	mutex             sync.Mutex
	closeOnce         sync.Once
	closeErr          error
	closed            bool
}

// NewHostAgent validates the configuration and composes the agent. Nothing
// is dialed or started here; Start does that.
func NewHostAgent(config HostAgentConfig) (*HostAgent, error) {
	nodeId, err := NewNodeId(config.NodeId.Value)
	if err != nil {
		return nil, err
	}
	if (config.Connection == nil) == (config.NatsURL == "") {
		return nil, &errs.Argument{
			Param:   "Connection",
			Message: "Exactly one of a wired connection or a NATS URL is required.",
		}
	}
	if config.Connection != nil && len(config.NatsOptions) != 0 {
		return nil, &errs.Argument{
			Param:   "NatsOptions",
			Message: "NATS dial options cannot accompany a pre-wired connection.",
		}
	}
	if config.Connection == nil && config.ConnectTimeout <= 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "ConnectTimeout",
			Message: "A positive connect timeout is required when dialing a NATS URL.",
		}
	}
	if config.Lifecycle == nil {
		return nil, &errs.Argument{Param: "Lifecycle", Message: "A lifecycle is required."}
	}
	if config.Facts == nil {
		return nil, &errs.Argument{Param: "Facts", Message: "A facts source is required."}
	}
	if config.ReconcileInterval <= 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "ReconcileInterval",
			Message: "The reconcile interval must be positive.",
		}
	}
	if config.HeartbeatInterval <= 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "HeartbeatInterval",
			Message: "The heartbeat interval must be positive.",
		}
	}
	if config.Now == nil {
		return nil, &errs.Argument{Param: "Now", Message: "A heartbeat clock is required."}
	}
	watcher, err := NewManifestWatcher(ManifestWatcherConfig{
		ManifestPath: config.ManifestPath,
		Interval:     config.ReconcileInterval,
		Lifecycle:    config.Lifecycle,
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
		lifecycle:         config.Lifecycle,
		facts:             config.Facts,
		manifestPath:      config.ManifestPath,
		reconcileInterval: config.ReconcileInterval,
		heartbeatInterval: config.HeartbeatInterval,
		nowFunc:           config.Now,
		watcher:           watcher,
		completion:        make(chan struct{}),
	}, nil
}

// Start wires the connection and transport, serves the node subjects, and
// runs the manifest watch until ctx is cancelled or Close is called. It
// returns once serving is up. Calling Start twice is an invalid operation.
func (a *HostAgent) Start(ctx context.Context) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The agent context must not be nil."}
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
	connectionClosed := make(chan struct{}, 1)
	if connection == nil {
		options := []nats.Option{
			nats.Timeout(a.connectTimeout),
			nats.MaxReconnects(hostAgentMaxReconnects),
			nats.ReconnectWait(hostAgentReconnectWait),
			nats.RetryOnFailedConnect(false),
			nats.ClosedHandler(func(*nats.Conn) {
				select {
				case connectionClosed <- struct{}{}:
				default:
				}
			}),
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
		Lifecycle:       a.lifecycle,
		Facts:           a.facts,
		Ticker:          ticker,
		Now:             a.nowFunc,
		CloseConnection: a.ownsConnection,
	})
	if err != nil {
		ticker.Stop()
		a.releaseDialed(connection)
		return err
	}
	runContext, runCancel := context.WithCancel(ctx)
	// Load the real desired set before command-journal recovery. A pending
	// drain or release must never be completed against a fresh empty lifecycle.
	if err := transport.prepareLifecycleForStartup(); err != nil {
		runCancel()
		ticker.Stop()
		a.releaseDialed(connection)
		return err
	}
	if err := a.watcher.HydrateOnce(); err != nil {
		runCancel()
		ticker.Stop()
		a.releaseDialed(connection)
		return err
	}
	if err := transport.Start(runContext); err != nil {
		runCancel()
		ticker.Stop()
		_ = transport.Close()
		return err
	}
	a.transport = transport
	a.runCancel = runCancel
	watcherDone := make(chan struct{})
	a.watcherDone = watcherDone
	go func() {
		defer close(watcherDone)
		a.watcher.Run(runContext)
	}()
	go func() {
		<-runContext.Done()
		// Context cancellation is the agent's lifecycle signal. Drain the
		// transport as part of that shutdown; merely closing Completion
		// would leave the NATS subscriptions serving commands after the
		// caller has observed the agent stop.
		_ = a.Close()
	}()
	if a.ownsConnection {
		go func() {
			select {
			case <-connectionClosed:
				_ = a.Close()
			case <-runContext.Done():
			}
		}()
	}
	return nil
}

// Close gracefully drains the transport's subscriptions and closes the
// resources the agent owns. Close is idempotent and safe to call from any
// goroutine.
func (a *HostAgent) Close() error {
	a.closeOnce.Do(func() {
		a.mutex.Lock()
		a.closed = true
		if a.runCancel != nil {
			a.runCancel()
		}
		if a.transport != nil {
			a.closeErr = a.transport.Close()
		}
		watcherDone := a.watcherDone
		a.mutex.Unlock()
		if watcherDone != nil {
			<-watcherDone
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

// Lifecycle exposes the agent's lifecycle for operators and tests.
func (a *HostAgent) Lifecycle() *Lifecycle { return a.lifecycle }

func (a *HostAgent) complete() {
	a.completionOnce.Do(func() { close(a.completion) })
}

func (a *HostAgent) releaseDialed(connection NatsConnection) {
	if a.ownsConnection {
		connection.Close()
	}
}
