package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

const globalWorkerPoll = time.Second
const globalWorkerJoin = 10 * time.Second

// globalWorkerSession binds concrete provider constructors to one actual owner.
// Guard checks are necessary at dispatch, but do not retract a remote mutation.
type globalWorkerSession struct {
	Lease      authority.RegionalAuthorityLeaseDocument
	Connection *nats.Conn
	guard      *keyrotation.NATSStateStore
	check      func(context.Context) error
}

func (s globalWorkerSession) CheckEffectAuthority(ctx context.Context) error {
	if ctx == nil || s.check == nil {
		return errors.New("global worker session is not active")
	}
	return s.check(ctx)
}

var errGlobalConnectionTimeout = errors.New("global worker connection construction did not stop")

type globalWorkerSessionConfig struct {
	CandidateID    string
	Snapshot       func() control.RegionalAuthoritySnapshot
	OpenConnection func(context.Context) (*nats.Conn, error)
	Start          func(context.Context, globalWorkerSession) (component, error)
}
type globalWorkerStatus struct {
	Ready   bool
	Epoch   int64
	LeaseID string
	Reason  string
}

// leaseOwnedGlobalWorkers supervises only GRU global operational workers.
// Regional delivery and the broker have separate process lifetimes.
type leaseOwnedGlobalWorkers struct {
	config globalWorkerSessionConfig
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	status globalWorkerStatus
	err    error
}

func startLeaseOwnedGlobalWorkers(ctx context.Context, config globalWorkerSessionConfig) (*leaseOwnedGlobalWorkers, error) {
	if ctx == nil || config.Snapshot == nil || config.OpenConnection == nil || config.Start == nil || !strings.HasPrefix(config.CandidateID, "global-controller-gru-") || len(config.CandidateID) <= len("global-controller-gru-") {
		return nil, errors.New("global workers require explicit GRU authority, connection factory and constructors")
	}
	lifetime, cancel := context.WithCancel(ctx)
	worker := &leaseOwnedGlobalWorkers{config: config, cancel: cancel, done: make(chan struct{}), status: globalWorkerStatus{Reason: "awaiting-global-authority"}}
	go worker.run(lifetime)
	return worker, nil
}
func (w *leaseOwnedGlobalWorkers) run(ctx context.Context) {
	defer close(w.done)
	defer w.setStatus(globalWorkerStatus{Reason: "stopped"})
	for ctx.Err() == nil {
		session, err := w.acquire(ctx)
		if errors.Is(err, errGlobalConnectionTimeout) {
			w.mu.Lock()
			w.err = err
			w.mu.Unlock()
			return
		}
		if err == nil {
			err = w.serve(ctx, session)
			session.Connection.Close()
			if err != nil {
				w.mu.Lock()
				w.err = err
				w.mu.Unlock()
				return
			}
		}
		w.setStatus(globalWorkerStatus{Reason: "awaiting-global-authority"})
		select {
		case <-ctx.Done():
			return
		case <-time.After(globalWorkerPoll):
		}
	}
}
func (w *leaseOwnedGlobalWorkers) acquire(ctx context.Context) (globalWorkerSession, error) {
	observed := w.config.Snapshot()
	if !observed.Ready() || !observed.IsLeader || observed.State != "leader" {
		return globalWorkerSession{}, errors.New("global worker process is not leader")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	type opened struct {
		connection *nats.Conn
		err        error
	}
	opening := make(chan opened, 1)
	go func() { connection, err := w.config.OpenConnection(bounded); opening <- opened{connection, err} }()
	var result opened
	select {
	case result = <-opening:
	case <-bounded.Done():
		select {
		case result = <-opening:
			if result.connection != nil {
				result.connection.Close()
			}
			return globalWorkerSession{}, bounded.Err()
		case <-time.After(globalWorkerJoin):
			go func() {
				late := <-opening
				if late.connection != nil {
					late.connection.Close()
				}
			}()
			return globalWorkerSession{}, errGlobalConnectionTimeout
		}
	}
	connection, err := result.connection, result.err
	if err != nil {
		if connection != nil {
			connection.Close()
		}
		return globalWorkerSession{}, err
	}
	if connection == nil {
		return globalWorkerSession{}, errors.New("global worker connection factory returned nil")
	}
	success := false
	defer func() {
		if !success {
			connection.Close()
		}
	}()
	raw, _, err := nodeauthority.ReadLeaderKV(bounded, connection, "ORCH_LEADERS", "authority.global")
	if err != nil {
		return globalWorkerSession{}, err
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if len(raw) > 16*1024 || json.Unmarshal(raw, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != "global" || lease.CandidateId != w.config.CandidateID || lease.Epoch != observed.Epoch {
		return globalWorkerSession{}, errors.New("global worker lease differs from election")
	}
	guard, err := keyrotation.NewNATSStateStore(keyrotation.NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId})
	if err != nil {
		return globalWorkerSession{}, err
	}
	// R1, follower reads and cached snapshots cannot pass this new quorum CAS.
	lease, err = guard.RefreshAuthority(bounded)
	if err != nil {
		return globalWorkerSession{}, err
	}
	success = true
	return globalWorkerSession{Lease: lease, Connection: connection, guard: guard}, nil
}
func (w *leaseOwnedGlobalWorkers) serve(ctx context.Context, session globalWorkerSession) error {
	lifetime, stop := context.WithCancel(ctx)
	cancel := func() { stop(); w.setStatus(globalWorkerStatus{Reason: "global-authority-lost"}) }
	defer cancel()
	deadline := session.Lease.IssuedAt.Add(time.Duration(session.Lease.DurationMilliseconds) * time.Millisecond)
	if !deadline.After(time.Now()) || lifetime.Err() != nil {
		return nil
	}
	session.check = func(ctx context.Context) error {
		if err := lifetime.Err(); err != nil {
			return err
		}
		proofCtx, stopProof := context.WithCancel(ctx)
		detach := context.AfterFunc(lifetime, stopProof)
		defer func() { detach(); stopProof() }()
		if err := session.guard.CheckEffectAuthority(proofCtx); err != nil {
			cancel()
			return context.Canceled
		}
		return lifetime.Err()
	}
	transport := session.Connection.StatusChanged(nats.CLOSED, nats.DISCONNECTED, nats.RECONNECTING)
	if !session.Connection.IsConnected() {
		cancel()
		return nil
	}
	expiry := time.AfterFunc(time.Until(session.Lease.IssuedAt.Add(time.Duration(session.Lease.DurationMilliseconds)*time.Millisecond)), cancel)
	defer expiry.Stop()
	monitored := make(chan struct{})
	go func() {
		defer close(monitored)
		ticker := time.NewTicker(globalWorkerPoll)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-transport:
				cancel()
				return
			case <-ticker.C:
			}
			observed := w.config.Snapshot()
			if !observed.Ready() || !observed.IsLeader || observed.State != "leader" || observed.Epoch != session.Lease.Epoch {
				cancel()
				return
			}
			lease, err := session.guard.RefreshAuthority(lifetime)
			if err != nil {
				cancel()
				return
			}
			if lifetime.Err() != nil {
				return
			}
			expiry.Reset(time.Until(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)))
		}
	}()
	defer func() { cancel(); <-monitored }()
	type constructed struct {
		worker component
		err    error
	}
	result := make(chan constructed, 1)
	go func() {
		if lifetime.Err() != nil || !deadline.After(time.Now()) {
			cancel()
			result <- constructed{err: context.Canceled}
			return
		}
		worker, err := w.config.Start(lifetime, session)
		result <- constructed{worker, err}
	}()
	var built constructed
	select {
	case built = <-result:
	case <-lifetime.Done():
		select {
		case built = <-result:
		case <-time.After(globalWorkerJoin):
			go func() {
				late := <-result
				if late.worker != nil {
					_ = joinGlobalWorker(late.worker)
				}
			}()
			return errors.New("global worker construction did not stop after ownership loss")
		}
	}
	if built.worker == nil || built.err != nil {
		wasCanceled := lifetime.Err() != nil
		cancel()
		if built.worker != nil {
			if err := joinGlobalWorker(built.worker); err != nil {
				return err
			}
		}
		if wasCanceled && (built.err == nil || built.err == context.Canceled) {
			return nil
		}
		if built.err != nil {
			return built.err
		}
		return errors.New("global worker constructor returned nil")
	}
	if built.worker.Completion() == nil {
		cancel()
		_ = joinGlobalWorker(built.worker)
		return errors.New("global workers have no completion signal")
	}
	if lifetime.Err() != nil {
		return joinGlobalWorker(built.worker)
	}
	select {
	case <-built.worker.Completion():
		cancel()
		if err := joinGlobalWorker(built.worker); err != nil {
			return err
		}
		return errors.New("global workers completed during construction")
	default:
	}
	w.mu.Lock()
	if lifetime.Err() == nil {
		w.status = globalWorkerStatus{Ready: true, Epoch: session.Lease.Epoch, LeaseID: session.Lease.LeaseId}
	}
	w.mu.Unlock()
	select {
	case <-lifetime.Done():
		w.setStatus(globalWorkerStatus{Reason: "global-authority-lost"})
		return joinGlobalWorker(built.worker)
	case <-built.worker.Completion():
		// A journal may discover takeover before the polling loop. Keep regional
		// work alive when this failure belongs to an already-lost global session.
		lost := lifetime.Err() != nil || session.guard.CheckEffectAuthority(lifetime) != nil
		cancel()
		if err := joinGlobalWorker(built.worker); err != nil {
			return err
		}
		if lost {
			return nil
		}
		return errors.New("global workers stopped while authority remained valid")
	}
}
func joinGlobalWorker(worker component) error {
	closed := make(chan error, 1)
	go func() { closed <- worker.Close() }()
	select {
	case err := <-closed:
		select {
		case <-worker.Completion():
			if err == context.Canceled {
				return nil
			}
			return err
		default:
			if err != nil {
				return err
			}
			return errors.New("global worker close did not prove completion")
		}
	case <-time.After(globalWorkerJoin):
		return errors.New("global worker shutdown timed out")
	}
}
func (w *leaseOwnedGlobalWorkers) setStatus(status globalWorkerStatus) {
	w.mu.Lock()
	w.status = status
	w.mu.Unlock()
}
func (w *leaseOwnedGlobalWorkers) Snapshot() globalWorkerStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}
func (w *leaseOwnedGlobalWorkers) Completion() <-chan struct{} { return w.done }
func (w *leaseOwnedGlobalWorkers) Close() error {
	w.cancel()
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
