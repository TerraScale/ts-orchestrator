package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type memoryMutations struct {
	mu       sync.Mutex
	sequence uint64
	entries  map[string]authority.LogEntry
	js       jetstream.JetStream
}

type gatedDesiredRead struct {
	authority.HostMutationStore
	blocked atomic.Bool
	started chan struct{}
	release chan struct{}
}

type oneShotSessionFailure struct {
	failNext atomic.Bool
	failures atomic.Int32
	failure  error
	reader   func(context.Context, string) (session, uint64, bool, error)
}

type sessionConflictState struct {
	jetstream.KeyValue
	stale      jetstream.KeyValueEntry
	reads      atomic.Int32
	conflicts  atomic.Int32
	onConflict func(context.Context, string, uint64) error
}

func (s *sessionConflictState) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	if key == sessionKey("gru", "node-a") && s.stale != nil {
		s.reads.Add(1)
		return s.stale, nil
	}
	return s.KeyValue.Get(ctx, key)
}

func (s *sessionConflictState) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if key == sessionKey("gru", "node-a") {
		for remaining := s.conflicts.Load(); remaining > 0; remaining = s.conflicts.Load() {
			if s.conflicts.CompareAndSwap(remaining, remaining-1) {
				if s.onConflict != nil {
					if err := s.onConflict(ctx, key, revision); err != nil {
						return 0, err
					}
				}
				return 0, jetstream.ErrKeyRevisionMismatch
			}
		}
	}
	return s.KeyValue.Update(ctx, key, value, revision)
}

func (s *oneShotSessionFailure) Read(ctx context.Context, key string) (session, uint64, bool, error) {
	if key == sessionKey("gru", "node-a") && s.failNext.CompareAndSwap(true, false) {
		s.failures.Add(1)
		return session{}, 0, false, s.failure
	}
	return s.reader(ctx, key)
}

func (g *gatedDesiredRead) ReadHostMutation(ctx context.Context, kind authority.HostMutationKind, subject string) (authority.LogEntry, error) {
	entry, err := g.HostMutationStore.ReadHostMutation(ctx, kind, subject)
	if kind == authority.MutationDesired && err == nil && g.blocked.CompareAndSwap(false, true) {
		close(g.started)
		<-g.release
	}
	return entry, err
}

func (m *memoryMutations) key(kind authority.HostMutationKind, subject string) string {
	return string(kind) + "." + subject
}
func (m *memoryMutations) ReadHostMutation(_ context.Context, kind authority.HostMutationKind, subject string) (authority.LogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[m.key(kind, subject)]
	if !ok {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return entry, nil
}
func (m *memoryMutations) CommitHostMutation(ctx context.Context, epoch uint64, kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(kind, subject)
	if m.entries[key].Sequence != expected {
		return 0, authority.ErrConflict
	}
	ack, err := m.js.Publish(ctx, "ts.control.gru.host."+string(kind)+"."+subject, payload)
	if err != nil {
		return 0, err
	}
	m.sequence = ack.Sequence
	m.entries[key] = authority.LogEntry{Kind: kind, SubjectKey: subject, OperationID: operation, Epoch: epoch, Sequence: m.sequence, Payload: append([]byte(nil), payload...)}
	return m.sequence, nil
}

type memoryRunner struct {
	mu       sync.Mutex
	observed map[string]Observation
	applied  int
}

type stoppedRunner struct {
	*memoryRunner
	stopped chan struct{}
	once    sync.Once
}

func (r *stoppedRunner) Close(ctx context.Context) error {
	err := r.memoryRunner.Close(ctx)
	r.once.Do(func() { close(r.stopped) })
	return err
}

type delayedStopRunner struct {
	*stoppedRunner
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (r *delayedStopRunner) Close(ctx context.Context) error {
	if r.calls.Add(1) == 1 {
		close(r.started)
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.stoppedRunner.Close(ctx)
}

type stalledArtifactStore struct {
	ArtifactStore
	started chan struct{}
	once    sync.Once
}

func (s *stalledArtifactStore) GetInfo(ctx context.Context, _ string, _ ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *memoryRunner) Recover(context.Context) error { return nil }
func (m *memoryRunner) Apply(_ context.Context, w Workload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied++
	m.observed[w.Role] = Observation{Role: w.Role, Digest: w.Digest, Fingerprint: w.Fingerprint, Running: true}
	return nil
}
func (m *memoryRunner) Stop(_ context.Context, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.observed, role)
	return nil
}
func (m *memoryRunner) Observe(_ context.Context, role string) (Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.observed[role], nil
}
func (m *memoryRunner) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.observed)
	return nil
}

func testController(t *testing.T) (*Controller, *nats.Conn, jetstream.ObjectStore, *memoryMutations, ed25519.PrivateKey) {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	log, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: "TS_CONTROL_LOG", Subjects: []string{"ts.control.gru.>"}, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	store, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "HOST_TEST_ARTIFACTS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mutations := &memoryMutations{entries: make(map[string]authority.LogEntry), js: js}
	c, err := NewController(t.Context(), ControllerConfig{Cell: "gru", Conn: conn, JS: js, ControlLog: log, Artifacts: store, ResponseKey: controllerKey, StateReplicas: 1, HostMutations: mutations, AuthorityEpoch: func() uint64 { return 1 }, AuthorityGuard: func(context.Context, uint64) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return c, conn, store, mutations, controllerKey
}

func registerTestHost(t *testing.T, c *Controller) ed25519.PrivateKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Register(t.Context(), Registration{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func TestManagedOCIBindingValidation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := Registration{
		Cell: "gru", Node: "host-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), Generation: 1,
		ManagedOCI: &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..host-a", Owner: "terrascale", FleetGeneration: 4, CreateKey: "host-a"},
	}
	tests := []struct {
		name    string
		change  func(*Registration)
		wantErr bool
	}{
		{name: "complete managed binding"},
		{name: "ordinary host without binding", change: func(r *Registration) { r.ManagedOCI = nil; r.FailureDomain = "fd-a" }},
		{name: "unmanaged OCI fault domain", change: func(r *Registration) { r.ManagedOCI = nil }, wantErr: true},
		{name: "missing region", change: func(r *Registration) { r.ManagedOCI.Region = "" }, wantErr: true},
		{name: "unknown region", change: func(r *Registration) { r.ManagedOCI.Region = "AMS" }, wantErr: true},
		{name: "missing instance", change: func(r *Registration) { r.ManagedOCI.InstanceID = "" }, wantErr: true},
		{name: "wrong instance type", change: func(r *Registration) { r.ManagedOCI.InstanceID = "ocid1.volume.oc1..a" }, wantErr: true},
		{name: "instance whitespace", change: func(r *Registration) { r.ManagedOCI.InstanceID += " x" }, wantErr: true},
		{name: "instance too long", change: func(r *Registration) { r.ManagedOCI.InstanceID = "ocid1.instance." + strings.Repeat("x", 256) }, wantErr: true},
		{name: "missing owner", change: func(r *Registration) { r.ManagedOCI.Owner = "" }, wantErr: true},
		{name: "missing fleet generation", change: func(r *Registration) { r.ManagedOCI.FleetGeneration = 0 }, wantErr: true},
		{name: "missing create key", change: func(r *Registration) { r.ManagedOCI.CreateKey = "" }, wantErr: true},
		{name: "create key whitespace", change: func(r *Registration) { r.ManagedOCI.CreateKey = "host a" }, wantErr: true},
		{name: "create key too long", change: func(r *Registration) { r.ManagedOCI.CreateKey = strings.Repeat("x", 129) }, wantErr: true},
		{name: "missing fault domain", change: func(r *Registration) { r.FailureDomain = "" }, wantErr: true},
		{name: "invalid OCI fault domain", change: func(r *Registration) { r.FailureDomain = "FAULT-DOMAIN-4" }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registration := valid
			binding := *valid.ManagedOCI
			registration.ManagedOCI = &binding
			if tt.change != nil {
				tt.change(&registration)
			}
			err := validateRegistration(registration, "gru")
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateRegistration() err=%v, wantErr=%t", err, tt.wantErr)
			}
		})
	}
}

func TestSessionRetryClassificationAndReserve(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, nats.ErrTimeout, nats.ErrNoResponders, nats.ErrDisconnected, jetstream.ErrNoStreamResponse, errSessionBackendUnavailable} {
		if !retrySessionExchange(err) {
			t.Fatalf("transient session error was terminal: %v", err)
		}
	}
	for _, err := range []error{errSessionOwned, errSessionRequestDenied, errors.New("renewed session binding mismatch"), nats.ErrConnectionClosed} {
		if retrySessionExchange(err) {
			t.Fatalf("terminal session error was retryable: %v", err)
		}
	}
	now := time.Now()
	if !sessionUsableUntil(session{ExpiresAt: now.Add(sessionExecutionReserve + time.Nanosecond)}, now) {
		t.Fatal("valid lease beyond reserve was rejected")
	}
	if sessionUsableUntil(session{ExpiresAt: now.Add(sessionExecutionReserve)}, now) {
		t.Fatal("lease at safety boundary remained usable")
	}
	if sessionUsableUntil(session{ExpiresAt: now.Add(-time.Second)}, now) {
		t.Fatal("expired lease remained usable")
	}
}

func TestSignedTransientSessionBackendRetriesWithinLease(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"deadline exceeded", context.DeadlineExceeded},
		{"no stream response", jetstream.ErrNoStreamResponse},
	} {
		t.Run(test.name, func(t *testing.T) { testSignedTransientSessionBackend(t, test.err) })
	}
}

func testSignedTransientSessionBackend(t *testing.T, backendErr error) {
	c, conn, _, mutations, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	state := &oneShotSessionFailure{failure: backendErr, reader: c.readLeaderSession}
	c.sessionRead = state.Read
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(controllerCtx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	state.failNext.Store(true)
	if err := agent.acquire(t.Context()); !errors.Is(err, errSessionBackendUnavailable) || !strings.Contains(err.Error(), backendErr.Error()) {
		t.Fatalf("signed controller failure was not classified as retryable: %v", err)
	}
	state.failNext.Store(true)
	startupCtx, stopWaiting := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopWaiting()
	if err := agent.waitForSession(startupCtx); err != nil {
		t.Fatalf("startup did not retry signed controller failure: %v", err)
	}
	agent.mu.RLock()
	initial := agent.session
	agent.mu.RUnlock()
	state.failNext.Store(true)
	monitorCtx, stopMonitor := context.WithCancel(t.Context())
	monitorDone := make(chan struct{})
	lost := make(chan error, 1)
	go func() {
		agent.maintainSession(monitorCtx, stopMonitor, lost)
		close(monitorDone)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		agent.mu.RLock()
		current := agent.session
		agent.mu.RUnlock()
		if current.ExpiresAt.After(initial.ExpiresAt) {
			break
		}
		select {
		case err := <-lost:
			t.Fatalf("signed renewal failure stopped the valid lease: %v", err)
		case <-monitorDone:
			t.Fatal("session monitor exited before retrying signed failure")
		case <-deadline.C:
			t.Fatal("signed renewal failure was not retried")
		case <-time.After(25 * time.Millisecond):
		}
	}
	stopMonitor()
	<-monitorDone
	if got := state.failures.Load(); got != 3 || agent.sessionLost.Load() {
		t.Fatalf("signed timeouts=%d, session lost=%t; want three retries and live session", got, agent.sessionLost.Load())
	}
	mutations.mu.Lock()
	delete(mutations.entries, mutations.key(authority.MutationRegistration, registrationSubjectKey("gru", "node-a")))
	mutations.mu.Unlock()
	if err := agent.acquire(t.Context()); !errors.Is(err, errSessionRequestDenied) || retrySessionExchange(err) {
		t.Fatalf("signed revocation denial became retryable: %v", err)
	}
	stopController()
	<-controllerDone
}

func TestStartupWaitsForOldSessionAndCancellation(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	oldKey := registerTestHost(t, c)
	acquire := func(key ed25519.PrivateKey, id string) request {
		t.Helper()
		req := request{Version: 1, Node: "node-a", Operation: "session", SessionID: id, Nonce: "abcdef0123456789abcdef0123456789", IssuedAt: time.Now().UTC(), Payload: []byte(`{"kind":"acquire"}`)}
		if err := signRequest(&req, key, "gru"); err != nil {
			t.Fatal(err)
		}
		return req
	}
	if _, err := c.handleSession(t.Context(), acquire(oldKey, "0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: oldKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, stopWaiting := context.WithCancel(t.Context())
	waitDone := make(chan error, 1)
	go func() { waitDone <- agent.waitForSession(waitCtx) }()
	select {
	case err := <-waitDone:
		t.Fatalf("startup gave up on old live session: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	stopWaiting()
	select {
	case err := <-waitDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled startup wait returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup wait ignored cancellation")
	}
	cancel()
	<-done
}

func TestTransientRenewalKeepsWorkloadUntilSignedLeaseReserve(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	install := filepath.Join(t.TempDir(), "install")
	state := filepath.Join(t.TempDir(), "state")
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: install, StateRoot: state})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	agent.mu.Lock()
	lease := agent.session
	lease.ExpiresAt = time.Now().Add(7 * time.Second)
	agent.session = lease
	agent.mu.Unlock()
	// All renewal requests now receive a transport timeout; the old signed
	// lease remains the only authority until its execution reserve is reached.
	stopController := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("controller did not stop")
		}
	}
	stopController()
	lostCtx, lostCancel := context.WithCancel(t.Context())
	lost := make(chan error, 1)
	go agent.maintainSession(lostCtx, lostCancel, lost)
	select {
	case err := <-lost:
		t.Fatalf("transient timeout stopped workload before signed reserve: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if agent.sessionLost.Load() || !sessionUsableUntil(lease, time.Now()) {
		t.Fatal("transient timeout invalidated a still-usable signed lease")
	}
	select {
	case err := <-lost:
		if err == nil || !agent.sessionLost.Load() || sessionUsableUntil(lease, time.Now()) {
			t.Fatalf("outage did not stop at lease reserve: err=%v lost=%t", err, agent.sessionLost.Load())
		}
	case <-time.After(4 * time.Second):
		t.Fatal("outage continued beyond signed lease reserve")
	}
}

func TestSessionLossStopsActiveWorkloadBeforePendingCycleFlush(t *testing.T) {
	c, conn, store, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nwhile :; do sleep 1; done\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	stalled := &stalledArtifactStore{ArtifactStore: store, started: make(chan struct{})}
	c.artifacts = stalled
	controllerCtx, stopController := context.WithCancel(t.Context())
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(controllerCtx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	oldHash := sha256.Sum256([]byte("old workload"))
	oldDigest := hex.EncodeToString(oldHash[:])
	runner := &delayedStopRunner{
		stoppedRunner: &stoppedRunner{memoryRunner: &memoryRunner{observed: make(map[string]Observation)}, stopped: make(chan struct{})},
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	releaseStop := sync.OnceFunc(func() { close(runner.release) })
	defer releaseStop()
	if err := runner.Apply(t.Context(), Workload{Role: "terrabase", Digest: oldDigest, Fingerprint: oldDigest}); err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state"), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(t.Context())
	defer stopAgent()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(agentCtx) }()
	select {
	case <-stalled.started:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not acquire a pending cycle and fetch artifact")
	}
	agent.mu.Lock()
	leaseExpiry := time.Now().Add(8 * time.Second)
	s := agent.session
	s.ExpiresAt = leaseExpiry
	agent.session = s
	agent.mu.Unlock()
	stopController()
	select {
	case <-controllerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop")
	}
	deadline := time.NewTimer(time.Until(leaseExpiry.Add(-500 * time.Millisecond)))
	defer deadline.Stop()
	select {
	case <-runner.started:
		if !time.Now().Before(leaseExpiry) {
			t.Fatal("active workload stop began after signed lease expiry")
		}
	case <-deadline.C:
		t.Fatal("pending-cycle cleanup kept active workload alive through signed lease expiry")
	}
	select {
	case err := <-agentDone:
		t.Fatalf("agent returned before workload stop reported the session failure: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	releaseStop()
	select {
	case <-runner.stopped:
		if !time.Now().Before(leaseExpiry) {
			t.Fatal("active workload stopped after signed lease expiry")
		}
	case <-time.After(time.Second):
		t.Fatal("active workload was not stopped after release")
	}
	select {
	case err := <-agentDone:
		if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "host session") {
			t.Fatalf("agent did not preserve the session-loss cause: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after session loss")
	}
}

func TestHostSessionRejectsReplayAndForeignIdentity(t *testing.T) {
	c, _, _, _, _ := testController(t)
	key := registerTestHost(t, c)
	id := "0123456789abcdef0123456789abcdef"
	nonce := "abcdef0123456789abcdef0123456789"
	makeAcquire := func(issued time.Time) request {
		r := request{Version: 1, Node: "node-a", Operation: "session", SessionID: id, Nonce: nonce, IssuedAt: issued, Payload: []byte(`{"kind":"acquire"}`)}
		if err := signRequest(&r, key, "gru"); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := makeAcquire(time.Now().UTC())
	first, err := c.handleSession(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.handleSession(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if first.(session).Epoch != second.(session).Epoch || !first.(session).ExpiresAt.Equal(second.(session).ExpiresAt) {
		t.Fatal("exact retry changed session lease")
	}
	if _, err := c.handleSession(t.Context(), makeAcquire(time.Now().Add(-requestTTL-time.Second).UTC())); err == nil {
		t.Fatal("expired enrollment request accepted")
	}
	_, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := makeAcquire(time.Now().UTC())
	if err := signRequest(&forged, foreignKey, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleSession(t.Context(), forged); err == nil {
		t.Fatal("foreign host key accepted")
	}
	renew := request{Version: 1, Node: "node-a", Operation: "session", SessionID: id, Epoch: 99, Nonce: "11111111111111111111111111111111", IssuedAt: time.Now().UTC(), Payload: []byte(`{"kind":"renew"}`)}
	if err := signRequest(&renew, key, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleSession(t.Context(), renew); err == nil {
		t.Fatal("wrong epoch renewal accepted")
	}
	wrongReplay := r
	wrongReplay.Epoch = first.(session).Epoch + 1
	if err := signRequest(&wrongReplay, key, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleSession(t.Context(), wrongReplay); err == nil {
		t.Fatal("same nonce acquire replay with wrong epoch accepted")
	}
	wrongKind := r
	wrongKind.Payload = []byte(`{"kind":"unknown"}`)
	if err := signRequest(&wrongKind, key, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleSession(t.Context(), wrongKind); err == nil {
		t.Fatal("same nonce replay with unknown operation accepted")
	}
}

func signedHostRequest(t *testing.T, key ed25519.PrivateKey, operation, sessionID string, epoch uint64, payload any) request {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	r := request{Version: 1, Node: "node-a", Operation: operation, SessionID: sessionID, Epoch: epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: data}
	if err := signRequest(&r, key, "gru"); err != nil {
		t.Fatal(err)
	}
	return r
}

func reportedTestHost(t *testing.T) (*Controller, ed25519.PrivateKey, session, Report) {
	t.Helper()
	c, _, store, _, _ := testController(t)
	hostKey := registerTestHost(t, c)
	sessionID := "0123456789abcdef0123456789abcdef"
	acquire := signedHostRequest(t, hostKey, "session", sessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	result, err := c.handleSession(t.Context(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	s := result.(session)
	data := []byte("status snapshot artifact")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	report := Report{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, SessionID: sessionID, Epoch: s.Epoch, State: "running", ObservedAt: time.Now().UTC()}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "report", sessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	return c, hostKey, s, report
}

func TestListHostsAcceptsSameBindingSessionChurn(t *testing.T) {
	for _, kind := range []string{"authorization write", "renewal"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, report := reportedTestHost(t)
			reads := 0
			var finalExpiry time.Time
			c.sessionRead = func(ctx context.Context, key string) (session, uint64, bool, error) {
				reads++
				if reads == 2 {
					current, revision, exists, err := c.readLeaderSession(ctx, key)
					if err != nil || !exists {
						return session{}, 0, false, err
					}
					if kind == "renewal" {
						current.ExpiresAt = current.ExpiresAt.Add(time.Second)
						current.LastIssuedAt = time.Now().UTC()
						current.LastNonce = "11111111111111111111111111111111"
					}
					finalExpiry = current.ExpiresAt
					if _, err := c.cas(ctx, key, current, revision); err != nil {
						return session{}, 0, false, err
					}
				}
				return c.readLeaderSession(ctx, key)
			}
			hosts, err := c.ListHosts(t.Context())
			if err != nil || len(hosts) != 1 || len(hosts[0].Reports) != 1 || !hosts[0].SessionExpiresAt.Equal(finalExpiry) || !sameJSON(hosts[0].Reports[0], report) {
				t.Fatalf("same-binding status rejected: hosts=%+v err=%v", hosts, err)
			}
		})
	}
}

func TestListHostsAcceptsNewerSameStateHeartbeat(t *testing.T) {
	c, hostKey, s, report := reportedTestHost(t)
	gate := &gatedDesiredRead{HostMutationStore: c.mutations, started: make(chan struct{}), release: make(chan struct{})}
	c.mutations = gate
	type statusResult struct {
		hosts []HostStatus
		err   error
	}
	done := make(chan statusResult, 1)
	go func() {
		hosts, err := c.ListHosts(t.Context())
		done <- statusResult{hosts, err}
	}()
	select {
	case <-gate.started:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	newer := report
	newer.ObservedAt = report.ObservedAt.Add(time.Millisecond)
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "report", s.SessionID, s.Epoch, newer)); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	result := <-done
	if result.err != nil || len(result.hosts) != 1 || len(result.hosts[0].Reports) != 1 || !sameJSON(result.hosts[0].Reports[0], newer) {
		t.Fatalf("newer same-state heartbeat rejected: hosts=%+v err=%v", result.hosts, result.err)
	}
}

func TestListHostsRejectsSessionTakeoverDuringRead(t *testing.T) {
	c, _, _, _ := reportedTestHost(t)
	reads := 0
	c.sessionRead = func(ctx context.Context, key string) (session, uint64, bool, error) {
		reads++
		if reads == 2 {
			current, revision, exists, err := c.readLeaderSession(ctx, key)
			if err != nil || !exists {
				return session{}, 0, false, err
			}
			current.SessionID = "11111111111111111111111111111111"
			current.Epoch++
			if _, err := c.cas(ctx, key, current, revision); err != nil {
				return session{}, 0, false, err
			}
		}
		return c.readLeaderSession(ctx, key)
	}
	if hosts, err := c.ListHosts(t.Context()); err == nil {
		t.Fatalf("status accepted replaced session: %+v", hosts)
	}
}

func TestListHostsRejectsReportStateChangeDuringRead(t *testing.T) {
	c, hostKey, s, report := reportedTestHost(t)
	gate := &gatedDesiredRead{HostMutationStore: c.mutations, started: make(chan struct{}), release: make(chan struct{})}
	c.mutations = gate
	done := make(chan error, 1)
	go func() {
		_, err := c.ListHosts(t.Context())
		done <- err
	}()
	select {
	case <-gate.started:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	changed := report
	changed.State = "failed"
	changed.Error = "native workload failed"
	changed.ObservedAt = report.ObservedAt.Add(time.Millisecond)
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "report", s.SessionID, s.Epoch, changed)); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-done; err == nil {
		t.Fatal("status kept running report after state changed to failed")
	}
}

func TestConcurrentRenewalAndAuthorizedRPCUseCurrentSession(t *testing.T) {
	c, _, store, _, _ := testController(t)
	hostKey := registerTestHost(t, c)
	sessionID := "0123456789abcdef0123456789abcdef"
	acquire := signedHostRequest(t, hostKey, "session", sessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	first, err := c.handleSession(t.Context(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	initial := first.(session)
	stale, err := c.state.Get(t.Context(), sessionKey("gru", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("host session contention artifact")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	artifact := signedHostRequest(t, hostKey, "artifact", sessionID, initial.Epoch, artifactQuery{Role: "terrabase", Digest: digest, Offset: 0, Length: len(data)})
	for deadline := time.Now().Add(3 * time.Second); ; {
		if _, err := c.handleAuthorized(t.Context(), artifact); err == nil {
			break
		} else if !errors.Is(err, errArtifactPreparing) || time.Now().After(deadline) {
			t.Fatalf("prepare artifact: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	probe := &sessionConflictState{KeyValue: c.state, stale: stale}
	probe.conflicts.Store(2)
	c.state = probe
	renewals := make([]request, 8)
	for i := range renewals {
		renewals[i] = signedHostRequest(t, hostKey, "session", sessionID, initial.Epoch, struct {
			Kind string `json:"kind"`
		}{"renew"})
		renewals[i].IssuedAt = acquire.IssuedAt.Add(time.Duration(i+1) * time.Millisecond)
		if err := signRequest(&renewals[i], hostKey, "gru"); err != nil {
			t.Fatal(err)
		}
	}
	renewDone := make(chan error, 1)
	go func() {
		for _, renew := range renewals {
			if _, err := c.handleSession(t.Context(), renew); err != nil {
				renewDone <- err
				return
			}
		}
		renewDone <- nil
	}()
	for range 8 {
		for _, call := range []struct {
			operation string
			payload   any
		}{
			{"desired", struct {
				Role string `json:"role"`
			}{"terrabase"}},
			{"artifact", artifactQuery{Role: "terrabase", Digest: digest, Offset: 0, Length: len(data)}},
			{"report", Report{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, SessionID: sessionID, Epoch: initial.Epoch, State: "running", ObservedAt: time.Now().UTC()}},
		} {
			req := signedHostRequest(t, hostKey, call.operation, sessionID, initial.Epoch, call.payload)
			if _, err := c.handleAuthorized(t.Context(), req); err != nil {
				t.Fatalf("%s during renewal: %v", call.operation, err)
			}
		}
	}
	if err := <-renewDone; err != nil {
		t.Fatalf("renewal during authorized RPCs: %v", err)
	}
	if got := probe.reads.Load(); got != 0 {
		t.Fatalf("session authorization used stale direct KV.Get %d times", got)
	}
	current, _, exists, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
	if err != nil || !exists || current.SessionID != sessionID || current.Epoch != initial.Epoch || !current.ExpiresAt.After(initial.ExpiresAt) {
		t.Fatalf("session changed identity or failed to renew: %+v exists=%t err=%v", current, exists, err)
	}
}

func TestSignedSessionContentionIsTransientWithoutLeaseChange(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	sessionID := "0123456789abcdef0123456789abcdef"
	acquire := signedHostRequest(t, hostKey, "session", sessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	first, err := c.handleSession(t.Context(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	initial := first.(session)
	probe := &sessionConflictState{KeyValue: c.state}
	c.state = probe
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatalf("controller stopped before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	probe.conflicts.Store(8)
	renew := signedHostRequest(t, hostKey, "session", sessionID, initial.Epoch, struct {
		Kind string `json:"kind"`
	}{"renew"})
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), renew, nil); !errors.Is(err, errSessionContention) || !retrySessionExchange(err) {
		t.Fatalf("signed same-session renewal contention was terminal: %v", err)
	}
	probe.conflicts.Store(8)
	desired := signedHostRequest(t, hostKey, "desired", sessionID, initial.Epoch, struct {
		Role string `json:"role"`
	}{"terrabase"})
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), desired, nil); !errors.Is(err, errSessionContention) {
		t.Fatalf("signed authorized contention was terminal: %v", err)
	}
	current, _, exists, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
	if err != nil || !exists || !sameJSON(current, initial) {
		t.Fatalf("contended request changed signed lease: %+v exists=%t err=%v", current, exists, err)
	}
	cancel()
	<-done
}

func TestAgentResumesOpenCycleAfterSignedSessionContention(t *testing.T) {
	c, conn, store, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	d := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatalf("controller stopped before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	attempt, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	query := cycleQuery{Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1, Attempt: attempt}
	var opened cycleReply
	if err := agent.request(t.Context(), "cycle", query, &opened); err != nil || opened.State != "active" {
		t.Fatalf("open cycle: %+v err=%v", opened, err)
	}
	query.CycleID, query.Fence = opened.CycleID, opened.Fence
	agent.pending["terrabase"] = pendingCycle{query: query}
	probe := &sessionConflictState{KeyValue: c.state}
	probe.conflicts.Store(8)
	c.state = probe
	if err := agent.reconcile(t.Context(), "terrabase"); !errors.Is(err, errSessionContention) {
		t.Fatalf("open-cycle request did not surface signed contention: %v", err)
	}
	if pending := agent.pending["terrabase"]; pending.outcomeReady || pending.query.CycleID != opened.CycleID || pending.query.Fence != opened.Fence {
		t.Fatalf("transient contention completed or replaced open cycle: %+v", pending)
	}
	var record cycleRecord
	if _, exists, err := c.get(t.Context(), cycleKey("gru", "node-a", "terrabase"), &record); err != nil || !exists || record.State != "active" {
		t.Fatalf("transient contention persisted failure: %+v exists=%t err=%v", record, exists, err)
	}
	if err := agent.reconcile(t.Context(), "terrabase"); err != nil {
		t.Fatalf("resume open cycle: %v", err)
	}
	if _, exists := agent.pending["terrabase"]; exists {
		t.Fatal("completed cycle outcome was not flushed")
	}
	if _, exists, err := c.get(t.Context(), cycleKey("gru", "node-a", "terrabase"), &record); err != nil || !exists || record.State != "succeeded" || record.CycleID != opened.CycleID || record.Fence != opened.Fence || !record.NotBefore.IsZero() {
		t.Fatalf("resumed cycle outcome: %+v exists=%t err=%v", record, exists, err)
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 1 {
		t.Fatalf("resumed cycle applied %d times, want once", applied)
	}
	query.Succeeded = true
	agent.pending["terrabase"] = pendingCycle{query: query, outcomeReady: true}
	if err := agent.reconcile(t.Context(), "terrabase"); err != nil {
		t.Fatalf("replay completed cycle outcome: %v", err)
	}
	if _, exists := agent.pending["terrabase"]; exists {
		t.Fatal("replayed completed cycle outcome remained pending")
	}
	runner.mu.Lock()
	applied = runner.applied
	runner.mu.Unlock()
	if applied != 1 {
		t.Fatalf("completed outcome replay applied %d times, want once", applied)
	}
	cancel()
	<-done
}

func TestWithdrawnTargetStopsRunningWorkloadWithOpenCycle(t *testing.T) {
	c, conn, store, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatalf("controller stopped before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	runner := &memoryRunner{observed: map[string]Observation{"terrabase": {Role: "terrabase", Digest: digest, Running: true}}}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state"), PollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	attempt, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	query := cycleQuery{Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1, Attempt: attempt}
	var opened cycleReply
	if err := agent.request(t.Context(), "cycle", query, &opened); err != nil || opened.State != "active" {
		t.Fatalf("open old cycle: %+v err=%v", opened, err)
	}
	query.CycleID, query.Fence = opened.CycleID, opened.Fence
	agent.pending["terrabase"] = pendingCycle{query: query}
	withdrawn := desired
	withdrawn.Generation = 2
	withdrawn.Digest = ""
	withdrawn.Withdrawn = true
	if _, err := c.ApplyDesired(t.Context(), withdrawn); err != nil {
		t.Fatal(err)
	}
	if err := agent.reconcile(t.Context(), "terrabase"); err != nil {
		t.Fatalf("withdrawn reconciliation: %v", err)
	}
	observed, err := runner.Observe(t.Context(), "terrabase")
	if err != nil || observed.Running {
		t.Fatalf("withdrawal waited for next poll to stop workload: %+v err=%v", observed, err)
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 0 {
		t.Fatalf("withdrawal applied a stale target %d times", applied)
	}
	var cycle cycleRecord
	if _, exists, err := c.get(t.Context(), cycleKey("gru", "node-a", "terrabase"), &cycle); err != nil || !exists || cycle.State != "failed" || cycle.CycleID != opened.CycleID {
		t.Fatalf("old cycle was not closed: %+v exists=%t err=%v", cycle, exists, err)
	}
	var report Report
	if _, exists, err := c.get(t.Context(), reportKey("gru", "node-a", "terrabase"), &report); err != nil || !exists || report.State != "stopped" || report.Generation != withdrawn.Generation {
		t.Fatalf("withdrawn target was not reported stopped: %+v exists=%t err=%v", report, exists, err)
	}
	cancel()
	<-done
}

func TestSessionRevalidationRejectsTakeoverExpiryAndRotation(t *testing.T) {
	for _, change := range []string{"takeover", "expiry", "rotation"} {
		t.Run(change, func(t *testing.T) {
			c, _, _, _, _ := testController(t)
			hostKey := registerTestHost(t, c)
			sessionID := "0123456789abcdef0123456789abcdef"
			acquire := signedHostRequest(t, hostKey, "session", sessionID, 0, struct {
				Kind string `json:"kind"`
			}{"acquire"})
			first, err := c.handleSession(t.Context(), acquire)
			if err != nil {
				t.Fatal(err)
			}
			initial := first.(session)
			switch change {
			case "takeover", "expiry":
				next := initial
				if change == "takeover" {
					next.SessionID = "11111111111111111111111111111111"
					next.Epoch++
					raw := c.state
					probe := &sessionConflictState{KeyValue: raw}
					probe.conflicts.Store(1)
					probe.onConflict = func(ctx context.Context, key string, revision uint64) error {
						data, err := json.Marshal(next)
						if err != nil {
							return err
						}
						_, err = raw.Update(ctx, key, data, revision)
						return err
					}
					c.state = probe
				} else {
					next.ExpiresAt = time.Now().Add(-time.Second)
					_, revision, exists, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
					if err != nil || !exists {
						t.Fatalf("read session: exists=%t err=%v", exists, err)
					}
					if _, err := c.cas(t.Context(), sessionKey("gru", "node-a"), next, revision); err != nil {
						t.Fatal(err)
					}
				}
			case "rotation":
				r, err := c.registration(t.Context(), "node-a")
				if err != nil {
					t.Fatal(err)
				}
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				r.Generation++
				r.PublicKey = base64.StdEncoding.EncodeToString(public)
				if _, err := c.Register(t.Context(), r); err != nil {
					t.Fatal(err)
				}
			}
			desired := signedHostRequest(t, hostKey, "desired", sessionID, initial.Epoch, struct {
				Role string `json:"role"`
			}{"terrabase"})
			if _, err := c.handleAuthorized(t.Context(), desired); err == nil || errors.Is(err, errSessionContention) {
				t.Fatalf("%s remained authorized or became transient: %v", change, err)
			}
			renew := signedHostRequest(t, hostKey, "session", sessionID, initial.Epoch, struct {
				Kind string `json:"kind"`
			}{"renew"})
			if _, err := c.handleSession(t.Context(), renew); err == nil || errors.Is(err, errSessionContention) {
				t.Fatalf("%s renewal remained live or became transient: %v", change, err)
			}
		})
	}
}

func TestAgentConvergesAndWithdrawalInvalidatesReadyReport(t *testing.T) {
	c, conn, store, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nsleep 30\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-controllerDone:
		t.Fatalf("host controller failed before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state"), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	awaitReport := func(state string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			hosts, err := c.ListHosts(t.Context())
			if err == nil && len(hosts) == 1 && len(hosts[0].Reports) == 1 && hosts[0].Reports[0].State == state {
				return
			}
			select {
			case err := <-agentDone:
				t.Fatalf("agent exited early: %v", err)
			default:
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("did not observe %s report", state)
	}
	awaitReport("running")
	changed := desired
	changed.Generation = 2
	changed.Args = []string{"--listen=127.0.0.1"}
	changed.Env = map[string]string{"TS_MODE": "test"}
	if _, err := c.ApplyDesired(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	reportedChanged := false
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		applied := runner.applied
		observed := runner.observed["terrabase"]
		runner.mu.Unlock()
		hosts, err := c.ListHosts(t.Context())
		if err == nil && applied == 2 && observed.Running && len(hosts) == 1 && len(hosts[0].Reports) == 1 && hosts[0].Reports[0].Generation == changed.Generation {
			reportedChanged = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 2 || !reportedChanged {
		t.Fatalf("same digest configuration applied %d times, reported=%t; want 2 applies and generation 2 report", applied, reportedChanged)
	}
	withdrawn := desired
	withdrawn.Generation = 3
	withdrawn.Withdrawn = true
	withdrawn.Digest = ""
	if _, err := c.ApplyDesired(t.Context(), withdrawn); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		hosts, err := c.ListHosts(t.Context())
		if err == nil {
			if len(hosts) != 1 {
				t.Fatalf("host count after withdrawal = %d", len(hosts))
			}
			for _, report := range hosts[0].Reports {
				if report.Generation != withdrawn.Generation || report.State == "running" {
					t.Fatalf("stale running report remained ready after withdrawal: %+v", report)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host status stayed contended after withdrawal: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	awaitReport("stopped")
	cancel()
	select {
	case <-agentDone:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop")
	}
	select {
	case <-controllerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop")
	}
}

func TestArtifactFetchRejectsWithdrawalAfterInitialRead(t *testing.T) {
	c, _, store, mutations, _ := testController(t)
	defer c.closeCache()
	registerTestHost(t, c)
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	for {
		_, _, err := c.readArtifactChunk(t.Context(), digest, 0, len(data))
		if err == nil {
			break
		}
		if !errors.Is(err, errArtifactPreparing) {
			t.Fatal(err)
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
	gate := &gatedDesiredRead{HostMutationStore: mutations, started: make(chan struct{}), release: make(chan struct{})}
	c.mutations = gate
	payload, err := json.Marshal(artifactQuery{Role: "terrabase", Digest: digest, Length: len(data)})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := c.serveArtifact(t.Context(), request{Node: "node-a", Payload: payload}, Registration{Roles: []string{"terrabase"}})
		result <- err
	}()
	select {
	case <-gate.started:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	withdrawn := desired
	withdrawn.Generation = 2
	withdrawn.Digest = ""
	withdrawn.Withdrawn = true
	if _, err := c.ApplyDesired(t.Context(), withdrawn); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	select {
	case err := <-result:
		if err == nil || err.Error() != "artifact target changed" {
			t.Fatalf("artifact request after withdrawal returned %v", err)
		}
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}

func TestOrderedHostMutationAndSignedNATSReply(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	authorityRuntime, err := authority.Start(t.Context(), js, authority.Config{Scope: "gru", CandidateID: "controller-a", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authorityRuntime.Close() })
	if !authorityRuntime.Current().CanMutate() {
		t.Fatal("R1 authority did not acquire lease")
	}
	store, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "HOST_ORDERED_ARTIFACTS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(t.Context(), ControllerConfig{
		Cell: "gru", Conn: conn, JS: js, Artifacts: store, ResponseKey: controllerKey,
		StateReplicas: 1, HostMutations: authorityRuntime,
		AuthorityEpoch: func() uint64 { return authorityRuntime.Current().Epoch },
		AuthorityGuard: authorityRuntime.Guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		Cell: "gru", Node: "node-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic), Generation: 1,
		ManagedOCI: &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..host-a", Owner: "terrascale", FleetGeneration: 4, CreateKey: "terrabase-host-a"},
	}
	registrationReceipt, err := c.Register(t.Context(), registration)
	if err != nil || registrationReceipt.Revision == 0 {
		t.Fatalf("commit managed registration: receipt=%+v err=%v", registrationReceipt, err)
	}
	committedRegistration, revision, exists, err := c.readRegistration(t.Context(), registration.Node)
	if err != nil || !exists || revision != registrationReceipt.Revision || !sameJSON(committedRegistration, registration) {
		t.Fatalf("managed registration round trip: value=%+v revision=%d exists=%t err=%v", committedRegistration, revision, exists, err)
	}
	changedRegistration := registration
	changedBinding := *registration.ManagedOCI
	changedBinding.InstanceID = "ocid1.instance.oc1..host-b"
	changedRegistration.ManagedOCI = &changedBinding
	if _, err := c.Register(t.Context(), changedRegistration); err == nil {
		t.Fatal("managed OCI instance changed within one registration generation")
	}
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: authorityRuntime.Current().Epoch}
	receipt, err := c.ApplyDesired(t.Context(), desired)
	if err != nil || receipt.Revision == 0 {
		t.Fatalf("commit desired: receipt=%+v err=%v", receipt, err)
	}
	allocations, err := c.ListDesired(t.Context(), "terrabase")
	if err != nil || len(allocations) != 1 || !sameJSON(allocations[0], desired) {
		t.Fatalf("committed allocations=%+v err=%v", allocations, err)
	}
	reader, err := NewReader(t.Context(), ReaderConfig{Cell: "gru", JS: js, StateReplicas: 1, HostMutations: authorityRuntime})
	if err != nil {
		t.Fatal(err)
	}
	readAllocations, err := reader.ListDesired(t.Context(), "")
	if err != nil || len(readAllocations) != 1 || !sameJSON(readAllocations[0], desired) {
		t.Fatalf("reader allocations=%+v err=%v", readAllocations, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatalf("host controller failed before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	requestID := "0123456789abcdef0123456789abcdef"
	makeSigned := func(operation string, epoch uint64, payload any) request {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := randomID()
		if err != nil {
			t.Fatal(err)
		}
		req := request{Version: 1, Node: "node-a", Operation: operation, SessionID: requestID, Epoch: epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: body}
		if err := signRequest(&req, hostKey, "gru"); err != nil {
			t.Fatal(err)
		}
		return req
	}
	var s session
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), makeSigned("session", 0, struct {
		Kind string `json:"kind"`
	}{"acquire"}), &s); err != nil {
		t.Fatal(err)
	}
	var reply desiredReply
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), makeSigned("desired", s.Epoch, struct {
		Role string `json:"role"`
	}{"terrabase"}), &reply); err != nil || reply.Desired == nil || !sameJSON(*reply.Desired, desired) || reply.Revision != receipt.Revision {
		t.Fatalf("signed desired reply=%+v err=%v", reply, err)
	}
	newPublic, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated := registration
	rotated.Generation = 2
	rotated.PublicKey = base64.StdEncoding.EncodeToString(newPublic)
	if _, err := c.Register(t.Context(), rotated); err != nil {
		t.Fatalf("rotate managed host key: %v", err)
	}
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), makeSigned("desired", s.Epoch, struct {
		Role string `json:"role"`
	}{"terrabase"}), &reply); err == nil {
		t.Fatal("old host key remained authorized after registration rotation")
	}
	acquire := makeSigned("session", 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	if err := signRequest(&acquire, newKey, "gru"); err != nil {
		t.Fatal(err)
	}
	var next session
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), acquire, &next); err != nil || next.RegistrationGeneration != rotated.Generation || next.Epoch <= s.Epoch {
		t.Fatalf("rotated key did not acquire a new session: session=%+v err=%v", next, err)
	}
	if err := authorityRuntime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: desired.Cell, Node: desired.Node, Environment: desired.Environment, Role: desired.Role, Generation: 2, AuthorityEpoch: desired.AuthorityEpoch, Withdrawn: true}); err == nil {
		t.Fatal("released authority committed desired")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("host controller did not stop")
	}
}

func testAgentIdentity() WorkloadIdentity {
	return WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}
