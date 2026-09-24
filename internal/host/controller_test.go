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

type stalledArtifactStore struct {
	ArtifactStore
	started chan struct{}
	once    sync.Once
}

func (s *stalledArtifactStore) Get(ctx context.Context, _ string, _ ...jetstream.GetObjectOpt) (jetstream.ObjectResult, error) {
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
	for _, err := range []error{context.DeadlineExceeded, nats.ErrTimeout, nats.ErrNoResponders, nats.ErrDisconnected} {
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
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: oldKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state")})
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
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: install, StateRoot: state})
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
	runner := &stoppedRunner{memoryRunner: &memoryRunner{observed: make(map[string]Observation)}, stopped: make(chan struct{})}
	if err := runner.Apply(t.Context(), Workload{Role: "terrabase", Digest: oldDigest, Fingerprint: oldDigest}); err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state"), PollInterval: 100 * time.Millisecond})
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
	case <-runner.stopped:
		if !time.Now().Before(leaseExpiry) {
			t.Fatal("active workload stopped after signed lease expiry")
		}
	case <-deadline.C:
		t.Fatal("pending-cycle cleanup kept active workload alive through signed lease expiry")
	}
	select {
	case err := <-agentDone:
		if err == nil {
			t.Fatal("agent exited without session-loss error")
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
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: filepath.Join(t.TempDir(), "install"), StateRoot: filepath.Join(t.TempDir(), "state"), PollInterval: 100 * time.Millisecond})
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
