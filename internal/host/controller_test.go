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

	"github.com/TerraScale/ts-orchestrator/internal/authority"

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

type managedRegistrationVerifierFunc func(context.Context, Registration) error

func (verify managedRegistrationVerifierFunc) VerifyManagedRegistration(ctx context.Context, registration Registration) error {
	return verify(ctx, registration)
}

func fixtureManagedDesiredVerifier(_ context.Context, desired Desired, registration Registration,
	current Desired, currentExists bool,
) error {
	if desired.ManagedMember == nil || desired.Withdrawn {
		return nil
	}
	placement := registration.ManagedPlacement
	if registration.ManagedOCI == nil || registration.ManagedMember == nil || placement == nil ||
		desired.Cell != registration.Cell || desired.Node != registration.Node ||
		desired.Environment != registration.Environment || desired.AuthorityEpoch == 0 ||
		placement.DatabaseID == "" || placement.PartitionID == "" || placement.SeatID == "" ||
		placement.IntentGeneration == 0 || !lowerHex(placement.IntentPayloadDigest, 64) ||
		!lowerHex(placement.CanonicalRosterDigest, 64) || !lowerHex(placement.ManagedHostProfileDigest, 64) {
		return errors.New("test durable desired verifier requires current placement identity")
	}
	launch := desired.ManagedMember
	if launch.OCI != *registration.ManagedOCI || launch.Member != *registration.ManagedMember {
		return errors.New("test durable desired verifier rejected a retargeted host")
	}
	if currentExists && current.ManagedMember != nil &&
		(current.ManagedMember.OCI != launch.OCI || current.ManagedMember.Member != launch.Member ||
			desired.Generation <= current.Generation) {
		return errors.New("test durable desired verifier rejected a stale placement target")
	}
	return nil
}

type oneRegistrationConflict struct {
	authority.HostMutationStore
	conflict atomic.Bool
}

func (store *oneRegistrationConflict) CommitHostMutation(ctx context.Context, epoch uint64, kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte) (uint64, error) {
	if kind == authority.MutationRegistration && store.conflict.CompareAndSwap(true, false) {
		return 0, authority.ErrConflict
	}
	return store.HostMutationStore.CommitHostMutation(ctx, epoch, kind, subject, operation, expected, payload)
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

func (*memoryMutations) ReadBackupOperation(context.Context, string, string) (
	authority.BackupOperationRecord, uint64, error,
) {
	return authority.BackupOperationRecord{}, 0, authority.ErrNotFound
}

func (m *memoryMutations) CommitHostMutation(ctx context.Context, epoch uint64, kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(kind, subject)
	if m.entries[key].Sequence != expected {
		return 0, authority.ErrConflict
	}
	record, err := json.Marshal(struct {
		Version     int                        `json:"version"`
		Kind        authority.HostMutationKind `json:"kind"`
		Scope       string                     `json:"scope"`
		SubjectKey  string                     `json:"subject_key"`
		OperationID string                     `json:"operation_id"`
		Epoch       uint64                     `json:"epoch"`
		Payload     []byte                     `json:"payload"`
	}{1, kind, "gru", subject, operation, epoch, payload})
	if err != nil {
		return 0, err
	}
	ack, err := m.js.Publish(ctx, "ts.control.gru.host."+string(kind)+"."+subject, record)
	if err != nil {
		return 0, err
	}
	m.sequence = ack.Sequence
	m.entries[key] = authority.LogEntry{Kind: kind, SubjectKey: subject, OperationID: operation, Epoch: epoch, Sequence: m.sequence, Payload: append([]byte(nil), payload...)}
	return m.sequence, nil
}

type memoryRunner struct {
	mu        sync.Mutex
	observed  map[string]Observation
	applied   int
	memoryMax uint64 // the last applied workload's cgroup memory cap
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
	m.memoryMax = w.CgroupMemoryMaxBytes
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
	return testControllerWithVerifier(t, nil)
}

func testControllerWithVerifier(t *testing.T, verifier ManagedRegistrationVerifier, options ...func(*ControllerConfig)) (*Controller, *nats.Conn, jetstream.ObjectStore, *memoryMutations, ed25519.PrivateKey) {
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
	config := ControllerConfig{
		Cell: "gru", Conn: conn, JS: js, ControlLog: log, Artifacts: store, ResponseKey: controllerKey,
		StateReplicas: 1, HostMutations: verifiedMemoryMutations{memoryMutations: mutations},
		ManagedRegistrationVerifier: verifier, ManagedDesiredVerifier: fixtureManagedDesiredVerifier,
		ManagedEffectGate: func(_ context.Context, epoch uint64, scope authority.WorkloadScope) (func(), error) {
			if epoch == 0 || scope.DatabaseID == "" || scope.PartitionID == "" {
				return nil, errors.New("test terminal effect gate requires a scoped placement")
			}
			return func() {}, nil
		},
		AuthorityEpoch: func() uint64 { return 1 }, AuthorityGuard: func(context.Context, uint64) error { return nil },
	}
	for _, option := range options {
		option(&config)
	}
	c, err := NewController(t.Context(), config)
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
	_, err = c.Register(t.Context(), Registration{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func TestHostSessionRejectsReplayAndForeignIdentity(t *testing.T) {
	c, _, _, _, _ := testController(t)
	key := registerTestHost(t, c)
	id := "014D2PF2DBSQQG28T5CY4TQKFF"
	nonce := "abcdef0123456789abcdef0123456789"
	makeAcquire := func(issued time.Time) request {
		r := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: "session", SessionID: id, Nonce: nonce, IssuedAt: issued, Payload: []byte(`{"kind":"acquire"}`)}
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
	renew := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: "session", SessionID: id, Epoch: 99, Nonce: "11111111111111111111111111111111", IssuedAt: time.Now().UTC(), Payload: []byte(`{"kind":"renew"}`)}
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
	nonce, err := randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	r := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: operation, SessionID: sessionID, Epoch: epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: data}
	if err := signRequest(&r, key, "gru"); err != nil {
		t.Fatal(err)
	}
	return r
}

func reportedTestHost(t *testing.T) (*Controller, ed25519.PrivateKey, session, Report) {
	t.Helper()
	c, _, store, _, _ := testController(t)
	hostKey := registerTestHost(t, c)
	sessionID := "014D2PF2DBSQQG28T5CY4TQKFF"
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

func TestOnlyTheAuthorityLeaderServesHostRequests(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	var leader atomic.Bool
	c.authorityLeader = leader.Load
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	<-c.Ready()
	acquire := func() error {
		r := signedHostRequest(t, hostKey, "session", "014D2PF2DBSQQG28T5CY4TQKFF", 0, struct {
			Kind string `json:"kind"`
		}{"acquire"})
		attempt, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		return exchange(attempt, conn, "gru", controllerKey.Public().(ed25519.PublicKey), r, nil)
	}
	if err := acquire(); !errors.Is(err, nats.ErrNoResponders) {
		t.Fatalf("follower served a host request: %v", err)
	}
	leader.Store(true)
	deadline := time.Now().Add(5 * hostLeaderPoll)
	for err := acquire(); err != nil; err = acquire() {
		if time.Now().After(deadline) {
			t.Fatalf("new leader did not serve host requests: %v", err)
		}
		time.Sleep(hostLeaderPoll / 5)
	}
	cancel()
	<-done
}

func TestAgentConvergesAndWithdrawalInvalidatesReadyReport(t *testing.T) {
	const convergenceTimeout = 15 * time.Second

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
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	awaitReport := func(state string) {
		t.Helper()
		deadline := time.Now().Add(convergenceTimeout)
		var lastErr error
		var hostCount, reportCount int
		var reportState string
		for time.Now().Before(deadline) {
			hosts, err := c.ListHosts(t.Context())
			if err == nil && len(hosts) == 1 && len(hosts[0].Reports) == 1 && hosts[0].Reports[0].State == state {
				return
			}
			lastErr = err
			hostCount = len(hosts)
			reportCount, reportState = 0, ""
			if len(hosts) == 1 {
				reportCount = len(hosts[0].Reports)
				if reportCount == 1 {
					reportState = hosts[0].Reports[0].State
				}
			}
			select {
			case err := <-agentDone:
				t.Fatalf("agent exited early: %v", err)
			default:
			}
			time.Sleep(25 * time.Millisecond)
		}
		runner.mu.Lock()
		applied := runner.applied
		observed := runner.observed["terrabase"]
		runner.mu.Unlock()
		t.Fatalf("did not observe %s report: hosts=%d reports=%d last_state=%q list_error=%v applies=%d observed=%+v",
			state, hostCount, reportCount, reportState, lastErr, applied, observed)
	}
	awaitReport("running")
	changed := desired
	changed.Generation = 2
	changed.Args = []string{"--listen=127.0.0.1"}
	changed.Env = map[string]string{"TS_MODE": "test"}
	if _, err := c.ApplyDesired(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(convergenceTimeout)
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
	deadline = time.Now().Add(convergenceTimeout)
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

// cycleConflictState fails the next cycle-record writes with a CAS
// conflict, as a concurrent writer would.
type cycleConflictState struct {
	jetstream.KeyValue
	conflicts atomic.Int32
}

func (s *cycleConflictState) conflict(key string) bool {
	return strings.HasPrefix(key, "cycle.") && s.conflicts.Add(-1) >= 0
}

func (s *cycleConflictState) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	if s.conflict(key) {
		return 0, jetstream.ErrKeyExists
	}
	return s.KeyValue.Create(ctx, key, value, opts...)
}

func (s *cycleConflictState) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if s.conflict(key) {
		return 0, jetstream.ErrKeyRevisionMismatch
	}
	return s.KeyValue.Update(ctx, key, value, revision)
}

func testAgentIdentity() WorkloadIdentity {
	if os.Geteuid() == 0 {
		return WorkloadIdentity{UID: 65534, GID: 65534}
	}
	return WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

func testAgentInstallParent(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "ts-host-install-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test install parent: %v", err)
		}
	})
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return parent
}

func testAgentInstallRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(testAgentInstallParent(t), "install")
}

func testAgentStateRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return filepath.Join(t.TempDir(), "state")
	}
	parent, err := os.MkdirTemp("/var/lib", "ts-host-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test state parent: %v", err)
		}
	})
	return filepath.Join(parent, "state")
}
