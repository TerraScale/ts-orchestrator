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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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

func TestManagedOCIBindingValidation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := Registration{
		Cell: "gru", Node: "host-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey("host-a"), Generation: 1,
		ManagedPlacement: &ManagedPlacementBinding{
			DatabaseID: "db-main", PartitionID: "partition-a", SeatID: "permanent-a", IntentGeneration: 7,
			IntentPayloadDigest: strings.Repeat("c", 64), CanonicalRosterDigest: strings.Repeat("d", 64),
			ManagedHostProfileDigest: strings.Repeat("e", 64),
		},
		ManagedOCI:         &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..host-a", Owner: "terrascale", FleetGeneration: 4, CreateKey: "host-a"},
		ManagedMember:      &ManagedMemberBinding{Scope: MemberScope{ClusterID: strings.Repeat("a", 32), TenantID: "018f0000-0000-7000-8000-000000000001", DatabaseID: "018f0000-0000-7000-8000-000000000001", ShardID: 1, MemberID: "018f0000-0000-7000-8000-000000000001", Incarnation: strings.Repeat("b", 32)}, HostAttempt: 1},
		SystemReserveBytes: 1 << 30, Capacity: Capacity{MemoryBytes: 8 << 30},
	}
	tests := []struct {
		name    string
		change  func(*Registration)
		wantErr bool
	}{
		{name: "complete managed binding"},
		{name: "ordinary host without binding", change: func(r *Registration) {
			r.ManagedOCI = nil
			r.ManagedPlacement = nil
			r.ManagedMember = nil
			r.SystemReserveBytes = 0
			r.FailureDomain = "fd-a"
		}},
		{name: "unmanaged OCI fault domain", change: func(r *Registration) { r.ManagedOCI = nil }, wantErr: true},
		{name: "missing member", change: func(r *Registration) { r.ManagedMember = nil }, wantErr: true},
		{name: "mixed roles", change: func(r *Registration) { r.Roles = []string{"terrabase", "other"} }, wantErr: true},
		{name: "zero shard", change: func(r *Registration) { r.ManagedMember.Scope.ShardID = 0 }, wantErr: true},
		{name: "zero host attempt", change: func(r *Registration) { r.ManagedMember.HostAttempt = 0 }, wantErr: true},
		{name: "reserve absent", change: func(r *Registration) { r.SystemReserveBytes = 0 }, wantErr: true},
		{name: "capacity absent", change: func(r *Registration) { r.Capacity.MemoryBytes = 0 }, wantErr: true},
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
			member := *valid.ManagedMember
			registration.ManagedMember = &member
			placement := *valid.ManagedPlacement
			registration.ManagedPlacement = &placement
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

func TestManagedRegistrationRequiresCurrentVerifierAndRechecksRetries(t *testing.T) {
	newRegistration := func(t *testing.T) Registration {
		t.Helper()
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return Registration{
			Cell: "gru", Node: "managed-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
			Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey("managed-a"), Generation: 1,
			ManagedPlacement: &ManagedPlacementBinding{
				DatabaseID: "db-main", PartitionID: "partition-a", SeatID: "permanent-a", IntentGeneration: 7,
				IntentPayloadDigest: strings.Repeat("c", 64), CanonicalRosterDigest: strings.Repeat("d", 64),
				ManagedHostProfileDigest: strings.Repeat("e", 64),
			},
			ManagedOCI: &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..managed-a", Owner: "terrascale", FleetGeneration: 4, CreateKey: "managed-a"},
			ManagedMember: &ManagedMemberBinding{Scope: MemberScope{
				ClusterID: strings.Repeat("a", 32), TenantID: "018f0000-0000-7000-8000-000000000001",
				DatabaseID: "018f0000-0000-7000-8000-000000000001", ShardID: 1,
				MemberID: "018f0000-0000-7000-8000-000000000001", Incarnation: strings.Repeat("b", 32),
			}, HostAttempt: 1},
			SystemReserveBytes: 1 << 30, Capacity: Capacity{MemoryBytes: 5 << 30},
		}
	}

	t.Run("missing verifier fails closed", func(t *testing.T) {
		controller, _, _, mutations, _ := testController(t)
		unbound := newRegistration(t)
		unbound.ManagedPlacement = nil
		if _, err := controller.Register(t.Context(), unbound); err == nil {
			t.Fatal("managed registration without schema-3 pins was accepted")
		}
		if _, err := controller.Register(t.Context(), newRegistration(t)); err == nil {
			t.Fatal("managed registration succeeded without an injected verifier")
		}
		if _, err := mutations.ReadHostMutation(t.Context(), authority.MutationRegistration, "gru.managed-a"); !errors.Is(err, authority.ErrNotFound) {
			t.Fatalf("missing verifier committed registration: err=%v", err)
		}
	})

	t.Run("idempotent replay and CAS retry revalidate", func(t *testing.T) {
		var calls atomic.Int32
		controller, _, _, mutations, _ := testControllerWithVerifier(t, managedRegistrationVerifierFunc(func(context.Context, Registration) error {
			calls.Add(1)
			return nil
		}))
		managed := newRegistration(t)
		if _, err := controller.Register(t.Context(), managed); err != nil {
			t.Fatalf("initial managed registration: %v", err)
		}
		if _, err := controller.Register(t.Context(), managed); err != nil {
			t.Fatalf("idempotent managed registration replay: %v", err)
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("verifier calls after registration and replay = %d, want 2", got)
		}

		managed.Node = "managed-retry"
		managed.ManagedOCI.InstanceID = "ocid1.instance.oc1..managed-retry"
		managed.ManagedOCI.CreateKey = "managed-retry"
		managed.ManagedMember.Scope.MemberID = "018f0000-0000-7000-8000-000000000002"
		conflict := &oneRegistrationConflict{HostMutationStore: mutations}
		conflict.conflict.Store(true)
		controller.mutations = conflict
		var retryCalls atomic.Int32
		controller.managedVerifier = managedRegistrationVerifierFunc(func(context.Context, Registration) error {
			if retryCalls.Add(1) == 2 {
				return errors.New("placement changed during CAS retry")
			}
			return nil
		})
		if _, err := controller.Register(t.Context(), managed); err == nil || !strings.Contains(err.Error(), "placement changed during CAS retry") {
			t.Fatalf("CAS retry did not revalidate: err=%v", err)
		}
		if got := retryCalls.Load(); got != 2 {
			t.Fatalf("verifier calls across CAS conflict = %d, want 2", got)
		}
	})
}

func TestSessionRetryClassificationAndReserve(t *testing.T) {
	clusterUnavailable := &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
	for _, err := range []error{context.DeadlineExceeded, nats.ErrTimeout, nats.ErrNoResponders, nats.ErrDisconnected, jetstream.ErrNoStreamResponse, errSessionBackendUnavailable, clusterUnavailable,
		&jetstream.APIError{Code: 503, ErrorCode: 10008}} {
		if !retrySessionExchange(err) {
			t.Fatalf("transient session error was terminal: %v", err)
		}
	}
	for _, err := range []error{errSessionOwned, errSessionRequestDenied, errors.New("renewed session binding mismatch"), nats.ErrConnectionClosed,
		&nats.APIError{Code: 403, ErrorCode: 10008}, &nats.APIError{Code: 503, ErrorCode: 10076},
		&jetstream.APIError{Code: 403, ErrorCode: 10008}, &jetstream.APIError{Code: 503, ErrorCode: jetstream.JSErrCodeJetStreamNotEnabled}} {
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
		{"legacy JetStream cluster temporarily unavailable", &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}},
		{"modern JetStream cluster temporarily unavailable", &jetstream.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}},
	} {
		t.Run(test.name, func(t *testing.T) { testSignedTransientSessionBackend(t, test.err) })
	}
}

func testSignedTransientSessionBackend(t *testing.T, backendErr error) {
	c, conn, _, _, controllerKey := testController(t)
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
	agent, err := NewAgent(AgentConfig{
		NATSUserPublicKey:   testNATSUserKey("node-a"),
		ClockCheck:          func() error { return nil },
		WorkloadIdentity:    testAgentIdentity(),
		Cell:                "gru",
		Node:                "node-a",
		Environment:         "production",
		Roles:               []string{"terrabase"},
		Conn:                conn,
		Identity:            hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		Runner:              &memoryRunner{observed: make(map[string]Observation)},
		InstallRoot:         testAgentInstallRoot(t),
		StateRoot:           testAgentStateRoot(t),
	})
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
	rotated, _, exists, err := c.readRegistration(t.Context(), "node-a")
	if err != nil || !exists {
		t.Fatalf("read registration before key rotation: exists=%t err=%v", exists, err)
	}
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated.Generation++
	rotated.PublicKey = base64.StdEncoding.EncodeToString(newPublic)
	if _, err := c.Register(t.Context(), rotated); err != nil {
		t.Fatalf("retire previous host key: %v", err)
	}
	if err := agent.acquire(t.Context()); !errors.Is(err, errSessionRequestDenied) || retrySessionExchange(err) {
		t.Fatalf("signed retired-key denial became retryable: %v", err)
	}
	stopController()
	<-controllerDone
}

func TestMissingHostRegistrationGetsNoSignedReply(t *testing.T) {
	c, conn, _, mutations, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(controllerCtx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	agent, err := NewAgent(AgentConfig{
		NATSUserPublicKey:   testNATSUserKey("node-a"),
		ClockCheck:          func() error { return nil },
		WorkloadIdentity:    testAgentIdentity(),
		Cell:                "gru",
		Node:                "node-a",
		Environment:         "production",
		Roles:               []string{"terrabase"},
		Conn:                conn,
		Identity:            hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		Runner:              &memoryRunner{observed: make(map[string]Observation)},
		InstallRoot:         testAgentInstallRoot(t),
		StateRoot:           testAgentStateRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatalf("acquire before registration removal: %v", err)
	}
	mutations.mu.Lock()
	delete(mutations.entries, mutations.key(authority.MutationRegistration, registrationSubjectKey("gru", "node-a")))
	mutations.mu.Unlock()
	requestCtx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	if err := agent.acquire(requestCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing registration received a signed reply: %v", err)
	}
	stopController()
	<-controllerDone
}

func TestSignedJetStreamUnavailableStopsAtExecutionReserve(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	backendErr := &nats.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream system temporarily unavailable"}
	read := c.readLeaderSession
	var unavailable atomic.Bool
	var failures atomic.Int32
	c.sessionRead = func(ctx context.Context, key string) (session, uint64, bool, error) {
		if unavailable.Load() {
			failures.Add(1)
			return session{}, 0, false, backendErr
		}
		return read(ctx, key)
	}
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(controllerCtx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	key := sessionKey("gru", "node-a")
	stored, revision, exists, err := read(t.Context(), key)
	if err != nil || !exists {
		t.Fatalf("read acquired session: exists=%t err=%v", exists, err)
	}
	agent.mu.RLock()
	short := agent.session
	agent.mu.RUnlock()
	short.ExpiresAt = time.Now().Add(9 * time.Second)
	if err := agent.acceptSession(short); err != nil {
		t.Fatal(err)
	}
	agent.mu.RLock()
	safeUntil := agent.sessionSafeUntil
	agent.mu.RUnlock()
	unavailable.Store(true)
	monitorCtx, stopMonitor := context.WithCancel(t.Context())
	defer stopMonitor()
	lost := make(chan error, 1)
	go agent.maintainSession(monitorCtx, stopMonitor, lost)
	select {
	case err := <-lost:
		t.Fatalf("temporary backend loss stopped a usable signed session: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if _, _, err := agent.executionLease(); err != nil {
		t.Fatalf("usable signed session was lost before its reserve: %v", err)
	}
	select {
	case err := <-lost:
		if !errors.Is(err, errSessionExecutionReserve) || !agent.sessionLost.Load() || time.Now().Before(safeUntil) {
			t.Fatalf("backend outage did not stop at signed execution reserve: err=%v lost=%t safe_until=%s", err, agent.sessionLost.Load(), safeUntil)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend outage continued beyond signed execution reserve")
	}
	if failures.Load() == 0 {
		t.Fatal("controller did not return a signed temporary backend failure")
	}
	current, currentRevision, exists, err := read(t.Context(), key)
	if err != nil || !exists || currentRevision != revision || !sameJSON(current, stored) {
		t.Fatalf("failed renewals changed the stored session: exists=%t err=%v revision=%d -> %d", exists, err, revision, currentRevision)
	}
	stopController()
	<-controllerDone
}

func TestStartupWaitsForOldSessionAndCancellation(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	oldKey := registerTestHost(t, c)
	acquire := func(key ed25519.PrivateKey, id string) request {
		t.Helper()
		req := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: "session", SessionID: id, Nonce: "abcdef0123456789abcdef0123456789", IssuedAt: time.Now().UTC(), Payload: []byte(`{"kind":"acquire"}`)}
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
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: oldKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
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
	install := testAgentInstallRoot(t)
	state := testAgentStateRoot(t)
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: install, StateRoot: state})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	agent.mu.Lock()
	lease := agent.session
	lease.ExpiresAt = time.Now().Add(7 * time.Second)
	agent.mu.Unlock()
	if err := agent.acceptSession(lease); err != nil {
		t.Fatal(err)
	}
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
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t), PollInterval: 100 * time.Millisecond})
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
	agent.mu.Unlock()
	if err := agent.acceptSession(s); err != nil {
		t.Fatal(err)
	}
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
	nonce, err := randomID()
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

// A single-OCPU host reports once per reconcile, so a report older than one
// poll interval is still current until ReportMaxAge.
func TestListHostsKeepsSlowReconcileReportsUntilReportMaxAge(t *testing.T) {
	for _, test := range []struct {
		age  time.Duration
		kept bool
	}{{45 * time.Second, true}, {ReportMaxAge + 5*time.Second, false}} {
		c, _, _, report := reportedTestHost(t)
		key := reportKey(c.cell, report.Node, report.Role)
		_, revision, _, err := c.reportSnapshot(t.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		report.ObservedAt = time.Now().UTC().Add(-test.age)
		if _, err := c.cas(t.Context(), key, report, revision); err != nil {
			t.Fatal(err)
		}
		hosts, err := c.ListHosts(t.Context())
		if err != nil || len(hosts) != 1 || (len(hosts[0].Reports) == 1) != test.kept {
			t.Fatalf("report aged %s: hosts=%+v err=%v, want kept=%t", test.age, hosts, err, test.kept)
		}
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
		r := signedHostRequest(t, hostKey, "session", "0123456789abcdef0123456789abcdef", 0, struct {
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

func TestAgentResendsRequestsDeniedByAFollowerController(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	// The queue group first delivers to followers, which deny the request.
	denials := 2
	sub, err := conn.Subscribe("ts.orch.v1.gru.agent.*.observation.session", func(msg *nats.Msg) {
		if denials == 0 {
			c.handle(t.Context(), msg)
			return
		}
		denials--
		var envelope protocol.Envelope
		var req request
		if protocol.DecodeStrict(msg.Data, &envelope, 64<<10) != nil ||
			protocol.DecodeStrict([]byte(envelope.Payload), &req, 64<<10) != nil {
			return
		}
		data, _ := protocol.EncodeJSON(response{Nonce: req.Nonce, Node: req.Node, SessionID: req.SessionID,
			Epoch: req.Epoch, Operation: req.Operation, Error: authority.ErrNotLeader.Error()})
		issued := time.Now().UTC()
		signed, _ := protocol.SignEnvelope(data, protocol.EnvelopeScope{Region: "gru", Kind: "host.response." + req.Operation,
			Actor: "controller", OperationID: req.Nonce, Epoch: req.Epoch}, issued, issued.Add(requestTTL), controllerKey)
		wire, _ := protocol.EncodeJSON(signed)
		_ = msg.Respond(wire)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil || denials != 0 {
		t.Fatalf("session acquire did not reach the leader after follower denials: %v (denials left %d)", err, denials)
	}
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
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
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
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t), PollInterval: time.Hour})
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

// TestRestartGateHoldsTheRunningWorkload checks that a cycle the restart
// gate does not grant leaves the running workload alone while the host
// reports it waiting at the new generation, and that the granted cycle then
// replaces it. A failing gate grants nothing, and a grant is asked for once
// per cycle: the host's revalidation before launch does not ask again.
func TestRestartGateHoldsTheRunningWorkload(t *testing.T) {
	var permitted atomic.Uint64
	var gateErr, oneGrant atomic.Bool
	var asked atomic.Int64
	permitted.Store(1)
	c, conn, store, _, controllerKey := testControllerWithVerifier(t, nil, func(config *ControllerConfig) {
		config.RestartGate = func(_ context.Context, node string, desired Desired) (bool, error) {
			asked.Add(1)
			if node != "node-a" || desired.Role != "terrabase" {
				return false, errors.New("gate asked about another seat: " + node + "/" + desired.Role)
			}
			if gateErr.Load() {
				return false, errors.New("seat state unavailable")
			}
			return desired.Generation <= permitted.Load() || oneGrant.CompareAndSwap(true, false), nil
		}
	})
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
	}
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t),
		StateRoot: testAgentStateRoot(t), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx) }()
	await := func(what string, done func(report Report, applied int, running bool) bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		var last Report
		for time.Now().Before(deadline) {
			runner.mu.Lock()
			applied, running := runner.applied, runner.observed["terrabase"].Running
			runner.mu.Unlock()
			hosts, err := c.ListHosts(t.Context())
			if err == nil && len(hosts) == 1 && len(hosts[0].Reports) == 1 {
				last = hosts[0].Reports[0]
				if done(last, applied, running) {
					return
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("%s: last report %+v", what, last)
	}
	await("first launch", func(r Report, applied int, _ bool) bool {
		return r.Generation == 1 && r.State == "running" && applied == 1
	})

	changed := desired
	changed.Generation = 2
	changed.Env = map[string]string{"TS_MODE": "test"}
	if _, err := c.ApplyDesired(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	await("held restart", func(r Report, applied int, running bool) bool {
		return r.Generation == 2 && r.State == "waiting" && applied == 1 && running
	})
	gateErr.Store(true)
	before := asked.Load()
	await("failing gate", func(_ Report, applied int, running bool) bool {
		return asked.Load() > before+2 && applied == 1 && running
	})
	gateErr.Store(false)
	runner.mu.Lock()
	if runner.applied != 1 {
		runner.mu.Unlock()
		t.Fatal("a held or failing gate restarted the workload")
	}
	runner.mu.Unlock()

	oneGrant.Store(true)
	await("granted restart", func(r Report, applied int, running bool) bool {
		return r.Generation == 2 && r.State == "running" && applied == 2 && running
	})
}

// TestRestartHoldKeepsTheRunningWorkload checks that a role's host-local
// hold file keeps its running workload on its generation, reported waiting
// at the new one without asking the controller for a cycle, that another
// role's hold does not, and that removing it restarts the workload into the
// new generation (TS-578).
func TestRestartHoldKeepsTheRunningWorkload(t *testing.T) {
	c, conn, store, _, controllerKey := testControllerWithVerifier(t, nil)
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
	go func() { _ = c.Run(ctx) }()
	<-c.Ready()
	runner := &memoryRunner{observed: make(map[string]Observation)}
	stateRoot := testAgentStateRoot(t)
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t),
		StateRoot: stateRoot, PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx) }()
	await := func(what string, done func(report Report, applied int, running bool) bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		var last Report
		for time.Now().Before(deadline) {
			runner.mu.Lock()
			applied, running := runner.applied, runner.observed["terrabase"].Running
			runner.mu.Unlock()
			hosts, err := c.ListHosts(t.Context())
			if err == nil && len(hosts) == 1 && len(hosts[0].Reports) == 1 {
				last = hosts[0].Reports[0]
				if done(last, applied, running) {
					return
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("%s: last report %+v", what, last)
	}
	await("first launch", func(r Report, applied int, _ bool) bool {
		return r.Generation == 1 && r.State == "running" && applied == 1
	})
	hold := filepath.Join(stateRoot, "terrabase"+RestartHoldSuffix)
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "ts-auth"+RestartHoldSuffix), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := desired
	changed.Generation = 2
	changed.Env = map[string]string{"TS_MODE": "other"}
	if _, err := c.ApplyDesired(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	await("restart beside another role's hold", func(r Report, applied int, running bool) bool {
		return r.Generation == 2 && r.State == "running" && applied == 2 && running
	})
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	changed.Generation = 3
	changed.Env = map[string]string{"TS_MODE": "test"}
	if _, err := c.ApplyDesired(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	await("held restart", func(r Report, applied int, running bool) bool {
		return r.Generation == 3 && r.State == "waiting" && applied == 2 && running
	})
	time.Sleep(500 * time.Millisecond)
	runner.mu.Lock()
	if runner.applied != 2 {
		runner.mu.Unlock()
		t.Fatal("a held workload restarted")
	}
	runner.mu.Unlock()
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	await("released restart", func(r Report, applied int, running bool) bool {
		return r.Generation == 3 && r.State == "running" && applied == 3 && running
	})
}

// TestRoleMemoryCapReachesTheRunner checks that a host's role memory cap
// (host.json role_memory_max_bytes) is the cgroup memory.max the runner
// starts the role with, and that a cap for a role the host does not run is
// refused (TS-578).
func TestRoleMemoryCapReachesTheRunner(t *testing.T) {
	c, conn, store, _, controllerKey := testControllerWithVerifier(t, nil)
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nsleep 30\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase",
		Digest: digest, Generation: 1, AuthorityEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	<-c.Ready()
	runner := &memoryRunner{observed: make(map[string]Observation)}
	config := AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t),
		StateRoot: testAgentStateRoot(t), PollInterval: 100 * time.Millisecond,
		RoleMemoryMaxBytes: map[string]uint64{"ts-auth": 1 << 30}}
	if _, err := NewAgent(config); err == nil {
		t.Fatal("agent accepted a memory cap for a role it does not run")
	}
	config.RoleMemoryMaxBytes = map[string]uint64{"terrabase": 3 << 30}
	agent, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		runner.mu.Lock()
		applied, memoryMax := runner.applied, runner.memoryMax
		runner.mu.Unlock()
		if applied == 1 {
			if memoryMax != 3<<30 {
				t.Fatalf("workload memory cap = %d", memoryMax)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("workload never started")
		}
		time.Sleep(25 * time.Millisecond)
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

// TestRestartGateNeverHoldsAManagedMember checks that a managed member's
// cycle is never put to the restart gate: the managed path stops the
// workload before it asks, so a hold there would be an outage. The same
// gate holds a static member's cycle.
func TestRestartGateNeverHoldsAManagedMember(t *testing.T) {
	var asked atomic.Int64
	var oneGrant atomic.Bool
	c, conn, store, mutations, controllerKey := testControllerWithVerifier(t, nil, func(config *ControllerConfig) {
		config.RestartGate = func(context.Context, string, Desired) (bool, error) {
			asked.Add(1)
			return oneGrant.CompareAndSwap(true, false), nil
		}
	})
	hostKey := registerTestHost(t, c)
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
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
	}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"}, Conn: conn, Identity: hostKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: &memoryRunner{observed: make(map[string]Observation)},
		InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	key := desiredSubjectKey("gru", "node-a", "terrabase")
	cycle := func(generation uint64, managed bool) cycleReply {
		t.Helper()
		d := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: generation, AuthorityEpoch: 1}
		if managed {
			// The cycle only reads the binding's presence; the launch is
			// checked where the host runs it.
			d.ManagedMember = &ManagedMemberLaunch{}
		}
		payload, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := mutations.ReadHostMutation(t.Context(), authority.MutationDesired, key)
		if _, err := mutations.CommitHostMutation(t.Context(), 1, authority.MutationDesired, key, "op-"+strconv.FormatUint(generation, 10), current.Sequence, payload); err != nil {
			t.Fatal(err)
		}
		attempt, err := randomID()
		if err != nil {
			t.Fatal(err)
		}
		var reply cycleReply
		if err := agent.request(t.Context(), "cycle", cycleQuery{Role: "terrabase", Digest: digest, Generation: generation, AuthorityEpoch: 1, Attempt: attempt}, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if reply := cycle(1, true); reply.State != "active" || asked.Load() != 0 {
		t.Fatalf("managed member: %+v, gate asked %d times", reply, asked.Load())
	}
	if reply := cycle(2, false); reply.State != "held" || asked.Load() != 1 {
		t.Fatalf("static member: %+v, gate asked %d times", reply, asked.Load())
	}
	// A grant survives a CAS retry: the request asks the gate once.
	conflicting := &cycleConflictState{KeyValue: c.state}
	conflicting.conflicts.Store(1)
	c.state = conflicting
	oneGrant.Store(true)
	if reply := cycle(3, false); reply.State != "active" || asked.Load() != 2 {
		t.Fatalf("granted cycle after a CAS conflict: %+v, gate asked %d times", reply, asked.Load())
	}
	cancel()
	<-done
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
		ManagedRegistrationVerifier: managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }),
		ManagedDesiredVerifier:      func(context.Context, Desired, Registration, Desired, bool) error { return nil },
		AuthorityEpoch:              func() uint64 { return authorityRuntime.Current().Epoch },
		AuthorityGuard:              authorityRuntime.Guard,
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
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1,
		ManagedPlacement: &ManagedPlacementBinding{
			DatabaseID: "db-main", PartitionID: "partition-a", SeatID: "permanent-a", IntentGeneration: 7,
			IntentPayloadDigest: strings.Repeat("c", 64), CanonicalRosterDigest: strings.Repeat("d", 64),
			ManagedHostProfileDigest: strings.Repeat("e", 64),
		},
		ManagedOCI:         &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..host-a", Owner: "terrascale", FleetGeneration: 4, CreateKey: "terrabase-host-a"},
		ManagedMember:      &ManagedMemberBinding{Scope: MemberScope{ClusterID: strings.Repeat("a", 32), TenantID: "018f0000-0000-7000-8000-000000000001", DatabaseID: "018f0000-0000-7000-8000-000000000001", ShardID: 1, MemberID: "018f0000-0000-7000-8000-000000000001", Incarnation: strings.Repeat("b", 32)}, HostAttempt: 1},
		SystemReserveBytes: 1 << 30, Capacity: Capacity{MemoryBytes: 8 << 30},
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
	changedRegistration.Generation = 2
	if _, err := c.Register(t.Context(), changedRegistration); err == nil {
		t.Fatal("managed OCI instance retargeted at a higher generation")
	}
	generic := Registration{Cell: "gru", Node: "node-e", Environment: "production", Roles: []string{"other"},
		PublicKey: registration.PublicKey, NATSUserPublicKey: testNATSUserKey("node-e"), Generation: 1}
	if _, err := c.Register(t.Context(), generic); err != nil {
		t.Fatalf("register generic host: %v", err)
	}
	converted := registration
	converted.Node = generic.Node
	converted.Generation = 2
	convertedOCI := *registration.ManagedOCI
	convertedOCI.InstanceID = "ocid1.instance.oc1..node-e"
	converted.ManagedOCI = &convertedOCI
	convertedMember := *registration.ManagedMember
	convertedMember.Scope.MemberID = "018f0000-0000-7000-8000-000000000003"
	converted.ManagedMember = &convertedMember
	if _, err := c.Register(t.Context(), converted); err == nil {
		t.Fatal("generic registration converted to managed")
	}
	downgraded := registration
	downgraded.Generation = 2
	downgraded.FailureDomain = "fd-a"
	downgraded.ManagedOCI = nil
	downgraded.ManagedMember = nil
	downgraded.SystemReserveBytes = 0
	if _, err := c.Register(t.Context(), downgraded); err == nil {
		t.Fatal("managed registration converted to generic")
	}
	results := make(chan error, 2)
	var registrations sync.WaitGroup
	for _, node := range []string{"node-b", "node-c"} {
		candidate := registration
		candidate.Node = node
		binding := *registration.ManagedOCI
		binding.InstanceID = "ocid1.instance.oc1.." + node
		candidate.ManagedOCI = &binding
		member := *registration.ManagedMember
		member.Scope.MemberID = "018f0000-0000-7000-8000-000000000002"
		candidate.ManagedMember = &member
		registrations.Go(func() { _, err := c.Register(t.Context(), candidate); results <- err })
	}
	registrations.Wait()
	close(results)
	var admitted int
	for err := range results {
		if err == nil {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("same managed member admitted to %d concurrent hosts", admitted)
	}
	newIncarnation := registration
	newIncarnation.Node = "node-d"
	newIncarnationOCI := *registration.ManagedOCI
	newIncarnationOCI.InstanceID = "ocid1.instance.oc1..node-d"
	newIncarnation.ManagedOCI = &newIncarnationOCI
	newIncarnationMember := *registration.ManagedMember
	newIncarnationMember.Scope.MemberID = "018f0000-0000-7000-8000-000000000002"
	newIncarnationMember.Scope.Incarnation = strings.Repeat("c", 32)
	newIncarnation.ManagedMember = &newIncarnationMember
	if _, err := c.Register(t.Context(), newIncarnation); err == nil {
		t.Fatal("another incarnation of the bound logical member was admitted")
	}
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest, Generation: 1, AuthorityEpoch: authorityRuntime.Current().Epoch,
		ManagedMember: &ManagedMemberLaunch{OCI: *registration.ManagedOCI, Member: *registration.ManagedMember,
			Authority:    MemberAuthority{Epoch: authorityRuntime.Current().Epoch, ConfigurationID: strings.Repeat("c", 64), CertificateSHA256: strings.Repeat("d", 64), TLSLeafSHA256: strings.Repeat("e", 64)},
			SourceDigest: strings.Repeat("f", 64), VolumeID: "ocid1.volume.retained", AttachmentID: "ocid1.volumeattachment.host-a",
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 6 << 30, SystemReserveBytes: 1 << 30}}
	c.managedDesiredVerifier = func(context.Context, Desired, Registration, Desired, bool) error {
		return errors.New("managed canary desired is not authorized")
	}
	if _, err := c.ApplyDesired(t.Context(), desired); err == nil {
		t.Fatal("forged managed desired passed its final durable authorization verifier")
	}
	if desiredRows, err := c.ListDesired(t.Context(), "terrabase"); err != nil || len(desiredRows) != 0 {
		t.Fatalf("rejected managed desired changed durable state: rows=%+v err=%v", desiredRows, err)
	}
	c.managedDesiredVerifier = func(context.Context, Desired, Registration, Desired, bool) error { return nil }
	receipt, err := c.ApplyDesired(t.Context(), desired)
	if err != nil || receipt.Revision == 0 {
		t.Fatalf("commit desired: receipt=%+v err=%v", receipt, err)
	}
	allocations, err := c.ListDesired(t.Context(), "terrabase")
	if err != nil || len(allocations) != 1 || !sameJSON(allocations[0], desired) {
		t.Fatalf("committed allocations=%+v err=%v", allocations, err)
	}
	reader, err := NewReader(t.Context(), ReaderConfig{Cell: "gru", Conn: c.conn, JS: js, StateReplicas: 1, HostMutations: authorityRuntime})
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
		req := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: operation, SessionID: requestID, Epoch: epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: body}
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
	}{"terrabase"}), &reply); err != nil || reply.Desired == nil || !sameJSON(*reply.Desired, desired) || reply.Revision != receipt.Revision ||
		reply.Registration == nil || !sameJSON(*reply.Registration, registration) || reply.RegistrationRevision != registrationReceipt.Revision {
		t.Fatalf("signed desired reply=%+v err=%v", reply, err)
	}
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent := &Agent{cfg: AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Identity: hostKey, NATSUserPublicKey: registration.NATSUserPublicKey,
		Conn: conn, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), InstallRoot: filepath.Join(t.TempDir(), "install"), ClockCheck: func() error { return nil }},
		runner: runner, session: s, processID: requestID, memoryCheck: func(Registration) error { return nil }}
	if err := agent.acceptSession(s); err != nil {
		t.Fatal(err)
	}
	if err := agent.reconcile(t.Context(), "terrabase"); err == nil || !strings.Contains(err.Error(), "managed member launch awaits") {
		t.Fatalf("managed launch did not hold before fetch/apply: %v", err)
	}
	if runner.applied != 0 {
		t.Fatal("managed launch reached native Apply")
	}
	if _, err := os.Stat(agent.cfg.InstallRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed launch fetched artifact: %v", err)
	}
	runner.observed["terrabase"] = Observation{Role: "terrabase", Running: true, CgroupMemoryMaxBytes: desired.ManagedMember.CgroupMemoryMaxBytes - uint64(os.Getpagesize())}
	if err := agent.reconcile(t.Context(), "terrabase"); err == nil || !strings.Contains(err.Error(), "memory.max drifted") {
		t.Fatalf("managed cap drift was accepted: %v", err)
	}
	if runner.observed["terrabase"].Running || runner.applied != 0 {
		t.Fatal("drifted managed process remained running or was reapplied")
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

// TestControlLogReadsAreSafeConcurrently: the workload reconciler and the
// delivery planner list hosts and desired state at once, and jetstream's
// Stream.Info writes its cache into the shared control log handle on every
// call. Run with -race.
func TestControlLogReadsAreSafeConcurrently(t *testing.T) {
	c, _, _, _, _ := testController(t)
	registerTestHost(t, c)
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 5 {
				if _, err := c.ListHosts(t.Context()); err != nil {
					t.Error(err)
				}
				if _, err := c.ListDesired(t.Context(), ""); err != nil {
					t.Error(err)
				}
			}
		})
	}
	readers.Wait()
}

// A host pool retires a host before terminating it: only an idle host
// retires, a retired host takes no new allocation while withdrawals still
// apply, and Unretire returns it.
func TestRetireIdleRefusesNewAllocations(t *testing.T) {
	c, _, store, _, _ := testController(t)
	registerTestHost(t, c)
	data := []byte("retire artifact")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: digest,
		Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if retired, err := c.RetireIdle(t.Context(), "node-a"); err != nil || retired {
		t.Fatalf("a host with an allocation retired: %v, %v", retired, err)
	}
	withdrawn := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Generation: 2,
		AuthorityEpoch: 1, Withdrawn: true}
	if _, err := c.ApplyDesired(t.Context(), withdrawn); err != nil {
		t.Fatal(err)
	}
	if retired, err := c.RetireIdle(t.Context(), "node-a"); err != nil || !retired {
		t.Fatalf("an idle host did not retire: %v, %v", retired, err)
	}
	next := desired
	next.Generation = 3
	if _, err := c.ApplyDesired(t.Context(), next); !errors.Is(err, ErrHostRetiring) {
		t.Fatalf("a retired host took an allocation: %v", err)
	}
	if _, err := c.ApplyDesired(t.Context(), withdrawn); err != nil {
		t.Fatalf("a retired host refused a withdrawal: %v", err)
	}
	// The mark is in the ordered log: a successor controller enforces it.
	successor := &Controller{cell: c.cell, conn: c.conn, state: c.state, controlLog: c.controlLog,
		mutations: c.mutations, artifacts: c.artifacts, authorityEpoch: c.authorityEpoch, authorityGuard: c.authorityGuard}
	if _, err := successor.ApplyDesired(t.Context(), next); !errors.Is(err, ErrHostRetiring) {
		t.Fatalf("a successor placed on a retired host: %v", err)
	}
	if err := successor.Unretire(t.Context(), "node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), next); err != nil {
		t.Fatalf("an unretired host refused an allocation: %v", err)
	}
}
