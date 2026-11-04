package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"errors"
	"fmt"
	"io"
	"maps"

	"net"

	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"

	"github.com/TerraScale/ts-orchestrator/internal/release"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"

	"github.com/TerraScale/ts-orchestrator/internal/trust"

	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"

	"github.com/nats-io/nats.go/jetstream"
)

type genericRuntimeNativeRunner struct {
	*inMemoryRunner
	stopEntered chan struct{}
	allowStop   chan struct{}
	entered     sync.Once
	released    sync.Once
}

func (runner *genericRuntimeNativeRunner) Stop(ctx context.Context, role string) error {
	runner.entered.Do(func() { close(runner.stopEntered) })
	select {
	case <-runner.allowStop:
		return runner.inMemoryRunner.Stop(ctx, role)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runner *genericRuntimeNativeRunner) releaseStop() {
	runner.released.Do(func() { close(runner.allowStop) })
}

type genericRuntimeHostSession struct {
	nativeRunner     *genericRuntimeNativeRunner
	mu               sync.Mutex
	config           host.AgentConfig
	registration     host.Registration
	hosts            *host.Controller
	controllerConfig host.ControllerConfig
	agent            *host.Agent
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan error
}

func startGenericRuntimeHostSession(t *testing.T, ctx context.Context, auth *authenticatedNATS, broker *natscell.Runtime,
	fencer *authority.Runtime, role, environment string, taskLoad host.TaskLoadSource,
) *genericRuntimeHostSession {
	t.Helper()
	responsePublic, responseKey := testEd25519(t, t.TempDir(), "generic-response.key")
	public, private := testEd25519(t, t.TempDir(), "generic-host.key")
	nkey, seed := testNKey(t)
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	controllerConfig := host.ControllerConfig{Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: responseKey, HostMutations: fencer, AuthorityEpoch: func() uint64 { return fencer.Current().Epoch }, AuthorityGuard: fencer.Guard,
		TaskLoadRoles: func(ctx context.Context, _ host.Registration) ([]string, error) {
			loads, err := taskLoad.ReadTaskLoad(ctx)
			if err != nil {
				return nil, err
			}
			var roles []string
			for _, load := range loads {
				roles = append(roles, load.Role)
			}
			return roles, nil
		}}
	hosts, err := host.NewController(ctx, controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: "gru-1-ctl-1", Environment: environment, Roles: []string{role}, Generation: 1,
		ID: entityid.Derive("host", "gru", "gru-1-ctl-1"), PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
		FailureDomain: "fault-domain-1", Capacity: host.Capacity{CPU: 8, MemoryBytes: 8 << 30, DiskBytes: 16 << 30}}
	if _, err := hosts.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	hostCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- hosts.Run(hostCtx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop current host controller: %v", err)
		}
	})
	select {
	case <-hosts.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	transport, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: registration.Node, URL: broker.URL(), ClientRole: "host", NKeySeedFile: seed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	nativeRunner := &genericRuntimeNativeRunner{inMemoryRunner: new(inMemoryRunner), stopEntered: make(chan struct{}), allowStop: make(chan struct{})}
	t.Cleanup(nativeRunner.releaseStop)
	session := &genericRuntimeHostSession{nativeRunner: nativeRunner, hosts: hosts, controllerConfig: controllerConfig, registration: registration, config: host.AgentConfig{Cell: "gru", Node: registration.Node,
		Environment: environment, Roles: registration.Roles, Conn: transport.Conn(), Identity: private, NATSUserPublicKey: nkey, ControllerPublicKey: responsePublic,
		Runner: nativeRunner, TaskLoad: taskLoad, PollInterval: 100 * time.Millisecond, InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(),
		ClockCheck: func() error { return nil }}}
	session.start(t, ctx, (*host.Agent).Run)
	t.Cleanup(func() { session.stop(t) })
	return session
}

func (session *genericRuntimeHostSession) start(t *testing.T, ctx context.Context, run func(*host.Agent, context.Context) error) {
	t.Helper()
	ready := make(chan struct{})
	config := session.config
	config.Initialized = func() { close(ready) }
	agent, err := host.NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	session.mu.Lock()
	session.agent, session.ctx, session.cancel, session.done = agent, runCtx, cancel, done
	session.mu.Unlock()
	go func() { done <- run(agent, runCtx) }()
	select {
	case <-ready:
	case err := <-done:
		done <- err // stop still joins this exit
		t.Fatal("signed host session ended before it initialized: ", err)
	case <-ctx.Done():
		t.Fatal("signed host session did not initialize: ", ctx.Err())
	}
	genericRuntimeEventually(t, ctx, func() bool { return session.verify(ctx) == nil })
}

func (session *genericRuntimeHostSession) stop(t *testing.T) {
	t.Helper()
	session.mu.Lock()
	cancel, done := session.cancel, session.done
	session.cancel, session.done = nil, nil
	session.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("stop signed host session: %v", err)
	}
}

func (session *genericRuntimeHostSession) verify(ctx context.Context) error {
	session.mu.Lock()
	current, agent := session.ctx, session.agent
	session.mu.Unlock()
	if current == nil || current.Err() != nil {
		return errors.New("authenticated host session has ended")
	}
	statuses, err := session.hosts.ListHosts(ctx)
	if err != nil || len(statuses) != 1 || !statuses[0].Verified || !time.Now().Before(statuses[0].SessionExpiresAt) {
		return errors.New("current signed host registration/session unavailable")
	}
	return agent.VerifyOwnRegistration(statuses[0].Registration, session.config.ControllerPublicKey)
}

func genericRuntimeContainerRelease(t *testing.T, signer functionPublicationSigner, target release.ContainerTarget,
	floors []release.SequenceFloor, sequence uint64, migrationWire []byte,
) (release.ContainerBundle, func(context.Context, string) (io.ReadCloser, error)) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	public := signer.leaf.Public().(ed25519.PublicKey)
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: signer.allocations.Namespace, Bucket: signer.allocations.Bucket,
		Region: "GRU", SignerKeyID: keyID, SignerPublicKey: encoded, Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	migration.Regions = floors
	var migrationEnvelope trust.Envelope
	if len(migrationWire) == 0 {
		migrationEnvelope, err = release.SignSequenceMigration(migration, now, signer.root)
		if err != nil {
			t.Fatal(err)
		}
		migrationWire, err = trust.EncodeEnvelope(migrationEnvelope)
	} else {
		migrationEnvelope, err = trust.DecodeEnvelope(migrationWire)
	}
	if err != nil {
		t.Fatal(err)
	}
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	scope := release.ContainerScope(target)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(2*time.Hour), signer.root)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []byte("retained local manager integration qualification evidence")
	evidenceSHA := sha256.Sum256(evidence)
	nativeSHA := sha256.Sum256(fmt.Appendf(nil, "local native image generation %d", sequence))
	nativeDigest := hex.EncodeToString(nativeSHA[:])
	index := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":42,"platform":{"os":"linux","architecture":%q}}]}`, "sha256:"+nativeDigest, target.Architecture)
	indexDigest := sha256.Sum256(index)
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{
		SourceRevision: fmt.Sprintf("%040x", sequence), ArtifactSHA256: nativeDigest, QualificationSHA256: hex.EncodeToString(indexDigest[:]), Cell: target.Cell,
		Environment: target.Environment, Runtime: release.ProductionRuntime, Architecture: target.Architecture, Role: target.Role}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: hex.EncodeToString(evidenceSHA[:]), Bytes: int64(len(evidence)), CompletedAt: now})
	}
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "example.invalid/api@sha256:" + nativeDigest,
		SourceRepository: "https://example.invalid/api", SourceRevision: qualification.Candidate.SourceRevision, SourceTreeSHA256: strings.Repeat("e", 64),
		Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: sequence,
		SequenceMigrationSHA256: migrationSHA, QualificationSHA256: qualification.Candidate.QualificationSHA256,
		Production: release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), signer.root)}}
	if err := signer.allocations.ImportMigration(t.Context(), migrationEnvelope, signer.roots, target.Role, target.Environment, now); err != nil {
		t.Fatal(err)
	}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	allocated, sequenceWire, err := signer.allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{Role: target.Role, Environment: target.Environment,
		SourceRevision: claim.SourceRevision, ManifestSHA256: family}, signer.roots, signer.leaf)
	if err != nil || allocated != claim.ReleaseSequence {
		t.Fatalf("allocate authentic shared sequence: got %d, want %d: %v", allocated, claim.ReleaseSequence, err)
	}
	return release.ContainerBundle{Claim: sign(claim, scope, signer.leaf), Delegation: delegationWire, Migration: migrationWire, Sequence: sequenceWire, Index: index},
		func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(evidence)), nil
		}
}

type genericRuntimeExecutor struct {
	mu          sync.Mutex
	controllers map[string]*genericRuntimeTask
	rejectImage string
	nodeID      string
}

func (*genericRuntimeExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: runtime.GOARCH}, Resources: &api.Resources{NanoCPUs: 8_000_000_000, MemoryBytes: 8 << 30,
		Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 16<<30)}}}, nil
}
func (*genericRuntimeExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (*genericRuntimeExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (executor *genericRuntimeExecutor) Controller(task *api.Task) (swarmexec.Controller, error) {
	spec, err := swarmruntime.DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	executor.mu.Lock()
	controller := &genericRuntimeTask{done: make(chan struct{}), reject: spec.Image == executor.rejectImage, assignment: task.Copy()}
	executor.controllers[task.ID] = controller
	executor.mu.Unlock()
	return controller, nil
}

// Local controller pins are genuine assignments; this simulated executor has
// no native cgroup measurements, so resource usage stays explicitly unknown.
func (executor *genericRuntimeExecutor) ReadTaskLoad(ctx context.Context) ([]hostload.RoleUsage, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	roles := make(map[string]hostload.RoleUsage)
	for _, id := range slices.Sorted(maps.Keys(executor.controllers)) {
		controller := executor.controllers[id]
		controller.mu.Lock()
		task := controller.assignment.Copy()
		removed := controller.removed
		controller.mu.Unlock()
		if removed || executor.nodeID == "" || task.NodeID != executor.nodeID {
			continue
		}
		select {
		case <-controller.done:
			continue
		default:
		}
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			return nil, err
		}
		role := task.ServiceAnnotations.Labels[swarmruntime.LabelRole]
		usage := roles[role]
		usage.Role = role
		usage.Tasks = append(usage.Tasks, hostload.TaskPin{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, Fingerprint: fingerprint})
		roles[role] = usage
	}
	var result []hostload.RoleUsage
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		result = append(result, roles[role])
	}
	return result, ctx.Err()
}

func (executor *genericRuntimeExecutor) fail(id string) error {
	executor.mu.Lock()
	controller := executor.controllers[id]
	executor.mu.Unlock()
	if controller == nil {
		return errors.New("running task controller is absent")
	}
	controller.failed.Store(true)
	controller.stop()
	return nil
}

type genericRuntimeTask struct {
	mu         sync.Mutex
	assignment *api.Task
	removed    bool
	done       chan struct{}
	once       sync.Once
	failed     atomic.Bool
	reject     bool
}

func (task *genericRuntimeTask) Update(_ context.Context, assignment *api.Task) error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.assignment = assignment.Copy()
	return nil
}
func (task *genericRuntimeTask) Prepare(context.Context) error {
	if task.reject {
		task.stop()
		return errors.New("application rejected candidate release")
	}
	return nil
}
func (*genericRuntimeTask) Start(context.Context) error { return nil }
func (task *genericRuntimeTask) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-task.done:
		if task.failed.Load() {
			return errors.New("application task failed")
		}
		return nil
	}
}
func (task *genericRuntimeTask) stop()                           { task.once.Do(func() { close(task.done) }) }
func (task *genericRuntimeTask) Shutdown(context.Context) error  { task.stop(); return nil }
func (task *genericRuntimeTask) Terminate(context.Context) error { task.stop(); return nil }
func (task *genericRuntimeTask) Remove(context.Context) error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.removed = true
	return nil
}
func (task *genericRuntimeTask) Close() error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.removed = true
	return nil
}

func genericRuntimeNodeConfigAdmission(name, role string) swarmruntime.Admission {
	return swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: name, InstanceID: "ocid1.instance.integration." + name, FounderID: "generic-manager", Role: role}
}

func genericRuntimeNodeConfig(t *testing.T, name, role string) swarmruntime.NodeConfig {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return swarmruntime.NodeConfig{StateDir: t.TempDir(), ListenAddress: address, AdvertiseAddress: address, Admission: genericRuntimeNodeConfigAdmission(name, role)}
}

func genericRuntimeEventually(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual manager did not converge: ", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
