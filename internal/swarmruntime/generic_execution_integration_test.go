//go:build linux

package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// Only the protected Foundation receipt is substituted here. Task assignment,
// hold journal, host RPC/session, node certificates and processes are genuine.
type genericDrainFixture struct {
	mu        sync.Mutex
	challenge *drainwire.DrainStopChallenge
	proof     *drainwire.SignedStop
	control   api.ControlClient
}

func (f *genericDrainFixture) GuardStart(ctx context.Context, hold drainwire.ExecutionHold) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.challenge != nil && f.challenge.InstanceID == hold.InstanceID {
		return ErrGenericExecutionPending
	}
	return ctx.Err()
}

func (f *genericDrainFixture) ReadChallenges(_ context.Context, holds []drainwire.SignedHold) ([]drainwire.DrainStopChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.challenge == nil || f.proof != nil {
		return nil, nil
	}
	for _, h := range holds {
		if f.challenge.Matches(h.Hold) {
			return []drainwire.DrainStopChallenge{*f.challenge}, nil
		}
	}
	return nil, errors.New("fixture capture has no exact original hold")
}

func (f *genericDrainFixture) StoreStop(ctx context.Context, p drainwire.SignedStop) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.challenge == nil {
		return errors.New("fixture capture absent")
	}
	node, err := f.control.GetNode(ctx, &api.GetNodeRequest{NodeID: f.challenge.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	task, err := f.control.GetTask(ctx, &api.GetTaskRequest{TaskID: f.challenge.TaskID})
	if err != nil || task == nil || task.Task == nil || !taskLoadTerminalState(task.Task.Status.State) || node.Node.Spec.Availability != api.NodeAvailabilityDrain {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	clusters, err := f.control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || clusters == nil || len(clusters.Clusters) != 1 {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	c := clusters.Clusters[0]
	if err := drainwire.VerifySignedStop(p, *f.challenge, node.Node.Certificate.Certificate, c.RootCA.CACert, c.ID, time.Now().UTC()); err != nil {
		return err
	}
	copy := p
	f.proof = &copy
	return nil
}

// A native runner cannot supply the evidence exercised by this scenario.
type genericSessionOnlyRunner struct{ host.Runner }

func TestContainerdGenericExecutionRetainsOriginalProcessAcrossReopen(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	js, connection := effectSessionR3(t)
	journal, err := authority.Start(ctx, js, authority.Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	founderCfg := nodeFixtureConfig(t, "founder", "manager")
	founder := nodeFixtureStart(t, ctx, founderCfg)
	control, err := founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || clusters == nil || len(clusters.Clusters) != 1 {
		t.Fatal("actual manager cluster unavailable", err)
	}
	cluster := clusters.Clusters[0]
	hostID := entityid.Derive("host", "gru", "generic-worker")
	workerCfg := nodeFixtureConfig(t, hostID, "container")
	workerCfg.Admission.Region = "sa-saopaulo-1"
	workerCfg.Admission.InstanceID = "ocid1.instance.oc1.sa-saopaulo-1.generic-worker"
	workerCfg.Admission.ManagerAddress, err = founder.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.Admission.JoinToken = cluster.RootCA.JoinTokens.Worker
	state := t.TempDir()
	executor, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	if err := executor.BindContainerMaterial(workerCfg.Admission, containerMaterialFixture(func(_ context.Context, b ContainerTaskBinding) (ContainerMaterial, error) {
		return ContainerMaterial{Binding: b, ExpiresAt: time.Now().Add(time.Minute), User: "65532:65532"}, nil
	})); err != nil {
		t.Fatal(err)
	}
	worker, err := StartNode(ctx, workerCfg, executor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeFixtureStop(t, worker) })
	if _, err := AdmitNode(ctx, control, worker.ID(), workerCfg.Admission); err != nil {
		t.Fatal(err)
	}
	drain := &genericDrainFixture{control: control}
	sessions, err := NewGenericExecutionSessions(control, journal, founder, drain)
	if err != nil {
		t.Fatal(err)
	}
	stateKV, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "TS_HOST_STATE", History: 2, Replicas: 3, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "GENERIC_DRAIN_ARTIFACTS", Replicas: 3, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostController, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: connection, JS: js, State: stateKV, StateReplicas: 3, Artifacts: artifacts, ResponseKey: controllerKey,
		HostMutations: journal, AuthorityEpoch: func() uint64 { return journal.Current().Epoch }, AuthorityGuard: journal.Guard, GenericExecutions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	controllerCtx, stopController := context.WithCancel(ctx)
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- hostController.Run(controllerCtx) }()
	t.Cleanup(func() {
		stopController()
		select {
		case <-controllerDone:
		case <-time.After(5 * time.Second):
			t.Error("host controller did not stop")
		}
	})
	select {
	case <-hostController.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	natsUser, err := user.PublicKey()
	user.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: "generic-worker", Environment: "integration", Roles: []string{"smoke"}, Generation: 1,
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: natsUser, Capacity: host.Capacity{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 8 << 30}}
	if _, err := hostController.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	registration.ID = hostID
	installParent := t.TempDir()
	if err := os.Chmod(installParent, 0755); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(installParent, "install")
	if err := os.Mkdir(install, 0755); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	agent, err := host.NewAgent(host.AgentConfig{Cell: "gru", Node: registration.Node, Environment: "integration", Roles: registration.Roles,
		Conn: connection, Identity: hostPrivate, NATSUserPublicKey: natsUser, ControllerPublicKey: controllerPublic,
		InstallRoot: install, StateRoot: t.TempDir(), WorkloadIdentity: host.WorkloadIdentity{UID: 65532, GID: 65532},
		ClockCheck: func() error { return nil }, Runner: genericSessionOnlyRunner{}, Initialized: func() { close(ready) }})
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	agentFinished := false
	go func() { agentDone <- agent.RunSession(agentCtx) }()
	t.Cleanup(func() {
		stopAgent()
		if agentFinished {
			return
		}
		select {
		case <-agentDone:
		case <-time.After(5 * time.Second):
			t.Error("host session did not stop")
		}
	})
	select {
	case <-ready:
	case err := <-agentDone:
		agentFinished = true
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := executor.BindGenericExecution(agent, worker); err != nil {
		t.Fatal(err)
	}
	service, err := applyService(ctx, control, ServiceIntent{ID: entityid.New(), Role: "smoke", Region: workerCfg.Admission.Region, Environment: "integration", Architecture: runtime.GOARCH, Replicas: 1,
		Container: &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", "echo original-ready; exec sleep 300"}}, Resources: containerTestResources(250_000_000, 64<<20)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_, _ = control.RemoveService(cleanup, &api.RemoveServiceRequest{ServiceID: service.ID})
	})
	var actual *api.Task
	var original genericExecutionWitness
	waitRuntime(t, ctx, func() (bool, error) {
		listed, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil {
			return false, err
		}
		for _, task := range listed.Tasks {
			if task.NodeID == worker.ID() && task.Status.State == api.TaskStateRunning {
				w, err := executor.readGenericWitness(task.ID)
				if err != nil {
					return false, err
				}
				if w.Hold == nil || w.Process == nil {
					return false, ErrGenericExecutionPending
				}
				actual, original = task.Copy(), w
				return true, nil
			}
		}
		return false, nil
	})
	if original.Hold.Hold.TaskID != actual.ID || original.Process.HostPID < 2 {
		t.Fatal("actual prestart process witness absent")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		handle, err := executor.Controller(actual.Copy())
		if err == nil {
			err = handle.Remove(cleanup)
		}
		if err != nil {
			t.Error("remove exact fixture runtime", err)
		}
	})
	witnessStat, err := diskFileStat(executor.genericWitnessPath(actual.ID))
	if err != nil || witnessStat.Uid != 0 || witnessStat.Mode&0077 != 0 {
		t.Fatal("original process witness is not private root-owned durable state", err)
	}
	managerRecord, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: founder.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := drainwire.VerifySignedHold(*original.Hold, managerRecord.Node.Certificate.Certificate, cluster.RootCA.CACert, cluster.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	retained, err := journal.ListGenericExecutions(ctx)
	if err != nil || len(retained) != 1 || !sameGenericHold(retained[0], *original.Hold) {
		t.Fatal("original possible execution not journaled", err)
	}
	if _, err := agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "acquire", Task: actual.Copy(), ExecutionSessionID: entityid.New()}); err == nil {
		t.Fatal("orphaned original execution acquired a duplicate hold")
	}
	// A new connection adopts the persisted original process, never new evidence.
	reopened, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	nodeRecord, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Configure(ctx, nodeRecord.Node); err != nil {
		t.Fatal(err)
	}
	if err := reopened.BindContainerMaterial(workerCfg.Admission, executor.containerMaterial); err != nil {
		t.Fatal(err)
	}
	if err := reopened.BindGenericExecution(agent, worker); err != nil {
		t.Fatal(err)
	}
	handle, err := reopened.Controller(actual.Copy())
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Start(ctx); !errors.Is(err, swarmexec.ErrTaskStarted) {
		t.Fatal("persisted survivor was not adopted", err)
	}
	adopted, err := reopened.readGenericWitness(actual.ID)
	if err != nil || adopted.Hold == nil || adopted.Process == nil || *adopted.Process != *original.Process || !sameGenericHold(*adopted.Hold, *original.Hold) {
		t.Fatal("adoption replaced original process pins", err)
	}
	process, err := handle.(*controller).runtimeTask(ctx)
	if err != nil || int(process.Pid()) != original.Process.HostPID {
		t.Fatal("adoption changed actual kernel PID", err)
	}
	spec := nodeRecord.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityPause
	paused, err := control.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: worker.ID(), NodeVersion: &nodeRecord.Node.Meta.Version, Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "acquire", Task: actual.Copy(), ExecutionSessionID: original.ExecutionSessionID}); err == nil || !strings.Contains(err.Error(), "ACTIVE") {
		t.Fatal("PAUSE admitted original execution for another start", err)
	}
	hostReader, err := host.NewReader(ctx, host.ReaderConfig{Cell: "gru", Conn: connection, JS: js, State: stateKV, StateReplicas: 3, HostMutations: journal})
	if err != nil {
		t.Fatal(err)
	}
	source, err := hostReader.CurrentGenericExecutionSession(ctx, registration.Node)
	if err != nil || !source.SameIdentity(original.Hold.Hold.HostSession) {
		t.Fatal("root host source lost original authenticated session", err)
	}
	h := original.Hold.Hold
	now := time.Now().UTC()
	deadline := now.Add(20 * time.Second)
	if source.ExpiresAt.Before(deadline) {
		deadline = source.ExpiresAt
	}
	challenge := drainwire.DrainStopChallenge{Cell: h.Cell, HostNode: h.HostNode, RemovalOperationID: entityid.New(), BirthOperationID: entityid.New(), InstanceID: h.InstanceID, NodeID: h.NodeID,
		RegistrationID: h.RegistrationID, HostSessionID: h.HostSessionID, RegistrationGeneration: h.RegistrationGeneration, Epoch: journal.Current().Epoch, HostEpoch: h.HostEpoch, OriginalEpoch: h.OriginalEpoch,
		ExecutionSessionID: h.ExecutionSessionID, TaskID: h.TaskID, ServiceID: h.ServiceID, TaskSHA256: h.TaskSHA256, ExecutionSHA256: h.ExecutionSHA256, Nonce: strings.Repeat("d", 64), IssuedAt: now, Deadline: deadline}
	drain.mu.Lock()
	drain.challenge = &challenge
	drain.mu.Unlock()
	if err := drain.GuardStart(ctx, h); err == nil {
		t.Fatal("protected capture did not fence its exact instance")
	}
	if _, err := reopened.observeGenericStop(ctx, reopened.genericExecution, challenge); err == nil {
		t.Fatal("live original process produced stopped evidence")
	}
	unknown := challenge
	unknown.TaskID = "uncaptured"
	if _, err := reopened.observeGenericStop(ctx, reopened.genericExecution, unknown); err == nil {
		t.Fatal("absent task produced stopped evidence")
	}
	spec = paused.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityDrain
	if _, err := control.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: worker.ID(), NodeVersion: &paused.Node.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	waitRuntime(t, ctx, func() (bool, error) {
		got, err := control.GetTask(ctx, &api.GetTaskRequest{TaskID: actual.ID})
		if err != nil || got == nil || got.Task == nil {
			return false, err
		}
		if !taskLoadTerminalState(got.Task.Status.State) {
			return false, nil
		}
		if err := reopened.reconcileGenericExecution(ctx); err != nil {
			return false, err
		}
		drain.mu.Lock()
		defer drain.mu.Unlock()
		return drain.proof != nil, nil
	})
	stopped, err := reopened.readGenericWitness(actual.ID)
	if err != nil || !stopped.Closing || stopped.Process == nil || *stopped.Process != *original.Process {
		t.Fatal("stopped process lost irreversible original pins", err)
	}
	if err := reopened.verifyGenericStopped(ctx, stopped); err != nil {
		t.Fatal("original process or descendant cgroup still live", err)
	}
	retained, err = journal.ListGenericExecutions(ctx)
	if err != nil || len(retained) != 1 {
		t.Fatal("stop or task removal discarded historical possible execution", err)
	}
	registration.Generation++
	if _, err := hostController.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	drain.mu.Lock()
	proof := *drain.proof
	drain.mu.Unlock()
	if _, err := agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "stop", Stop: &proof}); err == nil {
		t.Fatal("rotated registration accepted original-session stopped submission")
	}
	select {
	case err := <-agentDone:
		agentFinished = true
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatal("rotated host registration did not fence the original session", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := reopened.observeGenericStop(ctx, reopened.genericExecution, challenge); err == nil {
		t.Fatal("revoked local host session produced another stopped observation")
	}
}
