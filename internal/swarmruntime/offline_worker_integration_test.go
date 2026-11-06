package swarmruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/moby/swarmkit/v2/api"
)

// A STOPPED worker whose boot volume was armed offline restarts with no agent
// task database: the manager's reassigned b443 task stays fenced, and the
// pinned driver replaces it using the unreachable offline exit identity.
// Runtime/edge are fakes; manager, dispatcher, Raft, agent and exits are real.
func TestOfflineArmedWorkerRebootsFencedAndReplaces(t *testing.T) {
	if testing.Short() {
		t.Skip("dispatcher/agent restart drill runs in Slow")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	world := &bootstrapWorld{processes: map[string]*bootstrapProcess{}}
	t.Cleanup(func() {
		world.mu.Lock()
		ids := make([]string, 0, len(world.processes))
		for id := range world.processes {
			ids = append(ids, id)
		}
		world.mu.Unlock()
		for _, id := range ids {
			_ = world.stop(id)
		}
	})
	type host struct {
		cfg   NodeConfig
		state string
		node  *Node
		e     *bootstrapExecutorFixture
	}
	start := func(h *host) {
		store, err := rolloutmaintenance.Open(h.state)
		if err != nil {
			t.Fatal(err)
		}
		h.e = &bootstrapExecutorFixture{raw: &Executor{bootstrap: store, bootstrapTasks: map[string]*controller{}}, world: world, controllers: map[string]*bootstrapControllerFixture{}}
		if h.node, err = StartNode(ctx, h.cfg, h.e); err != nil {
			t.Fatal(err)
		}
	}
	stop := func(h *host) {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := h.node.Stop(c); err != nil {
			t.Fatal(err)
		}
	}
	manager := &host{cfg: serviceConfig(t, "ts-fra-1", "manager"), state: t.TempDir()}
	manager.cfg.Admission.FounderID = manager.cfg.Admission.HostID
	start(manager)
	defer stop(manager)
	client, err := manager.node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AdmitNode(ctx, client, manager.node.ID(), manager.cfg.Admission); err != nil {
		t.Fatal(err)
	}
	address, err := manager.node.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// The worker's state uses the production layout below a mounted root.
	root := t.TempDir()
	worker := &host{cfg: serviceConfig(t, "ts-fra-2", "container"), state: filepath.Join(root, "var/lib/ts-orch")}
	worker.cfg.StateDir = filepath.Join(worker.state, "swarm")
	worker.cfg.Admission.FounderID = manager.cfg.Admission.HostID
	worker.cfg.Admission.ManagerAddress = address
	worker.cfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	start(worker)
	if _, err = AdmitNode(ctx, client, worker.node.ID(), worker.cfg.Admission); err != nil {
		t.Fatal(err)
	}
	intent := serviceIntent()
	intent.Replicas = 2
	spec, err := intent.serviceSpec()
	if err != nil {
		t.Fatal(err)
	}
	spec.Annotations.Labels[LabelServiceSpec] = "terrabase"
	container := intent.Container.Copy()
	container.Env = []string{"TS_REGION=fra"}
	if spec.Task.Runtime, err = ContainerRuntime(container); err != nil {
		t.Fatal(err)
	}
	spec.Task.Placement.MaxReplicas = 1
	spec.Update.Order = api.UpdateConfig_STOP_FIRST
	spec.Update.FailureAction = api.UpdateConfig_PAUSE
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	target := "example.invalid/fixture@sha256:" + strings.Repeat("b", 64)
	running := func(h *host) rolloutmaintenance.Pin {
		var pin rolloutmaintenance.Pin
		serviceEventually(t, ctx, func() bool {
			h.e.mu.Lock()
			defer h.e.mu.Unlock()
			for _, c := range h.e.controllers {
				if c.raw.task.ServiceID == created.Service.ID && world.process(c.raw.task.ID) != nil {
					pin = c.raw.bootstrapPin()
					return true
				}
			}
			return false
		})
		return pin
	}
	// The founder is armed live, as in v2 step 5.
	founderPin := running(manager)
	founderIdentity, err := processIdentity(uint32(world.process(founderPin.Task).cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	founderJob := rolloutmaintenance.Job{ID: "zdt-ts-fra-1", Member: "ts-fra-1", Source: founderPin, Target: rolloutmaintenance.Pin{Node: founderPin.Node, Service: founderPin.Service, Image: target},
		Process: founderIdentity, Owner: "ts-fra-2", Epoch: 7}
	if err = manager.e.raw.bootstrap.Arm(ctx, founderJob); err != nil {
		t.Fatal(err)
	}

	// OCI STOP: the agent and the engine process are gone; the volume remains.
	source := running(worker)
	stop(worker)
	if err = world.stop(source.Task); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "etc/hostname"), []byte("ts-fra-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := rolloutmaintenance.Job{ID: "zdt-ts-fra-2", Member: "ts-fra-2", Source: source, Target: rolloutmaintenance.Pin{Node: source.Node, Service: source.Service, Image: target},
		Process: OfflineExitProcess, Owner: "ts-fra-2", Epoch: 7, Phase: "held"}
	if err = armOffline(ctx, root, "/var/lib/ts-orch", ColdBootstrap{Local: job, Owner: job}); err != nil {
		t.Fatal(err)
	}

	// A reboot leaves no process: any start that passes the fence would appear.
	stopped := world.process(source.Task)
	world.mu.Lock()
	delete(world.processes, source.Task)
	world.mu.Unlock()

	// START: no agent task database; the manager reassigns b443 and it is held.
	blocked := world.blocked.Load()
	start(worker)
	defer stop(worker)
	serviceEventually(t, ctx, func() bool {
		worker.e.mu.Lock()
		defer worker.e.mu.Unlock()
		return worker.e.controllers[source.Task] != nil && world.blocked.Load() > blocked
	})
	time.Sleep(time.Second) // several agent retry rounds
	if world.process(source.Task) != nil {
		t.Fatal("rebooted worker revived the b443 engine")
	}
	world.mu.Lock()
	world.processes[source.Task] = stopped // exit evidence for the fixture runtime
	world.mu.Unlock()

	current, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
	if err != nil {
		t.Fatal(err)
	}
	next := current.Service.Spec.Copy()
	next.Update.Parallelism = 0 // as the fenced founder's BootstrapStage apply renders it
	nextContainer := container.Copy()
	nextContainer.Image = target
	if next.Task.Runtime, err = ContainerRuntime(nextContainer); err != nil {
		t.Fatal(err)
	}
	if _, err = client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.Service.ID, ServiceVersion: &current.Service.Meta.Version, Spec: next}); err != nil {
		t.Fatal(err)
	}
	runtime := &bootstrapRuntimeFixture{e: worker.e, client: client}
	if err = (rolloutmaintenance.Driver{Store: worker.e.raw.bootstrap, Runtime: runtime}).Replace(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if old := world.process(source.Task); !old.exit.Before(runtime.started) {
		t.Fatal("new admission preceded the stopped worker's engine exit")
	}
	if err = world.process(founderPin.Task).cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("worker drive stopped the founder", err)
	}
	t.Logf("offline_armed_worker_reboot=fenced agent_db=absent replace=verified old_exit=%s new_admission=%s", world.process(source.Task).exit.Format(time.RFC3339Nano), runtime.started.Format(time.RFC3339Nano))
}
