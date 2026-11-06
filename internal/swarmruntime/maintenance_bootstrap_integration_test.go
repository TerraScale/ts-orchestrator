package swarmruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

type bootstrapProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	once sync.Once
	exit time.Time
}
type bootstrapWorld struct {
	mu        sync.Mutex
	processes map[string]*bootstrapProcess
	blocked   atomic.Int64
}

func (w *bootstrapWorld) process(task string) *bootstrapProcess {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.processes[task]
}
func (w *bootstrapWorld) start(task string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.processes[task] != nil {
		return swarmexec.ErrTaskStarted
	}
	cmd := exec.Command("sleep", "120")
	if err := cmd.Start(); err != nil {
		return err
	}
	w.processes[task] = &bootstrapProcess{cmd: cmd, done: make(chan struct{})}
	return nil
}

// live is the fixture's runtime probe: a task has a process until it exits.
func (w *bootstrapWorld) live(_ context.Context, c *controller) (bool, error) {
	p := w.process(c.task.ID)
	if p == nil {
		return false, nil
	}
	select {
	case <-p.done:
		return false, nil
	default:
		return true, nil
	}
}
func (w *bootstrapWorld) stop(task string) error {
	p := w.process(task)
	if p == nil {
		return nil
	}
	var result error
	p.once.Do(func() {
		result = p.cmd.Process.Signal(syscall.SIGTERM)
		_ = p.cmd.Wait()
		p.exit = time.Now().UTC()
		close(p.done)
	})
	return result
}

type bootstrapExecutorFixture struct {
	serviceExecutor
	raw         *Executor
	world       *bootstrapWorld
	mu          sync.Mutex
	controllers map[string]*bootstrapControllerFixture
}

func (e *bootstrapExecutorFixture) Configure(_ context.Context, node *api.Node) error {
	e.raw.mu.Lock()
	e.raw.functionNodeID = node.ID
	e.raw.mu.Unlock()
	return nil
}
func (e *bootstrapExecutorFixture) Controller(task *api.Task) (swarmexec.Controller, error) {
	raw, err := e.raw.Controller(task)
	if err != nil {
		return nil, err
	}
	c := &bootstrapControllerFixture{raw: raw.(*controller), world: e.world}
	e.mu.Lock()
	e.controllers[task.ID] = c
	e.mu.Unlock()
	return c, nil
}

type bootstrapControllerFixture struct {
	raw   *controller
	world *bootstrapWorld
}

func (c *bootstrapControllerFixture) Update(ctx context.Context, t *api.Task) error {
	return c.raw.Update(ctx, t)
}
func (c *bootstrapControllerFixture) guard(ctx context.Context, action string) error {
	_, done, err := c.raw.bootstrapOperation(ctx, action)
	defer done()
	if err != nil {
		c.world.blocked.Add(1)
	}
	return err
}
func (c *bootstrapControllerFixture) Prepare(ctx context.Context) error {
	j, err := c.raw.executor.bootstrap.Status(ctx)
	if err != nil {
		return err
	}
	if j != nil && j.Phase == "verified" && j.Target == c.raw.bootstrapPin() && c.world.process(c.raw.task.ID) != nil {
		return swarmexec.ErrTaskPrepared
	}
	return c.guard(ctx, "prepare")
}
func (c *bootstrapControllerFixture) Start(ctx context.Context) error {
	j, err := c.raw.executor.bootstrap.Status(ctx)
	if err != nil {
		return err
	}
	if j != nil && j.Phase == "verified" && j.Target == c.raw.bootstrapPin() && c.world.process(c.raw.task.ID) != nil {
		return swarmexec.ErrTaskStarted
	}
	if err = c.guard(ctx, "start"); err != nil {
		return err
	}
	return c.world.start(c.raw.task.ID)
}
func (c *bootstrapControllerFixture) Wait(ctx context.Context) error {
	p := c.world.process(c.raw.task.ID)
	if p == nil {
		return errors.New("fake runtime process missing")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return nil
	}
}
func (c *bootstrapControllerFixture) Shutdown(ctx context.Context) error {
	// Exercise the production Shutdown boundary: a held unselected task must
	// return before it could touch the intentionally absent containerd client.
	j, err := c.raw.executor.bootstrap.Status(ctx)
	if err != nil {
		return err
	}
	if j != nil {
		p := c.world.process(c.raw.task.ID)
		if p != nil {
			select {
			case <-p.done:
				return nil
			default:
			}
		}
		err = c.raw.Shutdown(ctx)
		if err != nil {
			c.world.blocked.Add(1)
		}
		return err
	}
	return c.world.stop(c.raw.task.ID)
}
func (c *bootstrapControllerFixture) Terminate(ctx context.Context) error {
	if err := c.guard(ctx, "terminate"); err != nil {
		return err
	}
	return c.world.stop(c.raw.task.ID)
}
func (c *bootstrapControllerFixture) Remove(ctx context.Context) error { return c.guard(ctx, "remove") }
func (c *bootstrapControllerFixture) Close() error                     { return nil } // container runtime survives daemon exit

type bootstrapRuntimeFixture struct {
	e       *bootstrapExecutorFixture
	client  api.ControlClient
	started time.Time
}

func (r *bootstrapRuntimeFixture) Staged(ctx context.Context, j rolloutmaintenance.Job) error {
	s, err := r.client.GetService(ctx, &api.GetServiceRequest{ServiceID: j.Source.Service})
	if err != nil {
		return err
	}
	container, decodeErr := DecodeContainer(&api.Task{ID: "inspection", ServiceID: s.Service.ID, Spec: s.Service.Spec.Task, ServiceAnnotations: s.Service.Spec.Annotations})
	if decodeErr != nil {
		return decodeErr
	}
	if container.Image != j.Target.Image {
		return errors.New("intent not staged")
	}
	return nil
}
func (r *bootstrapRuntimeFixture) Resolve(_ context.Context, j rolloutmaintenance.Job) (rolloutmaintenance.Pin, error) {
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	for _, c := range r.e.controllers {
		p := c.raw.bootstrapPin()
		if p.Node == j.Source.Node && p.Service == j.Source.Service && p.Image == j.Target.Image && p.Task != j.Source.Task {
			return p, nil
		}
	}
	return rolloutmaintenance.Pin{}, errors.New("dispatcher has not assigned the candidate yet")
}
func (r *bootstrapRuntimeFixture) find(p rolloutmaintenance.Pin) (*bootstrapControllerFixture, error) {
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	c := r.e.controllers[p.Task]
	if c == nil || c.raw.bootstrapPin() != p {
		return nil, rolloutmaintenance.ErrFenced
	}
	return c, nil
}
func (r *bootstrapRuntimeFixture) Prepare(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		return err
	}
	return c.guard(ctx, "prepare")
}
func (r *bootstrapRuntimeFixture) Quiesce(context.Context, rolloutmaintenance.Job) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}
func (r *bootstrapRuntimeFixture) Stop(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		return err
	}
	if err = c.guard(ctx, "stop"); err != nil {
		return err
	}
	return r.e.world.stop(p.Task)
}
func (r *bootstrapRuntimeFixture) Exited(_ context.Context, p rolloutmaintenance.Pin, identity rolloutmaintenance.Process) error {
	process := r.e.world.process(p.Task)
	if process == nil {
		return errors.New("old process evidence missing")
	}
	select {
	case <-process.done:
	default:
		return errors.New("old process has not exited")
	}
	current, err := processIdentity(identity.PID)
	if err == nil && current == identity {
		return errors.New("retained PID identity still alive")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (r *bootstrapRuntimeFixture) Start(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		return err
	}
	if err = c.guard(ctx, "start"); err != nil {
		return err
	}
	r.started = time.Now().UTC()
	return r.e.world.start(p.Task)
}
func (r *bootstrapRuntimeFixture) Verify(_ context.Context, j rolloutmaintenance.Job) error {
	if r.e.world.process(j.Target.Task) == nil {
		return errors.New("candidate is not ready")
	}
	return nil
}

// The runtime and HTTP edges are fakes; manager, CA, dispatcher, scheduler,
// stop-first task update, Raft persistence and OS process exit are real.
func TestBootstrapFenceAcrossSixDispatchedNodesAndDaemonRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("six-node dispatcher/process drill runs in Slow")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
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
		cfg    NodeConfig
		state  string
		node   *Node
		e      *bootstrapExecutorFixture
		job    rolloutmaintenance.Job
		client api.ControlClient
	}
	var hosts []*host
	start := func(h *host) {
		store, err := rolloutmaintenance.Open(h.state)
		if err != nil {
			t.Fatal(err)
		}
		h.e = &bootstrapExecutorFixture{raw: &Executor{bootstrap: store, bootstrapTasks: map[string]*controller{}, bootstrapLive: world.live}, world: world, controllers: map[string]*bootstrapControllerFixture{}}
		h.node, err = StartNode(ctx, h.cfg, h.e)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, region := range []string{"gru", "sjc", "fra"} {
		manager := &host{cfg: serviceConfig(t, "ts-"+region+"-1", "manager"), state: t.TempDir()}
		manager.cfg.Admission.FounderID = manager.cfg.Admission.HostID
		start(manager)
		hosts = append(hosts, manager)
		client, err := manager.node.ControlClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		manager.client = client
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
		worker := &host{cfg: serviceConfig(t, "ts-"+region+"-2", "container"), state: t.TempDir(), client: client}
		worker.cfg.Admission.FounderID = manager.cfg.Admission.HostID
		worker.cfg.Admission.ManagerAddress = address
		worker.cfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
		start(worker)
		hosts = append(hosts, worker)
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
		container.Env = []string{"TS_REGION=" + region}
		spec.Task.Runtime, err = ContainerRuntime(container)
		if err != nil {
			t.Fatal(err)
		}
		spec.Task.Placement.MaxReplicas = 1
		spec.Update.Order = api.UpdateConfig_STOP_FIRST
		spec.Update.FailureAction = api.UpdateConfig_PAUSE
		created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []*host{manager, worker} {
			serviceEventually(t, ctx, func() bool {
				h.e.mu.Lock()
				defer h.e.mu.Unlock()
				for _, c := range h.e.controllers {
					if c.raw.task.ServiceID == created.Service.ID && world.process(c.raw.task.ID) != nil {
						return true
					}
				}
				return false
			})
			h.e.mu.Lock()
			for _, c := range h.e.controllers {
				if c.raw.task.ServiceID == created.Service.ID && world.process(c.raw.task.ID) != nil {
					source := c.raw.bootstrapPin()
					target := source
					target.Task = ""
					target.Fingerprint = ""
					target.Image = "example.invalid/fixture@sha256:" + strings.Repeat("b", 64)
					identity, err := processIdentity(uint32(world.process(source.Task).cmd.Process.Pid))
					if err != nil {
						t.Fatal(err)
					}
					h.job = rolloutmaintenance.Job{ID: "bootstrap-" + h.cfg.Admission.HostID, Member: h.cfg.Admission.HostID, Source: source, Target: target, Process: identity, Owner: manager.cfg.Admission.HostID, Epoch: 7}
					break
				}
			}
			h.e.mu.Unlock()
			if err = h.e.raw.bootstrap.Arm(ctx, h.job); err != nil {
				t.Fatal(err)
			}
		}
		current, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
		if err != nil {
			t.Fatal(err)
		}
		next := current.Service.Spec.Copy()
		next.Update.Parallelism = 0 // as the fenced founder's BootstrapStage apply renders it
		nextContainer := container.Copy()
		nextContainer.Image = manager.job.Target.Image
		next.Task.Runtime, err = ContainerRuntime(nextContainer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.Service.ID, ServiceVersion: &current.Service.Meta.Version, Spec: next}); err != nil {
			t.Fatal(err)
		}
	}
	serviceEventually(t, ctx, func() bool { return world.blocked.Load() >= 3 })
	for _, h := range hosts {
		p := world.process(h.job.Source.Task)
		if err := p.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatal("published intent stopped an unselected source", err)
		}
		stop, done := context.WithTimeout(ctx, 10*time.Second)
		err := h.node.Stop(stop)
		done()
		if err != nil {
			t.Fatal(err)
		}
		start(h) // same durable Raft/agent/store; external processes survive
	}
	defer func() {
		for _, h := range hosts {
			stop, done := context.WithTimeout(context.Background(), 10*time.Second)
			_ = h.node.Stop(stop)
			done()
		}
	}()
	for _, h := range hosts {
		if err := world.process(h.job.Source.Task).cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatal("daemon restart stopped unselected source", err)
		}
	}
	// Choose one follower. Both other regions and its ready owner must remain up.
	selected := hosts[1]
	serviceEventually(t, ctx, func() bool {
		selected.e.mu.Lock()
		defer selected.e.mu.Unlock()
		return selected.e.controllers[selected.job.Source.Task] != nil
	})
	client, err := hosts[0].node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &bootstrapRuntimeFixture{e: selected.e, client: client}
	if err := (rolloutmaintenance.Driver{Store: selected.e.raw.bootstrap, Runtime: runtime}).Replace(ctx, selected.job.ID); err != nil {
		t.Fatal(err)
	}
	old := world.process(selected.job.Source.Task)
	if !old.exit.Before(runtime.started) {
		t.Fatal("new admission preceded physical old exit")
	}
	for _, h := range hosts {
		if h == selected {
			continue
		}
		if err := world.process(h.job.Source.Task).cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatal("selected driver stopped another node", err)
		}
	}
	t.Logf("six_nodes_intent_fenced=true daemon_restarts=6 selected=%s physical_old_exit=%s new_admission=%s blocked_calls=%d", selected.job.Member, old.exit.Format(time.RFC3339Nano), runtime.started.Format(time.RFC3339Nano), world.blocked.Load())
}
