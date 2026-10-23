package swarmruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"

	"github.com/containerd/containerd/api/types"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	gogotypes "github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/opencontainers/image-spec/identity"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

type controller struct {
	executor            *Executor
	task                *api.Task
	spec                *api.ContainerSpec
	id                  string
	fingerprint         string
	credentialExpiresAt time.Time
	stateful            *statefulController
	loadTerminal        bool // guarded by executor.mu
}

var _ exec.Controller = (*controller)(nil)
var _ exec.ContainerStatuser = (*controller)(nil)
var _ exec.ControllerLogs = (*controller)(nil)

func (c *controller) Update(_ context.Context, t *api.Task) error {
	if _, err := DecodeContainer(t); err != nil || t.ID != c.task.ID || taskFingerprint(t) != c.fingerprint {
		return exec.ErrTaskUpdateRejected
	}
	if taskLoadTerminalState(t.Status.State) {
		c.finishTaskLoad()
	}
	return nil
}

func (c *controller) container(ctx context.Context) (containerd.Container, error) {
	ctr, err := c.executor.client.LoadContainer(runtimeContext(ctx), c.id)
	if err != nil {
		return nil, err
	}
	labels, err := ctr.Labels(runtimeContext(ctx))
	if err != nil {
		return nil, err
	}
	if labels["terrascale.task"] != c.task.ID || labels["terrascale.service"] != c.task.ServiceID || labels["terrascale.spec"] != c.fingerprint {
		return nil, fmt.Errorf("container identity conflicts with task")
	}
	if c.stateful != nil && labels["terrascale.task-binding"] != c.fingerprint {
		return nil, execution.ErrUnsafe
	}
	return ctr, nil
}

func (c *controller) Prepare(ctx context.Context) (operationErr error) {
	defer func() { c.finishTaskLoadOperation(api.TaskStatePreparing, operationErr) }()
	defer func() { c.releaseFailedPorts(ctx, operationErr) }()
	defer func() { operationErr = canceledAsRetry(ctx, operationErr) }()
	if c.stateful != nil {
		if _, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins); !ok {
			return execution.ErrUnsafe
		}
	}
	c.executor.mu.Lock()
	if c.stateful == nil {
		c.executor.trackLoadTask(c)
	}
	backoff := c.executor.restartDelayLocked(c.task, c.fingerprint, time.Now())
	registry := c.executor.registry
	var node *api.Node
	if c.executor.node != nil {
		node = c.executor.node.Copy()
	}
	c.executor.mu.Unlock()
	if registry == nil {
		registry = publicRegistryResolver
	}
	if err := sleepContext(ctx, backoff); err != nil {
		return err
	}
	resolved, err := registry(runtimeContext(ctx), c.task.Copy(), node)
	if err != nil {
		return fmt.Errorf("resolve admitted container registry: %w", err)
	}
	if resolved == nil {
		return errors.New("registry admission returned no resolver")
	}
	// Pull and unpack outside executor.mu so tasks prepare in parallel; the
	// image record keeps the content, and the locked section re-verifies it.
	if _, err := c.container(ctx); errdefs.IsNotFound(err) {
		if err := c.diskAvailable(ctx); err != nil {
			return err
		}
		if err := c.executor.pullImage(ctx, c.spec.Image, resolved); err != nil {
			return fmt.Errorf("load admitted container image: %w", err)
		}
	}
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ports, unlock, err := c.reservePorts(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	ctx = runtimeContext(ctx)
	ctx, release, err := c.executor.client.WithLease(ctx)
	if err != nil {
		return err
	}
	defer release(ctx)
	materialMounts, err := c.functionMaterialMount(ctx)
	if err != nil {
		return err
	}
	containerMounts, containerEnv, err := c.containerMaterialMount(ctx)
	if err != nil {
		return err
	}
	dataMounts, err := c.dataMounts()
	if err != nil {
		return err
	}
	peersMounts, err := c.peersMount()
	if err != nil {
		return err
	}
	dataMounts = append(dataMounts, peersMounts...)
	ctr, err := c.container(ctx)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if errdefs.IsNotFound(err) {
		if err := c.diskAvailable(ctx); err != nil {
			return err
		}
		image, err := c.executor.client.GetImage(ctx, c.spec.Image)
		if err != nil {
			return fmt.Errorf("load admitted container image: %w", err)
		}
		_, pinned, _ := strings.Cut(c.spec.Image, "@")
		if image.Target().Digest.String() != pinned {
			return errors.New("container image target differs from pinned digest")
		}
		if image.Target().MediaType != imagespec.MediaTypeImageManifest && image.Target().MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
			return fmt.Errorf("container image must pin an architecture-specific child manifest")
		}
		config, err := image.Spec(ctx)
		if err != nil {
			return err
		}
		if config.OS != "linux" || config.Architecture != runtime.GOARCH {
			return fmt.Errorf("container image architecture does not match host")
		}
		if unpacked, err := image.IsUnpacked(ctx, imageSnapshotter); err != nil || !unpacked {
			return errors.Join(errors.New("container image is not unpacked"), err)
		}
		uid, gid, _ := strings.Cut(c.spec.User, ":")
		u, _ := strconv.ParseUint(uid, 10, 32)
		g, _ := strconv.ParseUint(gid, 10, 32)
		limits := c.task.Spec.Resources.Limits
		args := config.Config.Cmd
		if len(c.spec.Args) != 0 {
			args = c.spec.Args
		}
		args = append(slices.Clone(config.Config.Entrypoint), args...)
		cwd := config.Config.WorkingDir
		if cwd == "" {
			cwd = "/"
		}
		env := c.spec.Env
		if c.stateful == nil && usesTaskPort(env) {
			port, err := c.pickTaskPort(ctx)
			if err != nil {
				return err
			}
			ports, env = strconv.Itoa(int(port)), withTaskPort(env, port)
		}
		opts := []oci.SpecOpts{oci.WithProcessArgs(args...), oci.WithEnv(config.Config.Env), oci.WithEnv(env), oci.WithProcessCwd(cwd),
			oci.WithUIDGID(uint32(u), uint32(g)), oci.WithRootFSReadonly(), oci.WithNoNewPrivileges,
			oci.WithCapabilities(nil), seccomp.WithDefaultProfile(), oci.WithPidsLimit(256),
			oci.WithMemoryLimit(uint64(limits.MemoryBytes)), oci.WithMemorySwap(limits.MemoryBytes),
			oci.WithCPUCFS(limits.NanoCPUs/10_000, 100_000),
			// Host netns, so the host's resolvers (including the 127.0.0.53 stub) are reachable as-is.
			oci.WithHostNamespace(runtimespec.NetworkNamespace), oci.WithHostResolvconf, oci.WithHostHostsFile,
			// The root is read-only; runtimes such as .NET single-file apps need a scratch
			// directory. tmpfs pages count against the task's own memory limit.
			oci.WithMounts([]runtimespec.Mount{{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs",
				Options: []string{"nosuid", "nodev", "mode=1777", "size=1g"}}}),
		}
		if len(c.spec.Command) != 0 {
			opts = append(opts, oci.WithProcessArgs(append(slices.Clone(c.spec.Command), c.spec.Args...)...))
		}
		if c.spec.Dir != "" {
			opts = append(opts, oci.WithProcessCwd(c.spec.Dir))
		}
		if len(materialMounts) != 0 {
			opts = append(opts, oci.WithMounts(materialMounts))
		}
		if len(containerMounts) != 0 {
			opts = append(opts, oci.WithMounts(containerMounts), oci.WithEnv(containerEnv))
		}
		if len(dataMounts) != 0 {
			opts = append(opts, oci.WithMounts(dataMounts))
		}
		labels := map[string]string{"terrascale.task": c.task.ID, "terrascale.service": c.task.ServiceID, "terrascale.spec": c.fingerprint, portsLabel: cmp.Or(ports, releasedPorts), credentialExpiryLabel: c.credentialExpiryLabel()}
		if c.diskAccounted() {
			witness, err := c.prepareDisk(ctx, image)
			if err != nil {
				return err
			}
			labels[diskBytesLabel] = strconv.FormatInt(witness.DiskBytes, 10)
			labels[diskImageBytesLabel] = strconv.FormatInt(witness.ImageBytes, 10)
		}
		if c.stateful != nil {
			qualified, err := c.stateful.specOption(ctx)
			if err != nil {
				return err
			}
			opts = append(opts, qualified)
			labels["terrascale.task-binding"] = c.fingerprint
		}
		ctr, err = c.executor.client.NewContainer(ctx, c.id,
			containerd.WithSnapshotter(imageSnapshotter),
			containerd.WithImage(image), containerd.WithRuntime("io.containerd.runc.v2", nil),
			containerd.WithContainerLabels(labels),
			containerd.WithNewSpec(opts...))
		if err != nil {
			return err
		}
	}
	if err := c.verifyFunctionMount(ctx, ctr, materialMounts); err != nil {
		return err
	}
	if c.stateful != nil {
		if err := c.stateful.verifySpec(ctx, ctr); err != nil {
			return err
		}
	}
	if err := c.verifyContainerMaterial(ctx, ctr, containerMounts, containerEnv); err != nil {
		return err
	}
	info, err := ctr.Info(ctx)
	if err != nil {
		return err
	}
	if info.SnapshotKey == "" {
		image, err := ctr.Image(ctx)
		if err != nil {
			return err
		}
		// Metadata owns the identity before snapshot creation, so an interrupted prepare can resume.
		// Active, not a view: runc creates bind-mount targets in it before remounting the root read-only.
		err = ctr.Update(ctx, containerd.UpdateContainerOpts(containerd.WithNewSnapshot(c.id, image, snapshots.WithLabels(map[string]string{"terrascale.task": c.task.ID, "terrascale.spec": c.fingerprint}))))
		if errdefs.IsAlreadyExists(err) {
			store := c.executor.client.SnapshotService(info.Snapshotter)
			snapshot, statErr := store.Stat(ctx, c.id)
			if statErr != nil {
				return statErr
			}
			rootfs, rootErr := image.RootFS(ctx)
			if rootErr != nil {
				return rootErr
			}
			if snapshot.Labels["terrascale.task"] != c.task.ID || snapshot.Labels["terrascale.spec"] != c.fingerprint || snapshot.Kind != snapshots.KindActive || snapshot.Parent != identity.ChainID(rootfs).String() {
				return fmt.Errorf("snapshot ownership or image conflicts with task")
			}
			err = ctr.Update(ctx, containerd.UpdateContainerOpts(containerd.WithSnapshot(c.id)))
		}
		if err != nil {
			return err
		}
	}
	return c.verifyDisk(ctx, ctr)
}

func (c *controller) Start(ctx context.Context) (operationErr error) {
	defer func() { c.finishTaskLoadOperation(api.TaskStateStarting, operationErr) }()
	defer func() { c.releaseFailedPorts(ctx, operationErr) }()
	defer func() { operationErr = canceledAsRetry(ctx, operationErr) }()
	if err := c.start(ctx); err != nil {
		return err
	}
	return c.awaitReady(ctx)
}

// awaitReady holds a task whose spec names a readyPath in STARTING until the
// path answers 200, so SwarmKit counts a never-ready update as a failed task
// and rolls back to the previous spec. It runs outside executor.mu.
func (c *controller) awaitReady(ctx context.Context) error {
	if c.stateful != nil {
		return nil
	}
	if _, named := c.spec.Labels[LabelReadyPath]; !named {
		return nil
	}
	timeout := ReadyTimeout(c.task.ServiceAnnotations.Labels)
	ctx = runtimeContext(ctx)
	t, err := c.runtimeTask(ctx)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	exited, err := t.Wait(waitCtx)
	if err != nil {
		return err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(readyPoll)
	defer tick.Stop()
	port, portErr := hostPort(c.task)
	probed := port
	service, task, taskPort := c.taskPorts(ctx)
	if taskPort {
		probed = task
	}
	for {
		probeErr := portErr
		if probeErr == nil {
			probeErr = probeLocalPort(ctx, c.task, probed)
		}
		if probeErr == nil {
			if taskPort {
				// Serve before SwarmKit sees RUNNING and stops the predecessor.
				handoff.Serve(service, task)
			}
			handoff.Release(port)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case status := <-exited:
			code, _, _ := status.Result()
			return fmt.Errorf("container exited with status %d before it was ready", code)
		case <-deadline.C:
			// Stop (gracefully: it may own data) before failing so the rollback's task can start.
			return errors.Join(fmt.Errorf("not ready within %s: %w", timeout, probeErr), c.stopTask(ctx))
		case <-tick.C:
		}
	}
}

// readyPoll bounds how late a ready task leaves STARTING.
const readyPoll = 100 * time.Millisecond

func (c *controller) start(ctx context.Context) error {
	if c.stateful != nil {
		if _, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins); !ok {
			return execution.ErrUnsafe
		}
	}
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ctx = runtimeContext(ctx)
	materialMounts, err := c.functionMaterialMount(ctx)
	if err != nil {
		return err
	}
	containerMounts, containerEnv, err := c.containerMaterialMount(ctx)
	if err != nil {
		return err
	}
	ctr, err := c.container(ctx)
	if err != nil {
		return err
	}
	if err := c.verifyFunctionMount(ctx, ctr, materialMounts); err != nil {
		return err
	}
	if err := c.verifyContainerMaterial(ctx, ctr, containerMounts, containerEnv); err != nil {
		return err
	}
	if err := c.verifyDisk(ctx, ctr); err != nil {
		return err
	}
	t, err := ctr.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		loggerArgument, loggerErr := c.runtimeLoggerArgument(ctx)
		if loggerErr != nil {
			return loggerErr
		}
		uri, uriErr := cio.LogURIGenerator("binary-v2", c.executor.executable, map[string]string{"--runtime-logger": loggerArgument})
		if uriErr != nil {
			return uriErr
		}
		t, err = ctr.NewTask(ctx, cio.LogURI(uri))
	}
	if err != nil {
		return err
	}
	status, err := t.Status(ctx)
	if err != nil {
		return err
	}
	if c.stateful != nil && (status.Status == containerd.Created || status.Status == containerd.Running) {
		if err := c.stateful.observe(ctx); err != nil {
			return err
		}
	}
	switch status.Status {
	case containerd.Running:
		return exec.ErrTaskStarted
	case containerd.Created:
		if c.diskAccounted() {
			witness, err := readDiskWitness(c.executor.logRoot, c.id)
			if err != nil {
				return err
			}
			available, err := c.executor.diskCapacity(ctx)
			if err != nil || available < witness.LogBytes {
				return errors.Join(ErrDiskPending, err)
			}
		}
		if err := c.waitRuntimeCredentialGuard(ctx, ctr, t.Pid()); err != nil {
			return err
		}
		if !c.credentialExpiresAt.IsZero() && !c.credentialExpiresAt.After(time.Now()) {
			return ErrContainerMaterialPending
		}
		// The predecessor of a replacement may still be exiting; never start a second port owner.
		_, unlock, err := c.reservePorts(ctx, true)
		if err != nil {
			return err
		}
		defer unlock()
		if err := t.Start(ctx); err != nil {
			return err
		}
		if c.stateful != nil {
			return c.stateful.observe(ctx)
		}
		return nil
	case containerd.Stopped:
		return fmt.Errorf("durable task already exited with status %d", status.ExitStatus)
	default:
		return fmt.Errorf("unexpected runtime state %s", status.Status)
	}
}

// dataMounts ensures each bind source is a directory owned by the non-root container user.
// os.Root keeps symlinks planted under DataRoot from redirecting the mkdir or chown.
func (c *controller) dataMounts() ([]runtimespec.Mount, error) {
	if len(c.spec.Mounts) == 0 {
		return nil, nil
	}
	if c.stateful != nil {
		return nil, errors.New("stateful tasks receive volumes only through their qualified hooks")
	}
	if err := os.MkdirAll(DataRoot, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(DataRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	uid, gid, _ := strings.Cut(c.spec.User, ":")
	u, _ := strconv.Atoi(uid)
	g, _ := strconv.Atoi(gid)
	mounts := make([]runtimespec.Mount, 0, len(c.spec.Mounts))
	for _, m := range c.spec.Mounts {
		name := strings.TrimPrefix(m.Source, DataRoot+"/")
		if err := root.MkdirAll(name, 0o700); err != nil {
			return nil, fmt.Errorf("create bind mount source: %w", err)
		}
		if info, err := root.Lstat(name); err != nil || !info.IsDir() {
			return nil, errors.New("bind mount source is not a directory")
		}
		if err := root.Lchown(name, u, g); err != nil {
			return nil, fmt.Errorf("own bind mount source: %w", err)
		}
		mode := "rw"
		if m.ReadOnly {
			mode = "ro"
		}
		mounts = append(mounts, runtimespec.Mount{Destination: m.Target, Type: "bind", Source: m.Source, Options: []string{"rbind", mode, "nosuid", "nodev"}})
	}
	return mounts, nil
}

func (c *controller) runtimeTask(ctx context.Context) (containerd.Task, error) {
	ctr, err := c.container(ctx)
	if err != nil {
		return nil, err
	}
	return ctr.Task(runtimeContext(ctx), nil)
}

type taskExitError uint32

func (e taskExitError) Error() string { return fmt.Sprintf("container exited with status %d", e) }
func (e taskExitError) ExitCode() int { return int(e) }
func exitError(code uint32) error {
	if code == 0 {
		return nil
	}
	return taskExitError(code)
}

func (c *controller) Wait(ctx context.Context) (operationErr error) {
	defer func() { c.finishTaskLoadOperation(api.TaskStateRunning, operationErr) }()
	ctx = runtimeContext(ctx)
	started := time.Now()
	t, err := c.runtimeTask(ctx)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wait, err := t.Wait(waitCtx)
	if err != nil {
		return err
	}
	// A canceled Wait (any task update) keeps serving; exit and stopTask end it.
	unserve := c.serve(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case status := <-wait:
		code, exited, err := status.Result()
		if err != nil {
			return err // a canceled wait, not an exit
		}
		unserve()
		c.executor.mu.Lock()
		c.executor.recordExitLocked(c.task, c.fingerprint, exited.Sub(started), time.Now())
		c.executor.mu.Unlock()
		if code != 0 && c.oomKilled(ctx) {
			return taskOOMError{code: code, limitMiB: c.task.Spec.Resources.Limits.MemoryBytes >> 20}
		}
		return exitError(code)
	}
}

func (c *controller) Shutdown(ctx context.Context) (operationErr error) {
	defer func() { c.finishTaskLoadOperation(api.TaskStateShutdown, operationErr) }()
	if c.stateful != nil {
		if _, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins); !ok {
			return execution.ErrUnsafe
		}
	}
	return c.stopTask(ctx)
}

// stopTask sends SIGTERM and SIGKILLs only after stopGrace; it returns once
// the process is gone, so a replacement can take the port and the data.
func (c *controller) stopTask(ctx context.Context) error {
	ctx = runtimeContext(ctx)
	t, err := c.runtimeTask(ctx)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := t.Status(ctx)
	if err != nil {
		return err
	}
	if status.Status == containerd.Stopped {
		return nil
	}
	if status.Status == containerd.Created {
		return c.Terminate(ctx)
	}
	wait, err := t.Wait(ctx)
	if err != nil {
		return err
	}
	if service, task, ok := c.taskPorts(ctx); ok {
		// Its successor (or nobody, on removal) takes new connections; in-flight ones drain.
		handoff.Unserve(service, task)
	} else if _, named := c.spec.Labels[LabelReadyPath]; named && c.stateful == nil {
		// The edge holds new requests for the port until a replacement is ready.
		if port, err := hostPort(c.task); err == nil {
			handoff.Hold(port)
		}
	}
	if err := t.Kill(ctx, syscall.SIGTERM, containerd.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	grace := time.NewTimer(c.stopGrace())
	defer grace.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case status := <-wait:
		_, _, err := status.Result()
		return err
	case <-grace.C:
	}
	if err := c.Terminate(ctx); err != nil {
		return err
	}
	// Report SHUTDOWN only once the process is gone, so its replacement can bind the port.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wait:
		return nil
	}
}

// A replacement waits on this exit, so the default stays short; a spec may ask
// for more, up to the SIGKILL bound. Stateful tasks always get the full bound.
const (
	defaultStopGrace = 5 * time.Second
	maxStopGrace     = 10 * time.Second
	// A task that owns data (bind mounts or qualified volumes) flushes on
	// SIGTERM; a SIGKILL mid-write can lose acked TerraBase writes.
	dataStopGrace = 2 * time.Minute
)

func (c *controller) stopGrace() time.Duration {
	if c.stateful != nil || len(c.spec.Mounts) != 0 {
		return dataStopGrace
	}
	if c.spec.StopGracePeriod == nil {
		return defaultStopGrace
	}
	grace, err := gogotypes.DurationFromProto(c.spec.StopGracePeriod)
	if err != nil || grace <= 0 {
		return defaultStopGrace
	}
	return min(grace, maxStopGrace)
}

func (c *controller) Terminate(ctx context.Context) error {
	if c.stateful != nil {
		if _, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins); !ok {
			return execution.ErrUnsafe
		}
	}
	t, err := c.runtimeTask(ctx)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := t.Status(runtimeContext(ctx))
	if err != nil {
		return err
	}
	if status.Status == containerd.Stopped {
		return nil
	}
	err = t.Kill(runtimeContext(ctx), syscall.SIGKILL, containerd.WithKillAll)
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *controller) Remove(ctx context.Context) error {
	if c.stateful != nil {
		if _, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins); !ok {
			return execution.ErrUnsafe
		}
	}
	// Delete below kills a live process; give a data-owning one its grace first.
	if len(c.spec.Mounts) != 0 {
		if err := c.stopTask(ctx); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ctx = runtimeContext(ctx)
	ctr, err := c.container(ctx)
	if errdefs.IsNotFound(err) {
		return errors.Join(c.removeDiskLogs(), os.RemoveAll(c.functionMaterialPath()), os.RemoveAll(c.containerMaterialPath()))
	}
	if err != nil {
		return err
	}
	t, err := ctr.Task(ctx, nil)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if err == nil {
		if _, err := t.Delete(ctx, containerd.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}
	info, err := ctr.Info(ctx)
	if err != nil {
		return err
	}
	if info.SnapshotKey == "" {
		store := c.executor.client.SnapshotService(info.Snapshotter)
		snapshot, err := store.Stat(ctx, c.id)
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		if err == nil {
			if snapshot.Labels["terrascale.task"] != c.task.ID || snapshot.Labels["terrascale.spec"] != c.fingerprint {
				return fmt.Errorf("orphan snapshot ownership conflicts with task")
			}
			if err := store.Remove(ctx, c.id); err != nil {
				return err
			}
		}
	}
	if err := ctr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
		return err
	}
	return errors.Join(c.removeDiskLogs(), os.RemoveAll(c.functionMaterialPath()), os.RemoveAll(c.containerMaterialPath()))
}

func (c *controller) Close() error {
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	if c.executor.loadTasks[c.task.ID] == c {
		delete(c.executor.loadTasks, c.task.ID)
	}
	return nil
}

func (c *controller) ContainerStatus(ctx context.Context) (*api.ContainerStatus, error) {
	t, err := c.runtimeTask(ctx)
	if err != nil {
		return nil, err
	}
	s, err := t.Status(runtimeContext(ctx))
	if err != nil {
		return nil, err
	}
	return &api.ContainerStatus{ContainerID: c.id, PID: int32(t.Pid()), ExitCode: int32(s.ExitStatus)}, nil
}

func (c *controller) Metrics(ctx context.Context) (*types.Metric, error) {
	t, err := c.runtimeTask(ctx)
	if err != nil {
		return nil, err
	}
	return t.Metrics(runtimeContext(ctx))
}

// shortcut: snapshots omit original timestamps; frame records before adding time-filtered log subscriptions.
func (c *controller) Logs(ctx context.Context, publisher exec.LogPublisher, options api.LogSubscriptionOptions) error {
	if options.Follow || options.Since != nil || options.Tail != 0 {
		return fmt.Errorf("runtime logs support bounded snapshots only")
	}
	for _, stream := range []struct {
		name string
		kind api.LogStream
	}{{"stdout", api.LogStreamStdout}, {"stderr", api.LogStreamStderr}} {
		if len(options.Streams) != 0 && !slices.Contains(options.Streams, stream.kind) {
			continue
		}
		f, err := os.Open(filepath.Join(c.executor.logRoot, c.id, stream.name))
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(f, logSegmentBytes))
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		for len(data) > 0 {
			n := min(len(data), 16<<10)
			if err := publisher.Publish(ctx, api.LogMessage{Context: api.LogContext{NodeID: c.task.NodeID, ServiceID: c.task.ServiceID, TaskID: c.task.ID}, Stream: stream.kind, Data: data[:n]}); err != nil {
				return err
			}
			data = data[n:]
		}
	}
	return nil
}

// canceledAsRetry returns the bare context error when the agent canceled the
// operation (it does on every task update). SwarmKit retries only an unwrapped
// context.Canceled; a wrapped one failed every long image pull as fatal.
func canceledAsRetry(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
