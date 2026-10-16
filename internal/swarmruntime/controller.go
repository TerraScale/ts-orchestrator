package swarmruntime

import (
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

	"github.com/containerd/containerd/api/types"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/opencontainers/image-spec/identity"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

type controller struct {
	executor    *Executor
	task        *api.Task
	spec        *api.ContainerSpec
	id          string
	fingerprint string
}

var _ exec.Controller = (*controller)(nil)
var _ exec.ContainerStatuser = (*controller)(nil)
var _ exec.ControllerLogs = (*controller)(nil)

func (c *controller) Update(_ context.Context, t *api.Task) error {
	if _, err := DecodeContainer(t); err != nil || t.ID != c.task.ID || taskFingerprint(t) != c.fingerprint {
		return exec.ErrTaskUpdateRejected
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
	return ctr, nil
}

func (c *controller) Prepare(ctx context.Context) error {
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ctx = runtimeContext(ctx)
	ctx, release, err := c.executor.client.WithLease(ctx)
	if err != nil {
		return err
	}
	defer release(ctx)
	ctr, err := c.container(ctx)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if errdefs.IsNotFound(err) {
		image, err := c.executor.client.Pull(ctx, c.spec.Image, containerd.WithPullUnpack, containerd.WithPullSnapshotter("native"))
		if err != nil {
			return fmt.Errorf("pull container image: %w", err)
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
		opts := []oci.SpecOpts{oci.WithProcessArgs(args...), oci.WithEnv(config.Config.Env), oci.WithEnv(c.spec.Env), oci.WithProcessCwd(cwd),
			oci.WithUIDGID(uint32(u), uint32(g)), oci.WithRootFSReadonly(), oci.WithNoNewPrivileges,
			oci.WithCapabilities(nil), seccomp.WithDefaultProfile(), oci.WithPidsLimit(256),
			oci.WithMemoryLimit(uint64(limits.MemoryBytes)), oci.WithMemorySwap(limits.MemoryBytes),
			oci.WithCPUCFS(limits.NanoCPUs/10_000, 100_000),
			oci.WithHostNamespace(runtimespec.NetworkNamespace),
		}
		if len(c.spec.Command) != 0 {
			opts = append(opts, oci.WithProcessArgs(append(slices.Clone(c.spec.Command), c.spec.Args...)...))
		}
		if c.spec.Dir != "" {
			opts = append(opts, oci.WithProcessCwd(c.spec.Dir))
		}
		ctr, err = c.executor.client.NewContainer(ctx, c.id,
			containerd.WithSnapshotter("native"),
			containerd.WithImage(image), containerd.WithRuntime("io.containerd.runc.v2", nil),
			containerd.WithContainerLabels(map[string]string{"terrascale.task": c.task.ID, "terrascale.service": c.task.ServiceID, "terrascale.spec": c.fingerprint}),
			containerd.WithNewSpec(opts...))
		if err != nil {
			return err
		}
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
		err = ctr.Update(ctx, containerd.UpdateContainerOpts(containerd.WithNewSnapshotView(c.id, image, snapshots.WithLabels(map[string]string{"terrascale.task": c.task.ID, "terrascale.spec": c.fingerprint}))))
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
			if snapshot.Labels["terrascale.task"] != c.task.ID || snapshot.Labels["terrascale.spec"] != c.fingerprint || snapshot.Kind != snapshots.KindView || snapshot.Parent != identity.ChainID(rootfs).String() {
				return fmt.Errorf("snapshot ownership or image conflicts with task")
			}
			err = ctr.Update(ctx, containerd.UpdateContainerOpts(containerd.WithSnapshot(c.id)))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *controller) Start(ctx context.Context) error {
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ctx = runtimeContext(ctx)
	ctr, err := c.container(ctx)
	if err != nil {
		return err
	}
	t, err := ctr.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		t, err = ctr.NewTask(ctx, cio.BinaryIO(c.executor.executable, map[string]string{"--runtime-logger": c.executor.logRoot}))
	}
	if err != nil {
		return err
	}
	status, err := t.Status(ctx)
	if err != nil {
		return err
	}
	switch status.Status {
	case containerd.Running:
		return exec.ErrTaskStarted
	case containerd.Created:
		return t.Start(ctx)
	case containerd.Stopped:
		return fmt.Errorf("durable task already exited with status %d", status.ExitStatus)
	default:
		return fmt.Errorf("unexpected runtime state %s", status.Status)
	}
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

func (c *controller) Wait(ctx context.Context) error {
	ctx = runtimeContext(ctx)
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case status := <-wait:
		code, _, err := status.Result()
		if err != nil {
			return err
		}
		return exitError(code)
	}
}

func (c *controller) Shutdown(ctx context.Context) error {
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
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	wait, err := t.Wait(waitCtx)
	if err != nil {
		return err
	}
	if err := t.Kill(ctx, syscall.SIGTERM, containerd.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitCtx.Done():
		return c.Terminate(ctx)
	case status := <-wait:
		_, _, err := status.Result()
		return err
	}
}

func (c *controller) Terminate(ctx context.Context) error {
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
	c.executor.mu.Lock()
	defer c.executor.mu.Unlock()
	ctx = runtimeContext(ctx)
	ctr, err := c.container(ctx)
	if errdefs.IsNotFound(err) {
		return os.RemoveAll(filepath.Join(c.executor.logRoot, c.id))
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
	return os.RemoveAll(filepath.Join(c.executor.logRoot, c.id))
}

func (c *controller) Close() error { return nil }

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
