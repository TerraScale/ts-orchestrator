package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"golang.org/x/sys/unix"
)

const credentialExpiryLabel = "terrascale.credential-expires-at"
const runtimeGuardPIDLabel = "terrascale.runtime-guard-pid"

type runtimeCredentialGuard struct {
	Socket              string                `json:"socket"`
	TaskID              string                `json:"taskID"`
	Fingerprint         string                `json:"fingerprint"`
	CredentialExpiresAt time.Time             `json:"credentialExpiresAt,omitzero"`
	State               *StatefulRuntimeGuard `json:"state,omitzero"`
}

type runtimeLoggerInvocation struct {
	Root  string                 `json:"root"`
	Guard runtimeCredentialGuard `json:"guard"`
	Disk  *runtimeDiskWitness    `json:"disk,omitzero"`
}

func (c *controller) credentialExpiryLabel() string {
	if c.credentialExpiresAt.IsZero() {
		return ""
	}
	return c.credentialExpiresAt.UTC().Format(time.RFC3339Nano)
}

func (c *controller) runtimeLoggerArgument(ctx context.Context) (string, error) {
	state, err := c.statefulRuntimeGuard(ctx)
	if err != nil {
		return "", err
	}
	var disk *runtimeDiskWitness
	if c.diskAccounted() {
		witness, err := readDiskWitness(c.executor.logRoot, c.id)
		if err != nil || witness.Fingerprint != c.fingerprint || witness.Image != c.spec.Image {
			return "", errors.Join(ErrDiskPending, err)
		}
		disk = &witness
	}
	if c.credentialExpiresAt.IsZero() && state == nil && disk == nil {
		return c.executor.logRoot, nil
	}
	invocation := runtimeLoggerInvocation{Root: c.executor.logRoot, Disk: disk}
	if !c.credentialExpiresAt.IsZero() || state != nil {
		invocation.Guard = runtimeCredentialGuard{Socket: c.executor.socket, TaskID: c.id, Fingerprint: c.fingerprint, CredentialExpiresAt: c.credentialExpiresAt, State: state}
	}
	data, err := json.Marshal(invocation)
	return string(data), err
}

func parseRuntimeLoggerInvocation(argument string) (string, *runtimeCredentialGuard, *runtimeDiskWitness, error) {
	if filepath.IsAbs(argument) {
		return argument, nil, nil, nil
	}
	var invocation runtimeLoggerInvocation
	if err := json.Unmarshal([]byte(argument), &invocation, json.RejectUnknownMembers(true)); err != nil {
		return "", nil, nil, err
	}
	guard := invocation.Guard
	if !filepath.IsAbs(invocation.Root) || invocation.Disk != nil && !invocation.Disk.valid() {
		return "", nil, nil, ErrDiskPending
	}
	if guard == (runtimeCredentialGuard{}) && invocation.Disk != nil {
		return invocation.Root, nil, invocation.Disk, nil
	}
	if !filepath.IsAbs(invocation.Root) || !filepath.IsAbs(guard.Socket) || guard.TaskID == "" || guard.Fingerprint == "" || guard.CredentialExpiresAt.IsZero() && guard.State == nil || !guard.CredentialExpiresAt.IsZero() && !guard.CredentialExpiresAt.After(time.Now()) {
		return "", nil, nil, errors.New("invalid immutable runtime credential guard")
	}
	if invocation.Disk != nil && (invocation.Disk.TaskID != guard.TaskID || invocation.Disk.Fingerprint != guard.Fingerprint) {
		return "", nil, nil, ErrDiskPending
	}
	if guard.State != nil {
		if guard.State.TaskSHA256 != guard.Fingerprint {
			return "", nil, nil, errors.New("stateful guard differs from exact task binding")
		}
		if _, _, err := verifyStatefulRuntimeGuard(*guard.State, guard.State.Revision, guard.State.Deadline); err != nil {
			return "", nil, nil, err
		}
	}
	// Fail before logger readiness if this kernel cannot pin the exact process.
	fd, err := unix.PidfdOpen(unix.Getpid(), 0)
	if err != nil {
		return "", nil, nil, fmt.Errorf("pin runtime credential guard: %w", err)
	}
	_ = unix.Close(fd)
	return invocation.Root, &guard, invocation.Disk, nil
}

// The shim owns this logger process, so credential expiry survives agent exit.
func guardRuntimeCredential(ctx context.Context, guard runtimeCredentialGuard) error {
	client, err := containerd.New(guard.Socket, containerd.WithDefaultNamespace(runtimeNamespace))
	if err != nil {
		return err
	}
	defer client.Close()
	ctx = runtimeContext(ctx)
	var fd int
	var bound containerd.Container
	var pid uint32
	for {
		ctr, err := client.LoadContainer(ctx, guard.TaskID)
		if err == nil {
			labels, labelErr := ctr.Labels(ctx)
			if labelErr != nil {
				return labelErr
			}
			expiry := ""
			if !guard.CredentialExpiresAt.IsZero() {
				expiry = guard.CredentialExpiresAt.UTC().Format(time.RFC3339Nano)
			}
			if labels["terrascale.spec"] != guard.Fingerprint || labels[credentialExpiryLabel] != expiry {
				return errors.New("runtime credential guard task identity changed")
			}
			task, taskErr := ctr.Task(ctx, nil)
			if taskErr == nil && task.Pid() != 0 {
				if err := verifyRuntimeGuardCgroup(task.Pid(), guard.TaskID); err != nil {
					return err
				}
				fd, err = unix.PidfdOpen(int(task.Pid()), 0)
				if err != nil {
					if errors.Is(err, unix.ESRCH) {
						return nil
					}
					return err
				}
				bound, pid = ctr, task.Pid()
				break
			}
			if taskErr != nil && !errdefs.IsNotFound(taskErr) {
				return taskErr
			}
		} else if !errdefs.IsNotFound(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unix.Close(fd)
	if err := verifyRuntimeGuardCgroup(pid, guard.TaskID); err != nil {
		return err
	}
	// Returning early must not leave a credential consumer without its guardian.
	defer unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	if _, err := bound.SetLabels(ctx, map[string]string{runtimeGuardPIDLabel: fmt.Sprintf("%s:%d", guard.Fingerprint, pid)}); err != nil {
		return err
	}
	var revision uint64
	var leaseDeadline time.Time
	if guard.State != nil {
		revision, leaseDeadline = guard.State.Revision, guard.State.Deadline
	}
	for {
		deadline := guard.CredentialExpiresAt
		if guard.State != nil {
			var err error
			leaseDeadline, revision, err = verifyStatefulRuntimeGuard(*guard.State, revision, leaseDeadline)
			if err != nil {
				return err
			}
			if deadline.IsZero() || leaseDeadline.Before(deadline) {
				deadline = leaseDeadline
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
			return nil
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, int(min(remaining.Milliseconds()+1, 1000)))
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (c *controller) waitRuntimeCredentialGuard(ctx context.Context, ctr containerd.Container, pid uint32) error {
	state, err := c.statefulRuntimeGuard(ctx)
	if err != nil {
		return err
	}
	if c.credentialExpiresAt.IsZero() && state == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	expected := fmt.Sprintf("%s:%d", c.fingerprint, pid)
	for {
		if !c.credentialExpiresAt.IsZero() && !c.credentialExpiresAt.After(time.Now()) {
			return ErrContainerMaterialPending
		}
		labels, err := ctr.Labels(ctx)
		if err != nil {
			return err
		}
		if labels[runtimeGuardPIDLabel] == expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("credential guardian did not pin created task: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func verifyRuntimeGuardCgroup(pid uint32, taskID string) error {
	actual, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	if string(actual) != "0::/terrascale/"+taskID+"\n" {
		return errors.New("runtime credential guard process left its exact task cgroup")
	}
	return nil
}
