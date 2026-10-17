//go:build linux

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

// ObservedRuntimeStop can only be produced from this session's actual runtime.
type ObservedRuntimeStop struct {
	payload      executionwire.RuntimeStopPayload
	closingGrant protocol.Envelope
	observed     bool
}

func (o ObservedRuntimeStop) ClosingGrant() (protocol.Envelope, error) {
	if !o.observed {
		return protocol.Envelope{}, ErrUnsafe
	}
	grant := o.closingGrant
	grant.Payload = grant.Payload.Clone()
	return grant, nil
}

func (o ObservedRuntimeStop) Payload() (executionwire.RuntimeStopPayload, error) {
	if !o.observed {
		return executionwire.RuntimeStopPayload{}, ErrUnsafe
	}
	return o.payload, nil
}

// RuntimeStopSigner signs a sealed observation; signatures alone grant no authority.
type RuntimeStopSigner interface {
	SignRuntimeStop(context.Context, ObservedRuntimeStop) (executionwire.SignedRuntimeStop, error)
}

func (s *WorkerSession) BindRuntimeStopSigner(signer RuntimeStopSigner) error {
	if s == nil || signer == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	if s.stopSigner != nil || len(s.tasks) != 0 {
		s.mu.Unlock()
		return ErrUnsafe
	}
	s.stopSigner = signer
	s.mu.Unlock()
	s.startRecovery()
	return nil
}

// ObserveRuntimeStop requires a new manager challenge after the latest deadline;
// absence without a previously observed exact process is never a stopped proof.
func (s *WorkerSession) ObserveRuntimeStop(ctx context.Context, task *api.Task, grant VerifiedWorkerGrant, challenge string) (ObservedRuntimeStop, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || task == nil || challenge == "" || challenge != grant.payload.StopChallenge ||
		grant.payload.Phase != "closing" || !grant.challengeIssuedAt.After(grant.Deadline()) || time.Since(grant.challengeIssuedAt) > 10*time.Second ||
		time.Now().Before(grant.Deadline()) {
		return ObservedRuntimeStop{}, ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil {
		return ObservedRuntimeStop{}, err
	}
	s.mu.Lock()
	held := s.tasks[hash]
	if held == nil || !held.closing || held.pins == nil || grant.AdmissionSHA256() != held.grant.AdmissionSHA256() ||
		grant.Revision() != held.grant.Revision() || !grant.Deadline().Equal(held.grant.Deadline()) || grant.Identity() != held.grant.Identity() {
		s.mu.Unlock()
		return ObservedRuntimeStop{}, ErrUnsafe
	}
	pins, observed := *held.pins, held.observation
	s.mu.Unlock()
	if observed.ContainerID != "ts-"+task.ID || observed.Process.PID < 2 || observed.Process.KernelStart == "" ||
		observed.Process.Cgroup != "0::/terrascale/"+observed.ContainerID+"\n" || observed.PIDNamespace == 0 || observed.MountNamespace == 0 {
		return ObservedRuntimeStop{}, ErrUnsafe
	}
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	verify := func() error {
		container, err := s.client.LoadContainer(ctx, observed.ContainerID)
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		if err == nil {
			info, err := container.Info(ctx)
			if err != nil {
				return err
			}
			if info.ID != observed.ContainerID || info.Image != pins.Image || info.Runtime.Name != "io.containerd.runc.v2" ||
				info.Labels["terrascale.task"] != task.ID || info.Labels["terrascale.service"] != task.ServiceID ||
				info.Labels["terrascale.spec"] != hash || info.Labels["terrascale.task-binding"] != hash {
				return ErrUnsafe
			}
			spec, err := container.Spec(ctx)
			if err != nil {
				return err
			}
			if err := verifyRuntimeSpec(spec, pins, observed.ContainerID); err != nil {
				return err
			}
			process, err := container.Task(ctx, nil)
			if err != nil && !errdefs.IsNotFound(err) {
				return err
			}
			if err == nil {
				status, err := process.Status(ctx)
				if err != nil || status.Status != containerd.Stopped || process.Pid() != 0 && int(process.Pid()) != observed.Process.PID {
					return errors.Join(ErrUnsafe, err)
				}
			}
		}
		if err := originalProcessStopped(observed.Process.PID, observed.Process.KernelStart); err != nil {
			return err
		}
		// populated covers descendants as well as the already observed init.
		data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/terrascale", observed.ContainerID, "cgroup.events"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !strings.Contains("\n"+string(data), "\npopulated 0\n") {
			return ErrUnsafe
		}
		return ctx.Err()
	}
	if err := verify(); err != nil {
		return ObservedRuntimeStop{}, err
	}
	if err := verify(); err != nil {
		return ObservedRuntimeStop{}, err
	}
	now := time.Now().UTC()
	if ctx.Err() != nil || now.Before(grant.challengeIssuedAt) {
		return ObservedRuntimeStop{}, ErrUnsafe
	}
	closingGrant := grant.envelope
	closingGrant.Payload = closingGrant.Payload.Clone()
	wire, err := json.Marshal(closingGrant, json.Deterministic(true))
	if err != nil {
		return ObservedRuntimeStop{}, err
	}
	return ObservedRuntimeStop{observed: true, closingGrant: closingGrant, payload: executionwire.RuntimeStopPayload{
		ClosingGrantSHA256: fmt.Sprintf("%x", sha256.Sum256(wire)),
		EffectID:           grant.EffectID(), TaskSHA256: hash, InstanceID: s.identity.InstanceID, NodeID: s.identity.NodeID,
		ContainerID: observed.ContainerID, KernelStart: observed.Process.KernelStart, Cgroup: observed.Process.Cgroup,
		Challenge: challenge, Epoch: grant.Epoch(), Revision: grant.Revision(), PIDNamespace: observed.PIDNamespace,
		MountNamespace: observed.MountNamespace, HostPID: observed.Process.PID, Deadline: grant.Deadline(), ObservedAt: now,
	}}, nil
}

func originalProcessStopped(pid int, start string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, rest, ok := strings.CutLast(string(data), ") ")
	fields := strings.Fields(rest)
	if !ok || len(fields) < 20 {
		return ErrUnsafe
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return ErrUnsafe
	}
	if fields[19] != start || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return nil
	}
	return ErrUnsafe
}
