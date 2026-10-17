package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// TaskReadinessWitness retains the first Source observation's original lifetime.
// Only CaptureTaskReadiness can construct a usable witness.
type TaskReadinessWitness struct {
	deadline time.Time
	recheck  func(context.Context) error
}

func (w *TaskReadinessWitness) Deadline() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.deadline
}

func (w *TaskReadinessWitness) Recheck(ctx context.Context) error {
	if w == nil || w.recheck == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(w.deadline) {
		return authority.ErrFenced
	}
	ctx, cancel := context.WithDeadline(ctx, w.deadline)
	defer cancel()
	if err := w.recheck(ctx); err != nil {
		return err
	}
	if !time.Now().Before(w.deadline) {
		return authority.ErrFenced
	}
	return ctx.Err()
}

func (s *EffectSessions) CheckTaskReadiness(ctx context.Context, task *api.Task, hosts *host.Controller) error {
	_, err := s.CaptureTaskReadiness(ctx, task, hosts)
	return err
}

// CaptureTaskReadiness independently verifies current DATA authority around a
// nonce-bound Source observation. Neither Swarm running nor an execution hold
// alone establishes serving readiness.
func (s *EffectSessions) CaptureTaskReadiness(ctx context.Context, task *api.Task, hosts *host.Controller) (*TaskReadinessWitness, error) {
	if task == nil || hosts == nil || task.Status.State != api.TaskStateRunning {
		return nil, errors.New("running stateful task unavailable")
	}
	task = task.Copy()
	epoch, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.recover(ctx, epoch); err != nil {
		return nil, err
	}
	hash, err := executionwire.TaskSHA256(task)
	if err != nil {
		return nil, err
	}
	effects, err := s.authority.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil {
		return nil, err
	}
	var original *authority.RuntimeEffect
	for i := range effects {
		if effects[i].TaskID != task.ID {
			continue
		}
		if original != nil {
			return nil, errors.New("stateful task has ambiguous unresolved effects")
		}
		original = &effects[i]
	}
	if original == nil || original.TaskSHA256 != hash || original.ServiceID != task.ServiceID || original.NodeID != task.NodeID ||
		original.Phase != authority.RuntimeEffectHeld || original.Epoch != epoch || !time.Now().Before(original.ExpiresAt) {
		return nil, authority.ErrFenced
	}
	material, err := runtimeMaterial(*original)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, original.ExpiresAt)
	defer cancel()
	verify := func(check context.Context, caller host.RuntimeEffectCaller) error {
		if caller.Epoch() != epoch || caller.SessionID() != original.HostSessionID || caller.Registration().ID != original.RegistrationID ||
			!time.Now().Before(original.ExpiresAt) {
			return authority.ErrFenced
		}
		actual, err := s.currentTask(check, caller.Registration(), task, hash)
		if err != nil {
			return err
		}
		if actual.Status.State != api.TaskStateRunning {
			return errors.New("stateful task stopped serving")
		}
		history, err := s.authority.ListRuntimeEffectHistory(check, original.Scope)
		if err != nil {
			return err
		}
		found := false
		for _, current := range history {
			if current.EffectID != original.EffectID {
				continue
			}
			if !sameReadinessEffect(*original, current) {
				return authority.ErrFenced
			}
			found = true
		}
		if !found {
			return authority.ErrFenced
		}
		if err := s.producer.VerifyCurrent(check, actual, caller, material); err != nil {
			return err
		}
		if !time.Now().Before(original.ExpiresAt) {
			return authority.ErrFenced
		}
		return s.authority.Guard(check, epoch)
	}
	probe := func(check context.Context) (host.ManagedRuntimeReport, time.Time, error) {
		report, deadline, err := hosts.ObserveContainerReadiness(check, *original, verify)
		if err != nil {
			return host.ManagedRuntimeReport{}, time.Time{}, err
		}
		if report.Container == nil || report.ServingProof == nil {
			return host.ManagedRuntimeReport{}, time.Time{}, memberstatus.ErrNotServing
		}
		expected := memberstatus.Identity{Process: memberstatus.Process{PID: report.Container.MemberPID, StartNonce: report.ProcessBootID}, Scope: material.Scope, Authority: material.MemberAuthority}
		if err := memberstatus.VerifyReportedServing(*report.ServingProof, expected, material.Survivor); err != nil {
			return host.ManagedRuntimeReport{}, time.Time{}, err
		}
		if !time.Now().Before(deadline) {
			return host.ManagedRuntimeReport{}, time.Time{}, authority.ErrFenced
		}
		if err := s.authority.Guard(check, epoch); err != nil {
			return host.ManagedRuntimeReport{}, time.Time{}, err
		}
		return report, deadline, nil
	}
	report, deadline, err := probe(ctx)
	if err != nil {
		return nil, err
	}
	binding, boot, generation := *report.Container, report.ProcessBootID, report.ClientCredentialGeneration
	return &TaskReadinessWitness{deadline: deadline, recheck: func(check context.Context) error {
		current, _, err := probe(check)
		if err != nil {
			return err
		}
		if *current.Container != binding || current.ProcessBootID != boot || current.ClientCredentialGeneration != generation {
			return memberstatus.ErrStaleBinding
		}
		return nil
	}}, nil
}

func sameReadinessEffect(original, current authority.RuntimeEffect) bool {
	return current.EffectID == original.EffectID && current.Phase == authority.RuntimeEffectHeld && current.Epoch == original.Epoch && current.Scope == original.Scope &&
		current.RegistrationID == original.RegistrationID && current.HostSessionID == original.HostSessionID &&
		current.WorkerPublicKey == original.WorkerPublicKey && current.NATSUserPublicKey == original.NATSUserPublicKey &&
		current.RegistrationGeneration == original.RegistrationGeneration && current.InstanceID == original.InstanceID && current.NodeID == original.NodeID &&
		current.TaskID == original.TaskID && current.ServiceID == original.ServiceID && current.TaskSHA256 == original.TaskSHA256 &&
		current.AdmissionSHA256 == original.AdmissionSHA256 && current.MaterialSHA256 == original.MaterialSHA256 && bytes.Equal(current.Material, original.Material) &&
		current.IssuedAt.Equal(original.IssuedAt) && !current.ExpiresAt.Before(original.ExpiresAt) && current.Sequence >= original.Sequence
}
