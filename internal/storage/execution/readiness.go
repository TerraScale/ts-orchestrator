//go:build linux

package execution

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/moby/swarmkit/v2/api"
)

// A backup Prepare may block; readiness independently observes this same held
// Source and is canceled by withdrawal before publication or writer removal.
func (s *Source) runReadiness(ctx context.Context, agent *host.Agent, task *api.Task, entry *sourceEntry) {
	for {
		_ = s.reconcileReadiness(ctx, agent, task, entry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Source) reconcileReadiness(ctx context.Context, agent *host.Agent, task *api.Task, entry *sourceEntry) error {
	grant, err := s.session.Resolve(ctx, task)
	if err != nil {
		return err
	}
	query := host.ManagedContainerRuntime{TaskID: task.ID, TaskSHA256: grant.TaskSHA256(), AdmissionSHA256: grant.AdmissionSHA256(), EffectID: grant.EffectID()}
	challenge, err := agent.ContainerReadinessChallenge(ctx, query)
	if err != nil || challenge == nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, challenge.Deadline)
	defer cancel()
	held := &workerHeld{session: s.session, hash: grant.TaskSHA256(), admission: grant.AdmissionSHA256()}
	held.active.Store(true)
	defer held.active.Store(false)
	ctx = context.WithValue(ctx, workerHeldKey{}, held)
	observation, err := s.observeBackup(ctx, task, entry)
	if err != nil {
		return err
	}
	defer observation.mount.Close()
	if observation.proof == nil || observation.binding.TaskID != challenge.TaskID || observation.binding.TaskSHA256 != challenge.TaskSHA256 ||
		observation.binding.AdmissionSHA256 != challenge.AdmissionSHA256 || observation.binding.EffectID != challenge.EffectID {
		return memberstatus.ErrNotServing
	}
	s.mu.Lock()
	pins, observed, revoked := entry.pins, entry.observed, entry.revoked
	s.mu.Unlock()
	if pins == nil || revoked {
		return ErrUnsafe
	}
	actual, err := s.runtime.Observe(ctx, *pins)
	if err != nil || actual != observed {
		return errors.Join(ErrUnsafe, err)
	}
	if err := observation.mount.Recheck(); err != nil {
		return err
	}
	if err := s.session.CheckHeld(ctx, task); err != nil {
		return err
	}
	return agent.ContainerReadinessResult(ctx, *challenge, s.backupReport(entry, observation))
}
