package app

import (
	"bytes"
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// Resource accounting retains nonterminal assignments without granting material.
func (controller *containerMaterialController) verifyAllocation(ctx context.Context, registration host.Registration, task *api.Task) error {
	current, binding, err := controller.taskRegistration(ctx, task)
	if err != nil {
		return err
	}
	before, beforeErr := protocol.EncodeJSON(registration)
	after, afterErr := protocol.EncodeJSON(current)
	if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
		return containermaterial.ErrPending
	}
	config := controller.config
	var worker swarmruntime.VerifiedWorkerMembership
	if registration.ManagedOCI != nil {
		if config.WorkerMembership == nil {
			return containermaterial.ErrPending
		}
		worker, err = config.WorkerMembership(ctx, binding.NodeID)
		if err != nil {
			return err
		}
		if worker.Validate() != nil {
			return containermaterial.ErrPending
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, worker.Info().ExpiresAt)
		defer cancel()
	}
	evidence, err := controller.recipientEvidence(ctx, registration, binding)
	if err != nil {
		return err
	}
	selected := evidence.recipient
	if !proto.Equal(selected.Task, task) {
		return containermaterial.ErrPending
	}
	deadline := selected.Verified.ExpiresAt()
	if selected.controllerProof != nil {
		if selected.controllerProof.Deadline().Before(deadline) {
			deadline = selected.controllerProof.Deadline()
		}
		if selected.enrollmentExpiresAt.Before(deadline) {
			deadline = selected.enrollmentExpiresAt
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := containermaterial.VerifyTaskAllocation(ctx, config.Client, selected.Task, selected.Expected, selected.Verified, evidence.roots, selected.proof, registration, evidence.binding, selected.controllerProof, worker); err != nil {
		return err
	}
	latest, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil || latest.Revision() != evidence.entry.Revision() || !bytes.Equal(latest.Value(), evidence.entry.Value()) {
		return containermaterial.ErrPending
	}
	confirmed, err := config.Delivery.ContainerIntent(ctx, selected.Intent.OperationID)
	if err != nil {
		return err
	}
	previousFingerprint, beforeErr := selected.Intent.Fingerprint()
	currentFingerprint, afterErr := confirmed.Fingerprint()
	if beforeErr != nil || afterErr != nil || previousFingerprint != currentFingerprint {
		return containermaterial.ErrPending
	}
	if err := config.Authority.Guard(ctx, selected.epoch); err != nil {
		return err
	}
	if selected.controllerProof != nil {
		confirmed, err := completedControllerEnrollment(ctx, config, registration, binding.InstanceID)
		before, beforeErr := protocol.EncodeJSON(evidence.enrollment)
		after, afterErr := protocol.EncodeJSON(confirmed)
		if err != nil || beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
			return containermaterial.ErrPending
		}
	}
	if err := controllerHostSpecCurrent(ctx, config.JS, config.Specs, evidence.entry, selected.rootHead); err != nil {
		return err
	}
	if registration.ManagedOCI != nil {
		confirmed, err := config.WorkerMembership(ctx, binding.NodeID)
		if err != nil {
			return err
		}
		original, latest := worker.Info(), confirmed.Info()
		// A fresh observation may not extend the original finite proof.
		latest.ObservedAt, latest.ExpiresAt = original.ObservedAt, original.ExpiresAt
		if worker.Validate() != nil || confirmed.Validate() != nil || original != latest {
			return containermaterial.ErrPending
		}
	}
	if err := containermaterial.VerifyCurrentTaskAllocation(ctx, config.Client, selected.Task, selected.Expected, selected.Verified, evidence.roots, selected.proof, registration, evidence.binding, selected.controllerProof, worker); err != nil {
		return err
	}
	if err := controllerHostSpecCurrent(ctx, config.JS, config.Specs, evidence.entry, selected.rootHead); err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	currentAuthority := config.Authority.Current()
	now := time.Now().UTC()
	if revision != selected.SpecRevision || config.Specs.roots.reply("").Head != selected.rootHead || currentAuthority.Epoch != selected.epoch || !currentAuthority.CanMutate() ||
		!selected.Verified.Valid(now) || selected.controllerProof != nil && (!selected.controllerProof.Valid(now) || !now.Before(selected.enrollmentExpiresAt)) ||
		registration.ManagedOCI != nil && worker.Validate() != nil {
		return containermaterial.ErrPending
	}
	if err := config.Authority.Guard(ctx, selected.epoch); err != nil {
		return err
	}
	now = time.Now().UTC()
	if !selected.Verified.Valid(now) || selected.controllerProof != nil && (!selected.controllerProof.Valid(now) || !now.Before(selected.enrollmentExpiresAt)) ||
		registration.ManagedOCI != nil && worker.Validate() != nil {
		return containermaterial.ErrPending
	}
	return ctx.Err()
}
