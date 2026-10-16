package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

const nativeRestoreKind = "native.release.restore"

func prepareNativeRestore(ctx context.Context, cfg Config, runtime *natscell.Runtime, intent delivery.Intent) (delivery.Intent, error) {
	if intent.SchemaVersion == 0 {
		intent.SchemaVersion = delivery.SchemaVersion
	}
	if intent.Cell == "" {
		intent.Cell = cfg.NATS.Cell
	}
	if intent.OperationID == "" {
		intent.OperationID = entityid.New()
	}
	if intent.AuthorityEpoch == 0 {
		readCtx, stopRead := context.WithTimeout(ctx, operatorSubmitSetupTimeout)
		epoch, err := observeOperatorAuthority(readCtx, func(attempt context.Context) (authority.Snapshot, error) {
			return authority.Observe(attempt, runtime.JetStream(), cfg.NATS.Cell)
		})
		stopRead()
		if err != nil {
			return intent, err
		}
		intent.AuthorityEpoch = epoch
	}
	if err := intent.Validate(); err != nil {
		return intent, err
	}
	reply, err := requestNativeRelease(ctx, cfg, runtime, nativeRestoreKind, nativePrepareRequest{
		Intent: intent, Deadline: time.Now().UTC().Add(rollout.ObservationBudget)})
	if err != nil {
		return intent, err
	}
	if reply.Intent != intent {
		return intent, delivery.ErrConflict
	}
	return reply.Intent, nil
}

func nativeRestoreMatches(binding nativeReleaseBinding, intent delivery.Intent) bool {
	previous := binding.Intent
	return previous.Cell == intent.Cell && previous.Role == intent.Role && previous.Environment == intent.Environment &&
		previous.Source == intent.Source && previous.ArtifactDigest == intent.ArtifactDigest &&
		previous.ManifestDigest == intent.ManifestDigest && previous.ConfigDigest == intent.ConfigDigest &&
		previous.DesiredReplicas == intent.DesiredReplicas
}

func nativeRestoreTarget(state nativeReleaseHistory, intent delivery.Intent) (*nativeGoodRelease, error) {
	if state.Previous != nil && nativeRestoreMatches(state.Previous.Binding, intent) {
		return state.Previous, nil
	}
	var selected *nativeGoodRelease
	for i := range state.Good {
		good := &state.Good[i]
		if !nativeRestoreMatches(good.Binding, intent) {
			continue
		}
		if selected != nil && selected.Binding.ProfileDigest != good.Binding.ProfileDigest {
			return nil, fmt.Errorf("%w: rollback target identifies multiple retained resource profiles", delivery.ErrInvalid)
		}
		selected = good
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: rollback target is not a retained good release/configuration pair", delivery.ErrInvalid)
	}
	return selected, nil
}

func (h *nativeHistory) restore(ctx context.Context, request nativePrepareRequest, actor string) (reply nativePrepareReply, restoreErr error) {
	i := request.Intent
	if err := i.Validate(); err != nil {
		return reply, err
	}
	if !slices.Contains(serviceReleaseRoles, i.Role) || i.Cell != h.services.cell || request.RecoveryOf != "" || request.ResumeOf != "" {
		return reply, delivery.ErrInvalid
	}
	defer func() {
		if errors.Is(restoreErr, delivery.ErrInvalid) && ctx.Err() == nil {
			restoreErr = errors.Join(restoreErr, h.deliveries.RefuseIntent(ctx, i, actor, i.AuthorityEpoch, "rollback target is not an eligible, unambiguous retained good release/configuration pair"))
		}
	}()
	h.effects.Lock()
	defer h.effects.Unlock()
	if err := h.fencer.Guard(ctx, i.AuthorityEpoch); err != nil {
		return reply, err
	}
	h.services.launches.RLock()
	defer h.services.launches.RUnlock()
	state, revision, err := h.load(ctx, i.Role)
	if err != nil {
		return reply, err
	}
	fingerprint, err := i.Fingerprint()
	if err != nil {
		return reply, err
	}
	receipt, statusErr := h.deliveries.StatusFor(ctx, i)
	if statusErr != nil && !errors.Is(statusErr, delivery.ErrPending) {
		return reply, statusErr
	}
	if statusErr == nil && (receipt.Status != "accepted" || state.Recovery == nil || state.Recovery.Fingerprint != fingerprint) {
		return reply, delivery.ErrConflict
	}
	if state.Pending != nil && state.Pending.Intent.OperationID == i.OperationID {
		return reply, delivery.ErrConflict
	}
	if state.Recovery != nil && state.Recovery.Fingerprint == fingerprint {
		if err := h.verifyProfile(i.Role, state.Recovery.Profile, state.Recovery.Provenance); err != nil {
			return reply, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
		}
		if err := h.refuseKnownBad(ctx, state.Recovery.Artifact); err != nil {
			return reply, err
		}
		if bad, err := h.badProfile(ctx, *state.Recovery); err != nil {
			return reply, err
		} else if bad {
			return reply, fmt.Errorf("%w: retained artifact/profile is known bad", delivery.ErrInvalid)
		}
		if !slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fingerprint }) &&
			!time.Now().Before(state.Recovery.Deadline) {
			return reply, fmt.Errorf("%w: rollback observation deadline expired: %w", delivery.ErrInvalid, context.DeadlineExceeded)
		}
		return nativePrepareReply{Intent: i}, h.prepareGate(ctx, i, state)
	}
	if state.Recovery != nil && !slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool {
		return g.Binding.Fingerprint == state.Recovery.Fingerprint
	}) {
		return reply, delivery.ErrConflict
	}
	target, err := nativeRestoreTarget(state, i)
	if err != nil {
		return reply, err
	}
	if err := h.verifyProfile(i.Role, target.Binding.Profile, target.Binding.Provenance); err != nil {
		return reply, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if err := h.refuseKnownBad(ctx, target.Binding.Artifact); err != nil {
		return reply, err
	}
	if bad, err := h.badProfile(ctx, target.Binding); err != nil {
		return reply, err
	} else if bad {
		return reply, fmt.Errorf("%w: retained artifact/profile is known bad", delivery.ErrInvalid)
	}
	desired, err := h.hosts.ListDesired(ctx, i.Role)
	if err != nil {
		return reply, err
	}
	minimum := nextReleaseGeneration(desired)
	for _, binding := range []*nativeReleaseBinding{state.Pending, state.Recovery} {
		if binding != nil {
			if binding.Intent.Generation == ^uint64(0) {
				return reply, fmt.Errorf("%w: rollback generation space exhausted", delivery.ErrInvalid)
			}
			minimum = max(minimum, binding.Intent.Generation+1)
		}
	}
	if minimum == 0 || i.Generation < minimum {
		return reply, fmt.Errorf("%w: rollback generation does not supersede selected and committed releases", delivery.ErrInvalid)
	}
	if _, err := workload.ReleaseGeneration(i.Generation); err != nil {
		return reply, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if request.Deadline.IsZero() || !time.Now().Before(request.Deadline) || request.Deadline.After(time.Now().Add(rollout.ObservationBudget)) {
		return reply, fmt.Errorf("%w: invalid fixed rollback deadline", delivery.ErrInvalid)
	}
	binding, err := nativeBinding(i, target.Binding.Artifact, target.Binding.Profile, target.Binding.Provenance)
	if err != nil {
		return reply, err
	}
	binding.Deadline = request.Deadline.UTC()
	state.Recovery = &binding
	// Manual restoration preserves the good release the user chooses to leave.
	if err := h.save(ctx, i.AuthorityEpoch, i.Role, state, revision); err != nil {
		return reply, err
	}
	if err := h.prepareGate(ctx, i, state); err != nil {
		return reply, err
	}
	return nativePrepareReply{Intent: i}, nil
}
