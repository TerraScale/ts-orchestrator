package security

import (
	"context"
	"strconv"
	"time"
)

// Reconcile resumes durable transitions, retires expired overlap material,
// and issues a generation only when the current credential is within lead of
// expiry. Operation IDs follow durable generations rather than calendar dates,
// so a restart or a second rotation on the same date preserves idempotency.
// Callers must poll more often than lead minus their activation safety margin.
func (c *Coordinator) Reconcile(ctx context.Context, lead time.Duration) (RotationResult, error) {
	if c == nil || ctx == nil {
		return RotationResult{}, &RotationError{Code: "coordinator_invalid"}
	}
	if err := ctx.Err(); err != nil {
		return RotationResult{}, &RotationError{Code: "context_cancelled"}
	}
	if lead <= c.safety || lead < CapabilityOverlap || lead >= CapabilityPeriod {
		return RotationResult{}, &RotationError{Code: "rotation_lead_invalid"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.load(ctx)
	if err != nil {
		return RotationResult{}, err
	}
	now := c.clock().UTC()
	if now.IsZero() || !state.LastAt.IsZero() && now.Before(state.LastAt) {
		return RotationResult{}, &RotationError{Code: "clock_regressed"}
	}
	if state.Phase == PhaseFailed {
		return RotationResult{}, &RotationError{Code: "rotation_failed_closed"}
	}
	if state.Phase != "" && state.Phase != PhaseActive {
		return c.resume(ctx, state, now)
	}
	if state.Phase == PhaseActive {
		if state.OldVersion != 0 {
			if now.Before(state.OldExpiry) {
				// Starting another generation would discard the retained key's
				// retirement obligation before its overlap has elapsed.
				return c.result(state), nil
			}
			if err := c.retireAt(ctx, &state); err != nil {
				return RotationResult{}, c.retirementFailure(ctx, state, "retire_failed")
			}
		}
		if now.Before(state.CurrentExpiry.Add(-lead)) {
			return c.result(state), nil
		}
	}
	if state.LastVersion == ^uint64(0) || state.NewVersion == ^uint64(0) || state.CurrentVersion == ^uint64(0) {
		return RotationResult{}, &RotationError{Code: "version_exhausted"}
	}
	state = c.newState(state, "", now)
	state.OperationID = "capability-rotation-" + strconv.FormatUint(state.Generation, 10)
	if err := c.save(ctx, state); err != nil {
		return RotationResult{}, err
	}
	return c.resume(ctx, state, now)
}
