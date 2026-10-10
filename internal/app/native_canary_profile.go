package app

import "context"

func (h *nativeHistory) selectedCanaryGate(state nativeReleaseHistory, binding nativeReleaseBinding) canaryGate {
	if h.canary == nil {
		return nil
	}
	candidate := cloneNativeProfile(binding.Profile)
	baseline := candidate
	if state.Previous != nil {
		baseline = cloneNativeProfile(state.Previous.Binding.Profile)
	}
	check := h.canary
	return func(ctx context.Context, target canaryTarget) map[string]string {
		target.Profile = candidate
		if target.Baseline {
			target.Profile = baseline
		}
		return check(ctx, target)
	}
}
