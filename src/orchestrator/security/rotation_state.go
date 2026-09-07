package security

// ValidCurrentRotationState checks the current and previous credential
// references that represent durable retirement obligations. A
// partial record must never be repaired by deriving them from a candidate or
// by treating a missing version as an empty key ring.
func ValidCurrentRotationState(state PersistedState) bool {
	if state.CurrentVersion == 0 {
		if state.CurrentIdentityRef != "" || state.CurrentCapabilityRef != "" || state.CurrentCapabilityID != "" || state.CurrentOriginProofRef != "" || state.CurrentOriginProofID != "" || !state.CurrentExpiry.IsZero() {
			return false
		}
	} else if state.CurrentIdentityRef == "" || state.CurrentCapabilityRef == "" || state.CurrentCapabilityID == "" || state.CurrentExpiry.IsZero() || state.CurrentOriginProofRef != "" && state.CurrentOriginProofID == "" || state.CurrentOriginProofRef == "" && state.CurrentOriginProofID != "" {
		return false
	}
	if state.OldVersion == 0 {
		if state.OldIdentityRef != "" || state.OldCapabilityRef != "" || state.OldCapabilityID != "" || state.OldOriginProofRef != "" || state.OldOriginProofID != "" || !state.OldExpiry.IsZero() || !state.OldOriginProofExpiry.IsZero() {
			return false
		}
	} else if state.OldIdentityRef == "" || state.OldCapabilityRef == "" || state.OldCapabilityID == "" || state.OldExpiry.IsZero() || state.OldOriginProofRef != "" && (state.OldOriginProofID == "" || state.OldOriginProofExpiry.IsZero()) || state.OldOriginProofRef == "" && (state.OldOriginProofID != "" || !state.OldOriginProofExpiry.IsZero()) {
		return false
	}
	if state.Phase == PhaseActive || state.Phase == PhaseRetire {
		return state.CurrentVersion != 0 && state.CurrentVersion == state.NewVersion &&
			state.CurrentIdentityRef == state.NewIdentityRef && state.CurrentCapabilityRef == state.NewCapabilityRef &&
			state.CurrentCapabilityID == state.NewCapabilityID && state.CurrentExpiry.Equal(state.NewExpiry) &&
			state.PreviousCapabilityID == state.OldCapabilityID &&
			(state.OldVersion == 0 || state.OldVersion < state.CurrentVersion)
	}
	return true
}
