package bootstrap

import (
	"fmt"
	"slices"
	"strconv"
	"time"
)

// ReplacementManagedPeerIntent returns the next-attempt managed intent for a
// completed peer slot whose prior instance has root-signed retirement
// evidence. It pins the same founder plan row, private IP, slot and node name
// as attempt one, so the replacement keeps the controller's NATS server name
// and raft identity. Its create key and OCI retry token are fresh per attempt.
func (verified VerifiedFounderPlan) ReplacementManagedPeerIntent(slot string, previous SlotState,
	retirementWire []byte, createdAt time.Time,
) (Intent, error) {
	return replacementManagedPeerIntent(verified, slot, previous, retirementWire, createdAt)
}

func replacementManagedPeerIntent(verified FounderPlanAuthority, slot string, previous SlotState, retirementWire []byte, createdAt time.Time) (Intent, error) {
	if !verified.IsVerified() || !validFounderNow(createdAt) || len(retirementWire) == 0 {
		return Intent{}, ErrFounderPeerAuthorization
	}
	if previous.Intent.Slot != slot || previous.Head.ResultDigest == "" || previous.Result == nil ||
		previous.Intent.SchemaVersion != 1 || previous.Head.SchemaVersion != 1 || previous.Result.SchemaVersion != 1 ||
		previous.Head.Attempt == 0 || previous.Head.Attempt == ^uint64(0) ||
		previous.Head.Generation == ^uint64(0) || previous.Intent.Mode != IntentModeManaged {
		return Intent{}, fmt.Errorf("%w: only a completed managed slot can be replaced", ErrFounderPeerAuthorization)
	}
	intent, err := verified.InitialManagedPeerIntent(slot, createdAt)
	if err != nil {
		return Intent{}, err
	}
	attempt := previous.Head.Attempt + 1
	// Replacement tokens live in their own "replace-" namespace. Reusing the
	// initial "founder-<slot>-" form would let slot "b" at attempt 2 render
	// exactly the attempt-one token of a slot named "b-a2" under the same
	// plan. Read from the right, "-a<attempt>-<digest>" is unambiguous.
	token := "replace-" + slot + "-a" + strconv.FormatUint(attempt, 10) + "-" + verified.Digest()[:24]
	if !createTokenPattern.MatchString(token) {
		return Intent{}, fmt.Errorf("%w: replacement create key is unbounded", ErrFounderPeerAuthorization)
	}
	intent.Attempt, intent.Generation = attempt, previous.Head.Generation+1
	intent.RetirementDigest = objectDigest(retirementWire)
	intent.CreateKey, intent.RetryToken = token, token
	intent.NetworkSecurityGroupIDs = slices.Clone(intent.NetworkSecurityGroupIDs)
	return intent, nil
}
