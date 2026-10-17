package region

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/journal"
)

// NetBirdAccountEffect is the one protected account slot. Unknown dispatches
// remain pending; only a completed slot may turn over to its chained successor.
// These public values convey no request or completion authority.
type NetBirdAccountEffect struct {
	Reservation journal.Reservation `json:"reservation"`
	Completion  *journal.Completion `json:"completion,omitempty"`
}

func (effect NetBirdAccountEffect) Clone() NetBirdAccountEffect {
	effect.Reservation = effect.Reservation.Clone()
	if effect.Completion != nil {
		completion := *effect.Completion
		effect.Completion = &completion
	}
	return effect
}

func (record FoundationRecord) validateNetBirdAccountEffect() error {
	if record.NetBirdManager == nil || record.NetBirdManager.AccountEffect == nil {
		return nil
	}
	manager := record.NetBirdManager
	effect := manager.AccountEffect
	reservation := effect.Reservation
	if record.Cell != "GRU" || reservation.Validate() != nil || manager.InstanceID == "" ||
		reservation.Binding.ManagerInstanceID != manager.InstanceID || reservation.StartedAt.Before(manager.StartedAt) || reservation.StartedAt.After(record.UpdatedAt) {
		return errors.New("NetBird account effect differs from its original manager or finite reservation")
	}
	if effect.Completion != nil && (effect.Completion.Validate(reservation) != nil || effect.Completion.CompletedAt.After(record.UpdatedAt)) {
		return errors.New("NetBird account effect lacks its exact original synchronous response")
	}
	return nil
}

// Called from every whole-record CAS using its one current record/ETag read.
// It never compares independently progressing grants or other sibling state.
func (previous FoundationRecord) retainNetBirdAccountEffect(current FoundationRecord) error {
	var before, after *NetBirdAccountEffect
	if previous.NetBirdManager != nil {
		before = previous.NetBirdManager.AccountEffect
	}
	if current.NetBirdManager != nil {
		after = current.NetBirdManager.AccountEffect
	}
	if before == nil && after == nil {
		return nil
	}
	denied := errors.New("NetBird account effect cannot be removed, replayed or rebound")
	if current.NetBirdManager == nil || previous.NetBirdManager == nil || previous.NetBirdManager.original() != current.NetBirdManager.original() ||
		current.validateNetBirdAccountEffect() != nil || after == nil {
		return denied
	}
	if before == nil {
		if after.Reservation.Counter != 1 || after.Completion != nil {
			return denied
		}
		return nil
	}
	previousDigest, err := before.Reservation.Digest()
	currentDigest, currentErr := after.Reservation.Digest()
	if err != nil || currentErr != nil {
		return denied
	}
	if previousDigest != currentDigest {
		if before.Completion == nil || after.Completion != nil || after.Reservation.Follows(before.Reservation, *before.Completion) != nil {
			return denied
		}
		return nil
	}
	if before.Completion != nil {
		if after.Completion == nil {
			return denied
		}
		first, firstErr := journal.CompletionDigest(before.Reservation, *before.Completion)
		second, secondErr := journal.CompletionDigest(after.Reservation, *after.Completion)
		if firstErr != nil || secondErr != nil || first != second {
			return denied
		}
	}
	return nil
}
