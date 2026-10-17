package region

import (
	"errors"
	"maps"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
)

func (r FoundationRecord) validatePoolDrains() error {
	if len(r.PoolDrains) > drainwire.MaxPoolDrains {
		return errors.New("protected region exceeds its pending pool drain bound")
	}
	instances := make(map[string]bool, len(r.PoolDrains))
	for key, receipt := range r.PoolDrains {
		if receipt.Validate() != nil || key != receipt.Child.RemovalOperationID || receipt.Child.Cell != r.Cell ||
			receipt.CapturedAt.After(r.UpdatedAt) || receipt.StoppedAt.After(r.UpdatedAt) || instances[receipt.Child.InstanceID] {
			return errors.New("protected pool drain has no exact bounded own-cell capture")
		}
		child, exists := r.PoolChildren[receipt.Child.BirthOperationID]
		if !exists || child.OperationID != receipt.Child.BirthOperationID || child.InstanceID != receipt.Child.InstanceID ||
			child.PoolID != receipt.Child.PoolID || child.ConfigurationID != receipt.Child.ConfigurationID ||
			child.RecipeSHA256 != receipt.Child.RecipeSHA256 || child.Stage == PoolChildRetired {
			return errors.New("protected pool drain differs from its original live child birth")
		}
		instances[receipt.Child.InstanceID] = true
	}
	return nil
}

func (r FoundationRecord) retainPoolDrains(previous FoundationRecord) error {
	for key, old := range previous.PoolDrains {
		if next, exists := r.PoolDrains[key]; exists {
			if err := next.Retains(old); err != nil {
				return err
			}
			continue
		}
		child, exists := r.PoolChildren[old.Child.BirthOperationID]
		if !exists || child.Stage != PoolChildRetired || old.Phase != drainwire.PoolStopped || child.RetirementDrain == nil ||
			!sameCapacityValue(*child.RetirementDrain, old) || child.InstanceID != old.Child.InstanceID ||
			child.RemovalOperationID != old.Child.RemovalOperationID || child.InstanceRetiredAt.IsZero() || child.BootRetiredAt.IsZero() ||
			child.Terminate == nil || child.Terminate.AcceptedAt.IsZero() || child.DeleteBoot == nil || child.DeleteBoot.AcceptedAt.IsZero() {
			return errors.New("pending pool drain may leave only with exact full terminal child history")
		}
	}
	return nil
}

func (r *FoundationRecord) clonePoolDrains() {
	r.PoolDrains = maps.Clone(r.PoolDrains)
	for key, receipt := range r.PoolDrains {
		r.PoolDrains[key] = receipt.Clone()
	}
}
