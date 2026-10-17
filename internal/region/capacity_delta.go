package region

import "errors"

// validateCapacityOnlyDelta limits HOME's dedicated capacity writer to the
// existing capacity siblings. It cannot acquire the regional foundation lease,
// change signed scope/resources/source history, or publish a drain capture.
func validateCapacityOnlyDelta(previous, next FoundationRecord) error {
	preserved := next
	preserved.CapacityLedger, preserved.CapacityCreates = previous.CapacityLedger, previous.CapacityCreates
	preserved.CapacityPools, preserved.PoolChildren = previous.CapacityPools, previous.PoolChildren
	preserved.PoolQuarantines, preserved.PoolDrains = previous.PoolQuarantines, previous.PoolDrains
	preserved.UpdatedAt = previous.UpdatedAt
	if !sameCapacityValue(previous, preserved) {
		return errors.New("home capacity delta changed regional foundation ownership, signed scope or non-capacity history")
	}
	if err := next.retainCapacity(previous); err != nil {
		return err
	}
	// Only the target region may capture or advance a drain. HOME consumes one
	// exact stopped receipt by transferring its full history at terminal CAS.
	for key, receipt := range next.PoolDrains {
		old, exists := previous.PoolDrains[key]
		if !exists || !sameCapacityValue(receipt, old) {
			return errors.New("home capacity writer cannot produce or amend regional drain evidence")
		}
	}
	return next.retainPoolDrains(previous)
}
