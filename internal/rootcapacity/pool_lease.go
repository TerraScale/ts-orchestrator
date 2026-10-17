package rootcapacity

import "github.com/TerraScale/ts-orchestrator/internal/region"

// A completed operation may have lost only its final lease-release CAS. Its
// original positive history allows the next owner after that lease expires.
// Lease expiry alone never resolves an unfinished provider operation.
func completedPoolOperation(record region.FoundationRecord, poolID, operationID string) bool {
	if child, exists := record.PoolChildren[operationID]; exists && child.PoolID == poolID &&
		!child.ReadyAt.IsZero() && child.Attach != nil && !child.Attach.AcceptedAt.IsZero() && !child.Attach.WorkCompletedAt.IsZero() {
		return true
	}
	for _, child := range record.PoolChildren {
		if child.PoolID == poolID && child.RemovalOperationID == operationID && child.Stage == region.PoolChildRetired &&
			child.RetirementDrain != nil && child.Terminate != nil && !child.Terminate.AcceptedAt.IsZero() &&
			child.DeleteBoot != nil && !child.DeleteBoot.AcceptedAt.IsZero() && !child.InstanceRetiredAt.IsZero() && !child.BootRetiredAt.IsZero() {
			return true
		}
	}
	quarantine, exists := record.PoolQuarantines[operationID]
	return exists && quarantine.PoolID == poolID && !quarantine.DetachedAt.IsZero() && quarantine.Detach != nil &&
		!quarantine.Detach.AcceptedAt.IsZero() && !quarantine.Detach.WorkCompletedAt.IsZero()
}
