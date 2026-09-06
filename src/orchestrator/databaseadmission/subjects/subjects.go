// Package subjects defines the database control wire subjects without importing
// authority services, so broker policy can share the exact transport contract.
package subjects

const (
	Create                   = "orch.database.create"
	Status                   = "orch.database.status"
	DeletionBegin            = "orch.database.delete.begin"
	DeletionStatus           = "orch.database.delete.status"
	LifecycleEvent           = "orch.database.lifecycle.event"
	InventoryFreeze          = "orch.database.inventory.freeze"
	InventoryResources       = "orch.database.inventory.resources"
	HostInstallPattern       = "orch.database.host.*.install"
	HostBranchRestorePattern = "orch.database.host.*.branch_restore"
)
