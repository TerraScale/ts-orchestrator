package control

import "terrascale.tech/orchestrator/src/orchestrator/contracts"

// NatsProtocolPackageBytes mirrors NatsProtocolPackage.Bytes: the immutable
// canonical protocol package the controller compares against the object-store
// copy.
var NatsProtocolPackageBytes = []byte(`{"name":"terrascale-orchestrator","protocol":2}`)

// messagingCellTokenIsValid preserves the control-package helper while using
// the dependency-neutral shared cell-token contract.
func messagingCellTokenIsValid(cell string) bool {
	return contracts.CellTokenIsValid(cell)
}
