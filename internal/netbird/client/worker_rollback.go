package client

import "context"

// ManagedRollbackProof is private worker progress, persisted before install
// effects and before accepting rollback. It must never come from the relay.
type ManagedRollbackProof struct {
	InstallStarted        bool
	InstallCommitted      bool
	PreviousTransactionID string
}

// RollbackManagedForWorker also acknowledges an install that never committed.
// The worker's durable rollback authority prevents a delayed install afterward.
func RollbackManagedForWorker(ctx context.Context, transactionID string, proof ManagedRollbackProof) error {
	m, err := localManagedClient()
	if err != nil {
		return err
	}
	return m.finishModeWithProof(ctx, transactionID, true, false, &proof)
}
