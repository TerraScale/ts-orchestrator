package client

// ManagedRollbackProof is private worker progress, persisted before install
// effects and before accepting rollback. It must never come from the relay.
type ManagedRollbackProof struct {
	InstallStarted        bool
	InstallCommitted      bool
	PreviousTransactionID string
}
