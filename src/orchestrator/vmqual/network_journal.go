package vmqual

import (
	"fmt"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// ValidateNetworkJournal rejects hand-edited cleanup records before they reach
// a privileged runner. vmnet binds every namespace deletion to the journal's
// full run identity, prefix, fingerprint, and absolute tool paths.
func ValidateNetworkJournal(journal vmnet.Journal) error {
	if err := journal.Validate(); err != nil {
		return fmt.Errorf("vmqual: invalid network journal: %w", err)
	}
	return nil
}
