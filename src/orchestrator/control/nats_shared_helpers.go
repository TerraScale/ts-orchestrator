package control

import (
	"terrascale.tech/orchestrator/src/orchestrator/authority"
	"terrascale.tech/orchestrator/src/orchestrator/journal"
)

func isNatsTransientError(err error) bool {
	return authority.IsNatsTransientError(err)
}

// randomNatsNonce retains the journal caller's string contract. Entropy
// failure returns an invalid empty token so subject/proof validation fails
// closed instead of reusing a predictable nonce.
func randomNatsNonce() string {
	return journal.RandomNatsNonce()
}
