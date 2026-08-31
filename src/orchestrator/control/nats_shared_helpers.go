package control

import (
	"crypto/rand"
	"encoding/hex"

	"terrascale.tech/orchestrator/src/orchestrator/authority"
)

func isNatsTransientError(err error) bool {
	return authority.IsNatsTransientError(err)
}

// randomNatsNonce retains the journal caller's string contract. Entropy
// failure returns an invalid empty token so subject/proof validation fails
// closed instead of reusing a predictable nonce.
func randomNatsNonce() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}
