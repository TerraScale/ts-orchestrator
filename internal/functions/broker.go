package functions

import (
	"fmt"

	"github.com/nats-io/nkeys"
)

// WorkerInboxPrefix is the private reply prefix passed to nats.CustomInboxPrefix.
func WorkerInboxPrefix(userNKey string) (string, error) {
	if !nkeys.IsValidPublicUserKey(userNKey) {
		return "", fmt.Errorf("%w: invalid worker public key", ErrScope)
	}
	return "_INBOX.TS_FUNCTION." + userNKey, nil
}
