package shared

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// NatsAccountPublicKeyMaximumCharacters bounds an account public key.
const NatsAccountPublicKeyMaximumCharacters = 128

// IsNatsTransientError classifies recoverable NATS/JetStream conditions the
// caller may retry.
func IsNatsTransientError(err error) bool {
	return errors.Is(err, jetstream.ErrKeyNotFound) ||
		errors.Is(err, jetstream.ErrKeyExists) ||
		errors.Is(err, jetstream.ErrKeyRevisionMismatch) ||
		errors.Is(err, jetstream.ErrBucketNotFound) ||
		errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrTimeout)
}

// RandomNatsNonce returns a 32-hex-character random nonce; a broken entropy
// source yields the all-zero nonce rather than an error path.
func RandomNatsNonce() string {
	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return "00000000000000000000000000000000"
	}

	return hex.EncodeToString(sessionBytes)
}

// NatsRequireAccountPublicKey validates a NATS account public key.
func NatsRequireAccountPublicKey(value, message string) error {
	if len(value) == 0 || len(value) > NatsAccountPublicKeyMaximumCharacters {
		return errors.New(message)
	}
	decoded, err := nkeys.Decode(nkeys.PrefixByteAccount, []byte(value))
	if err != nil {
		return errors.New(message)
	}

	// nkeys.Decode strips the one-byte type prefix; account public keys
	// therefore decode to exactly the 32-byte payload.
	if len(decoded) != 32 {
		return errors.New(message)
	}

	return nil
}

// MessagingCellTokenIsValid replicates the root CellTokenRule.IsValid (1..63
// lowercase DNS-style characters that neither start nor end with a dash). The
// protocol package replicates the same rule privately.
func MessagingCellTokenIsValid(cell string) bool {
	if len(cell) < 1 || len(cell) > 63 {
		return false
	}

	if cell[0] == '-' || cell[len(cell)-1] == '-' {
		return false
	}

	for index := 0; index < len(cell); index++ {
		character := cell[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}

		return false
	}

	return true
}
