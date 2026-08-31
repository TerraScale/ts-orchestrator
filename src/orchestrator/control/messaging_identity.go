package control

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func newNatsMessageIdentity() (string, protocol.MessageIdentityToken, error) {
	identityBytes := make([]byte, 16)
	if _, err := rand.Read(identityBytes); err != nil {
		return "", protocol.MessageIdentityToken{}, err
	}
	identity := hex.EncodeToString(identityBytes)
	messageID, ok := protocol.MessageIdentityTokenTryCreate(identity)
	if !ok {
		return "", protocol.MessageIdentityToken{}, errors.New("NATS message identity was invalid.")
	}
	return identity, messageID, nil
}
