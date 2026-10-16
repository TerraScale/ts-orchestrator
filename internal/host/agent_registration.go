package host

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// VerifyOwnRegistration checks an independently read registration against this
// actual Agent's keys and current signed session, without granting task authority.
func (a *Agent) VerifyOwnRegistration(registration Registration, controllerPublic ed25519.PublicKey) error {
	if a == nil || a.sessionLost.Load() || len(a.cfg.Identity) != ed25519.PrivateKeySize ||
		len(controllerPublic) != ed25519.PublicKeySize || !bytes.Equal(a.cfg.ControllerPublicKey, controllerPublic) {
		return errors.New("ownhost agent has no current pinned controller identity")
	}
	current, _, err := a.executionLease()
	if err != nil {
		return err
	}
	if registration.Cell != a.cfg.Cell || registration.Node != a.cfg.Node || registration.Environment != a.cfg.Environment ||
		registration.Generation != current.RegistrationGeneration ||
		registration.PublicKey != base64.StdEncoding.EncodeToString(a.cfg.Identity.Public().(ed25519.PublicKey)) ||
		registration.NATSUserPublicKey != a.cfg.NATSUserPublicKey {
		return errors.New("registration differs from the actual ownhost session and keys")
	}
	return nil
}
