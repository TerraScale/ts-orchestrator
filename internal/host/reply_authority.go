package host

import (
	"context"
	"errors"
	"time"
)

// recheckReplyAuthority closes provider I/O races before any authenticated reply
// is signed. A changed caller receives no material or new runtime authority.
func (c *Controller) recheckReplyAuthority(ctx context.Context, epoch uint64, req request, registration Registration, requireActive bool) error {
	latest, err := c.registration(ctx, req.Node)
	if err != nil || !sameJSON(registration, latest) {
		return errors.New("host registration changed while handling request")
	}
	key, err := decodePublicKey(latest.PublicKey)
	if err != nil || verifyRequest(req, key, c.cell, time.Now().UTC()) != nil {
		return errors.New("host request expired while handling request")
	}
	active, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil {
		return err
	}
	if !exists || !currentAuthorizedSession(active, latest, req, time.Now()) {
		return errors.New("host session changed while handling request")
	}
	if requireActive {
		retired, err := c.retired(ctx, req.Node)
		if err != nil {
			return err
		}
		if retired {
			return errors.New("retired host cannot receive current material or runtime authority")
		}
	}
	if err := c.verifyCredentialProtocol(ctx, req, latest); err != nil {
		return err
	}
	return c.guard(ctx, epoch)
}
