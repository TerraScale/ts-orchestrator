package bootstrapmaterial

import "time"

func (issuer *ControllerIssuer) ExpiresAt() time.Time { return issuer.identity.expiresAt }

// RestrictExpiry narrows one loaded issuer to an independently admitted source
// minimum. A later deadline never extends the original issuer authority.
func (issuer *ControllerIssuer) RestrictExpiry(expires time.Time) error {
	if issuer == nil || expires.IsZero() || !time.Now().Before(expires) {
		return ErrMaterial
	}
	issuer.identity.expiresAt = minTime(issuer.identity.expiresAt, expires)
	if !time.Now().Before(issuer.identity.expiresAt) {
		return ErrMaterial
	}
	return nil
}
