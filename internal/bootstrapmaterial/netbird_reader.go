package bootstrapmaterial

import (
	"errors"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// IssueNetBirdReadCredentials issues a new user under the existing regional
// account signer. The root caller must bind it to the current dedicated manager
// in its signed Vault source, with deadline capped by that original authority.
func (issuer *ControllerIssuer) IssueNetBirdReadCredentials(deadline time.Time) ([]byte, error) {
	if issuer == nil || issuer.signer == nil || issuer.cert == nil || deadline.IsZero() {
		return nil, errors.New("NetBird reader needs the current regional issuer and original source deadline")
	}
	cell := strings.ToLower(issuer.identity.Cell)
	now := time.Now()
	for _, limit := range []time.Time{issuer.identity.expiresAt, issuer.cert.NotAfter, now.Add(issuer.lifetime() - issuedBackdate)} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	if natscell.NetBirdReaderPublishes(cell) == nil || deadline.Unix() <= now.Unix() || issuer.lifetime() <= issuedBackdate {
		return nil, errors.New("NetBird reader authority is absent or expired")
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		return nil, err
	}
	claim := jwt.NewUserClaims(public)
	claim.Name, claim.IssuerAccount, claim.Expires = "netbird-manager-read", issuer.identity.CellAccount, deadline.Unix()
	claim.Pub.Allow = natscell.NetBirdReaderPublishes(cell)
	claim.Sub.Allow = jwt.StringList{protocol.InboxGrant(cell, public)}
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeInProcess}
	creds, err := credentials(claim, issuer.signer, user)
	if err != nil {
		return nil, err
	}
	if err := CheckNetBirdReadCredentials(creds, cell, issuer.identity.CellAccount, issuer.identity.AccountSigner, deadline, time.Now()); err != nil {
		clear(creds)
		return nil, err
	}
	return creds, nil
}

// IssueNetBirdReadTLS issues only the dedicated manager's client identity,
// bounded by the original source and recipient deadline supplied by root.
func (issuer *ControllerIssuer) IssueNetBirdReadTLS(privateIP string, deadline time.Time) (certPEM, keyPEM []byte, err error) {
	if issuer == nil || deadline.IsZero() || !time.Now().Before(deadline) {
		return nil, nil, errors.New("NetBird reader TLS needs its original source deadline")
	}
	cell := strings.ToLower(issuer.identity.Cell)
	if natscell.NetBirdReaderPublishes(cell) == nil {
		return nil, nil, errors.New("NetBird reader cell is invalid")
	}
	identity := LeafIdentity{CommonName: "terrascale-" + cell + "-netbird-manager", DNSName: "netbird-manager", IP: privateIP}
	return issuer.renewTLSUntil(identity, time.Now(), deadline)
}

// CheckNetBirdReadCredentials checks the exact read ACL, private inbox and
// finite expiry against public keys pinned by the caller's genuine source.
// It grants no source, recipient, connection or currentness authority itself.
func CheckNetBirdReadCredentials(creds []byte, cell, account, signer string, deadline, now time.Time) error {
	if deadline.IsZero() || !now.Before(deadline) {
		return errors.New("NetBird reader source is expired")
	}
	if err := natscell.ValidateNetBirdReaderCredentialBytes(creds, cell); err != nil {
		return err
	}
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	if claim.Issuer != signer || claim.IssuerAccount != account ||
		time.Unix(claim.IssuedAt, 0).After(now) || !now.Before(time.Unix(claim.Expires, 0)) ||
		time.Unix(claim.Expires, 0).After(deadline) {
		return errors.New("NetBird reader differs from its original source issuer or deadline")
	}
	return nil
}
