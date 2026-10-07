package hostenroll

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"reflect"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// ValidateRoleScope checks that the broker's current cell account claim
// carries the role signer with exactly roleidentity.Scope, so issued users connect.
func (issuer *Issuer) ValidateRoleScope(raw string) error {
	if issuer == nil || issuer.NATSKey == nil {
		return errors.New("host NATS issuer is unavailable")
	}
	account, err := jwt.DecodeAccountClaims(raw)
	if err != nil || account.Subject != issuer.CellAccount {
		return errors.New("cell account claim is invalid")
	}
	signer, err := roleidentity.Signer(issuer.NATSKey)
	if err != nil {
		return err
	}
	public, err := signer.PublicKey()
	signer.Wipe()
	if err != nil {
		return err
	}
	bound, ok := account.SigningKeys.GetScope(public)
	scope, scoped := bound.(*jwt.UserScope)
	if !ok || !scoped || !reflect.DeepEqual(scope, roleidentity.Scope(public)) {
		return errors.New("the cell account has no role signer; apply ts-orch bootstrap role-claim (docs/broker-claim-rotation.md)")
	}
	return nil
}

// IssueRole issues node's member of role a user JWT for userKey, signed by the
// role signer and tagged with the role's buckets, and a client certificate
// for csrPEM, both expiring together.
func (issuer *Issuer) IssueRole(role, node, userKey, csrPEM string, now time.Time) (string, []byte, time.Time, error) {
	grant, granted := roleidentity.Grants[role]
	if !granted {
		return "", nil, time.Time{}, errors.New("role " + role + " has no NATS grant")
	}
	if issuer == nil || issuer.NATSKey == nil || issuer.TLSCert == nil || node == "" || !nkeys.IsValidPublicUserKey(userKey) {
		return "", nil, time.Time{}, errors.New("role credential issuer is unavailable")
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	expires := now.Add(credentialLifetime)
	if expires.After(issuer.TLSCert.NotAfter) {
		expires = issuer.TLSCert.NotAfter
	}
	expires = expires.Truncate(time.Second)
	if expires.Sub(now) < time.Hour {
		return "", nil, time.Time{}, errors.New("host TLS issuer expires before a useful credential can be issued")
	}
	claim := jwt.NewUserClaims(userKey)
	claim.SetScoped(true)
	claim.IssuerAccount = issuer.CellAccount
	claim.Name = role + "@" + node
	claim.IssuedAt, claim.Expires = now.Unix(), expires.Unix()
	claim.Tags.Add("role:" + role)
	for _, bucket := range grant.Buckets {
		claim.Tags.Add("kv:" + bucket.Name)
	}
	for _, query := range grant.Queries {
		claim.Tags.Add("query:" + query)
	}
	if len(grant.Queries) != 0 {
		claim.Tags.Add("cell:" + strings.ToLower(issuer.Cell))
	}
	signer, err := roleidentity.Signer(issuer.NATSKey)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	rawJWT, err := claim.Encode(signer)
	signer.Wipe()
	if err != nil {
		return "", nil, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", nil, time.Time{}, err
	}
	// The host issuer may name only its hosts' domain: a role is a path
	// beside the hosts' /instances/.
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + "." + node},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{Scheme: "spiffe", Host: "hosts." + issuer.Cell + ".terrascale.internal",
			Path: "/roles/" + role + "/" + node}}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer.TLSCert, csr.PublicKey, issuer.TLSKey)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuer.TLSCertPEM...)
	return rawJWT, chain, expires, nil
}
