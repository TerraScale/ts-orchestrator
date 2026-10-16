package bootstrapmaterial

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/jwt/v2"
)

// IssueFunctionCredentials retains the generation's account signer inside the
// controller. The caller reads the current durable account claim and fences
// publication against concurrent claim or function-intent changes.
func (issuer *ControllerIssuer) IssueFunctionCredentials(admitted release.VerifiedFunction, accountJWT string, existing []byte) ([]byte, functions.WorkerBrokerIdentity, error) {
	if issuer == nil || issuer.cert == nil || issuer.key == nil || !admitted.Valid() || !time.Now().Before(issuer.identity.expiresAt) {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function issuance requires a current admitted release and controller generation")
	}
	claim := admitted.Claim()
	account, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil || account.Subject != issuer.identity.CellAccount || account.Issuer != issuer.identity.Operator ||
		claim.Environment != issuer.identity.Environment || claim.Cell != issuer.identity.Cell {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function release or broker account differs from the controller generation")
	}
	credentials, identity, err := functions.IssueWorkerCredentials(admitted, issuer.identity.CellAccount, accountJWT, issuer.signer, existing)
	if err != nil {
		return nil, functions.WorkerBrokerIdentity{}, err
	}
	if identity.ExpiresAt.After(issuer.identity.expiresAt) {
		clear(credentials)
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function credentials outlive the current controller authority")
	}
	return credentials, identity, nil
}

// IssueFunctionTLS issues only the admitted function's fixed server identity.
// The returned issuer certificate is public; its signing key stays here.
func (issuer *ControllerIssuer) IssueFunctionTLS(admitted release.VerifiedFunction) (certPEM, keyPEM, issuerPEM []byte, err error) {
	return issuer.issueFunctionTLS(admitted, x509.ExtKeyUsageServerAuth)
}

// IssueFunctionClientTLS issues only the admitted tenant/function's client identity.
func (issuer *ControllerIssuer) IssueFunctionClientTLS(admitted release.VerifiedFunction) (certPEM, keyPEM, issuerPEM []byte, err error) {
	return issuer.issueFunctionTLS(admitted, x509.ExtKeyUsageClientAuth)
}

func (issuer *ControllerIssuer) issueFunctionTLS(admitted release.VerifiedFunction, usage x509.ExtKeyUsage) (certPEM, keyPEM, issuerPEM []byte, err error) {
	if issuer == nil || issuer.cert == nil || issuer.key == nil || !admitted.Valid() {
		return nil, nil, nil, errors.New("function TLS issuance requires a current admitted release and controller generation")
	}
	claim := admitted.Claim()
	now := time.Now()
	expires := minTime(minTime(admitted.ExpiresAt(), now.Add(time.Hour)), issuer.identity.expiresAt)
	if claim.Environment != issuer.identity.Environment || claim.Cell != issuer.identity.Cell ||
		now.Before(issuer.cert.NotBefore) || !now.Before(expires) {
		return nil, nil, nil, errors.New("function TLS release differs from the current controller generation")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	name := claim.FunctionID + "." + strings.ToLower(claim.TenantID) + ".functions." + strings.ToLower(claim.Cell) + ".terrascale.internal"
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-issuedBackdate), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		URIs:        []*url.URL{{Scheme: "spiffe", Host: "terrascale.tech", Path: "/tenants/" + claim.TenantID + "/functions/" + claim.FunctionID}}}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(keyDER)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuer.certPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), bytes.Clone(issuer.certPEM), nil
}
