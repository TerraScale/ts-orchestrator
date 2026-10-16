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
	if issuer == nil || !admitted.Valid() {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function issuance requires a current admitted release and controller generation")
	}
	claim := admitted.Claim()
	account, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil || account.Subject != issuer.generation.CellAccount || account.Issuer != issuer.generation.Operator ||
		claim.Environment != issuer.generation.Environment || claim.Cell != string(issuer.generation.Cell) {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function release or broker account differs from the controller generation")
	}
	return functions.IssueWorkerCredentials(admitted, issuer.generation.CellAccount, accountJWT, issuer.signer, existing)
}

// IssueFunctionTLS issues only the admitted function's fixed server identity.
// The returned issuer certificate is public; its signing key stays here.
func (issuer *ControllerIssuer) IssueFunctionTLS(admitted release.VerifiedFunction) (certPEM, keyPEM, issuerPEM []byte, err error) {
	if issuer == nil || !admitted.Valid() {
		return nil, nil, nil, errors.New("function TLS issuance requires a current admitted release and controller generation")
	}
	claim := admitted.Claim()
	now := time.Now()
	expires := minTime(minTime(admitted.ExpiresAt(), now.Add(time.Hour)), issuer.cert.NotAfter)
	if claim.Environment != issuer.generation.Environment || claim.Cell != string(issuer.generation.Cell) ||
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
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{name},
		URIs: []*url.URL{{Scheme: "spiffe", Host: "terrascale.tech", Path: "/tenants/" + claim.TenantID + "/functions/" + claim.FunctionID}}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuer.certPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), bytes.Clone(issuer.certPEM), nil
}
