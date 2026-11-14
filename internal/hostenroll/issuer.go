package hostenroll

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

// ParseTLSIssuer checks the host TLS issuer: one EC key and one certificate,
// each a single PEM block, that match; the certificate is a client-only,
// path-length-zero intermediate signed by one of roots and is not itself a
// root. It returns the root that signed it.
func ParseTLSIssuer(keyPEM, certPEM []byte, roots []*x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, nil, errors.New("host TLS issuer key format is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, nil, errors.New("host TLS issuer certificate format is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	var signer *x509.Certificate
	for _, root := range roots {
		if root.Equal(cert) {
			return nil, nil, nil, errors.New("host TLS issuer is a regional root")
		}
		if signer == nil && cert.CheckSignatureFrom(root) == nil {
			signer = root
		}
	}
	public, keyIsECDSA := cert.PublicKey.(*ecdsa.PublicKey)
	if signer == nil || cert.CheckSignatureFrom(cert) == nil || !cert.IsCA || !cert.MaxPathLenZero ||
		cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!keyIsECDSA || !public.Equal(&key.PublicKey) {
		return nil, nil, nil, errors.New("host TLS issuer is not a root-signed client-only intermediate")
	}
	return key, cert, signer, nil
}
