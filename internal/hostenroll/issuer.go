package hostenroll

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const credentialLifetime = 48 * time.Hour

// Issuer holds only the regional host-scoped NATS delegate and host-client TLS
// intermediate. The offline cell account seed and regional CA key stay absent.
type Issuer struct {
	CellAccount string
	Cell        string
	NATSKey     nkeys.KeyPair
	TLSKey      crypto.Signer
	TLSCert     *x509.Certificate
	TLSCertPEM  []byte
	Root        *x509.Certificate
}

func LoadIssuer(cell, cellAccount, natsSeedPath, keyPath, certPath string, rootPEM []byte) (*Issuer, error) {
	if !validCellRegion(cell, strings.ToUpper(cell)) || !nkeys.IsValidPublicAccountKey(cellAccount) {
		return nil, errors.New("host issuer cell account is invalid")
	}
	seed, err := os.ReadFile(natsSeedPath)
	if err != nil || len(seed) == 0 || len(seed) > 4096 {
		return nil, errors.New("host NATS issuer seed is unavailable")
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(seed))))
	if err != nil {
		return nil, fmt.Errorf("parse host NATS issuer seed: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil || len(keyPEM) == 0 || len(keyPEM) > 8192 {
		pair.Wipe()
		return nil, errors.New("host TLS issuer key is unavailable")
	}
	defer clear(keyPEM)
	certPEM, err := os.ReadFile(certPath)
	if err != nil || len(certPEM) == 0 || len(certPEM) > 8192 {
		pair.Wipe()
		return nil, errors.New("host TLS issuer certificate is unavailable")
	}
	var roots []*x509.Certificate
	for rest := rootPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			if len(strings.TrimSpace(string(rest))) != 0 {
				pair.Wipe()
				return nil, errors.New("host TLS regional root has trailing data")
			}
			break
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil {
			pair.Wipe()
			return nil, errors.New("host TLS regional root is invalid")
		}
		roots = append(roots, root)
	}
	key, cert, root, err := ParseTLSIssuer(keyPEM, certPEM, roots)
	if err != nil {
		pair.Wipe()
		return nil, err
	}
	return &Issuer{CellAccount: cellAccount, Cell: cell, NATSKey: pair, TLSKey: key, TLSCert: cert, TLSCertPEM: certPEM, Root: root}, nil
}

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

// ValidateAccountScope checks the broker-installed account claim, not a
// caller-supplied permission list, before the online delegate can issue users.
func (issuer *Issuer) ValidateAccountScope(raw string) error {
	if issuer == nil || issuer.NATSKey == nil {
		return errors.New("host NATS issuer is unavailable")
	}
	account, err := jwt.DecodeAccountClaims(raw)
	if err != nil || account.Subject != issuer.CellAccount {
		return errors.New("host issuer account claim is invalid")
	}
	public, err := issuer.NATSKey.PublicKey()
	if err != nil {
		return err
	}
	bound, ok := account.SigningKeys.GetScope(public)
	scope, scoped := bound.(*jwt.UserScope)
	if !ok || !scoped || scope.Role != "host" ||
		!slices.Equal(scope.Template.Pub.Allow, jwt.StringList{protocol.AgentObservation(issuer.Cell, protocol.TemplateSubject, "*")}) ||
		!slices.Equal(scope.Template.Sub.Allow, jwt.StringList{protocol.InboxGrant(issuer.Cell, protocol.TemplateSubject)}) ||
		len(scope.Template.Pub.Deny) != 0 || len(scope.Template.Sub.Deny) != 0 ||
		scope.Template.Resp != nil {
		return errors.New("host NATS delegate lacks the exact user scope")
	}
	return nil
}

func (issuer *Issuer) Issue(request Request, csr *x509.CertificateRequest, node string, now time.Time) (string, []byte, time.Time, error) {
	if issuer == nil || issuer.NATSKey == nil || issuer.TLSCert == nil || csr == nil || node == "" ||
		csr.CheckSignature() != nil || !now.Before(issuer.TLSCert.NotAfter) {
		return "", nil, time.Time{}, errors.New("host credential issuer is unavailable")
	}
	parsedCSR, err := ParseCSR(request.CSRPEM)
	if err != nil || !bytes.Equal(parsedCSR.Raw, csr.Raw) {
		return "", nil, time.Time{}, errors.New("host credential CSR differs from the approved P-256 request")
	}
	expires := now.Add(credentialLifetime)
	if expires.After(issuer.TLSCert.NotAfter) {
		expires = issuer.TLSCert.NotAfter
	}
	// X.509 encodes NotAfter to whole seconds. The signed response must use
	// those same bytes so the guest can compare the validated leaf exactly.
	expires = expires.Truncate(time.Second)
	if expires.Sub(now) < time.Hour {
		return "", nil, time.Time{}, errors.New("host TLS issuer expires before a useful credential can be issued")
	}
	claim := jwt.NewUserClaims(request.NATSUserPublicKey)
	claim.SetScoped(true)
	claim.IssuerAccount = issuer.CellAccount
	claim.Name = node
	claim.IssuedAt, claim.Expires = now.Unix(), expires.Unix()
	if !claim.HasEmptyPermissions() {
		return "", nil, time.Time{}, errors.New("host scoped JWT unexpectedly contains permissions")
	}
	rawJWT, err := claim.Encode(issuer.NATSKey)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", nil, time.Time{}, err
	}
	uri, err := url.Parse("spiffe://hosts." + issuer.Cell + ".terrascale.internal/instances/" + url.PathEscape(request.InstanceID))
	if err != nil {
		return "", nil, time.Time{}, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: node},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{node + ".hosts." + issuer.Cell + ".terrascale.internal"}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer.TLSCert, csr.PublicKey, issuer.TLSKey)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuer.TLSCertPEM...)
	return rawJWT, chain, expires, nil
}
