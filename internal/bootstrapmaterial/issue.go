package bootstrapmaterial

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
)

// issuedBackdate is how far before issue an issued leaf is valid, to absorb
// clock skew between controllers; issued lifetimes allow for it.
const issuedBackdate = time.Minute

const controllerIssuedLifetime = 90 * 24 * time.Hour

// IssuedFiles are the files a controller issues itself under a material
// generation (TS-568): its TLS leaf followed by the controller issuer, the
// leaf's key, and its NATS user credentials.
func IssuedFiles(slot string) []string {
	return []string{slot + "-tls-cert.pem", slot + "-tls-key.pem", slot + ".creds"}
}

// LeafIdentity is the subject and names of one controller slot's TLS leaf.
type LeafIdentity struct {
	CommonName string
	DNSName    string
	IP         string
}

// ControllerLeafIdentity is the identity bootstrap material gives a slot.
func ControllerLeafIdentity(cell, slot, privateIP string) LeafIdentity {
	return LeafIdentity{CommonName: naming.NATSServer(cell, slot), DNSName: slot, IP: privateIP}
}

// ControllerIssuer is a generation's online issuing material, which every
// controller holds: the controller TLS issuer and the cell account signer.
type ControllerIssuer struct {
	identity issuerIdentity
	certPEM  []byte
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	signer   nkeys.KeyPair
}

type issuerIdentity struct {
	Cell, Environment, Operator, CellAccount, AccountSigner string
	lifetime                                                time.Duration
	expiresAt                                               time.Time
}

func loadControllerIssuer(identity issuerIdentity, certPEM, keyPEM, signerSeed []byte) (*ControllerIssuer, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("controller TLS issuer certificate is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("controller TLS issuer certificate: %w", err)
	}
	if identity.expiresAt.IsZero() || cert.NotAfter.Before(identity.expiresAt) {
		identity.expiresAt = cert.NotAfter
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("controller TLS issuer key is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("controller TLS issuer key: %w", err)
	}
	signer, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(signerSeed))))
	if err != nil {
		return nil, errors.New("controller account signer seed is invalid")
	}
	if public, err := signer.PublicKey(); err != nil || public != identity.AccountSigner {
		signer.Wipe()
		return nil, errors.New("controller account signer differs from the generation's")
	}
	return &ControllerIssuer{identity: identity, certPEM: pem.EncodeToMemory(block), cert: cert, key: key,
		signer: signer}, nil
}

// Wipe clears the account signer seed.
func (issuer *ControllerIssuer) Wipe() { issuer.signer.Wipe() }

// CheckIssuedTLS checks a slot's TLS leaf issued under generation: the
// certificate file holds the leaf and the generation's controller issuer;
// the issuer signed the leaf and chains to bundle; the leaf is a server and
// client leaf with exactly identity, a lifetime within the generation's,
// current at now, and its key matches.
func CheckIssuedTLS(generation bootstrap.MaterialGeneration, issuerPEM, bundlePEM, certPEM, keyPEM []byte,
	identity LeafIdentity, now time.Time,
) error {
	var blocks []*pem.Block
	for rest := certPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return errors.New("issued TLS leaf has trailing data")
			}
			break
		}
		blocks = append(blocks, block)
	}
	issuerBlock, _ := pem.Decode(issuerPEM)
	if len(blocks) != 2 || blocks[0].Type != "CERTIFICATE" || issuerBlock == nil ||
		!bytes.Equal(blocks[1].Bytes, issuerBlock.Bytes) {
		return errors.New("issued TLS leaf must be followed by exactly the generation's controller issuer")
	}
	leaf, err := x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		return fmt.Errorf("issued TLS leaf: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return fmt.Errorf("controller TLS issuer: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundlePEM) {
		return errors.New("generation CA bundle is invalid")
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return fmt.Errorf("issued TLS leaf does not chain to the generation: %w", err)
		}
	}
	lifetime := time.Duration(generation.IssuedLifetimeHours) * time.Hour
	if leaf.CheckSignatureFrom(issuer) != nil || leaf.IsCA || leaf.Subject.CommonName != identity.CommonName ||
		!slices.Equal(leaf.DNSNames, []string{identity.DNSName}) || len(leaf.IPAddresses) != 1 ||
		!leaf.IPAddresses[0].Equal(net.ParseIP(identity.IP)) || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 ||
		leaf.NotAfter.Sub(leaf.NotBefore) > lifetime {
		return errors.New("issued TLS leaf has another identity or a longer lifetime than the generation allows")
	}
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("issued TLS key format is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	public, isECDSA := leaf.PublicKey.(*ecdsa.PublicKey)
	if err != nil || !isECDSA || !public.Equal(&key.PublicKey) {
		return errors.New("issued TLS key does not match its leaf")
	}
	return nil
}

// CheckIssuedCredentials checks a controller's NATS credentials issued under
// generation: the seed matches the user JWT, which the account signer issued
// for the cell account with a lifetime within the generation's, current at
// now. Their grants are checked where the broker validates them.
func CheckIssuedCredentials(generation bootstrap.MaterialGeneration, creds []byte, now time.Time) error {
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return err
	}
	claims, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	user, err := jwt.ParseDecoratedUserNKey(creds)
	if err != nil {
		return err
	}
	public, err := user.PublicKey()
	user.Wipe()
	lifetime := time.Duration(generation.IssuedLifetimeHours) * time.Hour
	if err != nil || public != claims.Subject || claims.Issuer != generation.AccountSigner ||
		claims.IssuerAccount != generation.CellAccount || claims.Expires == 0 ||
		time.Unix(claims.IssuedAt, 0).After(now.Add(bootstrap.ManifestClockSkew)) ||
		time.Unix(claims.Expires, 0).Sub(time.Unix(claims.IssuedAt, 0)) > lifetime ||
		!now.Before(time.Unix(claims.Expires, 0)) || claims.NotBefore > now.Unix() {
		return errors.New("issued NATS credentials are not the account signer's, current and within the generation's lifetime")
	}
	return nil
}
