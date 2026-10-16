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
	"fmt"
	"math/big"
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
	generation bootstrap.MaterialGeneration
	certPEM    []byte
	cert       *x509.Certificate
	key        *ecdsa.PrivateKey
	signer     nkeys.KeyPair
}

// LoadControllerIssuer parses the generation's controller-tls-issuer-cert.pem,
// controller-tls-issuer-key.pem and controller-account-signer.seed, which
// CheckGenerationFiles has already verified against the generation.
func LoadControllerIssuer(generation bootstrap.MaterialGeneration, certPEM, keyPEM, signerSeed []byte,
) (*ControllerIssuer, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("controller TLS issuer certificate is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("controller TLS issuer certificate: %w", err)
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
	if public, err := signer.PublicKey(); err != nil || public != generation.AccountSigner {
		signer.Wipe()
		return nil, errors.New("controller account signer differs from the generation's")
	}
	return &ControllerIssuer{generation: generation, certPEM: pem.EncodeToMemory(block), cert: cert, key: key,
		signer: signer}, nil
}

// Wipe clears the account signer seed.
func (issuer *ControllerIssuer) Wipe() { issuer.signer.Wipe() }

func (issuer *ControllerIssuer) lifetime() time.Duration {
	return time.Duration(issuer.generation.IssuedLifetimeHours) * time.Hour
}

// RenewTLS issues a leaf with identity and a fresh key, valid for the
// generation's issued lifetime and never past the issuer. certPEM holds the
// leaf followed by the issuer, so peers can build the chain to the bundle.
func (issuer *ControllerIssuer) RenewTLS(identity LeafIdentity, now time.Time) (certPEM, keyPEM []byte, err error) {
	ip := net.ParseIP(identity.IP)
	if identity.CommonName == "" || identity.DNSName == "" || ip == nil {
		return nil, nil, errors.New("controller leaf identity is incomplete")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(issuer.lifetime() - issuedBackdate)
	if notAfter.After(issuer.cert.NotAfter) {
		notAfter = issuer.cert.NotAfter
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: identity.CommonName},
		NotBefore: now.Add(-issuedBackdate), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{ip}, DNSNames: []string{identity.DNSName}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(leaf, issuer.certPEM...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// RenewCredentials re-signs the user JWT of current credentials, keeping its
// user key and grants, under the account signer for the generation's issued
// lifetime. A NATS JWT is always stamped with the wall clock, so the lifetime
// starts now.
func (issuer *ControllerIssuer) RenewCredentials(current []byte) ([]byte, error) {
	raw, err := jwt.ParseDecoratedJWT(current)
	if err != nil {
		return nil, err
	}
	claims, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, err
	}
	user, err := jwt.ParseDecoratedUserNKey(current)
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	if public, err := user.PublicKey(); err != nil || public != claims.Subject {
		return nil, errors.New("controller credential seed and user JWT differ")
	}
	seed, err := user.Seed()
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	claims.IssuerAccount = issuer.generation.CellAccount
	// Encode stamps IssuedAt with the wall clock (nats-io/jwt claims.go), so
	// Expires is set from the same clock just before.
	claims.Expires = time.Now().Add(issuer.lifetime() - issuedBackdate).Unix()
	claims.NotBefore = 0
	encoded, err := claims.Encode(issuer.signer)
	if err != nil {
		return nil, err
	}
	return jwt.FormatUserConfig(encoded, seed)
}

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
