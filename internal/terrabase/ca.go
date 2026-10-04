package terrabase

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"syscall"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	memberValidity = 90 * 24 * time.Hour
	// renewBefore is when a host replaces a member certificate. A running
	// member keeps the certificate it loaded until it restarts.
	renewBefore = 30 * 24 * time.Hour
)

// CA is a cell's TerraBase member certificate authority. Every member's TLS
// certificate chains to it, and every member accepts exactly the peer
// clients that do. The controller holds its key; hosts never see it.
type CA struct {
	certificate *x509.Certificate
	pem         []byte
	key         crypto.Signer
}

// NewCA creates the member CA of a cell and returns its PEM certificate and
// PKCS#8 PEM private key.
func NewCA(cell string, now time.Time) (certificatePEM, keyPEM []byte, err error) {
	if !nameRE.MatchString(cell) {
		return nil, nil, errors.New("invalid cell name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "TerraBase member CA " + cell},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// LoadCA reads a member CA written by NewCA. The key must be a regular
// file that only this process user owns and can read.
func LoadCA(certificateFile, keyFile string) (*CA, error) {
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readOwnerOnly(keyFile)
	if err != nil {
		return nil, fmt.Errorf("terrabase member CA key: %w", err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("terrabase member CA: %w", err)
	}
	certificate := pair.Leaf
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if len(pair.Certificate) != 1 || !ok || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("terrabase member CA must be one CA certificate and its key")
	}
	return &CA{certificate: certificate, pem: certificatePEM, key: signer}, nil
}

// CertificatePEM is the CA certificate members trust.
func (ca *CA) CertificatePEM() []byte { return slices.Clone(ca.pem) }

// Issue signs a member's certificate request for its listed peer entry. The
// certificate names the member and its peer address, and serves both as the
// peer listener's server certificate and as the client certificate a member
// presents to other members.
func (ca *CA) Issue(csrDER []byte, peer Peer, now time.Time) ([]byte, error) {
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		return nil, errors.New("invalid member certificate request")
	}
	if key, ok := request.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("member certificate request must use an ECDSA P-256 key")
	}
	notAfter := now.Add(memberValidity)
	if ca.certificate.NotAfter.Before(notAfter) {
		notAfter = ca.certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: peer.Name},
		DNSNames: []string{peer.Name}, IPAddresses: []net.IP{peer.Address.Addr().AsSlice()},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, request.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// NewMemberKey creates a member's private key and the certificate request
// the host sends to the controller. The key never leaves the host.
func NewMemberKey() (keyPEM, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), csrDER, nil
}

// CertificateRequest recreates the request for an existing member key.
func CertificateRequest(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("member key is not a PKCS#8 PEM key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

// CurrentCertificate reports whether a member certificate matches its key,
// chains to caPEM, names peer and is not yet due for renewal.
func CurrentCertificate(certificatePEM, keyPEM, caPEM []byte, peer Peer, now time.Time) bool {
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return false
	}
	leaf := pair.Leaf
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}})
	return err == nil && now.Add(renewBefore).Before(leaf.NotAfter) && leaf.Subject.CommonName == peer.Name &&
		len(leaf.IPAddresses) == 1 && leaf.IPAddresses[0].Equal(peer.Address.Addr().AsSlice())
}

func readOwnerOnly(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("must be a regular file readable only by its owner, this process user")
	}
	return io.ReadAll(io.LimitReader(file, 64<<10))
}

// ServedCertificateExpiry completes a TLS handshake with a member's listener
// on loopback, presenting the member's own certificate as a peer would, and
// returns when the certificate the member serves expires. A member that
// reloads renewed files (TerraBase TS-464) serves the renewed certificate.
func ServedCertificateExpiry(ctx context.Context, port int, peer Peer, certificateFile, keyFile string, caPEM []byte) (time.Time, error) {
	pair, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return time.Time{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return time.Time{}, errors.New("member CA does not parse")
	}
	// The served certificate names the member's peer address, not loopback.
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: peer.Address.Addr().String(),
		NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return time.Time{}, err
	}
	defer connection.Close()
	return connection.(*tls.Conn).ConnectionState().PeerCertificates[0].NotAfter, nil
}

// CertificateExpiry is a PEM certificate's NotAfter, or zero when it does not parse.
func CertificateExpiry(certificatePEM []byte) time.Time {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return time.Time{}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return certificate.NotAfter
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}
