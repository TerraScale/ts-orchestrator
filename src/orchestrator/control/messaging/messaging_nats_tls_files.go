package messaging

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nats.go"
)

// NatsTlsFiles holds the three PEM file references of one mTLS identity.
type NatsTlsFiles struct {
	CaFile          string
	CertificateFile string
	KeyFile         string
}

// NatsTlsFilesResolve resolves the three PEM files. A nil result with a nil
// error means no TLS files were supplied.
func NatsTlsFilesResolve(caFile, certificateFile, keyFile, optionPrefix string) (*NatsTlsFiles, error) {
	values := []string{caFile, certificateFile, keyFile}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	if supplied == 0 {
		return nil, nil
	}

	if supplied != 3 {
		return nil, fmt.Errorf("%s requires CA, certificate, and key files together.", optionPrefix)
	}

	ca, err := natsTlsResolvePublic(caFile, optionPrefix+" CA")
	if err != nil {
		return nil, err
	}

	certificate, err := natsTlsResolvePublic(certificateFile, optionPrefix+" certificate")
	if err != nil {
		return nil, err
	}

	key, err := natsTlsResolvePrivate(keyFile, optionPrefix+" key")
	if err != nil {
		return nil, err
	}

	if err := natsTlsValidateIdentity(certificate, key, ca, optionPrefix); err != nil {
		return nil, err
	}

	return &NatsTlsFiles{CaFile: ca, CertificateFile: certificate, KeyFile: key}, nil
}

// SameIdentity reports whether both identities present the same certificate
// public key.
func (t *NatsTlsFiles) SameIdentity(other *NatsTlsFiles) bool {
	if t == nil || other == nil {
		return false
	}
	first, err := natsTlsSubjectPublicKeyInfo(t.CertificateFile)
	if err != nil {
		return false
	}

	second, err := natsTlsSubjectPublicKeyInfo(other.CertificateFile)
	if err != nil {
		return false
	}

	return bytes.Equal(first, second)
}

// HasSubjectPublicKeyInfo reports whether the certificate presents the given
// subject public key.
func (t *NatsTlsFiles) HasSubjectPublicKeyInfo(subjectPublicKeyInfo []byte) bool {
	if t == nil {
		return false
	}
	key, err := natsTlsSubjectPublicKeyInfo(t.CertificateFile)
	if err != nil {
		return false
	}

	return bytes.Equal(key, subjectPublicKeyInfo)
}

// Options returns the nats.go TLS options: TLS is required, the CA pins the
// trust root, and the certificate/key pair is the client identity.
func (t *NatsTlsFiles) Options() []nats.Option {
	if t == nil {
		return nil
	}

	return []nats.Option{
		nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13}),
		nats.RootCAs(t.CaFile),
		nats.ClientCert(t.CertificateFile, t.KeyFile),
	}
}

func natsTlsResolvePublic(value, optionName string) (string, error) {
	path, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s must identify a bounded existing PEM file.", optionName)
	}
	if err := messagingRejectSymlinkPath(path); err != nil {
		return "", fmt.Errorf("%s must not contain symbolic links.", optionName)
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 65536 {
		return "", fmt.Errorf("%s must identify a bounded existing PEM file.", optionName)
	}

	return path, nil
}

func natsTlsResolvePrivate(value, optionName string) (string, error) {
	path, err := natsTlsResolvePublic(value, optionName)
	if err != nil {
		return "", err
	}

	mode, err := MessagingUnixFileMode(path)
	if err != nil {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if mode&(MessagingGroupAny|MessagingOtherAny) != 0 {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	return path, nil
}

// natsTlsValidateIdentity checks the key pair matches the certificate and the
// CA declares the CA basic constraint.
func natsTlsValidateIdentity(certificateFile, keyFile, caFile, optionPrefix string) error {
	if _, err := tls.LoadX509KeyPair(certificateFile, keyFile); err != nil {
		return fmt.Errorf("%s files are not valid matching PEM credentials.", optionPrefix)
	}

	authority, err := natsTlsLoadCertificate(caFile)
	if err != nil {
		return fmt.Errorf("%s files are not valid matching PEM credentials.", optionPrefix)
	}

	if !authority.IsCA {
		return fmt.Errorf("%s files do not contain a usable identity and CA.", optionPrefix)
	}

	return nil
}

func natsTlsLoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	return x509.ParseCertificate(block.Bytes)
}

func natsTlsSubjectPublicKeyInfo(path string) ([]byte, error) {
	certificate, err := natsTlsLoadCertificate(path)
	if err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(certificate.PublicKey)
}
