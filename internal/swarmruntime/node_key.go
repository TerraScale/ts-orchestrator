package swarmruntime

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// nodeSigningKey retains the actual joined identity; no caller supplies a key.
func (n *Node) nodeSigningKey() (crypto.Signer, [][]byte, error) {
	if n == nil || n.upstream == nil || n.stateDir == "" {
		return nil, nil, errors.New("joined upstream node identity unavailable")
	}
	wire, err := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-node.key"))
	if err != nil {
		return nil, nil, err
	}
	defer clear(wire)
	certificateWire, err := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-node.crt"))
	if err != nil {
		return nil, nil, err
	}
	rootWire, err := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-root-ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	key, chain, _, err := parseNodeSigningKey(n.ID(), wire, certificateWire, rootWire)
	return key, chain, err
}

func parseNodeSigningKey(nodeID string, wire, certificateWire, rootWire []byte) (crypto.Signer, [][]byte, time.Time, error) {
	block, rest := pem.Decode(wire)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, time.Time{}, errors.New("upstream node private key unavailable")
	}
	var key crypto.Signer
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(crypto.Signer)
	}
	if key == nil {
		if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			key = parsed
		}
	}
	if key == nil {
		return nil, nil, time.Time{}, errors.New("unsupported upstream node private key")
	}
	var chain [][]byte
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(certificateWire)) != 0 {
		block, rest := pem.Decode(certificateWire)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, time.Time{}, errors.New("invalid upstream node certificate chain")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		chain = append(chain, bytes.Clone(block.Bytes))
		certificates = append(certificates, certificate)
		certificateWire = rest
	}
	if len(certificates) == 0 || certificates[0].Subject.CommonName != nodeID {
		return nil, nil, time.Time{}, errors.New("upstream node certificate differs from live identity")
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(public, certificates[0].RawSubjectPublicKeyInfo) {
		return nil, nil, time.Time{}, errors.New("upstream node signing key differs from certificate")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootWire) {
		return nil, nil, time.Time{}, errors.New("upstream node certificate authority unavailable")
	}
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	verified, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	deadline := certificates[0].NotAfter
	for _, verifiedChain := range verified {
		for _, certificate := range verifiedChain {
			if certificate.NotAfter.Before(deadline) {
				deadline = certificate.NotAfter
			}
		}
	}
	return key, chain, deadline, nil
}
