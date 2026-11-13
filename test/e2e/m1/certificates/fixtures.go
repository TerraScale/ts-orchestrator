package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func fixtureCertificate(name string, key crypto.Signer, root *x509.Certificate, signer crypto.Signer, until time.Time) ([]byte, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, DNSNames: []string{name}, Subject: pkix.Name{CommonName: name}, NotBefore: until.Add(-90 * 24 * time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if leaf.NotBefore.After(time.Now().Add(-time.Hour)) {
		leaf.NotBefore = time.Now().Add(-time.Hour)
	}
	if name == "journey CA" {
		leaf.IsCA, leaf.BasicConstraintsValid, leaf.KeyUsage = true, true, x509.KeyUsageCertSign
		leaf.NotBefore = time.Now().Add(-time.Hour)
		root, signer = leaf, key
	}
	if name == "identity" {
		leaf.Subject.OrganizationalUnit = []string{"opc-tenant:ocid1.tenancy.oc1..journey"}
		leaf.DNSNames = []string{"acme-v02.api.letsencrypt.org"}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), signer)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func fixtures(cfg configuration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert, _, err := fixtureCertificate("journey CA", key, nil, nil, time.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(cert)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err = os.WriteFile(cfg.Work+"/ca.pem", cert, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(cfg.Work+"/ca.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return err
	}
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert, private, err := fixtureCertificate("identity", identity, root, key, time.Now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	if err = os.WriteFile(cfg.Work+"/identity.pem", cert, 0600); err != nil {
		return err
	}
	return os.WriteFile(cfg.Work+"/identity.key", private, 0600)
}
