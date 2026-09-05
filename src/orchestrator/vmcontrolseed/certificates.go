package vmcontrolseed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"
)

func newCertificateIssuer(runID string) ([]byte, func(Guest, bool) ([]byte, []byte, error), func(), error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vmqual guest GRU control " + runID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		clear(caPrivate)
		return nil, nil, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(guest Guest, server bool) ([]byte, []byte, error) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		defer clear(private)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			return nil, nil, err
		}
		role := "orchestrator"
		usage := x509.ExtKeyUsageClientAuth
		if server {
			role = "regional-nats"
			usage = x509.ExtKeyUsageServerAuth
		}
		uri := &url.URL{Scheme: "spiffe", Host: "vmqual.terrascale.test", Path: "/" + runID + "/" + role + "/" + guest.ID}
		leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + "-" + guest.ID}, URIs: []*url.URL{uri}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP(guest.Address)}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
		if err != nil {
			return nil, nil, err
		}
		key, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, nil, err
		}
		defer clear(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
	}
	return caPEM, issue, func() { clear(caPrivate) }, nil
}
