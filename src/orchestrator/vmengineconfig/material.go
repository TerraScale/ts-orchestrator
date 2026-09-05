package vmengineconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func prepare(d Declaration, artifact, release string, bindings []Binding) (result map[string]*Material, err error) {
	nodes, err := validate(d, artifact, release, bindings)
	if err != nil {
		return nil, err
	}
	// The renderer produces the same bytes regardless of declaration ordering.
	d.Hosts = slices.Clone(d.Hosts)
	d.Databases = slices.Clone(d.Databases)
	slices.SortFunc(d.Hosts, func(a, b Host) int { return strings.Compare(a.NodeID, b.NodeID) })
	slices.SortFunc(d.Databases, func(a, b Database) int { return strings.Compare(a.Database, b.Database) })
	materials := map[string]*Material{}
	defer func() {
		if err != nil {
			for _, m := range materials {
				m.Clear()
			}
		}
	}()
	var sharedCA []byte
	for _, h := range d.Hosts {
		m := &Material{nodeID: h.NodeID, address: nodes[h.NodeID].Address, artifact: artifact, release: release}
		materials[h.NodeID] = m
		m.settings, err = render(d, h, nodes)
		if err != nil {
			return nil, err
		}
		for _, file := range []struct {
			path    string
			target  *[]byte
			private bool
		}{
			{h.CertificateFile, &m.certificate, false}, {h.PrivateKeyFile, &m.privateKey, true}, {h.CAFile, &m.ca, false},
		} {
			*file.target, err = initialgrant.ReadMaterialFile(file.path, 64<<10, file.private)
			if err != nil {
				return nil, errors.New("vmengineconfig: protected TLS material read refused")
			}
		}
		if sharedCA == nil {
			sharedCA = m.ca
		}
		if !bytes.Equal(sharedCA, m.ca) {
			return nil, errors.New("vmengineconfig: member trust bundles differ")
		}
		if err = validateTLS(m, identity(d, h)); err != nil {
			return nil, err
		}
	}
	return materials, nil
}

func validateTLS(m *Material, expected string) error {
	bad := errors.New("vmengineconfig: TLS material does not bind the declared member and address")
	pair, err := tls.X509KeyPair(m.certificate, m.privateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return bad
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected || leaf.VerifyHostname(m.address) != nil {
		return bad
	}
	roots := x509.NewCertPool()
	raw := m.ca
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN CERTIFICATE-----")) {
			return bad
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return bad
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !ca.IsCA || !ca.BasicConstraintsValid {
			return bad
		}
		roots.AddCert(ca)
		count++
		raw = rest
	}
	if count == 0 {
		return bad
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return bad
		}
		intermediates.AddCert(cert)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: time.Now()}); err != nil {
			return bad
		}
	}
	return nil
}
