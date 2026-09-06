package vmengineconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"slices"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
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
	controlKeys := map[string]bool{}
	for _, h := range d.Hosts {
		m := &Material{cell: strings.ToLower(nodes[h.NodeID].Region), nodeID: h.NodeID, address: nodes[h.NodeID].Address, artifact: artifact, release: release}
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
			{h.ObserverCertificateFile, &m.observerCertificate, false}, {h.ObserverPrivateKeyFile, &m.observerPrivateKey, true},
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
		if err = validateObserver(m, d, h); err != nil {
			return nil, err
		}
		if err = prepareControl(m, d, h, nodes[h.NodeID]); err != nil {
			return nil, err
		}
		if public := m.controlAuthorization.PublicNKey; public != "" {
			if controlKeys[public] {
				return nil, errors.New("vmengineconfig: control NKey reused across hosts")
			}
			controlKeys[public] = true
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

func validateObserver(m *Material, d Declaration, h Host) error {
	bad := errors.New("vmengineconfig: observer identity, credentials or database scope invalid")
	uri, err := url.Parse(h.ObserverIdentity)
	if err != nil || uri.Scheme != "spiffe" || uri.Host != "terrascale.tech" || uri.RawQuery != "" || uri.Fragment != "" || uri.User != nil || uri.Path != "/"+d.Environment+"/engine-observer/"+h.NodeID || len(h.ObserverIdentity) > 128 {
		return bad
	}
	pair, err := tls.X509KeyPair(m.observerCertificate, m.observerPrivateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return bad
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != h.ObserverIdentity {
		return bad
	}
	server, err := tls.X509KeyPair(m.certificate, m.privateKey)
	if err != nil {
		return bad
	}
	serverLeaf, err := x509.ParseCertificate(server.Certificate[0])
	if err != nil || bytes.Equal(leaf.RawSubjectPublicKeyInfo, serverLeaf.RawSubjectPublicKeyInfo) {
		return bad
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.ca) {
		return bad
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return bad
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return bad
	}
	for _, db := range d.Databases {
		if db.Database == h.ObserverDatabase {
			m.observation = tbep.FileConfig{Endpoint: "127.0.0.1:8421", ServerIdentity: identity(d, h), CertificateFile: ObserverCertificatePath, PrivateKeyFile: ObserverPrivateKeyPath, TrustBundleFile: ObserverCAPath, Tenant: db.Tenant, Project: db.Project, Database: db.Database}
			return nil
		}
	}
	return bad
}
