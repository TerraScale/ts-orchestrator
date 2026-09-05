package vmcontrolseed

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

// Validate binds the sideband credentials to the exact owner-granted public inputs.
func (m Material) Validate() error {
	bad := func() error {
		return errors.New("vmcontrolseed: controller material differs from admitted configuration")
	}
	config, err := initialgrant.ParseConfig([]byte(m.Settings))
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(m.Address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || config.NodeID != m.HostID || config.Instance != m.HostID || m.Selected != (config.Role == "seed") || config.Membership.SigningKeyFile != MembershipKeyPath || config.Membership.PinsFile != MembershipPinsPath || config.Broker.StoreDir != StorePath || config.Broker.ServerName != config.SeedInstance || config.Regional.Account != RegionalAccount {
		return bad()
	}
	endpoint, err := url.Parse(config.Broker.Endpoint)
	if err != nil {
		return bad()
	}
	brokerIP, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !brokerIP.Is4() || !brokerIP.IsPrivate() || endpoint.Port() != "4222" || m.Selected && brokerIP != ip {
		return bad()
	}
	profile, err := initialcontrol.ProfileDigest("gru", config.SeedInstance)
	if err != nil || profile != config.ProfileSHA256 {
		return bad()
	}
	budget, err := initialcontrol.RequiredStorageBytes("gru", config.SeedInstance)
	if err != nil || budget != config.Broker.StorageBudgetBytes {
		return bad()
	}
	pins := map[string]string{}
	for _, peer := range config.Peers {
		pins[peer.Instance] = peer.MembershipPublicKey
	}
	raw, err := json.Marshal(pins)
	if err != nil || digest(raw) != config.Membership.PinsSHA256 {
		return bad()
	}

	reader := config.AuthorityReader
	if reader.NKeySeedFile != AuthorityNKeyPath || reader.CAFile != AuthorityCAPath || reader.CertificateFile != AuthorityCertificatePath || reader.KeyFile != AuthorityPrivateKeyPath || digest(m.Files[AuthorityCAPath]) != reader.CASHA256 || digest(m.Files[AuthorityCertificatePath]) != reader.CertificateSHA256 {
		return bad()
	}
	readerPair, err := nkeys.FromSeed(m.Files[AuthorityNKeyPath])
	if err != nil {
		return bad()
	}
	readerPublic, err := readerPair.PublicKey()
	readerPair.Wipe()
	if err != nil || readerPublic != reader.PublicNKey {
		return bad()
	}
	readerTLS, err := tls.X509KeyPair(m.Files[AuthorityCertificatePath], m.Files[AuthorityPrivateKeyPath])
	if err != nil {
		return bad()
	}
	readerCert, err := x509.ParseCertificate(readerTLS.Certificate[0])
	if err != nil {
		return bad()
	}
	tlsPublic := map[string][]byte{}
	if !bytes.Equal(m.Files[AuthorityCAPath], m.Files[CAPath]) {
		return bad()
	}
	expected := map[string]bool{AuthorityNKeyPath: true, AuthorityCAPath: true, AuthorityCertificatePath: true, AuthorityPrivateKeyPath: true}

	checkTLS := func(t initialgrant.TLSFiles, certPath, keyPath string, server bool) error {
		if t.CAFile != CAPath || t.CertificateFile != certPath || t.KeyFile != keyPath || digest(m.Files[CAPath]) != t.CASHA256 || digest(m.Files[certPath]) != t.CertificateSHA256 {
			return bad()
		}
		expected[CAPath], expected[certPath], expected[keyPath] = true, true, true
		pair, err := tls.X509KeyPair(m.Files[certPath], m.Files[keyPath])
		if err != nil {
			return bad()
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return bad()
		}
		if bytes.Equal(readerCert.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
			return bad()
		}
		tlsPublic[certPath] = cert.RawSubjectPublicKeyInfo
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(m.Files[CAPath]) {
			return bad()
		}
		opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			opts.DNSName = m.Address
		}
		if _, err := cert.Verify(opts); err != nil {
			return bad()
		}
		return nil
	}
	checkConnection := func(c initialgrant.Connection, path string, provisioner bool) error {
		if c.NKeySeedFile != path {
			return bad()
		}
		expected[path] = true
		pair, err := nkeys.FromSeed(m.Files[path])
		if err != nil {
			return bad()
		}
		defer pair.Wipe()
		public, err := pair.PublicKey()
		if err != nil || public != c.PublicNKey {
			return bad()
		}
		cert, key := CertificatePath, PrivateKeyPath
		if provisioner {
			cert, key = ProvisionerCertificatePath, ProvisionerPrivateKeyPath
		}
		return checkTLS(c.TLS, cert, key, false)
	}
	if err := checkConnection(config.Regional.Runtime, NKeyPath, false); err != nil {
		return err
	}
	if m.Selected {
		if config.Global.Account != GlobalAccount {
			return bad()
		}
		for _, entry := range []struct {
			connection  initialgrant.Connection
			path        string
			provisioner bool
		}{{*config.Regional.Provisioner, RegionalProvisionerNKeyPath, true}, {*config.Global.Provisioner, GlobalProvisionerNKeyPath, true}, {config.Global.Runtime, GlobalNKeyPath, false}} {
			if err := checkConnection(entry.connection, entry.path, entry.provisioner); err != nil {
				return err
			}
		}
		if bytes.Equal(tlsPublic[CertificatePath], tlsPublic[ProvisionerCertificatePath]) {
			return bad()
		}
		if err := checkTLS(config.Broker.TLS, ServerCertificatePath, ServerPrivateKeyPath, true); err != nil {
			return err
		}
		wanted, err := renderBroker(config)
		if err != nil || wanted != config.Broker.Configuration {
			return bad()
		}
	}
	if len(expected) != len(m.Files) {
		return bad()
	}
	for path, data := range m.Files {
		if !expected[path] || (!IsFilePath(path) && !IsAuthorityFilePath(path)) || len(data) == 0 || len(data) > 64<<10 {
			return bad()
		}
	}
	return nil
}

// ValidateMembership checks the separately supplied private membership sideband
// against the public signer and complete peer pins in the signed launch.
func (m Material) ValidateMembership(private []byte, pins map[string]string) error {
	config, err := initialgrant.ParseConfig([]byte(m.Settings))
	if err != nil {
		return err
	}
	_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(private)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	if public != config.Membership.PublicKey || digest(raw) != config.Membership.PinsSHA256 {
		return errors.New("vmcontrolseed: membership sideband differs from owner-granted identity")
	}
	return nil
}
