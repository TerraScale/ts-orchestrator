//go:build sandboxvm

package vmqualruntime

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualartifact"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type qualificationNATSIdentity struct {
	seed, certificate, privateKey []byte
	pair                          nkeys.KeyPair
	publicKey, uri                string
	tls                           tls.Certificate
}

type qualificationNATSAuthority struct {
	ca             []byte
	roots          *x509.CertPool
	server         tls.Certificate
	serverName     string
	controller     *qualificationNATSIdentity
	guests         map[string]*qualificationNATSIdentity
	memberships    map[string]*qualificationMembershipIdentity
	commandSigners map[string]*qualificationMembershipIdentity
	users          []*natsserver.NkeyUser
}

func newQualificationNATSAuthority(plan vmnet.NetworkPlan) (*qualificationNATSAuthority, error) {
	listener, ok := plan.Listener("nats")
	if !ok {
		return nil, errors.New("vmqual: authenticated NATS requires planned listener")
	}
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(caPrivate)
	serial, err := vmqualartifact.CertificateSerial()
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "vmqual NATS CA " + plan.RunID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	authority := &qualificationNATSAuthority{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), roots: x509.NewCertPool(), serverName: listener.Address, guests: make(map[string]*qualificationNATSIdentity), memberships: make(map[string]*qualificationMembershipIdentity), commandSigners: make(map[string]*qualificationMembershipIdentity)}
	authority.roots.AppendCertsFromPEM(authority.ca)
	failed := true
	defer func() {
		if failed {
			authority.close()
		}
	}()
	issue := func(role, id string, server bool) (*qualificationNATSIdentity, error) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(private)
		serial, err := vmqualartifact.CertificateSerial()
		if err != nil {
			return nil, err
		}
		identityURI := "spiffe://vmqual.terrascale.test/" + plan.RunID + "/" + role + "/" + id
		uri, _ := url.Parse(identityURI)
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + "-" + id}, URIs: []*url.URL{uri}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			cert.IPAddresses = []net.IP{net.ParseIP(listener.Address)}
			for _, region := range plan.Regions {
				cert.IPAddresses = append(cert.IPAddresses, net.ParseIP(region.Gateway))
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, public, caPrivate)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(keyDER)
		identity := &qualificationNATSIdentity{certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), privateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), uri: identityURI}
		identity.tls, err = tls.X509KeyPair(identity.certificate, identity.privateKey)
		if err != nil {
			return nil, err
		}
		if !server {
			identity.pair, err = nkeys.CreateUser()
			if err != nil {
				return nil, err
			}
			identity.seed, err = identity.pair.Seed()
			if err != nil {
				return nil, err
			}
			identity.publicKey, err = identity.pair.PublicKey()
			if err != nil {
				return nil, err
			}
		}
		return identity, nil
	}
	server, err := issue("server", "transport", true)
	if err != nil {
		return nil, err
	}
	authority.server = server.tls
	zeroBytes(server.privateKey)
	authority.controller, err = issue("controller", "bootstrap", false)
	if err != nil {
		return nil, err
	}
	authority.users = append(authority.users, &natsserver.NkeyUser{Nkey: authority.controller.publicKey, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: []string{">"}}, Subscribe: &natsserver.SubjectPermission{Allow: []string{">"}}}})
	for _, region := range plan.Regions {
		if err := authority.issueCommandIdentities(region); err != nil {
			return nil, err
		}
		for _, guest := range region.Guests {
			identity, err := issue("ts-node", guest.ID, false)
			if err != nil {
				return nil, err
			}
			authority.guests[guest.ID] = identity
			membership, err := newQualificationMembershipIdentity()
			if err != nil {
				return nil, err
			}
			authority.memberships[guest.ID] = membership
			node, err := hostagent.NewNodeId(guest.ID)
			if err != nil {
				return nil, err
			}
			heartbeat, err := hostagent.NodeHeartbeatSubject(node)
			if err != nil {
				return nil, err
			}
			commands := []string{}
			for _, subject := range []func(hostagent.NodeId) (string, error){hostagent.NodeDrainSubject, hostagent.NodeDrainStatusSubject, hostagent.NodeDeploySubject, hostagent.NodeRollbackSubject, hostagent.NodeApplyManifestSubject} {
				value, err := subject(node)
				if err != nil {
					return nil, err
				}
				commands = append(commands, value)
			}
			authority.users = append(authority.users, &natsserver.NkeyUser{Nkey: identity.publicKey, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: []string{heartbeat}}, Subscribe: &natsserver.SubjectPermission{Allow: commands}, Response: &natsserver.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}}})
		}
	}
	failed = false
	return authority, nil
}

func (authority *qualificationNATSAuthority) options(identity *qualificationNATSIdentity) ([]nats.Option, error) {
	if authority == nil || identity == nil || identity.pair == nil || len(identity.seed) == 0 {
		return nil, errors.New("vmqual: authenticated NATS identity is unavailable")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authority.roots, Certificates: []tls.Certificate{identity.tls}, ServerName: authority.serverName}
	return []nats.Option{nats.Secure(tlsConfig), nats.Nkey(identity.publicKey, identity.pair.Sign), nats.NoReconnect()}, nil
}

func (authority *qualificationNATSAuthority) close() {
	if authority == nil {
		return
	}
	destroy := func(identity *qualificationNATSIdentity) {
		if identity == nil {
			return
		}
		zeroBytes(identity.seed)
		zeroBytes(identity.privateKey)
		if private, ok := identity.tls.PrivateKey.(ed25519.PrivateKey); ok {
			zeroBytes(private)
		}
		if identity.pair != nil {
			identity.pair.Wipe()
		}
		identity.pair = nil
		identity.seed = nil
		identity.privateKey = nil
	}
	destroy(authority.controller)
	for _, identity := range authority.guests {
		destroy(identity)
	}
	if private, ok := authority.server.PrivateKey.(ed25519.PrivateKey); ok {
		zeroBytes(private)
	}
	for _, identity := range authority.memberships {
		zeroBytes(identity.PrivatePEM)
	}
	for _, identity := range authority.commandSigners {
		zeroBytes(identity.PrivatePEM)
	}
	authority.commandSigners = nil
	authority.memberships = nil
	authority.server = tls.Certificate{}
	authority.guests = nil
	authority.controller = nil
	authority.users = nil
}

func (services *qualificationRuntimeServices) authenticatedNATSOptions() ([]nats.Option, error) {
	if services == nil {
		return nil, errors.New("vmqual: qualification services missing")
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || !services.started || services.nats == nil || services.natsAuthority == nil {
		return nil, errors.New("vmqual: authenticated qualification NATS is not running")
	}
	return services.natsAuthority.options(services.natsAuthority.controller)
}
