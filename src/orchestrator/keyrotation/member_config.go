package keyrotation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
)

// MemberGatewayFileConfig contains deployment references only. Each identity
// belongs to the rotation controller, while endpoint IDs select host identities.
type MemberGatewayFileConfig struct {
	Members         []MemberEndpoint `json:"members"`
	CertificateFile string           `json:"certificate_file"`
	PrivateKeyFile  string           `json:"private_key_file"`
	TrustBundleFile string           `json:"trust_bundle_file"`
}

func (c MemberGatewayFileConfig) transportConfig(authority func(context.Context) error) (MemberGatewayConfig, error) {
	cert, err := bootstrapcredentials.ReadFile(c.CertificateFile, false, 128<<10)
	if err != nil {
		return MemberGatewayConfig{}, err
	}
	defer clear(cert)
	key, err := bootstrapcredentials.ReadFile(c.PrivateKeyFile, true, 128<<10)
	if err != nil {
		return MemberGatewayConfig{}, err
	}
	defer clear(key)
	trust, err := bootstrapcredentials.ReadFile(c.TrustBundleFile, false, 128<<10)
	if err != nil {
		return MemberGatewayConfig{}, err
	}
	defer clear(trust)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return MemberGatewayConfig{}, configurationError("member transport identity is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return MemberGatewayConfig{}, configurationError("member trust is invalid")
	}
	return MemberGatewayConfig{Members: c.Members, TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots}, CheckAuthority: authority}, nil
}
func (c MemberGatewayFileConfig) OpenForLease(authority func(context.Context) error, epoch uint64, leaseID string) (*MemberGateway, error) {
	config, err := c.transportConfig(authority)
	if err != nil {
		return nil, err
	}
	config.AuthorityEpoch = epoch
	config.AuthorityLeaseID = leaseID
	return NewMemberGateway(config)
}
func (c MemberGatewayFileConfig) OpenReloaderForLease(authority func(context.Context) error, epoch uint64, leaseID string) (*ControlReloader, error) {
	config, err := c.transportConfig(authority)
	if err != nil {
		return nil, err
	}
	config.AuthorityEpoch = epoch
	config.AuthorityLeaseID = leaseID
	return NewControlReloader(config)
}

// Validate admits static paths and endpoints without opening a connection.
func (c MemberGatewayFileConfig) Validate() error {
	config, err := c.transportConfig(func(context.Context) error { return nil })
	if err != nil {
		return err
	}
	config.AuthorityEpoch = 1
	config.AuthorityLeaseID = "static-validation"
	gateway, err := NewMemberGateway(config)
	if err != nil {
		return err
	}
	return gateway.Close()
}
