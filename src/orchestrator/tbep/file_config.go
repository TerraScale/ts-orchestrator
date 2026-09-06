package tbep

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"time"
)

// FileConfig identifies the admitted same-host engine and its scoped TLS identity.
type FileConfig struct {
	Endpoint        string `json:"endpoint"`
	ServerIdentity  string `json:"serverIdentity"`
	CertificateFile string `json:"certificateFile"`
	PrivateKeyFile  string `json:"privateKeyFile"`
	TrustBundleFile string `json:"trustBundleFile"`
	Tenant          string `json:"tenant"`
	Project         string `json:"project"`
	Database        string `json:"database"`
}

func (f FileConfig) Open() (*Client, error) {
	cert, err := bootstrapcredentials.ReadFile(f.CertificateFile, false, 64<<10)
	if err != nil {
		return nil, err
	}
	key, err := bootstrapcredentials.ReadFile(f.PrivateKeyFile, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	ca, err := bootstrapcredentials.ReadFile(f.TrustBundleFile, false, 1<<20)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("TBEP: empty trust bundle")
	}
	return New(Config{Endpoint: f.Endpoint, ServerIdentity: f.ServerIdentity, Certificate: pair, Roots: roots, Tenant: f.Tenant, Project: f.Project, Database: f.Database, Timeout: 5 * time.Second})
}
