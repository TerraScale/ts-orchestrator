package placementpublisher

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net/url"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
)

// HostFilePath is the admitted local control service configuration in the guest.
const HostFilePath = "/etc/terrascale/placement/host.json"

type TLSFiles struct {
	CertificateFile string `json:"certificateFile"`
	PrivateKeyFile  string `json:"privateKeyFile"`
	TrustBundleFile string `json:"trustBundleFile"`
}
type HostFileConfig struct {
	Version        int      `json:"version"`
	Cell           string   `json:"cell"`
	Instance       string   `json:"instance"`
	NATSURL        string   `json:"natsUrl"`
	NKeyFile       string   `json:"nkeyFile"`
	NATSIdentity   TLSFiles `json:"natsIdentity"`
	EngineEndpoint string   `json:"engineEndpoint"`
	EngineIdentity string   `json:"engineIdentity"`
	EngineTLS      TLSFiles `json:"engineTls"`
}

func (files TLSFiles) LoadTLS() (*tls.Config, error) {
	cert, err := bootstrapcredentials.ReadFile(files.CertificateFile, false, 64<<10)
	if err != nil {
		return nil, err
	}
	key, err := bootstrapcredentials.ReadFile(files.PrivateKeyFile, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("placement host: invalid TLS identity")
	}
	ca, err := bootstrapcredentials.ReadFile(files.TrustBundleFile, false, 1<<20)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("placement host: trust bundle is empty")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots}, nil
}
func ParseHostFile(data []byte, cell, instance string) (HostFileConfig, error) {
	var config HostFileConfig
	if len(data) == 0 || len(data) > 32<<10 || json.Unmarshal(data, &config, json.RejectUnknownMembers(true)) != nil || config.Version != 1 || config.Cell != cell || config.Instance != instance || config.Instance == "" {
		return config, errors.New("placement host: invalid exact-host configuration")
	}
	endpoint, err := url.Parse(config.NATSURL)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return config, errors.New("placement host: dedicated global NATS TLS endpoint required")
	}
	for _, path := range []string{config.NKeyFile, config.NATSIdentity.CertificateFile, config.NATSIdentity.PrivateKeyFile, config.NATSIdentity.TrustBundleFile, config.EngineTLS.CertificateFile, config.EngineTLS.PrivateKeyFile, config.EngineTLS.TrustBundleFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return config, errors.New("placement host: absolute credential file references required")
		}
	}
	if _, err := HostSubject(config.EngineIdentity); err != nil {
		return config, err
	}
	if config.EngineEndpoint == "" {
		return config, errors.New("placement host: local engine endpoint required")
	}
	return config, nil
}
