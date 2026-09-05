package ociinstance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

// Config is included in the original owner-signed host admission. Qualification
// is explicit and cannot be enabled through SDK environment variables.
type Config struct {
	Region        string               `json:"region"`
	Qualification *QualificationConfig `json:"qualification,omitempty"`
}

// QualificationConfig pins one mTLS fixture server. Requests retain their
// canonical OCI host and path, including actual SDK metadata and federation.
// This transport is qualification evidence only, never real-provider evidence.
type QualificationConfig struct {
	Endpoint             string `json:"endpoint"`
	ServerName           string `json:"serverName"`
	RootCAPEM            string `json:"rootCaPem"`
	ClientCertificatePEM string `json:"clientCertificatePem"`
	ClientPrivateKeyFile string `json:"clientPrivateKeyFile"`
}

func ValidateConfig(config Config) error {
	if !validHomeRegion(config.Region) {
		return ErrIdentity
	}
	q := config.Qualification
	if q == nil {
		return nil
	}
	endpoint, err := url.Parse(q.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.Hostname() == "" || len(q.Endpoint) > 2048 {
		return ErrIdentity
	}
	if q.ServerName == "" || len(q.ServerName) > 253 || strings.ContainsAny(q.ServerName, "/\\:@\x00\r\n\t ") {
		return ErrIdentity
	}
	if q.ClientPrivateKeyFile == "" || len(q.ClientPrivateKeyFile) > 4096 || !filepath.IsAbs(q.ClientPrivateKeyFile) || filepath.Clean(q.ClientPrivateKeyFile) != q.ClientPrivateKeyFile || strings.ContainsAny(q.ClientPrivateKeyFile, "\x00\r\n") {
		return ErrIdentity
	}
	if len(q.RootCAPEM) == 0 || len(q.RootCAPEM) > 64<<10 || len(q.ClientCertificatePEM) == 0 || len(q.ClientCertificatePEM) > 64<<10 {
		return ErrIdentity
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(q.RootCAPEM)) {
		return ErrIdentity
	}
	block, _ := pem.Decode([]byte(q.ClientCertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrIdentity
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA {
		return ErrIdentity
	}
	if len(cert.ExtKeyUsage) > 0 {
		client := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				client = true
			}
		}
		if !client {
			return ErrIdentity
		}
	}
	return nil
}

// NewFromConfig reads qualification private material through the caller's
// protected file reader. Production identities require no credential file.
func NewFromConfig(ctx context.Context, config Config, readPrivate func(string) ([]byte, error)) (*Identity, error) {
	if ValidateConfig(config) != nil {
		return nil, ErrIdentity
	}
	if config.Qualification == nil {
		return New(ctx, config.Region, Options{})
	}
	q := config.Qualification
	if readPrivate == nil {
		return nil, ErrIdentity
	}
	key, err := readPrivate(q.ClientPrivateKeyFile)
	if err != nil {
		return nil, ErrIdentity
	}
	defer clear(key)
	if len(key) == 0 || len(key) > 64<<10 {
		return nil, ErrIdentity
	}
	cert, err := tls.X509KeyPair([]byte(q.ClientCertificatePEM), key)
	if err != nil {
		return nil, ErrIdentity
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(q.RootCAPEM)) {
		return nil, ErrIdentity
	}
	transport := productionTransport()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: q.ServerName, Certificates: []tls.Certificate{cert}}
	endpoint, _ := url.Parse(q.Endpoint)
	return New(ctx, config.Region, Options{Transport: &qualificationTransport{transport: transport, endpoint: endpoint}})
}

type qualificationTransport struct {
	transport *http.Transport
	endpoint  *url.URL
}

func (t *qualificationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, ErrRequest
	}
	// The production dispatchers validate the canonical destination first. Keep
	// Host unchanged so HTTP signatures bind the same OCI request in both modes.
	copy := request.Clone(request.Context())
	copyURL := *copy.URL
	copyURL.Scheme = "https"
	copyURL.Host = t.endpoint.Host
	copy.URL = &copyURL
	if copy.Host == "" {
		copy.Host = request.URL.Host
	}
	return t.transport.RoundTrip(copy)
}
func (t *qualificationTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }
