package publicapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// OriginPull pins an operator-reviewed zone client certificate to its dedicated
// customer-owned root. The certificate and private key are uploaded separately.
type OriginPull struct {
	CACertificate string `json:"ca_certificate"`
	CertificateID string `json:"certificate_id"`
}

// Validate rejects missing configuration, unsafe IDs, and shared or unusable CAs.
func (o OriginPull) Validate() error {
	_, err := o.root()
	return err
}

func (o OriginPull) root() (*x509.Certificate, error) {
	if o.CertificateID == "" || strings.Trim(o.CertificateID, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return nil, errors.New("public_api.origin_pull.certificate_id must contain only letters, digits and hyphens and be nonempty")
	}
	if err := validCA(o.CACertificate); err != nil {
		return nil, fmt.Errorf("public_api.origin_pull.ca_certificate: %w", err)
	}
	block, _ := pem.Decode([]byte(o.CACertificate))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sharedBlock, _ := pem.Decode([]byte(originPullCA))
	if sharedBlock == nil {
		return nil, errors.New("shared Cloudflare origin pull CA denylist is unavailable")
	}
	shared, err := x509.ParseCertificate(sharedBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(root.RawSubjectPublicKeyInfo, shared.RawSubjectPublicKeyInfo) {
		return nil, errors.New("public_api.origin_pull.ca_certificate must not trust Cloudflare's shared origin pull CA")
	}
	now := time.Now()
	if !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil ||
		now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return nil, errors.New("public_api.origin_pull.ca_certificate must be a currently valid self-signed signing CA")
	}
	return root, nil
}

// hostnameNotFound is Cloudflare's error code for a hostname without an
// origin pull association.
const hostnameNotFound = 1553

type originPullCertificate struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
}

// originPullState checks the effective zone certificate and target hostname
// associations. Multiple active certificates do not identify the deployed one.
func (c Cloudflare) originPullState(ctx context.Context, zone string, names []string, o OriginPull, requireEnabled bool) (bool, error) {
	root, err := o.root()
	if err != nil {
		return false, err
	}
	path := "/zones/" + zone + "/origin_tls_client_auth"
	var certificates []originPullCertificate
	if err := c.do(ctx, http.MethodGet, path, nil, &certificates); err != nil {
		return false, err
	}
	if len(certificates) != 1 || certificates[0].ID != o.CertificateID || certificates[0].Status != "active" {
		return false, fmt.Errorf("zone origin pulls require exactly one certificate, reviewed ID %s with status active", o.CertificateID)
	}
	block, rest := pem.Decode([]byte(certificates[0].Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false, errors.New("zone origin pull client must be one PEM leaf certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("zone origin pull client certificate: %w", err)
	}
	if leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return false, errors.New("zone origin pull client must be a non-CA leaf with explicit client auth usage")
	}
	if err := leaf.CheckSignatureFrom(root); err != nil {
		return false, fmt.Errorf("zone origin pull client is not directly signed by the reviewed CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return false, fmt.Errorf("zone origin pull client certificate: %w", err)
	}
	for _, name := range names {
		var association struct {
			Hostname string         `json:"hostname"`
			Enabled  jsontext.Value `json:"enabled"`
		}
		// The supported GET is per hostname; collection /hostnames is PUT only.
		// Cloudflare stores no association without a certificate (PUT fails
		// with 1404), so 404 with code 1553 is the absent state and zone AOP
		// applies; verified live 2026-10-05. A successful explicit null also
		// voids it. Every other error fails closed.
		err := c.do(ctx, http.MethodGet, path+"/hostnames/"+url.PathEscape(name), nil, &association)
		var cf *cloudflareError
		if errors.As(err, &cf) && cf.Status == http.StatusNotFound && slices.Contains(cf.Codes, hostnameNotFound) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("cannot verify origin pull override for %s: %w", name, err)
		}
		if association.Hostname != name || string(association.Enabled) != "null" {
			return false, fmt.Errorf("origin pull hostname override for %s must be explicitly voided (enabled null) before publishing DNS", name)
		}
	}
	var settings struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.do(ctx, http.MethodGet, path+"/settings", nil, &settings); err != nil {
		return false, err
	}
	if settings.Enabled == nil || requireEnabled && !*settings.Enabled {
		return false, errors.New("custom zone origin pulls must read back enabled")
	}
	return *settings.Enabled, nil
}
