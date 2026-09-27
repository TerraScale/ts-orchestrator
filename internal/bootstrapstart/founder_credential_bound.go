package bootstrapstart

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// CredentialBound is derived from the exact installed, manifest-pinned file
// inventory. The cutoff is the first JWT or TLS leaf expiry in that inventory.
type CredentialBound struct {
	SHA256     string
	ValidUntil time.Time
}

func (check LiveCredentials) CurrentCredentialBound(expected map[string]string,
	manifest bootstrap.Manifest,
) (CredentialBound, error) {
	if len(expected) == 0 || check.Config.Embedded == nil || check.verifyPaths(expected, manifest) != nil {
		return CredentialBound{}, ErrLiveCredentials
	}
	if err := check.verifyInventory(expected); err != nil {
		return CredentialBound{}, err
	}
	inventorySHA256, err := bootstrap.InstallContinuityCredentialDigest(expected)
	if err != nil {
		return CredentialBound{}, ErrLiveCredentials
	}
	dir, err := openMaterialDirectory(check.directory, check.ServiceUID, check.ServiceGID, 0o700, check.allowUnsafeAncestors)
	if err != nil {
		return CredentialBound{}, err
	}
	defer unix.Close(dir)
	read := func(path string) ([]byte, error) {
		name := filepath.Base(path)
		if path != filepath.Join(check.directory, name) || expected[name] == "" {
			return nil, ErrLiveCredentials
		}
		return readMaterial(dir, name, check.ServiceUID, check.ServiceGID, expected[name], bootstrap.MaxSecretBytes)
	}
	var cutoff time.Time
	add := func(expiry time.Time) error {
		if expiry.IsZero() || !expiry.After(time.Now()) {
			return ErrLiveCredentials
		}
		if cutoff.IsZero() || expiry.Before(cutoff) {
			cutoff = expiry
		}
		return nil
	}
	e := check.Config.Embedded
	for _, item := range []struct {
		path   string
		decode func(string) (jwt.Claims, error)
	}{
		{e.OperatorJWTFile, func(raw string) (jwt.Claims, error) { return jwt.DecodeOperatorClaims(raw) }},
		{e.SystemJWTFile, func(raw string) (jwt.Claims, error) { return jwt.DecodeAccountClaims(raw) }},
		{e.CellJWTFile, func(raw string) (jwt.Claims, error) { return jwt.DecodeAccountClaims(raw) }},
		{e.SystemCredentialsFile, func(raw string) (jwt.Claims, error) { return jwt.DecodeUserClaims(raw) }},
		{check.Config.CredentialsFile, func(raw string) (jwt.Claims, error) { return jwt.DecodeUserClaims(raw) }},
	} {
		data, err := read(item.path)
		if err != nil {
			return CredentialBound{}, err
		}
		var raw string
		if item.path == e.SystemCredentialsFile || item.path == check.Config.CredentialsFile {
			raw, err = nkeys.ParseDecoratedJWT(data)
		} else {
			raw = strings.TrimSpace(string(data))
		}
		clear(data)
		if err != nil {
			return CredentialBound{}, err
		}
		claim, err := item.decode(raw)
		if err != nil || claim.Claims().Expires <= 0 {
			return CredentialBound{}, ErrLiveCredentials
		}
		if err := add(time.Unix(claim.Claims().Expires, 0).UTC()); err != nil {
			return CredentialBound{}, err
		}
	}
	for _, path := range []string{check.Config.TLS.CertFile, e.TLS.CertFile, e.RouteTLS.CertFile} {
		data, err := read(path)
		if err != nil {
			return CredentialBound{}, err
		}
		block, _ := pem.Decode(data)
		clear(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return CredentialBound{}, ErrLiveCredentials
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CredentialBound{}, fmt.Errorf("%w: parse installed TLS leaf: %v", ErrLiveCredentials, err)
		}
		if err := add(certificate.NotAfter.UTC()); err != nil {
			return CredentialBound{}, err
		}
	}
	return CredentialBound{SHA256: inventorySHA256, ValidUntil: cutoff}, nil
}
