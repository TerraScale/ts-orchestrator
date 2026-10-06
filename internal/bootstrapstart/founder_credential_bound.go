package bootstrapstart

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// CredentialBound is derived from the exact installed, manifest-pinned file
// inventory. The cutoff is the first JWT or TLS leaf expiry in that inventory.
// An install that adopted a material generation is bound to the newest
// generation instead, until it expires (TS-568).
type CredentialBound struct {
	SHA256     string
	ValidUntil time.Time
	// Generation is the fingerprint of the newest adopted generation.
	Generation string
}

func (check LiveCredentials) CurrentCredentialBound(expected map[string]string,
	manifest bootstrap.Manifest, roots trust.Keyring, privateIP string,
) (CredentialBound, error) {
	if len(expected) == 0 || check.Config.Embedded == nil {
		return CredentialBound{}, ErrLiveCredentials
	}
	if bound, adopted, err := check.generationBound(manifest, roots, privateIP); adopted || err != nil {
		return bound, err
	}
	if check.verifyPaths(ManifestPins(expected), manifest) != nil {
		return CredentialBound{}, ErrLiveCredentials
	}
	if err := check.verifyInventory(ManifestPins(expected)); err != nil {
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
	e := check.Config.Embedded
	cutoff, err := credentialCutoff(read, CredentialFiles{
		OperatorJWT: e.OperatorJWTFile, SystemJWT: e.SystemJWTFile, CellJWT: e.CellJWTFile,
		SystemCredentials: e.SystemCredentialsFile, Credentials: check.Config.CredentialsFile,
		TLSCertificates: []string{check.Config.TLS.CertFile, e.TLS.CertFile, e.RouteTLS.CertFile},
	})
	if err != nil {
		return CredentialBound{}, err
	}
	return CredentialBound{SHA256: inventorySHA256, ValidUntil: cutoff}, nil
}

// generationBound checks the install against its adopted material generation
// and binds the newest one; adopted is false without an adopted chain.
func (check LiveCredentials) generationBound(manifest bootstrap.Manifest, roots trust.Keyring, privateIP string,
) (CredentialBound, bool, error) {
	dir, err := openMaterialDirectory(check.directory, check.ServiceUID, check.ServiceGID, 0o700, check.allowUnsafeAncestors)
	if err != nil {
		return CredentialBound{}, false, err
	}
	defer unix.Close(dir)
	pins, err := restartPins(dir, check.ServiceUID, check.ServiceGID, manifest, roots, privateIP)
	if err != nil {
		return CredentialBound{}, true, fmt.Errorf("%w: %w", ErrLiveCredentials, err)
	}
	if pins.Generation == nil {
		return CredentialBound{}, false, nil
	}
	if err := check.verifyPaths(pins, manifest); err != nil {
		return CredentialBound{}, true, err
	}
	if err := check.verifyInventory(pins); err != nil {
		return CredentialBound{}, true, err
	}
	now := time.Now()
	if err := pins.verifyGeneration(dir, check.ServiceUID, check.ServiceGID, now); err != nil {
		return CredentialBound{}, true, fmt.Errorf("%w: %w", ErrLiveCredentials, err)
	}
	if !now.Before(pins.Generation.ExpiresAt()) {
		return CredentialBound{}, true, fmt.Errorf("%w: the adopted material generation has expired", ErrLiveCredentials)
	}
	digest, err := bootstrap.InstallContinuityGenerationDigest(pins.Generation.Fingerprint())
	if err != nil {
		return CredentialBound{}, true, err
	}
	return CredentialBound{SHA256: digest, ValidUntil: pins.Generation.ExpiresAt(),
		Generation: pins.Generation.Fingerprint()}, true, nil
}

// CredentialFiles names one controller's JWT, NATS credential and TLS leaf
// files whose earliest expiry bounds its install continuity.
type CredentialFiles struct {
	OperatorJWT       string
	SystemJWT         string
	CellJWT           string
	SystemCredentials string
	Credentials       string
	TLSCertificates   []string
}

// SlotCredentialFiles returns the generated material file names a controller
// slot installs, for computing its continuity bound offline.
func SlotCredentialFiles(slot string) CredentialFiles {
	return CredentialFiles{OperatorJWT: "operator.jwt", SystemJWT: "system.jwt", CellJWT: "cell.jwt",
		SystemCredentials: "system.creds", Credentials: slot + ".creds",
		TLSCertificates: []string{slot + "-tls-cert.pem"}}
}

// CredentialValidUntil is the continuity cutoff the controller derives from
// the same files: the first JWT or TLS leaf expiry.
func CredentialValidUntil(read func(string) ([]byte, error), files CredentialFiles) (time.Time, error) {
	return credentialCutoff(read, files)
}

func credentialCutoff(read func(string) ([]byte, error), files CredentialFiles) (time.Time, error) {
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
	for _, item := range []struct {
		path      string
		decorated bool
		decode    func(string) (jwt.Claims, error)
	}{
		{files.OperatorJWT, false, func(raw string) (jwt.Claims, error) { return jwt.DecodeOperatorClaims(raw) }},
		{files.SystemJWT, false, func(raw string) (jwt.Claims, error) { return jwt.DecodeAccountClaims(raw) }},
		{files.CellJWT, false, func(raw string) (jwt.Claims, error) { return jwt.DecodeAccountClaims(raw) }},
		{files.SystemCredentials, true, func(raw string) (jwt.Claims, error) { return jwt.DecodeUserClaims(raw) }},
		{files.Credentials, true, func(raw string) (jwt.Claims, error) { return jwt.DecodeUserClaims(raw) }},
	} {
		data, err := read(item.path)
		if err != nil {
			return time.Time{}, err
		}
		var raw string
		if item.decorated {
			raw, err = nkeys.ParseDecoratedJWT(data)
		} else {
			raw = strings.TrimSpace(string(data))
		}
		clear(data)
		if err != nil {
			return time.Time{}, err
		}
		claim, err := item.decode(raw)
		if err != nil || claim.Claims().Expires <= 0 {
			return time.Time{}, ErrLiveCredentials
		}
		if err := add(time.Unix(claim.Claims().Expires, 0).UTC()); err != nil {
			return time.Time{}, err
		}
	}
	for _, path := range files.TLSCertificates {
		data, err := read(path)
		if err != nil {
			return time.Time{}, err
		}
		block, _ := pem.Decode(data)
		clear(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return time.Time{}, ErrLiveCredentials
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: parse installed TLS leaf: %v", ErrLiveCredentials, err)
		}
		if err := add(certificate.NotAfter.UTC()); err != nil {
			return time.Time{}, err
		}
	}
	return cutoff, nil
}
