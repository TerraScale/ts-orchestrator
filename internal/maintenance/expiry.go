// Package maintenance keeps a cell's credentials and hosts current without an
// operator (TS-568). This file finds when the credentials a member runs with
// expire, so the insights, the metrics and later renewal see every expiry
// ahead instead of discovering it as an outage.
package maintenance

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/jwt/v2"
)

// maxCredentialBytes bounds one credential file; real ones are a few KiB.
const maxCredentialBytes = 1 << 20

// CredentialFile is one configured credential file: PEM certificates (a leaf
// or a CA bundle), a NATS JWT, or a NATS credentials file.
type CredentialFile struct {
	// Name is the file's role, for example "nats tls"; it names the
	// credential in insights and metrics, so it never carries a secret.
	Name string
	Path string
}

// Scan reads every file and returns the expiry of each certificate and NATS
// JWT in it. A JWT without an expiry is omitted. Files are read on every call,
// so a renewed file is seen without a restart. Scan returns everything it
// could read, plus one joined error naming each file it could not; seeds and
// keys in a credentials file are never parsed or reported.
func Scan(files []CredentialFile) ([]observability.CredentialView, error) {
	var out []observability.CredentialView
	var errs []error
	seen := map[string]bool{}
	for _, file := range files {
		if file.Path == "" || seen[file.Path] {
			continue
		}
		seen[file.Path] = true
		found, err := scanFile(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s credential %s: %w", file.Name, file.Path, err))
			continue
		}
		out = append(out, found...)
	}
	return out, errors.Join(errs...)
}

func scanFile(file CredentialFile) ([]observability.CredentialView, error) {
	handle, err := os.Open(file.Path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCredentialBytes {
		return nil, errors.New("file is larger than 1 MiB")
	}
	if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return certificates(file.Name, data)
	}
	token, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return nil, errors.New("not a certificate or NATS JWT")
	}
	// Decode verifies the signature against the claim's own issuer, so an
	// edited payload is rejected. Whether that issuer is trusted is the NATS
	// server's decision; an expiry observation grants no authority.
	claims, err := jwt.Decode(strings.TrimSpace(token))
	if err != nil {
		return nil, errors.New("not a certificate or NATS JWT")
	}
	issued := claims.Claims()
	if issued.Expires == 0 {
		return nil, nil
	}
	credential := observability.CredentialView{Name: file.Name, Kind: "nats-jwt", NotAfter: time.Unix(issued.Expires, 0).UTC()}
	if issued.IssuedAt != 0 {
		credential.NotBefore = time.Unix(issued.IssuedAt, 0).UTC()
	}
	return []observability.CredentialView{credential}, nil
}

func certificates(name string, data []byte) ([]observability.CredentialView, error) {
	var parsed []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(parsed)+1, err)
		}
		parsed = append(parsed, certificate)
	}
	if len(parsed) == 0 {
		return nil, errors.New("no parsable certificate")
	}
	subjects := map[string]int{}
	for _, certificate := range parsed {
		subjects[certificate.Subject.CommonName]++
	}
	out := make([]observability.CredentialView, 0, len(parsed))
	for _, certificate := range parsed {
		label := name
		if len(parsed) > 1 {
			// A bundle names each certificate, so two CAs in one trust
			// file stay two credentials. An old and a new CA share their
			// subject during a rotation; the serial tells them apart.
			subject := certificate.Subject.CommonName
			if subject == "" || subjects[subject] > 1 {
				subject = strings.TrimSpace(subject + " " + serial(certificate))
			}
			label += " (" + subject + ")"
		}
		out = append(out, observability.CredentialView{Name: label, Kind: "tls",
			NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC()})
	}
	return out, nil
}

// serial is a short, stable form of a certificate's serial number.
func serial(certificate *x509.Certificate) string {
	text := certificate.SerialNumber.Text(16)
	if len(text) > 8 {
		text = text[:8]
	}
	return "serial " + text
}
