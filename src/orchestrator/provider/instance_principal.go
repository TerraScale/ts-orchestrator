package provider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// InstancePrincipalSigner is a small OCI HTTP-signature implementation. The
// key is supplied by the host's instance-principal credential loader, so this
// package never reads metadata endpoints or stores a credential on disk.
type InstancePrincipalSigner struct {
	Key   *rsa.PrivateKey
	KeyID string
	Now   func() time.Time
}

func NewInstancePrincipalSigner(keyID string, key *rsa.PrivateKey) (*InstancePrincipalSigner, error) {
	if strings.TrimSpace(keyID) == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return nil, &ArgumentError{Message: "instance-principal signer requires a 2048-bit RSA key and key ID"}
	}
	return &InstancePrincipalSigner{Key: key, KeyID: keyID, Now: time.Now}, nil
}

func (s *InstancePrincipalSigner) Sign(req *http.Request) error {
	if s == nil || s.Key == nil || strings.TrimSpace(s.KeyID) == "" {
		return &InvalidOperationError{Message: "instance-principal signer is unavailable"}
	}
	if req == nil || req.URL == nil {
		return &ArgumentError{Message: "OCI request is required"}
	}
	if strings.ContainsAny(s.KeyID, "\r\n\"") || req.Host == "" || strings.ContainsAny(req.Host, "\r\n") {
		return &ArgumentError{Message: "OCI signing identity is invalid"}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", now().UTC().Format(http.TimeFormat))
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}
	// The transport buffers bodies, so GetBody is available for the digest.
	if req.Body != nil && req.Body != http.NoBody && req.Header.Get("x-content-sha256") == "" {
		if req.GetBody == nil {
			return &InvalidOperationError{Message: "OCI request body cannot be signed"}
		}
		body, err := req.GetBody()
		if err != nil {
			return err
		}
		defer body.Close()
		buf, err := io.ReadAll(io.LimitReader(body, 16<<20+1))
		if err != nil {
			return err
		}
		if len(buf) > 16<<20 {
			return &InvalidDataError{Message: "OCI request body exceeds limit"}
		}
		sum := sha256.Sum256(buf)
		req.Header.Set("x-content-sha256", base64.StdEncoding.EncodeToString(sum[:]))
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	headerNames := []string{"date", "(request-target)", "host"}
	canonical := "date: " + req.Header.Get("Date") + "\n(request-target): " + strings.ToLower(req.Method) + " " + path + "\nhost: " + req.Host
	if req.Body != nil && req.Body != http.NoBody {
		if req.ContentLength < 0 || req.Header.Get("Content-Type") == "" || req.Header.Get("x-content-sha256") == "" {
			return &InvalidOperationError{Message: "OCI request body signing metadata is incomplete"}
		}
		contentLength := strconv.FormatInt(req.ContentLength, 10)
		req.Header.Set("Content-Length", contentLength)
		headerNames = append(headerNames, "content-length", "content-type", "x-content-sha256")
		canonical += "\ncontent-length: " + contentLength + "\ncontent-type: " + req.Header.Get("Content-Type") + "\nx-content-sha256: " + req.Header.Get("x-content-sha256")
	}
	hash := sha256.Sum256([]byte(canonical))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, hash[:])
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Signature version="1",keyId="`+s.KeyID+`",algorithm="rsa-sha256",headers="`+strings.Join(headerNames, " ")+`",signature="`+base64.StdEncoding.EncodeToString(signature)+`"`)
	return nil
}

var _ RequestSigner = (*InstancePrincipalSigner)(nil)
