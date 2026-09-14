package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const instancePrincipalMetadataLimit = 64 << 10

type InstancePrincipalCredentials struct {
	KeyID string
	Key   *rsa.PrivateKey
}

type InstancePrincipalCredentialSource interface {
	Retrieve(context.Context) (InstancePrincipalCredentials, error)
}

// OCIInstancePrincipalMetadataSource retrieves the short-lived private key and
// certificate exposed by the OCI instance metadata service. The endpoint is
// fixed to the link-local metadata address; callers cannot redirect signing
// authority to a tenant-controlled host.
type OCIInstancePrincipalMetadataSource struct {
	Client *http.Client
}

func NewOCIInstancePrincipalMetadataSource(client *http.Client) (*OCIInstancePrincipalMetadataSource, error) {
	if client == nil {
		client = &http.Client{Transport: directMetadataTransport(nil)}
	}
	return &OCIInstancePrincipalMetadataSource{Client: client}, nil
}

func (s *OCIInstancePrincipalMetadataSource) Retrieve(ctx context.Context) (InstancePrincipalCredentials, error) {
	if s == nil || s.Client == nil {
		return InstancePrincipalCredentials{}, &InvalidOperationError{Message: "instance-principal metadata source is unavailable"}
	}
	if ctx == nil {
		return InstancePrincipalCredentials{}, &errs.Argument{Message: "instance-principal metadata context is required"}
	}
	metadataCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := *s.Client
	client.Transport = directMetadataTransport(client.Transport)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return errors.New("metadata redirects are forbidden") }
	read := func(path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(metadataCtx, http.MethodGet, "http://169.254.169.254"+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer Oracle")
		resp, err := client.Do(req)
		if err != nil {
			return nil, &ProviderOutcomeUnknownError{Message: "instance-principal metadata request failed"}
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = ReadBoundedBody(resp, instancePrincipalMetadataLimit)
			return nil, &ProviderOutcomeUnknownError{Message: "instance-principal metadata request was rejected"}
		}
		body, err := ReadBoundedBody(resp, instancePrincipalMetadataLimit)
		if err != nil {
			return nil, &InvalidDataError{Message: "instance-principal metadata response is invalid"}
		}
		return body, nil
	}
	keyPEM, err := read("/opc/v2/identity/key.pem")
	if err != nil {
		return InstancePrincipalCredentials{}, err
	}
	certPEM, err := read("/opc/v2/identity/cert.pem")
	if err != nil {
		return InstancePrincipalCredentials{}, err
	}
	key, err := parseMetadataRSAKey(keyPEM)
	if err != nil {
		return InstancePrincipalCredentials{}, err
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return InstancePrincipalCredentials{}, &InvalidDataError{Message: "instance-principal certificate is invalid"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return InstancePrincipalCredentials{}, &InvalidDataError{Message: "instance-principal certificate is invalid"}
	}
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.Cmp(key.N) != 0 || public.E != key.E {
		return InstancePrincipalCredentials{}, &InvalidDataError{Message: "instance-principal certificate does not match its private key"}
	}
	return InstancePrincipalCredentials{KeyID: "http://169.254.169.254/opc/v2/identity/cert.pem", Key: key}, nil
}

func directMetadataTransport(transport http.RoundTripper) http.RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if base, ok := transport.(*http.Transport); ok {
		clone := base.Clone()
		clone.Proxy = nil
		return clone
	}
	// Custom transports remain injectable for tests. Production construction
	// uses the standard transport above, with proxying explicitly disabled.
	return transport
}

func parseMetadataRSAKey(raw []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 {
		return nil, &InvalidDataError{Message: "instance-principal private key is invalid"}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil && key.N.BitLen() >= 2048 {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || key.N.BitLen() < 2048 {
		return nil, &InvalidDataError{Message: "instance-principal private key is invalid"}
	}
	return key, nil
}

// InstancePrincipalSigner is a small OCI HTTP-signature implementation. The
// key is supplied by an injected instance-principal credential source, so the
// signer never stores a credential on disk.
type InstancePrincipalSigner struct {
	key        *rsa.PrivateKey
	keyID      string
	Now        func() time.Time
	federation *InstancePrincipalFederation
}

// snapshot returns an independent signer so an adapter's signing authority
// cannot be changed through the caller-owned signer after construction.
func (s *InstancePrincipalSigner) snapshot() (*InstancePrincipalSigner, error) {
	if s == nil || s.Key == nil || strings.TrimSpace(s.KeyID) == "" || s.Key.Validate() != nil {
		return nil, &InvalidOperationError{Message: "instance-principal signer is unavailable"}
	}
	key, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(s.Key))
	if err != nil {
		return nil, &InvalidOperationError{Message: "instance-principal signer cannot be snapshotted"}
	}
	return &InstancePrincipalSigner{Key: key, KeyID: s.KeyID, Now: s.Now}, nil
}

func NewInstancePrincipalSigner(keyID string, key *rsa.PrivateKey) (*InstancePrincipalSigner, error) {
	if strings.TrimSpace(keyID) == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, &errs.Argument{Message: "instance-principal signer requires a 2048-bit RSA key and key ID"}
	}
	return &InstancePrincipalSigner{key: key, keyID: keyID, Now: time.Now}, nil
}

func newFederatedInstancePrincipalSigner(federation *InstancePrincipalFederation) (*InstancePrincipalSigner, error) {
	if federation == nil {
		return nil, &errs.Argument{Message: "instance-principal federation is required"}
	}
	return &InstancePrincipalSigner{Now: federation.now, federation: federation}, nil
}

func newOCIFederatedInstancePrincipalTransport(config OCITransportConfig, client *http.Client, federation *InstancePrincipalFederation) (*OCIHTTPTransport, error) {
	signer, err := newFederatedInstancePrincipalSigner(federation)
	if err != nil {
		return nil, err
	}
	return NewOCIHTTPTransport(config, client, signer)
}

func (s *InstancePrincipalSigner) String() string   { return "InstancePrincipalSigner{<redacted>}" }
func (s *InstancePrincipalSigner) GoString() string { return "InstancePrincipalSigner{<redacted>}" }
func (s *InstancePrincipalSigner) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

func (s *InstancePrincipalSigner) Sign(req *http.Request) error {
	if s == nil {
		return &InvalidOperationError{Message: "instance-principal signer is unavailable"}
	}
	if req == nil || req.URL == nil {
		return &errs.Argument{Message: "OCI request is required"}
	}
	key, keyID := s.key, s.keyID
	if s.federation != nil {
		credential, err := s.federation.credentials(req.Context())
		if err != nil {
			return err
		}
		key, keyID = credential.key, credential.keyID
	}
	if key == nil || strings.TrimSpace(keyID) == "" {
		return &InvalidOperationError{Message: "instance-principal signer is unavailable"}
	}
	if strings.ContainsAny(keyID, "\r\n\"") || req.Host == "" || strings.ContainsAny(req.Host, "\r\n") {
		return &errs.Argument{Message: "OCI signing identity is invalid"}
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Signature version="1",keyId="`+keyID+`",algorithm="rsa-sha256",headers="`+strings.Join(headerNames, " ")+`",signature="`+base64.StdEncoding.EncodeToString(signature)+`"`)
	return nil
}

var _ RequestSigner = (*InstancePrincipalSigner)(nil)
