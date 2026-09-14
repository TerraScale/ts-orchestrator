package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const (
	instanceMetadataAuthority = "http://169.254.169.254/opc/v2"
	maximumFederationBody     = 64 << 10
	maximumSecurityToken      = 16 << 10
	maximumMetadataAttempts   = 8
	maximumFederationAttempts = 3
)

var instancePrincipalRefreshWindow = 5 * time.Minute

type instancePrincipalCredential struct {
	keyID string
	key   *rsa.PrivateKey
}

// InstancePrincipalFederation obtains short-lived OCI session credentials
// from the fixed instance metadata authority and OCI Auth. Credentials never
// leave memory and a failed refresh can only reuse an unexpired token.
type InstancePrincipalFederation struct {
	expectedRegion  string
	expectedTenancy string
	metadataClient  *http.Client
	authClient      *http.Client
	now             func() time.Time
	retryDelay      func(context.Context, int) error

	mu         sync.Mutex
	token      string
	expiresAt  time.Time
	sessionKey *rsa.PrivateKey
}

func NewInstancePrincipalFederation(expectedRegion, expectedTenancy string, metadataClient, authClient *http.Client) (*InstancePrincipalFederation, error) {
	if len(expectedRegion) < 1 || len(expectedRegion) > 63 || !regionPattern.MatchString(expectedRegion) || !isOCID(expectedTenancy, "tenancy") {
		return nil, &errs.Argument{Message: "instance-principal federation scope is invalid"}
	}
	return &InstancePrincipalFederation{
		expectedRegion:  expectedRegion,
		expectedTenancy: expectedTenancy,
		metadataClient:  instanceMetadataHTTPClient(metadataClient),
		authClient:      noRedirectHTTPClient(authClient, 15*time.Second),
		now:             time.Now,
		retryDelay:      boundedOCIRetryDelay,
	}, nil
}

type instanceMetadataTransport struct{ base *http.Transport }

func (t *instanceMetadataTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || request == nil || request.URL == nil || request.URL.Scheme != "http" ||
		request.URL.Host != "169.254.169.254" || request.URL.User != nil || !strings.HasPrefix(request.URL.Path, "/opc/v2/") {
		return nil, &InvalidOperationError{Message: "instance metadata request escaped its fixed authority"}
	}
	return t.base.RoundTrip(request)
}

func instanceMetadataHTTPClient(source *http.Client) *http.Client {
	if source != nil {
		return noRedirectHTTPClient(source, 5*time.Second)
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	base := &http.Transport{}
	if ok {
		base = defaultTransport.Clone()
	}
	// IMDS is link-local. It must never inherit HTTP_PROXY or any other
	// process-wide proxy configuration because the response includes the
	// instance identity private key.
	base.Proxy = nil
	return noRedirectHTTPClient(&http.Client{Transport: &instanceMetadataTransport{base: base}}, 5*time.Second)
}

func noRedirectHTTPClient(source *http.Client, timeout time.Duration) *http.Client {
	if source == nil {
		source = &http.Client{}
	}
	clone := *source
	if clone.Timeout <= 0 || clone.Timeout > timeout {
		clone.Timeout = timeout
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

func boundedOCIRetryDelay(ctx context.Context, attempt int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 4 {
		attempt = 4
	}
	base := time.Second << (attempt - 1)
	// Jitter prevents every regional controller from retrying OCI in lockstep
	// after a shared service or metadata outage. Delays progress from 1-1.5s
	// through 2-3s and 4-6s, then stay capped at 8-12s.
	jitter := time.Duration(uint64(time.Now().UnixNano()) % uint64(base/2+1))
	timer := time.NewTimer(base + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (f *InstancePrincipalFederation) String() string {
	return "InstancePrincipalFederation{<redacted>}"
}
func (f *InstancePrincipalFederation) GoString() string {
	return "InstancePrincipalFederation{<redacted>}"
}
func (f *InstancePrincipalFederation) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

func (f *InstancePrincipalFederation) credentials(ctx context.Context) (instancePrincipalCredential, error) {
	if f == nil || f.metadataClient == nil || f.authClient == nil || f.now == nil {
		return instancePrincipalCredential{}, &InvalidOperationError{Message: "instance-principal federation is unavailable"}
	}
	if ctx == nil {
		return instancePrincipalCredential{}, &errs.Argument{Message: "instance-principal context is required"}
	}
	if err := ctx.Err(); err != nil {
		return instancePrincipalCredential{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now().UTC()
	if f.sessionKey != nil && f.token != "" && now.Add(instancePrincipalRefreshWindow).Before(f.expiresAt) {
		return instancePrincipalCredential{keyID: "ST$" + f.token, key: f.sessionKey}, nil
	}
	credential, expiresAt, err := f.refresh(ctx, now)
	if err == nil {
		f.token = strings.TrimPrefix(credential.keyID, "ST$")
		f.expiresAt = expiresAt
		f.sessionKey = credential.key
		return credential, nil
	}
	if f.sessionKey != nil && f.token != "" && now.Before(f.expiresAt) {
		return instancePrincipalCredential{keyID: "ST$" + f.token, key: f.sessionKey}, nil
	}
	return instancePrincipalCredential{}, &InvalidOperationError{Message: "instance-principal credentials are unavailable"}
}

func (f *InstancePrincipalFederation) refresh(ctx context.Context, now time.Time) (instancePrincipalCredential, time.Time, error) {
	regionRaw, err := f.readMetadata(ctx, "/instance/region")
	if err != nil || strings.TrimSpace(string(regionRaw)) != f.expectedRegion {
		return instancePrincipalCredential{}, time.Time{}, &InvalidDataError{Message: "instance metadata region is invalid"}
	}
	leafPEM, err := f.readMetadata(ctx, "/identity/cert.pem")
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	leafKeyPEM, err := f.readMetadata(ctx, "/identity/key.pem")
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	intermediatePEM, err := f.readMetadata(ctx, "/identity/intermediate.pem")
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	leaf, err := parseInstanceCertificate(leafPEM)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	intermediate, err := parseInstanceCertificate(intermediatePEM)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	leafKey, err := parseInstancePrivateKey(leafKeyPEM)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	if err := validateInstanceCertificateChain(leaf, intermediate, leafKey, f.expectedTenancy, now); err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, &InvalidOperationError{Message: "instance-principal session key generation failed"}
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&sessionKey.PublicKey)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, &InvalidOperationError{Message: "instance-principal session key encoding failed"}
	}
	payload, err := json.Marshal(struct {
		Certificate              string   `json:"certificate"`
		FingerprintAlgorithm     string   `json:"fingerprintAlgorithm"`
		IntermediateCertificates []string `json:"intermediateCertificates"`
		PublicKey                string   `json:"publicKey"`
	}{
		Certificate:              base64.StdEncoding.EncodeToString(leaf.Raw),
		FingerprintAlgorithm:     "SHA256",
		IntermediateCertificates: []string{base64.StdEncoding.EncodeToString(intermediate.Raw)},
		PublicKey:                base64.StdEncoding.EncodeToString(publicDER),
	})
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, &InvalidOperationError{Message: "instance-principal federation request encoding failed"}
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	keyID := f.expectedTenancy + "/fed-x509-sha256/" + colonSeparatedFingerprint(fingerprint)
	signer, err := NewInstancePrincipalSigner(keyID, leafKey)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	signer.Now = f.now
	body, err := f.exchangeFederationToken(ctx, payload, signer)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	var document struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return instancePrincipalCredential{}, time.Time{}, &InvalidDataError{Message: "instance-principal federation response is invalid"}
	}
	expiresAt, err := boundedJWTExpiry(document.Token, now)
	if err != nil {
		return instancePrincipalCredential{}, time.Time{}, err
	}
	return instancePrincipalCredential{keyID: "ST$" + document.Token, key: sessionKey}, expiresAt, nil
}

func (f *InstancePrincipalFederation) readMetadata(ctx context.Context, path string) ([]byte, error) {
	for attempt := 1; attempt <= maximumMetadataAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, instanceMetadataAuthority+path, nil)
		if err != nil {
			return nil, &InvalidOperationError{Message: "instance metadata request is invalid"}
		}
		request.Header.Set("Authorization", "Bearer Oracle")
		response, requestErr := f.metadataClient.Do(request)
		if requestErr == nil && response != nil {
			if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
				if response.Body != nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumFederationBody+1))
					_ = response.Body.Close()
				}
				return nil, &InvalidDataError{Message: "instance metadata response is invalid"}
			}
			if response.Body != nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumFederationBody+1))
				_ = response.Body.Close()
				if readErr == nil && len(body) > 0 && len(body) <= maximumFederationBody && response.StatusCode == http.StatusOK {
					return body, nil
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt != maximumMetadataAttempts {
			if f.retryDelay == nil {
				return nil, &InvalidOperationError{Message: "instance metadata retry was interrupted"}
			}
			if err := f.retryDelay(ctx, attempt); err != nil {
				return nil, err
			}
		}
	}
	return nil, &InvalidDataError{Message: "instance metadata response is invalid"}
}

func (f *InstancePrincipalFederation) exchangeFederationToken(ctx context.Context, payload []byte, signer *InstancePrincipalSigner) ([]byte, error) {
	authURL := "https://auth." + f.expectedRegion + ".oraclecloud.com/v1/x509"
	for attempt := 1; attempt <= maximumFederationAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, bytes.NewReader(payload))
		if err != nil {
			return nil, &InvalidOperationError{Message: "instance-principal federation request is invalid"}
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		if err := signer.Sign(request); err != nil {
			return nil, &InvalidOperationError{Message: "instance-principal federation request signing failed"}
		}
		response, requestErr := f.authClient.Do(request)
		if requestErr == nil && response != nil {
			if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
				if response.Body != nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumFederationBody+1))
					_ = response.Body.Close()
				}
				return nil, &InvalidDataError{Message: "instance-principal federation response is invalid"}
			}
			if response.Body != nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumFederationBody+1))
				_ = response.Body.Close()
				if readErr == nil && len(body) <= maximumFederationBody && response.StatusCode >= 200 && response.StatusCode < 300 {
					return body, nil
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt != maximumFederationAttempts {
			if f.retryDelay == nil {
				return nil, &InvalidOperationError{Message: "instance-principal federation retry was interrupted"}
			}
			if err := f.retryDelay(ctx, attempt); err != nil {
				return nil, err
			}
		}
	}
	return nil, &InvalidDataError{Message: "instance-principal federation response is invalid"}
}

func parseInstanceCertificate(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, &InvalidDataError{Message: "instance metadata certificate is invalid"}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &InvalidDataError{Message: "instance metadata certificate is invalid"}
	}
	return certificate, nil
}

func parseInstancePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, &InvalidDataError{Message: "instance metadata private key is invalid"}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil && validInstancePrivateKey(key) {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || !validInstancePrivateKey(key) {
		return nil, &InvalidDataError{Message: "instance metadata private key is invalid"}
	}
	return key, nil
}

func validInstancePrivateKey(key *rsa.PrivateKey) bool {
	return key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.Validate() == nil
}

func validateInstanceCertificateChain(leaf, intermediate *x509.Certificate, key *rsa.PrivateKey, tenancy string, now time.Time) error {
	if leaf == nil || intermediate == nil || key == nil || !intermediate.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		now.Before(intermediate.NotBefore) || !now.Before(intermediate.NotAfter) || leaf.NotAfter.Before(now.Add(time.Minute)) {
		return &InvalidDataError{Message: "instance metadata certificate chain is invalid"}
	}
	leafPublicKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || leafPublicKey.N == nil || key.PublicKey.N.Cmp(leafPublicKey.N) != 0 || key.PublicKey.E != leafPublicKey.E {
		return &InvalidDataError{Message: "instance metadata certificate chain is invalid"}
	}
	foundTenancy := ""
	for _, attribute := range leaf.Subject.Names {
		value, ok := attribute.Value.(string)
		if !ok || !strings.HasPrefix(value, "opc-tenant:") {
			continue
		}
		candidate := strings.TrimPrefix(value, "opc-tenant:")
		if foundTenancy != "" && foundTenancy != candidate {
			return &InvalidDataError{Message: "instance metadata tenancy is invalid"}
		}
		foundTenancy = candidate
	}
	if foundTenancy != tenancy || !isOCID(foundTenancy, "tenancy") {
		return &InvalidDataError{Message: "instance metadata tenancy is invalid"}
	}
	roots := x509.NewCertPool()
	roots.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return &InvalidDataError{Message: "instance metadata certificate chain is invalid"}
	}
	return nil
}

func colonSeparatedFingerprint(sum [sha256.Size]byte) string {
	encoded := make([]byte, 0, sha256.Size*3-1)
	const hexadecimal = "0123456789abcdef"
	for index, value := range sum {
		if index > 0 {
			encoded = append(encoded, ':')
		}
		encoded = append(encoded, hexadecimal[value>>4], hexadecimal[value&0x0f])
	}
	return string(encoded)
}

func boundedJWTExpiry(token string, now time.Time) (time.Time, error) {
	if len(token) < 16 || len(token) > maximumSecurityToken || strings.ContainsAny(token, "\r\n") {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || len(parts[0]) > 2<<10 || len(parts[1]) > 8<<10 || len(parts[2]) > 8<<10 {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	headerRaw, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	var header struct {
		Algorithm string `json:"alg"`
	}
	if headerErr != nil || len(headerRaw) == 0 || len(headerRaw) > 2<<10 || signatureErr != nil || len(signature) == 0 || len(signature) > 8<<10 ||
		json.Unmarshal(headerRaw, &header) != nil || header.Algorithm != "RS256" {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 8<<10 {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	var exp json.Number
	decoder := json.NewDecoder(bytes.NewReader(claims["exp"]))
	decoder.UseNumber()
	if decoder.Decode(&exp) != nil {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	seconds, err := strconv.ParseInt(exp.String(), 10, 64)
	if err != nil {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token is invalid"}
	}
	expiresAt := time.Unix(seconds, 0).UTC()
	if !expiresAt.After(now.Add(time.Minute)) || expiresAt.After(now.Add(24*time.Hour)) {
		return time.Time{}, &InvalidDataError{Message: "instance-principal security token expiry is invalid"}
	}
	return expiresAt, nil
}

// InstancePrincipalSigner signs OCI API requests with either a fixed key or a
// short-lived credential supplied by instance-principal federation.
type InstancePrincipalSigner struct {
	key        *rsa.PrivateKey
	keyID      string
	Now        func() time.Time
	federation *InstancePrincipalFederation
}

func NewInstancePrincipalSigner(keyID string, key *rsa.PrivateKey) (*InstancePrincipalSigner, error) {
	if strings.TrimSpace(keyID) != keyID || keyID == "" || len(keyID) > maximumSecurityToken+3 || strings.ContainsAny(keyID, "\r\n\"") || !validInstancePrivateKey(key) {
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
