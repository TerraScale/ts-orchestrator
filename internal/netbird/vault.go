package netbird

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type bundleClient interface {
	GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)
}

func validSetupKey(key []byte) bool {
	if len(key) != 36 {
		return false
	}
	parsed, err := uuid.Parse(string(key))
	return err == nil && parsed != uuid.Nil()
}

func readOCISetupKey(ctx context.Context, cfg Config) ([]byte, error) {
	return readOCISecret(ctx, cfg.Region, cfg.SetupKeySecretID, "setup-key", setupKeyMaxBytes, validSetupKey)
}

// setupKeyMaxBytes bounds the encoded setup-key bundle read from OCI Vault.
const setupKeyMaxBytes = 128

// Admin PAT bounds. NetBird issues "nbp_" + a 30-character secret + a
// 6-character base62 checksum (40 bytes); longer future tokens are accepted
// up to maxAdminPATBytes.
const (
	minAdminPATBytes = 40
	maxAdminPATBytes = 256
)

// validAdminPAT is the single NetBird personal access token shape check: the
// "nbp_" prefix followed by a bounded base62 body.
func validAdminPAT(token []byte) bool {
	if len(token) < minAdminPATBytes || len(token) > maxAdminPATBytes || !bytes.HasPrefix(token, []byte("nbp_")) {
		return false
	}
	for _, c := range token[4:] {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// ValidAdminPAT reports whether token has NetBird's PAT shape. The manager
// client and the OCI Vault reader share this predicate.
func ValidAdminPAT(token []byte) bool { return validAdminPAT(token) }

// ReadAdminPAT reads the current NetBird admin PAT version from OCI Vault with
// the instance principal. The caller must clear the returned bytes.
func ReadAdminPAT(ctx context.Context, cfg Config) ([]byte, error) {
	if cfg.AdminPATSecretID == "" {
		return nil, errors.New("NetBird admin_pat_secret_id is not configured")
	}
	return readOCISecret(ctx, cfg.Region, cfg.AdminPATSecretID, "admin PAT", maxAdminPATBytes, validAdminPAT)
}

func readOCISecret(ctx context.Context, region, secretID, label string, maxBytes int, valid func([]byte) bool) ([]byte, error) {
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, overridden := os.LookupEnv(name); overridden {
			return nil, errors.New("NetBird OCI Vault access does not permit OCI debug logging, endpoint or TLS overrides")
		}
	}
	if ctx.Err() != nil {
		return nil, errors.New("NetBird OCI Vault read was canceled")
	}
	client, err := initializeSecretsClient(ctx, func() (secrets.SecretsClient, error) {
		provider, err := ociclient.InstancePrincipalProvider(common.Region(region), func(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
			bounded, err := boundedInstancePrincipalDispatcher(dispatcher)
			if err != nil {
				return nil, err
			}
			return instancePrincipalContextDispatcher{ctx: ctx, dispatcher: bounded}, nil
		})
		if err != nil {
			return secrets.SecretsClient{}, errors.New("cannot create OCI instance-principal credentials for NetBird")
		}
		return secrets.NewSecretsClientWithConfigurationProvider(provider)
	})
	if err != nil {
		return nil, errors.New("cannot create OCI Secrets client for NetBird")
	}
	client.SetRegion(region)
	httpClient, err := bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, errors.New("cannot bound OCI Secrets client transport")
	}
	httpClient.Transport = responseLimitTransport{transport: httpClient.Transport, limit: 16 << 10}
	client.HTTPClient = httpClient
	return readCurrentSecret(ctx, secretID, label, maxBytes, client, valid)
}

// vaultBackoff bounds retries of a transient Vault failure. A first boot races
// instance-principal federation and the service gateway; a short in-process
// retry is far cheaper than the enrollment unit's restart delay.
var vaultBackoff = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond, time.Second}

func readCurrentSetupKey(ctx context.Context, secretID string, client bundleClient) ([]byte, error) {
	return readCurrentSecret(ctx, secretID, "setup-key", setupKeyMaxBytes, client, validSetupKey)
}

// readCurrentSecret reads the CURRENT bundle version; maxBytes is the decoded
// per-secret budget, gated on its base64 encoded length before decoding.
func readCurrentSecret(ctx context.Context, secretID, label string, maxBytes int, client bundleClient, valid func([]byte) bool) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// The SDK retry policy stays off: the loop below shares one deadline and
	// repeats only transport, throttling and server errors.
	retry := common.NoRetryPolicy()
	var response secrets.GetSecretBundleResponse
	var err error
	for attempt := 0; ; attempt++ {
		response, err = client.GetSecretBundle(requestCtx, secrets.GetSecretBundleRequest{
			SecretId: new(secretID), Stage: secrets.GetSecretBundleStageCurrent,
			RequestMetadata: common.RequestMetadata{RetryPolicy: &retry},
		})
		if err == nil || attempt >= len(vaultBackoff) || !retryableVaultError(err) {
			break
		}
		// Jitter in [d/2, d) spreads a fleet booting from one image.
		delay := vaultBackoff[attempt]/2 + rand.N(vaultBackoff[attempt]/2+1)
		select {
		case <-requestCtx.Done():
			return nil, errors.New("OCI Vault setup-key read failed")
		case <-time.After(delay):
		}
	}
	if err != nil || response.SecretId == nil || *response.SecretId != secretID || response.VersionNumber == nil || *response.VersionNumber < 1 {
		return nil, errors.New("OCI Vault " + label + " read failed")
	}
	invalid := errors.New("OCI Vault " + label + " content is invalid")
	content, ok := response.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok {
		pointer, pointerOK := response.SecretBundleContent.(*secrets.Base64SecretBundleContentDetails)
		if !pointerOK || pointer == nil {
			return nil, invalid
		}
		content = *pointer
	}
	if content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, invalid
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil {
		clear(decoded)
		return nil, invalid
	}
	defer clear(decoded)
	key := bytes.TrimSpace(decoded)
	if !valid(key) {
		return nil, invalid
	}
	return bytes.Clone(key), nil
}

// retryableVaultError admits transport failures, throttling and server errors.
// Authorization and not-found answers are final: repeating them only delays
// the unit's own retry.
func retryableVaultError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	failure, ok := common.IsServiceError(err)
	if !ok {
		return true
	}
	status := failure.GetHTTPStatusCode()
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

// SDK credential retries sleep without context checks. Initialization is
// read-only, so cancellation can release the caller while its backoff finishes.
func initializeSecretsClient(ctx context.Context, initialize func() (secrets.SecretsClient, error)) (secrets.SecretsClient, error) {
	if err := ctx.Err(); err != nil {
		return secrets.SecretsClient{}, err
	}
	type result struct {
		client secrets.SecretsClient
		err    error
	}
	done := make(chan result, 1)
	go func() {
		client, err := initialize()
		done <- result{client, err}
	}()
	select {
	case <-ctx.Done():
		return secrets.SecretsClient{}, ctx.Err()
	case initialized := <-done:
		return initialized.client, initialized.err
	}
}

type instancePrincipalContextDispatcher struct {
	ctx        context.Context
	dispatcher common.HTTPRequestDispatcher
}

func (d instancePrincipalContextDispatcher) Do(request *http.Request) (*http.Response, error) {
	return d.dispatcher.Do(request.WithContext(d.ctx))
}

// Preserve OCI's TLS refresh wrapper while bounding metadata/federation access.
// This follows bootstrap's hardened dispatcher without inventing an anchor.
func boundedInstancePrincipalDispatcher(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
	source, ok := dispatcher.(*http.Client)
	if !ok || source == nil {
		return nil, errors.New("unsupported OCI instance-principal HTTP dispatcher")
	}
	client, err := bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, err
	}
	switch transport := source.Transport.(type) {
	case nil:
	case *http.Transport:
		clone := transport.Clone()
		clone.Proxy = nil
		client.Transport = clone
	case *common.OciHTTPTransportWrapper:
		if transport == nil || transport.TLSConfigProvider == nil {
			return nil, errors.New("incomplete OCI TLS refresh transport")
		}
		client.Transport = &common.OciHTTPTransportWrapper{
			RefreshRate: transport.RefreshRate, TLSConfigProvider: transport.TLSConfigProvider,
			TransportTemplate: func(config *tls.Config) (http.RoundTripper, error) {
				provided, err := transport.TransportTemplate.NewOrDefault(config)
				if err != nil {
					return nil, errors.New("OCI TLS transport initialization failed")
				}
				template, ok := provided.(*http.Transport)
				if !ok || template == nil {
					return nil, errors.New("unsupported OCI TLS transport template")
				}
				clone := template.Clone()
				clone.Proxy = nil
				return clone, nil
			},
		}
	default:
		return nil, errors.New("unsupported OCI instance-principal HTTP transport")
	}
	client.Transport = responseLimitTransport{transport: client.Transport, limit: 1 << 20}
	return client, nil
}

type responseLimitTransport struct {
	transport http.RoundTripper
	limit     int64
}

func (transport responseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.transport.RoundTrip(request)
	if err == nil && response.Body != nil {
		response.Body = limitedBody{Reader: io.LimitReader(response.Body, transport.limit), Closer: response.Body}
	}
	return response, err
}

type limitedBody struct {
	io.Reader
	io.Closer
}
