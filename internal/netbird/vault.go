package netbird

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
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
	return readOCISecret(ctx, cfg.Region, cfg.SetupKeySecretID, "setup-key", validSetupKey)
}

// validAdminPAT accepts NetBird personal access tokens: "nbp_" followed by a
// 30-character secret and a 6-character checksum.
func validAdminPAT(token []byte) bool {
	if len(token) != 40 || !bytes.HasPrefix(token, []byte("nbp_")) {
		return false
	}
	for _, c := range token[4:] {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// ValidAdminPAT reports whether token has NetBird's PAT shape.
func ValidAdminPAT(token []byte) bool { return validAdminPAT(token) }

// ReadAdminPAT reads the current NetBird admin PAT version from OCI Vault with
// the instance principal. The caller must clear the returned bytes.
func ReadAdminPAT(ctx context.Context, cfg Config) ([]byte, error) {
	if cfg.AdminPATSecretID == "" {
		return nil, errors.New("NetBird admin_pat_secret_id is not configured")
	}
	return readOCISecret(ctx, cfg.Region, cfg.AdminPATSecretID, "admin PAT", validAdminPAT)
}

func readOCISecret(ctx context.Context, region, secretID, label string, valid func([]byte) bool) ([]byte, error) {
	for _, name := range []string{"OCI_GO_SDK_DEBUG", "OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL", "OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"} {
		if _, overridden := os.LookupEnv(name); overridden {
			return nil, errors.New("NetBird OCI Vault access does not permit OCI debug logging, endpoint or TLS overrides")
		}
	}
	if ctx.Err() != nil {
		return nil, errors.New("NetBird OCI Vault read was canceled")
	}
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region(region), boundedInstancePrincipalDispatcher)
	if err != nil {
		return nil, errors.New("cannot create OCI instance-principal credentials for NetBird")
	}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
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
	return readCurrentSecret(ctx, secretID, label, client, valid)
}

func readCurrentSetupKey(ctx context.Context, secretID string, client bundleClient) ([]byte, error) {
	return readCurrentSecret(ctx, secretID, "setup-key", client, validSetupKey)
}

func readCurrentSecret(ctx context.Context, secretID, label string, client bundleClient, valid func([]byte) bool) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	retry := common.NoRetryPolicy()
	response, err := client.GetSecretBundle(requestCtx, secrets.GetSecretBundleRequest{
		SecretId: new(secretID), Stage: secrets.GetSecretBundleStageCurrent,
		RequestMetadata: common.RequestMetadata{RetryPolicy: &retry},
	})
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
	if content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(128) {
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
