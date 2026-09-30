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
	for _, name := range []string{"OCI_GO_SDK_DEBUG", "OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL", "OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"} {
		if _, overridden := os.LookupEnv(name); overridden {
			return nil, errors.New("NetBird enrollment does not permit OCI debug logging, endpoint or TLS overrides")
		}
	}
	if ctx.Err() != nil {
		return nil, errors.New("NetBird enrollment was canceled")
	}
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region(cfg.Region), boundedInstancePrincipalDispatcher)
	if err != nil {
		return nil, errors.New("cannot create OCI instance-principal credentials for NetBird")
	}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, errors.New("cannot create OCI Secrets client for NetBird")
	}
	client.SetRegion(cfg.Region)
	httpClient, err := bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, errors.New("cannot bound OCI Secrets client transport")
	}
	httpClient.Transport = responseLimitTransport{transport: httpClient.Transport, limit: 16 << 10}
	client.HTTPClient = httpClient
	return readCurrentSetupKey(ctx, cfg.SetupKeySecretID, client)
}

func readCurrentSetupKey(ctx context.Context, secretID string, client bundleClient) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	retry := common.NoRetryPolicy()
	response, err := client.GetSecretBundle(requestCtx, secrets.GetSecretBundleRequest{
		SecretId: new(secretID), Stage: secrets.GetSecretBundleStageCurrent,
		RequestMetadata: common.RequestMetadata{RetryPolicy: &retry},
	})
	if err != nil || response.SecretId == nil || *response.SecretId != secretID || response.VersionNumber == nil || *response.VersionNumber < 1 {
		return nil, errors.New("OCI Vault setup-key read failed")
	}
	content, ok := response.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok {
		pointer, pointerOK := response.SecretBundleContent.(*secrets.Base64SecretBundleContentDetails)
		if !pointerOK || pointer == nil {
			return nil, errors.New("OCI Vault setup-key content is invalid")
		}
		content = *pointer
	}
	if content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(128) {
		return nil, errors.New("OCI Vault setup-key content is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil {
		clear(decoded)
		return nil, errors.New("OCI Vault setup-key content is invalid")
	}
	defer clear(decoded)
	key := bytes.TrimSpace(decoded)
	if !validSetupKey(key) {
		return nil, errors.New("OCI Vault setup-key content is invalid")
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
