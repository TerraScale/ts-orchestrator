package host

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

// ManagedS3Credentials exist only in the host's child process environment.
// The signed desired carries an immutable Vault reference, never these values.
type ManagedS3Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

type ManagedS3CredentialResolver interface {
	Resolve(context.Context, oci.SecretVersionReference) (ManagedS3Credentials, error)
}

// ManagedBackupDataKeyResolver returns only the exact retained 32-byte key
// version. Callers clear the returned bytes after installing the protected
// host file. Its Vault reference is pinned by signed desired state.
type ManagedBackupDataKeyResolver interface {
	ResolveBackupDataKey(context.Context, oci.SecretVersionReference) ([]byte, error)
}

type managedS3BundleClient interface {
	GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)
}

type OCIS3CredentialResolver struct{ client managedS3BundleClient }

// NewOCIS3CredentialResolver uses the host instance principal in its signed cell.
func NewOCIS3CredentialResolver(region oci.Region) (*OCIS3CredentialResolver, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil {
		return nil, errors.New("managed S3 resolver region is invalid")
	}
	// The resolver moves S3 keys and the backup data key through the SDK.
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, overridden := os.LookupEnv(name); overridden {
			return nil, errors.New("managed S3 Vault access does not permit OCI debug logging, endpoint or TLS overrides")
		}
	}
	provider, err := ociclient.InstancePrincipalProvider(common.Region(ociRegion), bootstrap.BoundInstancePrincipalDispatcher)
	if err != nil {
		return nil, errors.New("managed S3 instance principal is unavailable")
	}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, errors.New("managed S3 OCI Secrets client is unavailable")
	}
	client.SetRegion(ociRegion)
	client.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, errors.New("managed S3 OCI HTTP client is unavailable")
	}
	return &OCIS3CredentialResolver{client: client}, nil
}

func (resolver *OCIS3CredentialResolver) Resolve(ctx context.Context, reference oci.SecretVersionReference) (ManagedS3Credentials, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || reference.Validate() != nil {
		return ManagedS3Credentials{}, errors.New("managed S3 secret reference is invalid")
	}
	response, err := resolver.client.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{
		SecretId: new(reference.SecretOCID), VersionNumber: new(reference.VersionNumber),
	})
	if err != nil {
		return ManagedS3Credentials{}, errors.New("managed S3 exact Vault read failed")
	}
	bundle := response.SecretBundle
	if bundle.SecretId == nil || *bundle.SecretId != reference.SecretOCID ||
		bundle.VersionNumber == nil || *bundle.VersionNumber != reference.VersionNumber {
		return ManagedS3Credentials{}, errors.New("managed S3 Vault version differs from signed reference")
	}
	content, ok := bundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok {
		if pointer, pointerOK := bundle.SecretBundleContent.(*secrets.Base64SecretBundleContentDetails); pointerOK && pointer != nil {
			content, ok = *pointer, true
		}
	}
	if !ok || content.Content == nil || len(*content.Content) == 0 || len(*content.Content) > base64.StdEncoding.EncodedLen(4096) {
		return ManagedS3Credentials{}, errors.New("managed S3 Vault content is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || len(decoded) == 0 || len(decoded) > 4096 || base64.StdEncoding.EncodeToString(decoded) != *content.Content {
		clear(decoded)
		return ManagedS3Credentials{}, errors.New("managed S3 Vault encoding is invalid")
	}
	defer clear(decoded)
	var payload struct {
		Version         uint64 `json:"version"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if err := json.Unmarshal(decoded, &payload, json.RejectUnknownMembers(true)); err != nil ||
		payload.Version != 1 || !validS3Credential(payload.AccessKeyID) || !validS3Credential(payload.SecretAccessKey) {
		return ManagedS3Credentials{}, errors.New("managed S3 Vault payload is invalid")
	}
	return ManagedS3Credentials{AccessKeyID: payload.AccessKeyID, SecretAccessKey: payload.SecretAccessKey}, nil
}

func (resolver *OCIS3CredentialResolver) ResolveBackupDataKey(ctx context.Context,
	reference oci.SecretVersionReference,
) ([]byte, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || reference.Validate() != nil {
		return nil, errors.New("managed backup data-key reference is invalid")
	}
	response, err := resolver.client.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{
		SecretId: new(reference.SecretOCID), VersionNumber: new(reference.VersionNumber),
	})
	if err != nil {
		return nil, errors.New("managed backup exact Vault read failed")
	}
	bundle := response.SecretBundle
	if bundle.SecretId == nil || *bundle.SecretId != reference.SecretOCID ||
		bundle.VersionNumber == nil || *bundle.VersionNumber != reference.VersionNumber {
		return nil, errors.New("managed backup Vault version differs from signed reference")
	}
	content, ok := bundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok {
		if pointer, pointerOK := bundle.SecretBundleContent.(*secrets.Base64SecretBundleContentDetails); pointerOK && pointer != nil {
			content, ok = *pointer, true
		}
	}
	if !ok || content.Content == nil || len(*content.Content) != base64.StdEncoding.EncodedLen(32) {
		return nil, errors.New("managed backup Vault key content is invalid")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != *content.Content {
		clear(key)
		return nil, errors.New("managed backup Vault key encoding is invalid")
	}
	return key, nil
}

func validS3Credential(value string) bool {
	if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}
