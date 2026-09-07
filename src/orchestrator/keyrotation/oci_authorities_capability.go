package keyrotation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"terrascale.tech/orchestrator/src/orchestrator/internal/ociworker"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Prevent SDK debug sinks from logging request or response secret material.
type rotationSilentSDKLogger struct{}

func (rotationSilentSDKLogger) LogLevel() int                 { return 0 }
func (rotationSilentSDKLogger) Log(int, string, ...any) error { return nil }
func init()                                                   { common.SetSDKLogger(rotationSilentSDKLogger{}) }

type ociHMACVaultConfig struct {
	Provider                              common.ConfigurationProvider
	Region, CompartmentID, VaultID, KeyID string
	Authority                             func(context.Context) error
}

type capabilityManagement interface {
	CreateSecret(context.Context, vault.CreateSecretRequest) (vault.CreateSecretResponse, error)
	ListSecrets(context.Context, vault.ListSecretsRequest) (vault.ListSecretsResponse, error)
	GetSecret(context.Context, vault.GetSecretRequest) (vault.GetSecretResponse, error)
	ScheduleSecretDeletion(context.Context, vault.ScheduleSecretDeletionRequest) (vault.ScheduleSecretDeletionResponse, error)
}
type capabilityBundles interface {
	GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)
}

type ociHMACVault struct {
	purpose    string
	config     ociHMACVaultConfig
	management capabilityManagement
	bundles    capabilityBundles
}

// Requests and material inside the OCI implementation carry no consumer role.
// Only constructors choose a fixed purpose; Fetch and Retire enforce it too.
type ociHMACRequest security.CapabilityRequest
type ociHMACMaterial security.CapabilityMaterial

type OCICapabilityVaultConfig ociHMACVaultConfig
type OCICapabilityVault struct{ *ociHMACVault }

func NewOCICapabilityVault(c OCICapabilityVaultConfig) (*OCICapabilityVault, error) {
	v, err := newOCIHMACVault(ociHMACVaultConfig(c), "ts-capability")
	if err != nil {
		return nil, err
	}
	return &OCICapabilityVault{v}, nil
}
func (v *OCICapabilityVault) Generate(ctx context.Context, r security.CapabilityRequest) (security.CapabilityMaterial, error) {
	m, err := v.generate(ctx, ociHMACRequest(r))
	return security.CapabilityMaterial(m), err
}
func (v *OCICapabilityVault) Fetch(ctx context.Context, reference string) (security.CapabilityMaterial, error) {
	m, err := v.fetch(ctx, reference)
	return security.CapabilityMaterial(m), err
}
func (v *OCICapabilityVault) Retire(ctx context.Context, reference, operation string) error {
	return v.retire(ctx, reference, operation)
}
func (v *ociHMACVault) retryToken(key string) string {
	digest := sha256.Sum256([]byte(v.purpose + "\x00" + key))
	return hex.EncodeToString(digest[:])
}

func newOCIHMACVault(c ociHMACVaultConfig, purpose string) (*ociHMACVault, error) {
	if isNil(c.Provider) || c.Region == "" || c.CompartmentID == "" || c.VaultID == "" || c.KeyID == "" || c.Authority == nil {
		return nil, configurationError("OCI HMAC vault configuration is incomplete")
	}
	if (OCICapabilityVaultFileConfig{Region: c.Region, CompartmentID: c.CompartmentID, VaultID: c.VaultID, KeyID: c.KeyID}).Validate() != nil {
		return nil, capabilityError()
	}
	m, e := vault.NewVaultsClientWithConfigurationProvider(c.Provider)
	if e != nil {
		return nil, capabilityError()
	}
	m.SetRegion(c.Region)
	m.HTTPClient = NewOCIAuthorityDispatcher(c.Region, c.Authority)
	b, e := secrets.NewSecretsClientWithConfigurationProvider(c.Provider)
	if e != nil {
		return nil, capabilityError()
	}
	b.SetRegion(c.Region)
	b.HTTPClient = NewOCIAuthorityDispatcher(c.Region, c.Authority)
	return &ociHMACVault{purpose: purpose, config: c, management: m, bundles: b}, nil
}
func capabilityError() error { return errors.New("key rotation: OCI secret authority failed") }
func (v *ociHMACVault) name(key string) string {
	s := sha256.Sum256([]byte(key))
	return v.purpose + "-" + hex.EncodeToString(s[:])
}
func (v *ociHMACVault) authorize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.config.Authority(ctx)
}
func (v *ociHMACVault) metadata(r ociHMACRequest) map[string]string {
	return map[string]string{"purpose": v.purpose, "generation": strconv.FormatUint(r.Generation, 10), "bucket": strconv.FormatInt(r.Bucket, 10), "not-before": r.NotBefore.UTC().Format(time.RFC3339Nano), "expires-at": r.ExpiresAt.UTC().Format(time.RFC3339Nano), "operation": v.name(r.OperationID)}
}
func (v *ociHMACVault) find(ctx context.Context, name string) (string, error) {
	var page *string
	var found string
	for {
		if err := v.authorize(ctx); err != nil {
			return "", err
		}
		r, e := ociAuthorityCall(ctx, func() (vault.ListSecretsResponse, error) {
			return v.management.ListSecrets(ctx, vault.ListSecretsRequest{CompartmentId: new(v.config.CompartmentID), VaultId: new(v.config.VaultID), Name: new(name), Page: page, RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
		})
		if e != nil {
			return "", capabilityError()
		}
		for _, s := range r.Items {
			if s.SecretName != nil && *s.SecretName == name && s.Id != nil {
				if found != "" && found != *s.Id {
					return "", capabilityError()
				}
				found = *s.Id
			}
		}
		if r.OpcNextPage == nil || *r.OpcNextPage == "" {
			return found, nil
		}
		if page != nil && *page == *r.OpcNextPage {
			return "", capabilityError()
		}
		page = r.OpcNextPage
	}
}
func (v *ociHMACVault) generate(ctx context.Context, r ociHMACRequest) (ociHMACMaterial, error) {
	if !validOperationKey(r.IdempotencyKey) || !validOperationKey(r.OperationID) || r.Generation == 0 || r.NotBefore.IsZero() || !r.ExpiresAt.After(r.NotBefore) {
		return ociHMACMaterial{}, capabilityError()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	name := v.name(r.IdempotencyKey)
	ref, e := v.find(ctx, name)
	if e != nil {
		return ociHMACMaterial{}, e
	}
	if ref == "" {
		key := make([]byte, 32)
		rand.Read(key)
		defer clear(key)
		if e = v.authorize(ctx); e != nil {
			return ociHMACMaterial{}, e
		}
		result, createErr := ociAuthorityCall(ctx, func() (vault.CreateSecretResponse, error) {
			return v.management.CreateSecret(ctx, vault.CreateSecretRequest{CreateSecretDetails: vault.CreateSecretDetails{CompartmentId: new(v.config.CompartmentID), VaultId: new(v.config.VaultID), KeyId: new(v.config.KeyID), SecretName: new(name), FreeformTags: v.metadata(r), SecretContent: vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(key))}}, OpcRetryToken: new(v.retryToken(r.IdempotencyKey)), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
		})
		if createErr == nil && result.Id != nil {
			ref = *result.Id
		} else {
			ref, e = v.find(ctx, name)
			if e != nil || ref == "" {
				return ociHMACMaterial{}, capabilityError()
			}
		}
	}
	receipt, e := v.waitActive(ctx, ref)
	if e != nil {
		return ociHMACMaterial{}, e
	}
	if receipt.FreeformTags["operation"] != v.name(r.OperationID) {
		return ociHMACMaterial{}, capabilityError()
	}
	material, e := v.fetch(ctx, ref)
	if e != nil {
		return ociHMACMaterial{}, e
	}
	if material.ID != name || material.Version != r.Generation || material.Bucket != r.Bucket || !material.NotBefore.Equal(r.NotBefore) || !material.ExpiresAt.Equal(r.ExpiresAt) {
		clear(material.Key)
		return ociHMACMaterial{}, capabilityError()
	}
	return material, nil
}
func (v *ociHMACVault) waitActive(ctx context.Context, ref string) (vault.Secret, error) {
	for {
		s, e := v.secret(ctx, ref)
		if e != nil {
			return vault.Secret{}, e
		}
		if s.LifecycleState == vault.SecretLifecycleStateActive {
			return s, nil
		}
		if s.LifecycleState != vault.SecretLifecycleStateCreating {
			return vault.Secret{}, capabilityError()
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return vault.Secret{}, ctx.Err()
		case <-timer.C:
		}
	}
}
func (v *ociHMACVault) secret(ctx context.Context, reference string) (vault.Secret, error) {
	if !validOperationKey(reference) {
		return vault.Secret{}, capabilityError()
	}
	if e := v.authorize(ctx); e != nil {
		return vault.Secret{}, e
	}
	s, e := ociAuthorityCall(ctx, func() (vault.GetSecretResponse, error) {
		return v.management.GetSecret(ctx, vault.GetSecretRequest{SecretId: new(reference), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
	})
	if e != nil {
		return vault.Secret{}, capabilityError()
	}
	if s.Id == nil || *s.Id != reference || s.CompartmentId == nil || *s.CompartmentId != v.config.CompartmentID || s.VaultId == nil || *s.VaultId != v.config.VaultID || s.KeyId == nil || *s.KeyId != v.config.KeyID || s.FreeformTags["purpose"] != v.purpose || s.SecretName == nil || !strings.HasPrefix(*s.SecretName, v.purpose+"-") {
		return vault.Secret{}, capabilityError()
	}
	return s.Secret, nil
}
func (v *ociHMACVault) fetch(ctx context.Context, reference string) (ociHMACMaterial, error) {
	s, e := v.secret(ctx, reference)
	if e != nil {
		return ociHMACMaterial{}, e
	}
	generation, e1 := strconv.ParseUint(s.FreeformTags["generation"], 10, 64)
	bucket, e2 := strconv.ParseInt(s.FreeformTags["bucket"], 10, 64)
	before, e3 := time.Parse(time.RFC3339Nano, s.FreeformTags["not-before"])
	expiry, e4 := time.Parse(time.RFC3339Nano, s.FreeformTags["expires-at"])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || generation == 0 || !expiry.After(before) || s.SecretName == nil || s.LifecycleState != vault.SecretLifecycleStateActive {
		return ociHMACMaterial{}, capabilityError()
	}
	if s.TimeOfDeletion != nil || (s.CurrentVersionNumber != nil && *s.CurrentVersionNumber != 1) || (s.TimeOfCurrentVersionExpiry != nil && s.TimeOfCurrentVersionExpiry.Before(expiry)) {
		return ociHMACMaterial{}, capabilityError()
	}
	if e = v.authorize(ctx); e != nil {
		return ociHMACMaterial{}, e
	}
	b, e := ociAuthorityCall(ctx, func() (secrets.GetSecretBundleResponse, error) {
		return v.bundles.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{SecretId: new(reference), VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
	})
	if e != nil {
		return ociHMACMaterial{}, capabilityError()
	}
	if b.SecretId == nil || *b.SecretId != reference || b.VersionNumber == nil || *b.VersionNumber != 1 || b.TimeOfDeletion != nil || (b.TimeOfExpiry != nil && b.TimeOfExpiry.Before(expiry)) {
		return ociHMACMaterial{}, capabilityError()
	}
	content, ok := b.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) != base64.StdEncoding.EncodedLen(32) {
		return ociHMACMaterial{}, capabilityError()
	}
	key, e := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if e != nil || len(key) != 32 {
		clear(key)
		return ociHMACMaterial{}, capabilityError()
	}
	return ociHMACMaterial{ID: *s.SecretName, Reference: reference, Version: generation, Bucket: bucket, NotBefore: before, ExpiresAt: expiry, Key: key}, nil
}
func (v *ociHMACVault) retire(ctx context.Context, reference, idempotencyKey string) error {
	if !validOperationKey(idempotencyKey) {
		return capabilityError()
	}
	s, e := v.secret(ctx, reference)
	if e != nil {
		return e
	}
	if s.LifecycleState == vault.SecretLifecycleStatePendingDeletion || s.LifecycleState == vault.SecretLifecycleStateDeleted {
		return nil
	}
	if e = v.authorize(ctx); e != nil {
		return e
	}
	_, e = ociAuthorityCall(ctx, func() (vault.ScheduleSecretDeletionResponse, error) {
		return v.management.ScheduleSecretDeletion(ctx, vault.ScheduleSecretDeletionRequest{SecretId: new(reference), ScheduleSecretDeletionDetails: vault.ScheduleSecretDeletionDetails{TimeOfDeletion: new(common.SDKTime{Time: time.Now().UTC().Add(25 * time.Hour)})}, RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
	})
	if e != nil {
		return capabilityError()
	}
	return nil
}

// NewOCIAuthorityDispatcher fences every HTTP dispatch after SDK signing and
// permits only the regional OCI certificate and secret authority endpoints.
func NewOCIAuthorityDispatcher(region string, authority func(context.Context) error) common.HTTPRequestDispatcher {
	hosts := make(map[string]bool)
	for _, service := range []string{"vaults", "secrets.vaults", "certificates", "certificatesmanagement"} {
		endpoint := common.StringToRegion(region).EndpointForTemplate(service, "https://"+service+".{region}.oci.{secondLevelDomain}")
		u, e := url.Parse(endpoint)
		if e == nil {
			hosts[u.Host] = true
		}
	}
	return &ociAuthorityDispatcher{hosts: hosts, authority: authority, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type ociAuthorityDispatcher struct {
	hosts     map[string]bool
	authority func(context.Context) error
	client    *http.Client
}

func (d *ociAuthorityDispatcher) Do(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.User != nil || !d.hosts[r.URL.Host] || d.authority == nil {
		return nil, capabilityError()
	}
	if e := r.Context().Err(); e != nil {
		return nil, e
	}
	if e := d.authority(r.Context()); e != nil {
		return nil, e
	}
	response, e := d.client.Do(r)
	if e != nil {
		return nil, capabilityError()
	}
	response.Body = &ociLimitedBody{Reader: io.LimitReader(response.Body, 2<<20), Closer: response.Body}
	return response, nil
}

type ociLimitedBody struct {
	io.Reader
	io.Closer
}

// ociAuthorityCall bounds caller cancellation even while SDK federation refresh
// is blocked, retaining the process-wide SDK gate until that call exits.
func ociAuthorityCall[T any](ctx context.Context, call func() (T, error)) (T, error) {
	var zero T
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case ociworker.Gate <- struct{}{}:
	}
	type result struct {
		value T
		err   error
	}
	completed := make(chan result)
	go func() {
		defer func() { <-ociworker.Gate }()
		if ctx.Err() != nil {
			return
		}
		value, e := call()
		select {
		case completed <- result{value, e}:
		case <-ctx.Done():
		}
	}()
	select {
	case r := <-completed:
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		return r.value, r.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
