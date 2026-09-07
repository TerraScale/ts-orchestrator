package keyrotation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

// EnrollmentCredentialRequest contains transient credential bytes. Only the
// returned exact Vault version reference may enter a host seed or GRU journal.
// The caller must reserve the operation and destination before issuing bytes.
type EnrollmentCredentialRequest struct {
	OperationID string
	Destination string
	Content     []byte
}

// PublishEnrollmentCredential publishes one immutable host credential under
// the existing lease-guarded OCI Vault authority. A changed retry is rejected;
// an unknown create response is recovered by its deterministic provider name.
func (v *OCICapabilityVault) PublishEnrollmentCredential(ctx context.Context, request EnrollmentCredentialRequest) (hostsecrets.Entry, error) {
	if ctx == nil || v == nil || !validOperationKey(request.OperationID) || len(request.Content) == 0 || len(request.Content) > hostsecrets.MaxSecretBytes {
		return hostsecrets.Entry{}, capabilityError()
	}
	digest := sha256.Sum256(request.Content)
	expected := hex.EncodeToString(digest[:])
	entry := hostsecrets.Entry{VersionNumber: 1, SHA256: expected, Destination: request.Destination}
	if hostsecrets.ValidateSeedIdentity(v.config.Region, request.OperationID) != nil || hostsecrets.ValidateCredentialDestination(request.Destination) != nil {
		return hostsecrets.Entry{}, capabilityError()
	}
	name := "ts-enrollment-" + identityHash(request.OperationID+"\x00"+request.Destination)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ref, err := v.find(ctx, name)
	if err != nil {
		return hostsecrets.Entry{}, err
	}
	if ref == "" {
		if err := v.authorize(ctx); err != nil {
			return hostsecrets.Entry{}, err
		}
		response, createErr := ociAuthorityCall(ctx, func() (vault.CreateSecretResponse, error) {
			return v.management.CreateSecret(ctx, vault.CreateSecretRequest{CreateSecretDetails: vault.CreateSecretDetails{CompartmentId: new(v.config.CompartmentID), VaultId: new(v.config.VaultID), KeyId: new(v.config.KeyID), SecretName: new(name), FreeformTags: map[string]string{"purpose": "ts-member-enrollment", "operation": request.OperationID, "destination": request.Destination, "sha256": expected}, SecretContent: vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(request.Content))}}, OpcRetryToken: new(identityHash(name)), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
		})
		if createErr == nil && response.Id != nil {
			ref = *response.Id
		} else {
			ref, err = v.find(ctx, name)
			if err != nil || ref == "" {
				return hostsecrets.Entry{}, capabilityError()
			}
		}
	}
	for {
		if err := v.authorize(ctx); err != nil {
			return hostsecrets.Entry{}, err
		}
		response, err := ociAuthorityCall(ctx, func() (vault.GetSecretResponse, error) {
			return v.management.GetSecret(ctx, vault.GetSecretRequest{SecretId: new(ref), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
		})
		s := response.Secret
		if err != nil || s.Id == nil || *s.Id != ref || s.SecretName == nil || *s.SecretName != name || s.CompartmentId == nil || *s.CompartmentId != v.config.CompartmentID || s.VaultId == nil || *s.VaultId != v.config.VaultID || s.KeyId == nil || *s.KeyId != v.config.KeyID || s.FreeformTags["purpose"] != "ts-member-enrollment" || s.FreeformTags["operation"] != request.OperationID || s.FreeformTags["destination"] != request.Destination || s.FreeformTags["sha256"] != expected || s.TimeOfDeletion != nil || (s.CurrentVersionNumber != nil && *s.CurrentVersionNumber != 1) {
			return hostsecrets.Entry{}, capabilityError()
		}
		if s.LifecycleState == vault.SecretLifecycleStateActive {
			break
		}
		if s.LifecycleState != vault.SecretLifecycleStateCreating {
			return hostsecrets.Entry{}, capabilityError()
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return hostsecrets.Entry{}, ctx.Err()
		case <-timer.C:
		}
	}
	if err := v.authorize(ctx); err != nil {
		return hostsecrets.Entry{}, err
	}
	response, err := ociAuthorityCall(ctx, func() (secrets.GetSecretBundleResponse, error) {
		return v.bundles.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{SecretId: new(ref), VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
	})
	content, ok := response.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if err != nil || !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(hostsecrets.MaxSecretBytes) || response.SecretId == nil || *response.SecretId != ref || response.VersionNumber == nil || *response.VersionNumber != 1 || response.TimeOfDeletion != nil {
		return hostsecrets.Entry{}, capabilityError()
	}
	bytes, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	defer clear(bytes)
	if err != nil || sha256.Sum256(bytes) != digest {
		return hostsecrets.Entry{}, capabilityError()
	}
	entry.SecretID = ref
	if hostsecrets.ValidateSeed(hostsecrets.Seed{Region: v.config.Region, OperationID: request.OperationID, Entries: []hostsecrets.Entry{entry}}) != nil {
		return hostsecrets.Entry{}, capabilityError()
	}
	return entry, nil
}
