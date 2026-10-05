// Package vaultsecret keeps TerraScale's secrets in OCI Vault: one naming
// scheme, create-once storage and reads that never print a value.
package vaultsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// VaultClient is the part of the OCI Vault management API that stores secrets.
type VaultClient interface {
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
	CreateSecret(context.Context, ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error)
}

// BundleClient reads secret contents.
type BundleClient interface {
	GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error)
}

// Target is where a new secret goes: its compartment, which decides who may
// read it, and the Vault and master key that hold it.
type Target struct {
	CompartmentID, VaultID, KeyID string
}

var (
	secretOCIDRE = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	nameRE       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Name is the Vault secret holding key of scope, a cell such as gru-1: the
// scope, then the key lower-cased with hyphens for underscores. The key
// starts with its service, so TS_AUTH_MASTER_KEY of gru-1 is
// gru-1-ts-auth-master-key.
func Name(scope, key string) string {
	return scope + "-" + strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

// Stored is one secret of the Vault; it never carries the value.
type Stored struct {
	Secret  string `json:"secret"`
	ID      string `json:"id"`
	Created bool   `json:"created"`
	// Provisioning is true when an existing OCI secret is still becoming
	// readable. It is internal state, so it never appears in CLI output.
	Provisioning bool `json:"-"`
}

// Ensure stores value as secret name unless the Vault holds a secret of that
// name. value runs only when the secret is absent, so an existing secret is
// never regenerated, replaced or rotated. OCI keeps secret names unique in a
// Vault, so two runs cannot both create one.
func Ensure(ctx context.Context, client VaultClient, target Target, name, description string, value func(context.Context) (string, error)) (Stored, error) {
	stored := Stored{Secret: name}
	if err := safeEnv(); err != nil {
		return stored, err
	}
	id, provisioning, err := lookup(ctx, client, target, name)
	if err != nil || id != "" {
		stored.ID = id
		stored.Provisioning = provisioning
		return stored, err
	}
	secret, err := value(ctx)
	if err != nil {
		return stored, err
	}
	content := base64.StdEncoding.EncodeToString([]byte(secret))
	response, err := client.CreateSecret(ctx, ocivault.CreateSecretRequest{
		CreateSecretDetails: ocivault.CreateSecretDetails{
			CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), KeyId: new(target.KeyID),
			SecretName: new(name), Description: new(description),
			SecretContent: ocivault.Base64SecretContentDetails{Content: new(content), Stage: ocivault.SecretContentDetailsStageCurrent},
		},
		// The SDK retries a lost response with the same token, which OCI
		// answers with the first result instead of a second secret.
		OpcRetryToken: new(uuid.New().String()),
	})
	if err != nil {
		if id, provisioning, lookupErr := lookup(ctx, client, target, name); lookupErr == nil && id != "" {
			stored.ID, stored.Provisioning = id, provisioning
			return stored, nil
		}
		return stored, fmt.Errorf("create Vault secret %s: %w", name, err)
	}
	if response.Id == nil || !secretOCIDRE.MatchString(*response.Id) {
		return stored, fmt.Errorf("create Vault secret %s: OCI returned no secret OCID", name)
	}
	stored.ID, stored.Created = *response.Id, true
	return stored, nil
}

// lookup returns the OCID of the active secret name, or "" when the Vault has
// none. A secret of that name in any other state needs an operator: it may be
// pending deletion, and OCI refuses its name until it is deleted.
func lookup(ctx context.Context, client VaultClient, target Target, name string) (string, bool, error) {
	found := ""
	provisioning := false
	request := ocivault.ListSecretsRequest{CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), Name: new(name)}
	for range 32 {
		response, err := client.ListSecrets(ctx, request)
		if err != nil {
			return "", false, fmt.Errorf("list Vault secret %s: %w", name, err)
		}
		for _, item := range response.Items {
			if item.SecretName == nil || *item.SecretName != name {
				continue
			}
			if item.Id == nil || !secretOCIDRE.MatchString(*item.Id) || found != "" ||
				item.LifecycleState != ocivault.SecretSummaryLifecycleStateActive &&
					item.LifecycleState != ocivault.SecretSummaryLifecycleStateCreating {
				return "", false, fmt.Errorf("Vault secret %s exists in state %s; inspect it before rerunning", name, item.LifecycleState)
			}
			found = *item.Id
			provisioning = item.LifecycleState == ocivault.SecretSummaryLifecycleStateCreating
		}
		if response.OpcNextPage == nil {
			return found, provisioning, nil
		}
		request.Page = response.OpcNextPage
	}
	return "", false, fmt.Errorf("list Vault secret %s: too many pages", name)
}

// Read reads the current version of secret name. Errors name the secret,
// never its content.
func Read(ctx context.Context, client BundleClient, vaultID, name string) (string, error) {
	if err := safeEnv(); err != nil {
		return "", err
	}
	response, err := client.GetSecretBundleByName(ctx, ocisecrets.GetSecretBundleByNameRequest{
		SecretName: new(name), VaultId: new(vaultID), Stage: ocisecrets.GetSecretBundleByNameStageCurrent,
	})
	if err != nil {
		return "", fmt.Errorf("read Vault secret %s: %w", name, err)
	}
	var content *string
	switch bundle := response.SecretBundleContent.(type) {
	case ocisecrets.Base64SecretBundleContentDetails:
		content = bundle.Content
	case *ocisecrets.Base64SecretBundleContentDetails:
		if bundle != nil {
			content = bundle.Content
		}
	}
	if content == nil {
		return "", fmt.Errorf("Vault secret %s has no base64 content", name)
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*content)
	if err != nil {
		return "", fmt.Errorf("Vault secret %s is not base64", name)
	}
	return string(value), nil
}

// ReadBack reads a secret that may have been created a moment ago: a new
// secret can take some seconds to become readable.
func ReadBack(ctx context.Context, client BundleClient, vaultID, name string, created bool) (string, error) {
	for attempt := 1; ; attempt++ {
		value, err := Read(ctx, client, vaultID, name)
		if err == nil || !created || attempt == 30 || !retrySecretRead(err) {
			return value, err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// safeEnv refuses OCI SDK settings that log request and response bodies or
// redirect endpoints and TLS trust: secret contents would leak.
func safeEnv() error {
	for _, variable := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(variable); set {
			return fmt.Errorf("OCI Vault access refuses to run while %s is set", variable)
		}
	}
	return nil
}

func retrySecretRead(err error) bool {
	var serviceErr common.ServiceError
	if !errors.As(err, &serviceErr) {
		return false
	}
	status := serviceErr.GetHTTPStatusCode()
	return status == http.StatusNotFound || status == http.StatusConflict
}
