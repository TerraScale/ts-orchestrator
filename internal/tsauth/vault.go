package tsauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"uuid"

	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// VaultClient is the part of the OCI Vault management API that stores secrets.
type VaultClient interface {
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
	CreateSecret(context.Context, ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error)
}

func retrySecretRead(err error) bool {
	var serviceErr common.ServiceError
	if !errors.As(err, &serviceErr) {
		return false
	}
	status := serviceErr.GetHTTPStatusCode()
	return status == http.StatusNotFound || status == http.StatusConflict
}

// BundleClient reads secret contents.
type BundleClient interface {
	GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error)
}

// Target is the cell's Vault: the control compartment, the Vault created in
// phase 1 and its master key. The controllers may read secret bundles there.
type Target struct {
	CompartmentID, VaultID, KeyID string
}

var secretOCIDRE = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

// SecretName is the Vault secret holding key for cell, for example
// gru-1-ts-auth-master-key.
func SecretName(cell, key string) string {
	return cell + "-" + strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

// Stored is one secret of the Vault; it never carries the value.
type Stored struct {
	Key     string `json:"key"`
	Secret  string `json:"secret"`
	ID      string `json:"id"`
	Created bool   `json:"created"`
	// Provisioning is true when an existing OCI secret is still becoming
	// readable. It is internal state, so it never appears in CLI output.
	Provisioning bool `json:"-"`
}

// Ensure stores the value of key in the Vault unless a secret of its name
// exists. value runs only when the secret is absent, so an existing secret is
// never regenerated, replaced or rotated. OCI keeps secret names unique in a
// Vault, so two runs cannot both create one.
func Ensure(ctx context.Context, client VaultClient, target Target, cell, key string, value func(context.Context) (string, error)) (Stored, error) {
	name := SecretName(cell, key)
	stored := Stored{Key: key, Secret: name}
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
	if err := validSecret(key, secret); err != nil {
		return stored, err
	}
	content := base64.StdEncoding.EncodeToString([]byte(secret))
	response, err := client.CreateSecret(ctx, ocivault.CreateSecretRequest{
		CreateSecretDetails: ocivault.CreateSecretDetails{
			CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), KeyId: new(target.KeyID),
			SecretName: new(name), Description: new(key + " of cell " + cell + "; created once by ts-orch."),
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

// Generate returns 32 random bytes in base64, the form of the Generated secrets.
func Generate(context.Context) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ReadSecrets reads the current version of every secret of cell's ts-auth
// from the Vault.
func ReadSecrets(ctx context.Context, client BundleClient, vaultID, cell string) (map[string]string, error) {
	secrets := make(map[string]string, len(Secrets))
	for _, key := range Secrets {
		value, err := readSecret(ctx, client, vaultID, cell, key)
		if err != nil {
			return nil, err
		}
		secrets[key] = value
	}
	return secrets, nil
}

// readSecret reads and checks the current version of one secret.
func readSecret(ctx context.Context, client BundleClient, vaultID, cell, key string) (string, error) {
	name := SecretName(cell, key)
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
	if err := validSecret(key, string(value)); err != nil {
		return "", errors.Join(fmt.Errorf("Vault secret %s", name), err)
	}
	return string(value), nil
}
