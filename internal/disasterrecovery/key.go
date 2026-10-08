package disasterrecovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// requireVaultKey binds the configured Vault to the bucket encryption key.
// Otherwise a typo can replicate an unrelated Vault while copying its bucket.
func requireVaultKey(ctx context.Context, factory *ociclient.Factory, config Region) error {
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return err
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	vault, err := client.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: &config.VaultID})
	if err != nil {
		return err
	}
	if !same(vault.Id, config.VaultID) || !same(vault.CompartmentId, config.CompartmentID) || vault.ManagementEndpoint == nil {
		return errors.New("recovery Vault differs from its pinned control compartment")
	}
	if _, err := kmsEndpoint(vault.ManagementEndpoint, factory.Region(), "management"); err != nil {
		return err
	}
	keys, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(factory.Provider(), *vault.ManagementEndpoint)
	if err != nil {
		return err
	}
	factory.Configure(&keys.BaseClient, ociclient.ServiceKMS)
	key, err := keys.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: &config.KeyID})
	if err != nil {
		return err
	}
	return validateVaultKey(key.Key, config)
}

// OCI Vault endpoints use both oraclecloud.com and oci.oraclecloud.com.
// Validate the region and service before passing the endpoint to the signer.
func kmsEndpoint(endpoint *string, region, operation string) (string, error) {
	if endpoint != nil {
		u, err := url.Parse(*endpoint)
		suffix := "-" + operation + ".kms." + region
		if err == nil && u.Scheme == "https" && u.Host == u.Hostname() && u.User == nil && u.Path == "" &&
			u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
			(strings.HasSuffix(u.Hostname(), suffix+".oraclecloud.com") || strings.HasSuffix(u.Hostname(), suffix+".oci.oraclecloud.com")) {
			return *endpoint, nil
		}
	}
	return "", fmt.Errorf("Vault has no valid %s endpoint in region %s", operation, region)
}

func validateVaultKey(key keymanagement.Key, config Region) error {
	if !same(key.Id, config.KeyID) || !same(key.VaultId, config.VaultID) || !same(key.CompartmentId, config.CompartmentID) ||
		key.LifecycleState != keymanagement.KeyLifecycleStateEnabled {
		return errors.New("recovery encryption key is not enabled in the configured Vault and compartment")
	}
	return nil
}
