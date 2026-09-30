package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

var errMaterialLiveTarget = errors.New("live OCI material target differs from manual foundation readback")

// Read the publication target again with the same OCI profile that will write
// the secrets. The manual inspector checks the wider foundation before it
// emits its readback; this check protects the immediate Vault write boundary.
func newMaterialOCIClients(ctx context.Context, configPath, profile string, readback manualFoundationReadback) (
	bootstrapmaterial.VaultClient, bootstrapmaterial.BundleClient, error,
) {
	provider, err := common.ConfigurationProviderFromFileWithProfile(configPath, profile, "")
	if err != nil {
		return nil, nil, err
	}
	region, regionErr := provider.Region()
	tenancy, tenancyErr := provider.TenancyOCID()
	if regionErr != nil || tenancyErr != nil || region != readback.OCIRegion || tenancy != readback.TenancyID {
		return nil, nil, errMaterialLiveTarget
	}
	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, nil, err
	}
	identityClient.SetRegion(region)
	for _, id := range []string{readback.ControlCompartmentID, readback.NetworkCompartmentID, readback.WorkloadCompartmentID} {
		response, err := identityClient.GetCompartment(ctx, identity.GetCompartmentRequest{CompartmentId: new(id)})
		if err != nil {
			return nil, nil, fmt.Errorf("read material compartment: %w", err)
		}
		if !liveMaterialCompartmentMatches(id, response.Compartment) {
			return nil, nil, errMaterialLiveTarget
		}
	}
	vaultClient, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, nil, err
	}
	vaultClient.SetRegion(region)
	vaultResponse, err := vaultClient.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: new(readback.VaultID)})
	if err != nil {
		return nil, nil, fmt.Errorf("read material Vault: %w", err)
	}
	endpoint, err := liveMaterialVaultEndpoint(readback, vaultResponse.Vault)
	if err != nil {
		return nil, nil, err
	}
	keyClient, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(provider, endpoint)
	if err != nil {
		return nil, nil, err
	}
	keyResponse, err := keyClient.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: new(readback.KeyID)})
	if err != nil {
		return nil, nil, fmt.Errorf("read material KMS key: %w", err)
	}
	if !liveMaterialKeyMatches(readback, keyResponse.Key) {
		return nil, nil, errMaterialLiveTarget
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, nil, err
	}
	management.SetRegion(region)
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, nil, err
	}
	bundles.SetRegion(region)
	return management, bundles, nil
}

func liveMaterialCompartmentMatches(id string, compartment identity.Compartment) bool {
	return compartment.Id != nil && *compartment.Id == id &&
		compartment.LifecycleState == identity.CompartmentLifecycleStateActive
}

func liveMaterialVaultEndpoint(readback manualFoundationReadback, vault keymanagement.Vault) (string, error) {
	if vault.Id == nil || *vault.Id != readback.VaultID || vault.CompartmentId == nil ||
		*vault.CompartmentId != readback.ControlCompartmentID ||
		vault.LifecycleState != keymanagement.VaultLifecycleStateActive ||
		vault.VaultType != keymanagement.VaultVaultTypeDefault || vault.ManagementEndpoint == nil {
		return "", errMaterialLiveTarget
	}
	endpoint, err := url.Parse(*vault.ManagementEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Port() != "" ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		!strings.HasSuffix(endpoint.Hostname(), ".oraclecloud.com") ||
		!strings.Contains(endpoint.Hostname(), "."+readback.OCIRegion+".") {
		return "", errMaterialLiveTarget
	}
	return endpoint.String(), nil
}

func liveMaterialKeyMatches(readback manualFoundationReadback, key keymanagement.Key) bool {
	return key.Id != nil && *key.Id == readback.KeyID && key.CompartmentId != nil &&
		*key.CompartmentId == readback.ControlCompartmentID && key.VaultId != nil &&
		*key.VaultId == readback.VaultID && key.LifecycleState == keymanagement.KeyLifecycleStateEnabled &&
		key.ProtectionMode == keymanagement.KeyProtectionModeHsm && key.KeyShape != nil &&
		key.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes &&
		key.KeyShape.Length != nil && *key.KeyShape.Length == 32
}
