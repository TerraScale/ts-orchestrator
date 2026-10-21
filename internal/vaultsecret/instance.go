package vaultsecret

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// instanceVault is the regional Vault of the instance's own cell, found once.
var instanceVault struct {
	sync.Mutex
	scope, vaultID string
}

// ReadInstanceSecrets reads the current value of each environment key from the
// Vault of the instance's own cell, with its instance principal. It needs no
// configuration: the cell comes from the instance metadata region, and the
// Vault is the one named <cell>-vault in the instance's compartment.
func ReadInstanceSecrets(ctx context.Context, keys []string) (map[string]string, error) {
	if err := safeEnv(); err != nil {
		return nil, err
	}
	scope, vaultID, err := discoverInstanceVault(ctx)
	if err != nil {
		return nil, err
	}
	return ReadScoped(ctx, vaultID, scope, keys, func(region string) (BundleClient, error) {
		factory, err := ociclient.InstancePrincipalContext(ctx, region)
		if err != nil {
			return nil, err
		}
		return SecretsClient(factory)
	})
}

// ReadScoped reads keys as the Vault secrets of scope. A key ending in _FILE
// names the secret without that suffix: the value is delivered as a file.
func ReadScoped(ctx context.Context, vaultID, scope string, keys []string, client func(region string) (BundleClient, error)) (map[string]string, error) {
	refs := make(map[string]Ref, len(keys))
	for _, key := range keys {
		refs[key] = Ref{Vault: vaultID, Name: Name(scope, strings.TrimSuffix(key, "_FILE"))}
	}
	return Resolve(ctx, refs, client)
}

func discoverInstanceVault(ctx context.Context) (string, string, error) {
	instanceVault.Lock()
	defer instanceVault.Unlock()
	if instanceVault.vaultID != "" {
		return instanceVault.scope, instanceVault.vaultID, nil
	}
	metadata, err := instanceMetadata(ctx)
	if err != nil {
		return "", "", err
	}
	entry, ok := catalog.CellForOCIRegion(metadata.Region)
	if !ok {
		return "", "", fmt.Errorf("instance region %q is not a TerraScale cell", metadata.Region)
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, metadata.Region)
	if err != nil {
		return "", "", err
	}
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return "", "", fmt.Errorf("create OCI KMS Vault client: %w", err)
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	name := entry.Name() + "-vault"
	var found []string
	request := keymanagement.ListVaultsRequest{CompartmentId: &metadata.CompartmentID}
	for range 32 {
		response, err := client.ListVaults(ctx, request)
		if err != nil {
			return "", "", fmt.Errorf("list Vaults for %s failed", name)
		}
		for _, vault := range response.Items {
			if vault.DisplayName != nil && *vault.DisplayName == name && vault.Id != nil &&
				vault.LifecycleState == keymanagement.VaultSummaryLifecycleStateActive {
				found = append(found, *vault.Id)
			}
		}
		if response.OpcNextPage == nil {
			break
		}
		request.Page = response.OpcNextPage
	}
	if len(found) != 1 {
		return "", "", fmt.Errorf("instance compartment needs exactly one active Vault %s, found %d", name, len(found))
	}
	// shortcut: one cell per region (scope <cell>-1); derive the number when a region gets a second cell.
	instanceVault.scope, instanceVault.vaultID = entry.Name()+"-1", found[0]
	return instanceVault.scope, instanceVault.vaultID, nil
}

type metadata struct {
	Region        string `json:"canonicalRegionName"`
	CompartmentID string `json:"compartmentId"`
}

func instanceMetadata(ctx context.Context) (metadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return metadata{}, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return metadata{}, errors.New("Vault secrets need OCI instance metadata")
	}
	defer response.Body.Close()
	var result metadata
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(data, &result) != nil ||
		result.Region == "" || result.CompartmentID == "" {
		return metadata{}, errors.New("OCI instance metadata has no region or compartment")
	}
	return result, nil
}
