package vaultsecret

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
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
	cell, vaultID string
}

// serviceKeyRE is a single-host service's secret key; it also names the file.
var serviceKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// sharedSecrets lists the Vault secrets, by purpose after <cell>-<n>-, that a
// service other than their owner reads, and which services.
var sharedSecrets = map[string][]string{
	"terrabase-peer-secret":           {"ts-auth", "ts-dashboard"},
	"ts-auth-dashboard-client-secret": {"ts-dashboard"},
	"cloudflare-account-id":           {"ts-auth"},
	"cloudflare-email-token":          {"ts-auth"},
	"stripe-secret-key":               {"ts-dashboard"},
	"stripe-webhook-secret":           {"ts-dashboard"},
}

// ValidateServiceRefs binds a single-host service's secrets to one Vault of
// cell (vaultID, or any one Vault in the cell's region when vaultID is ""):
// each key is a *_FILE name, so a value never enters the task environment,
// and each ref names <cell>-<n>-<service>-<purpose> or a secret sharedSecrets
// lets the service read. A service named like an infrastructure family (or a
// prefix of one, such as "ts") names no secrets.
func ValidateServiceRefs(cell, vaultID, service string, refs map[string]Ref) error {
	if len(refs) == 0 {
		return nil
	}
	if slices.ContainsFunc(infrastructure, func(family string) bool {
		return family != "ts-dashboard" && (service == family || strings.HasPrefix(family, service+"-"))
	}) {
		return fmt.Errorf("service %s shares a name with the cell's infrastructure secrets and names no Vault secrets", service)
	}
	entry, known := catalog.LookupName(cell)
	own := map[string]Ref{}
	for key, ref := range refs {
		if !serviceKeyRE.MatchString(key) || !FileKey(key) {
			return fmt.Errorf("Vault secret key %q of %s must match %s and end in _FILE", key, service, serviceKeyRE)
		}
		if vaultID == "" {
			vaultID = ref.Vault
		}
		if !known || ref.Vault != vaultID || ref.region() != entry.OCIRegion {
			return fmt.Errorf("Vault secret %s of %s must name cell %s's Vault", key, service, cell)
		}
		index, purpose, _ := strings.Cut(strings.TrimPrefix(ref.Name, cell+"-"), "-")
		if strings.HasPrefix(ref.Name, cell+"-") && strings.Trim(index, "0123456789") == "" && slices.Contains(sharedSecrets[purpose], service) {
			continue
		}
		own[key] = ref
	}
	return ValidateDeliveryRefs(cell, service, own, nil)
}

// ReadInstanceSecrets reads the current value of each of service's refs from
// the Vault of the instance's own cell, with its instance principal, after
// ValidateServiceRefs. It needs no configuration: the cell comes from the
// instance metadata region, and the Vault is the one named <cell>-vault in the
// instance's compartment.
func ReadInstanceSecrets(ctx context.Context, service string, refs map[string]Ref) (map[string]string, error) {
	if err := safeEnv(); err != nil {
		return nil, err
	}
	cell, vaultID, err := discoverInstanceVault(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateServiceRefs(cell, vaultID, service, refs); err != nil {
		return nil, err
	}
	return Resolve(ctx, refs, instanceClient(ctx))
}

// SharedVault is gru-vault (compartment gru-1-control), the one Vault every
// region reads cross-region with its instance principal (policy ts-orch-hosts-vault).
const SharedVault = "ocid1.vault.oc1.sa-saopaulo-1.ffvnrldqaaexa.abtxeljrlqoda2dl7r527hwngvx5k5j7lhfytswubkmx6rtg5f4mjtv4xzlq"

// ReadGHCRPullToken reads the read-only GHCR pull token every region shares
// from SharedVault.
func ReadGHCRPullToken(ctx context.Context) (string, error) {
	if err := safeEnv(); err != nil {
		return "", err
	}
	bundles, err := instanceClient(ctx)(Ref{Vault: SharedVault}.region())
	if err != nil {
		return "", fmt.Errorf("Vault secret gru-1-ghcr-pull-token: %w", err)
	}
	return Read(ctx, bundles, SharedVault, "gru-1-ghcr-pull-token")
}

func instanceClient(ctx context.Context) func(region string) (BundleClient, error) {
	return func(region string) (BundleClient, error) {
		factory, err := ociclient.InstancePrincipalContext(ctx, region)
		if err != nil {
			return nil, err
		}
		return SecretsClient(factory)
	}
}

func discoverInstanceVault(ctx context.Context) (string, string, error) {
	instanceVault.Lock()
	defer instanceVault.Unlock()
	if instanceVault.vaultID != "" {
		return instanceVault.cell, instanceVault.vaultID, nil
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
	instanceVault.cell, instanceVault.vaultID = entry.Name(), found[0]
	return instanceVault.cell, instanceVault.vaultID, nil
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
