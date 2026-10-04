package teardown

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// OCI's shortest deletion windows, plus an hour of clock margin.
const (
	secretWindow = 25 * time.Hour
	keyWindow    = 7*24*time.Hour + time.Hour
)

// SDKProvider serves Provider through the OCI Go SDK with the operator's
// ~/.oci/config DEFAULT profile.
type SDKProvider struct {
	factory  *ociclient.Factory
	secrets  vault.VaultsClient
	vaults   keymanagement.KmsVaultClient
	identity identity.IdentityClient
}

func NewSDKProvider(ctx context.Context, region string) (*SDKProvider, error) {
	f, err := ociclient.OperatorConfig(region)
	if err != nil {
		return nil, err
	}
	p := &SDKProvider{factory: f}
	if p.secrets, err = vault.NewVaultsClientWithConfigurationProvider(f.Provider()); err != nil {
		return nil, err
	}
	p.secrets.SetRegion(region)
	f.Configure(&p.secrets.BaseClient, ociclient.ServiceKMS)
	if p.vaults, err = keymanagement.NewKmsVaultClientWithConfigurationProvider(f.Provider()); err != nil {
		return nil, err
	}
	p.vaults.SetRegion(region)
	f.Configure(&p.vaults.BaseClient, ociclient.ServiceKMS)
	if p.identity, err = f.Identity(); err != nil {
		return nil, err
	}
	if err := p.useHomeIdentity(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Compartment deletion is a home-region operation. KMS stays in the cell's
// region, and the shared identity limiter and retry policy stay installed.
func (p *SDKProvider) useHomeIdentity(ctx context.Context) error {
	tenancy, err := p.factory.Provider().TenancyOCID()
	if err != nil {
		return err
	}
	if tenancy == "" {
		return fmt.Errorf("OCI configuration has no tenancy")
	}
	lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := p.identity.ListRegionSubscriptions(lookup, identity.ListRegionSubscriptionsRequest{TenancyId: &tenancy})
	if err != nil {
		return fmt.Errorf("read the tenancy home region: %w", err)
	}
	home := ""
	for _, subscription := range response.Items {
		if subscription.IsHomeRegion == nil || !*subscription.IsHomeRegion {
			continue
		}
		region := deref(subscription.RegionName)
		if home != "" || !catalog.IsOCIRegion(region) || subscription.Status != identity.RegionSubscriptionStatusReady {
			return fmt.Errorf("invalid or ambiguous home-region subscription %q", region)
		}
		home = region
	}
	if home == "" {
		return fmt.Errorf("region subscriptions do not identify a home region")
	}
	p.identity.SetRegion(home)
	return nil
}

func (p *SDKProvider) Get(ctx context.Context, r Resource) (Observed, error) {
	var o Observed
	var err error
	switch r.Kind {
	case "vault-secret":
		var resp vault.GetSecretResponse
		resp, err = p.secrets.GetSecret(ctx, vault.GetSecretRequest{SecretId: &r.ID})
		s := resp.Secret
		o = Observed{deref(s.SecretName), deref(s.CompartmentId), string(s.LifecycleState), sdkTime(s.TimeOfDeletion)}
	case "kms-vault":
		var resp keymanagement.GetVaultResponse
		resp, err = p.vaults.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: &r.ID})
		v := resp.Vault
		o = Observed{deref(v.DisplayName), deref(v.CompartmentId), string(v.LifecycleState), sdkTime(v.TimeOfDeletion)}
	case "kms-key":
		var keys *keymanagement.KmsManagementClient
		var vaultState string
		if keys, vaultState, err = p.keys(ctx, r.VaultID); err == nil && keys == nil {
			return Observed{State: vaultState}, nil
		}
		if err == nil {
			var resp keymanagement.GetKeyResponse
			resp, err = keys.GetKey(ctx, keymanagement.GetKeyRequest{KeyId: &r.ID})
			k := resp.Key
			o = Observed{deref(k.DisplayName), deref(k.CompartmentId), string(k.LifecycleState), sdkTime(k.TimeOfDeletion)}
		}
	case "compartment":
		var resp identity.GetCompartmentResponse
		resp, err = p.identity.GetCompartment(ctx, identity.GetCompartmentRequest{CompartmentId: &r.ID})
		c := resp.Compartment
		o = Observed{Name: deref(c.Name), Compartment: deref(c.CompartmentId), State: string(c.LifecycleState)}
	default:
		return o, fmt.Errorf("unsupported kind %q", r.Kind)
	}
	if notFound(err) {
		return Observed{State: NotFound}, nil
	}
	return o, err
}

func (p *SDKProvider) Delete(ctx context.Context, r Resource) error {
	switch r.Kind {
	case "vault-secret":
		_, err := p.secrets.ScheduleSecretDeletion(ctx, vault.ScheduleSecretDeletionRequest{SecretId: &r.ID,
			ScheduleSecretDeletionDetails: vault.ScheduleSecretDeletionDetails{TimeOfDeletion: after(secretWindow)}})
		return err
	case "kms-vault":
		_, err := p.vaults.ScheduleVaultDeletion(ctx, keymanagement.ScheduleVaultDeletionRequest{VaultId: &r.ID,
			ScheduleVaultDeletionDetails: keymanagement.ScheduleVaultDeletionDetails{TimeOfDeletion: after(keyWindow)}})
		return err
	case "kms-key":
		keys, state, err := p.keys(ctx, r.VaultID)
		if err != nil {
			return err
		}
		if keys == nil {
			return fmt.Errorf("cannot schedule key %s: vault %s is %s", r.ID, r.VaultID, state)
		}
		_, err = keys.ScheduleKeyDeletion(ctx, keymanagement.ScheduleKeyDeletionRequest{KeyId: &r.ID,
			ScheduleKeyDeletionDetails: keymanagement.ScheduleKeyDeletionDetails{TimeOfDeletion: after(keyWindow)}})
		return err
	case "compartment":
		_, err := p.identity.DeleteCompartment(ctx, identity.DeleteCompartmentRequest{CompartmentId: &r.ID})
		return err
	}
	return fmt.Errorf("unsupported kind %q", r.Kind)
}

// keys returns a management client for a vault's keys. Without a vault it
// returns nil and the state its keys share: DELETED with a deleted vault,
// NotFound when OCI answers 404 for the vault.
func (p *SDKProvider) keys(ctx context.Context, vaultID string) (*keymanagement.KmsManagementClient, string, error) {
	resp, err := p.vaults.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: &vaultID})
	if notFound(err) {
		return nil, NotFound, nil
	}
	if err != nil {
		return nil, "", err
	}
	if resp.LifecycleState == keymanagement.VaultLifecycleStateDeleted {
		return nil, "DELETED", nil
	}
	client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(p.factory.Provider(), deref(resp.ManagementEndpoint))
	if err != nil {
		return nil, "", err
	}
	p.factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	return &client, "", nil
}

// VaultContents lists the vault's keys and secrets in every compartment of
// the tenancy, since either may live outside the vault's compartment.
func (p *SDKProvider) VaultContents(ctx context.Context, r Resource) ([]Resource, error) {
	keys, state, err := p.keys(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		if state == "DELETED" {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot verify contents of vault %s: %s", r.ID, state)
	}
	tenancy, err := p.factory.Provider().TenancyOCID()
	if err != nil {
		return nil, err
	}
	compartments := []string{tenancy}
	var page *string
	for {
		resp, err := p.identity.ListCompartments(ctx, identity.ListCompartmentsRequest{CompartmentId: &tenancy,
			CompartmentIdInSubtree: common.Bool(true), AccessLevel: identity.ListCompartmentsAccessLevelAny, Page: page})
		if err != nil {
			return nil, err
		}
		for _, c := range resp.Items {
			if c.LifecycleState != identity.CompartmentLifecycleStateDeleted {
				compartments = append(compartments, deref(c.Id))
			}
		}
		if page = resp.OpcNextPage; page == nil {
			break
		}
	}
	var contents []Resource
	for _, compartment := range compartments {
		for page = nil; ; {
			resp, err := keys.ListKeys(ctx, keymanagement.ListKeysRequest{CompartmentId: &compartment, Page: page})
			if err != nil {
				return nil, err
			}
			for _, k := range resp.Items {
				if k.LifecycleState != keymanagement.KeySummaryLifecycleStateDeleted {
					contents = append(contents, Resource{Kind: "kms-key", ID: deref(k.Id), Name: deref(k.DisplayName),
						Compartment: deref(k.CompartmentId), VaultID: deref(k.VaultId)})
				}
			}
			if page = resp.OpcNextPage; page == nil {
				break
			}
		}
		for page = nil; ; {
			resp, err := p.secrets.ListSecrets(ctx, vault.ListSecretsRequest{CompartmentId: &compartment, VaultId: &r.ID, Page: page})
			if err != nil {
				return nil, err
			}
			for _, s := range resp.Items {
				if s.LifecycleState != vault.SecretSummaryLifecycleStateDeleted {
					contents = append(contents, Resource{Kind: "vault-secret", ID: deref(s.Id), Name: deref(s.SecretName),
						Compartment: deref(s.CompartmentId), VaultID: deref(s.VaultId)})
				}
			}
			if page = resp.OpcNextPage; page == nil {
				break
			}
		}
	}
	return contents, nil
}

func notFound(err error) bool {
	failure, ok := common.IsServiceError(err)
	return ok && failure.GetHTTPStatusCode() == http.StatusNotFound
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func sdkTime(t *common.SDKTime) *time.Time {
	if t == nil {
		return nil
	}
	return &t.Time
}

func after(d time.Duration) *common.SDKTime {
	return &common.SDKTime{Time: time.Now().Add(d)}
}
