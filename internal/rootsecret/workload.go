//go:build linux

package rootsecret

import (
	"context"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

// MaterialService accepts independently verified opaque root admissions, never
// caller-selected Vault references or secret identifiers.
type MaterialService struct {
	AdmitContainer  func(context.Context, rootoci.Call, host.ContainerMaterialEvidence) (containermaterial.Admission, error)
	AdmitGeneration func(context.Context, rootoci.Call, string) (containermaterial.GenerationAdmission, error)
}

type materialAdmission interface {
	Profile() containermaterial.Profile
	Deadline() time.Time
	Guard(context.Context) error
}

func (service MaterialService) MaterializeContainer(ctx context.Context, call rootoci.Call, request rootoci.MaterializeContainerRequest) (rootoci.ContainerMaterialReceipt, error) {
	if service.AdmitContainer == nil || workloadCall(ctx, call, rootoci.OperationMaterializeContainer) != nil {
		return rootoci.ContainerMaterialReceipt{}, ErrDelivery
	}
	admitted, err := service.AdmitContainer(ctx, call, request.Evidence)
	if err != nil {
		return rootoci.ContainerMaterialReceipt{}, ErrDelivery
	}
	ctx, cancel := materialContext(ctx, call, admitted)
	defer cancel()
	guard := materialGuard(ctx, call, admitted)
	if guard() != nil {
		return rootoci.ContainerMaterialReceipt{}, ErrDelivery
	}
	profile := admitted.Profile()
	result := rootoci.ContainerMaterialReceipt{Task: containerTaskReceipt(admitted.Task()), Values: make(map[string]rootoci.ContainerSecretValue)}
	if profile.NoSecrets() {
		if guard() != nil {
			return rootoci.ContainerMaterialReceipt{}, ErrDelivery
		}
		return result, nil
	}
	values, err := vaultsecret.ResolveCurrent(ociclient.RequestContext(ctx), profile.Profile().Secrets, func(region string) (vaultsecret.BundleClient, error) {
		if guard() != nil {
			return nil, ErrDelivery
		}
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return nil, ErrDelivery
		}
		client, err := vaultsecret.SecretsClient(factory)
		if err != nil {
			return nil, ErrDelivery
		}
		client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: guard}
		return client, nil
	})
	if err != nil {
		return rootoci.ContainerMaterialReceipt{}, ErrDelivery
	}
	for key, value := range values {
		result.Values[key] = rootoci.ContainerSecretValue{ID: value.ID, Version: value.Version, ExpiresAt: value.ExpiresAt, Value: value.Value()}
	}
	if guard() != nil {
		return rootoci.ContainerMaterialReceipt{}, ErrDelivery
	}
	for _, value := range result.Values {
		if !value.ExpiresAt.IsZero() && !time.Now().Before(value.ExpiresAt) {
			return rootoci.ContainerMaterialReceipt{}, ErrDelivery
		}
	}
	return result, nil
}

func (service MaterialService) ObserveContainerGeneration(ctx context.Context, call rootoci.Call, request rootoci.ObserveContainerGenerationRequest) (rootoci.ContainerGenerationReceipt, error) {
	if service.AdmitGeneration == nil || workloadCall(ctx, call, rootoci.OperationObserveContainerGeneration) != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	admitted, err := service.AdmitGeneration(ctx, call, request.TaskID)
	if err != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	ctx, cancel := materialContext(ctx, call, admitted)
	defer cancel()
	guard := materialGuard(ctx, call, admitted)
	if guard() != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	profile := admitted.Profile()
	result := rootoci.ContainerGenerationReceipt{Task: containerTaskReceipt(admitted.Task()), Values: make(map[string]rootoci.ContainerSecretMetadata)}
	if profile.NoSecrets() {
		if guard() != nil {
			return rootoci.ContainerGenerationReceipt{}, ErrDelivery
		}
		return result, nil
	}
	region, known := catalog.LookupName(profile.Identity().Cell)
	if !known {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	factory, err := ociclient.InstancePrincipal(region.OCIRegion)
	if err != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	management, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	management.HTTPClient = credentialDispatcher{next: management.HTTPClient, guard: guard}
	metadata, err := vault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	metadata.SetRegion(factory.Region())
	factory.Configure(&metadata.BaseClient, ociclient.ServiceVault)
	metadata.HTTPClient = credentialDispatcher{next: metadata.HTTPClient, guard: guard}
	compartments := make(map[string]string)
	for key, reference := range profile.Profile().Secrets {
		compartment := compartments[reference.Vault]
		if compartment == "" {
			response, err := management.GetVault(ociclient.RequestContext(ctx), keymanagement.GetVaultRequest{VaultId: new(reference.Vault)})
			if err != nil || response.Id == nil || *response.Id != reference.Vault || response.CompartmentId == nil || *response.CompartmentId == "" || response.LifecycleState != keymanagement.VaultLifecycleStateActive {
				return rootoci.ContainerGenerationReceipt{}, ErrDelivery
			}
			compartment = *response.CompartmentId
			compartments[reference.Vault] = compartment
		}
		value, err := observeCurrentMetadata(ctx, &metadata, compartment, reference)
		if err != nil {
			return rootoci.ContainerGenerationReceipt{}, ErrDelivery
		}
		result.Values[key] = value
	}
	if guard() != nil {
		return rootoci.ContainerGenerationReceipt{}, ErrDelivery
	}
	for _, value := range result.Values {
		if !value.ExpiresAt.IsZero() && !time.Now().Before(value.ExpiresAt) {
			return rootoci.ContainerGenerationReceipt{}, ErrDelivery
		}
	}
	return result, nil
}

func containerTaskReceipt(task containermaterial.TaskMaterial) rootoci.ContainerTaskMaterial {
	return rootoci.ContainerTaskMaterial{
		Binding: task.Binding, OperationID: task.OperationID, ConfigDigest: task.ConfigDigest,
		Generation: task.Generation, User: task.User, ExpiresAt: task.ExpiresAt,
	}
}

func workloadCall(ctx context.Context, call rootoci.Call, operation rootoci.Operation) error {
	if os.Geteuid() != 0 || call.Operation() != "" && call.Operation() != operation || call.Guard(ctx) != nil {
		return ErrDelivery
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return ErrDelivery
		}
	}
	return nil
}

func materialContext(ctx context.Context, call rootoci.Call, admitted materialAdmission) (context.Context, context.CancelFunc) {
	deadline := minDeadline(call.Deadline(), admitted.Deadline())
	return context.WithDeadline(ctx, deadline)
}

func minDeadline(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}

func materialGuard(ctx context.Context, call rootoci.Call, admitted materialAdmission) func() error {
	return func() error {
		if call.Guard(ctx) != nil || admitted.Guard(ctx) != nil || call.Guard(ctx) != nil ||
			admitted.Deadline().IsZero() || !time.Now().Before(admitted.Deadline()) {
			return ErrDelivery
		}
		return nil
	}
}

func observeCurrentMetadata(ctx context.Context, client *vault.VaultsClient, compartment string, reference vaultsecret.Ref) (rootoci.ContainerSecretMetadata, error) {
	listed, err := client.ListSecrets(ociclient.RequestContext(ctx), vault.ListSecretsRequest{
		CompartmentId: new(compartment), VaultId: new(reference.Vault), Name: new(reference.Name), Limit: new(2), LifecycleState: vault.SecretSummaryLifecycleStateActive,
	})
	if err != nil || len(listed.Items) != 1 || listed.OpcNextPage != nil && *listed.OpcNextPage != "" {
		return rootoci.ContainerSecretMetadata{}, ErrDelivery
	}
	summary := listed.Items[0]
	if summary.Id == nil || *summary.Id == "" || summary.SecretName == nil || *summary.SecretName != reference.Name || summary.VaultId == nil || *summary.VaultId != reference.Vault || summary.CompartmentId == nil || *summary.CompartmentId != compartment {
		return rootoci.ContainerSecretMetadata{}, ErrDelivery
	}
	response, err := client.GetSecret(ociclient.RequestContext(ctx), vault.GetSecretRequest{SecretId: summary.Id})
	if err != nil || response.Id == nil || *response.Id != *summary.Id || response.SecretName == nil || *response.SecretName != reference.Name ||
		response.VaultId == nil || *response.VaultId != reference.Vault || response.CompartmentId == nil || *response.CompartmentId != compartment ||
		response.LifecycleState != vault.SecretLifecycleStateActive || response.CurrentVersionNumber == nil || *response.CurrentVersionNumber <= 0 {
		return rootoci.ContainerSecretMetadata{}, ErrDelivery
	}
	version, err := client.GetSecretVersion(ociclient.RequestContext(ctx), vault.GetSecretVersionRequest{SecretId: response.Id, SecretVersionNumber: response.CurrentVersionNumber})
	if err != nil || version.SecretId == nil || *version.SecretId != *response.Id || version.VersionNumber == nil || *version.VersionNumber != *response.CurrentVersionNumber || !slices.Contains(version.Stages, vault.SecretVersionStagesCurrent) {
		return rootoci.ContainerSecretMetadata{}, ErrDelivery
	}
	var expires time.Time
	for _, deadline := range []*common.SDKTime{response.TimeOfDeletion, response.TimeOfCurrentVersionExpiry, version.TimeOfDeletion, version.TimeOfCurrentVersionExpiry} {
		if deadline != nil && (expires.IsZero() || deadline.Time.Before(expires)) {
			expires = deadline.Time
		}
	}
	if !expires.IsZero() && !time.Now().Before(expires) {
		return rootoci.ContainerSecretMetadata{}, ErrDelivery
	}
	return rootoci.ContainerSecretMetadata{ID: *response.Id, Version: *version.VersionNumber, ExpiresAt: expires}, nil
}
