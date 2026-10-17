package functionmaterial

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// RetirementClient is the OCI metadata and conditional secret-deletion API.
type RetirementClient interface {
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
	GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error)
	ScheduleSecretDeletion(context.Context, ocivault.ScheduleSecretDeletionRequest) (ocivault.ScheduleSecretDeletionResponse, error)
}

// Retirement contains no secret material. Already pending secrets expose only
// their provider identity and deletion date because their bundles are unreadable.
type Retirement struct {
	SecretID       string    `json:"secret_id"`
	Name           string    `json:"name"`
	TaskID         string    `json:"task_id,omitempty"`
	MaterialSHA256 string    `json:"material_sha256,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	DeleteAt       time.Time `json:"delete_at"`
}

var retirementID = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

// RetireExpired schedules only exact, expired, independently unused deliveries.
// Authority grants remain in the control log for audit after Vault deletion.
func (store RootStore) RetireExpired(ctx context.Context, lifecycle RetirementClient, requireUnused func(context.Context, Binding) error) ([]Retirement, error) {
	if os.Geteuid() != 0 {
		return nil, ErrMaterial
	}
	return store.retireExpired(ctx, lifecycle, requireUnused)
}

func (store RootStore) retireExpired(ctx context.Context, lifecycle RetirementClient, requireUnused func(context.Context, Binding) error) ([]Retirement, error) {
	if store.Reader.Authority == nil || lifecycle == nil || requireUnused == nil || store.Bundles == nil || store.Target.CompartmentID == "" || store.Target.VaultID == "" {
		return nil, ErrMaterial
	}
	parts := strings.Split(store.Target.VaultID, ".")
	if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != "vault" || parts[2] != "oc1" {
		return nil, ErrMaterial
	}
	cell, ok := catalog.CellForOCIRegion(parts[3])
	if !ok {
		return nil, ErrMaterial
	}
	prefix := cell.Name() + "-function-worker-"
	names := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `[0-9a-f]{64}$`)
	ctx = ociclient.WithAuthority(ctx, store.guard)
	if err := store.guard(ctx); err != nil {
		return nil, err
	}
	var retired []Retirement
	var failures []error
	var page *string
	pages, ids := map[string]bool{}, map[string]bool{}
	for range 32 {
		response, err := lifecycle.ListSecrets(ociclient.RequestContext(ctx), ocivault.ListSecretsRequest{
			CompartmentId: new(store.Target.CompartmentID), VaultId: new(store.Target.VaultID), Limit: new(1000), Page: page,
			SortBy: ocivault.ListSecretsSortByName, SortOrder: ocivault.ListSecretsSortOrderAsc,
		})
		if err != nil || len(response.Items) > 1000 {
			return retired, errors.Join(append(failures, ErrMaterial)...)
		}
		for _, item := range response.Items {
			if item.SecretName == nil || !names.MatchString(*item.SecretName) {
				continue
			}
			if item.Id == nil || !retirementID.MatchString(*item.Id) || strings.Split(*item.Id, ".")[3] != parts[3] || ids[*item.Id] {
				failures = append(failures, ErrMaterial)
				continue
			}
			ids[*item.Id] = true
			result, err := store.retireSecret(ctx, lifecycle, requireUnused, *item.Id, *item.SecretName)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if result.SecretID != "" {
				retired = append(retired, result)
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			if err := store.guard(ctx); err != nil {
				return nil, err
			}
			return retired, errors.Join(failures...)
		}
		if pages[*response.OpcNextPage] {
			return retired, errors.Join(append(failures, ErrMaterial)...)
		}
		pages[*response.OpcNextPage] = true
		page = response.OpcNextPage
	}
	return retired, errors.Join(append(failures, ErrMaterial)...)
}

func (store RootStore) retirementMetadata(ctx context.Context, lifecycle interface {
	GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error)
}, id, name string) (ocivault.GetSecretResponse, error) {
	response, err := lifecycle.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: new(id)})
	secret := response.Secret
	if err != nil || secret.Id == nil || *secret.Id != id || secret.SecretName == nil || *secret.SecretName != name ||
		secret.VaultId == nil || *secret.VaultId != store.Target.VaultID || secret.CompartmentId == nil || *secret.CompartmentId != store.Target.CompartmentID ||
		secret.Description == nil || *secret.Description != "Admitted function task material" || response.Etag == nil || *response.Etag == "" {
		return ocivault.GetSecretResponse{}, ErrMaterial
	}
	return response, nil
}

func (store RootStore) retireSecret(ctx context.Context, lifecycle RetirementClient, requireUnused func(context.Context, Binding) error, id, name string) (Retirement, error) {
	metadata, err := store.retirementMetadata(ctx, lifecycle, id, name)
	if err != nil {
		return Retirement{}, err
	}
	if metadata.LifecycleState == ocivault.SecretLifecycleStatePendingDeletion {
		if metadata.TimeOfDeletion == nil || metadata.TimeOfDeletion.IsZero() {
			return Retirement{}, ErrMaterial
		}
		return Retirement{SecretID: id, Name: name, DeleteAt: metadata.TimeOfDeletion.Time}, nil
	}
	if metadata.LifecycleState != ocivault.SecretLifecycleStateActive {
		return Retirement{}, nil
	}
	if metadata.TimeOfDeletion != nil || metadata.CurrentVersionNumber == nil || *metadata.CurrentVersionNumber < 1 {
		return Retirement{}, ErrMaterial
	}
	ref := vaultsecret.Ref{Vault: store.Target.VaultID, Name: name}
	current, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), store.Bundles, ref)
	if err != nil || current.ID != id || current.Version != *metadata.CurrentVersionNumber {
		return Retirement{}, ErrMaterial
	}
	wire := []byte(current.Value())
	defer clear(wire)
	material, err := decodeMaterial(wire)
	if err != nil {
		return Retirement{}, ErrMaterial
	}
	defer func() {
		for _, value := range material.Files {
			clear(value)
		}
	}()
	expected, err := secretRef(store.Target.VaultID, material.Binding)
	if err != nil || expected != ref || material.ExpiresAt.IsZero() {
		return Retirement{}, ErrMaterial
	}
	if time.Now().Before(material.ExpiresAt) {
		return Retirement{}, nil
	}
	manifest := sum(wire)
	entry, err := store.Reader.Authority.ReadFunctionGrant(ctx, material.Binding.TaskID)
	if err == nil {
		grant, err := authority.DecodeFunctionGrant(entry)
		if err != nil || grant.Binding != bindingGrant(material.Binding, manifest) || grant.TenantID != material.TenantID || grant.FunctionID != material.FunctionID || grant.EnvelopeSHA256 != material.EnvelopeSHA256 {
			return Retirement{}, ErrMaterial
		}
	} else if !errors.Is(err, authority.ErrNotFound) {
		return Retirement{}, ErrMaterial
	}
	// A missing grant can be an interrupted publication; it still needs the
	// exact owned binding, expired bytes and independent task-absence checks.
	if err := requireUnused(ctx, material.Binding); err != nil {
		return Retirement{}, err
	}
	if err := store.guard(ctx); err != nil {
		return Retirement{}, err
	}
	after, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), store.Bundles, ref)
	if err != nil || after.ID != current.ID || after.Version != current.Version || after.Value() != current.Value() {
		return Retirement{}, ErrMaterial
	}
	latest, err := store.retirementMetadata(ctx, lifecycle, id, name)
	if err != nil || latest.LifecycleState != ocivault.SecretLifecycleStateActive || latest.TimeOfDeletion != nil || latest.CurrentVersionNumber == nil || *latest.CurrentVersionNumber != current.Version || *latest.Etag != *metadata.Etag {
		return Retirement{}, ErrMaterial
	}
	if err := requireUnused(ctx, material.Binding); err != nil {
		return Retirement{}, err
	}
	if err := store.guard(ctx); err != nil {
		return Retirement{}, err
	}
	// OCI requires at least 24 hours; the extra hour covers clock margin.
	deleteAt := time.Now().UTC().Add(25 * time.Hour).Truncate(time.Second)
	_, _ = lifecycle.ScheduleSecretDeletion(ociclient.RequestContext(ctx), ocivault.ScheduleSecretDeletionRequest{
		SecretId: new(id), IfMatch: latest.Etag,
		ScheduleSecretDeletionDetails: ocivault.ScheduleSecretDeletionDetails{TimeOfDeletion: &common.SDKTime{Time: deleteAt}},
		RequestMetadata:               common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())},
	})
	// Both success and a lost response need exact provider confirmation. Never
	// replay a destructive request merely because its reply was uncertain.
	pending, err := store.retirementMetadata(ctx, lifecycle, id, name)
	if err != nil || pending.LifecycleState != ocivault.SecretLifecycleStatePendingDeletion || pending.TimeOfDeletion == nil || !pending.TimeOfDeletion.Equal(deleteAt) {
		return Retirement{}, ErrMaterial
	}
	return Retirement{SecretID: id, Name: name, TaskID: material.Binding.TaskID, MaterialSHA256: manifest, ExpiresAt: material.ExpiresAt, DeleteAt: deleteAt}, nil
}
