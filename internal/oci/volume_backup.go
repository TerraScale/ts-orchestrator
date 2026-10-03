package oci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// CloudVolumeBackup is a normalized OCI block volume backup.
type CloudVolumeBackup struct {
	ID             string
	VolumeID       string
	CompartmentID  string
	DisplayName    string
	Type           string
	LifecycleState string
	ETag           string
	SizeGB         int64
	CreatedAt      time.Time
	FreeformTags   map[string]string
}

// VolumeBackupProvider is the narrow OCI Block Volume backup seam. It is
// pinned to the region config's compartment; ownership and retention policy
// live in internal/storage/backup.
type VolumeBackupProvider interface {
	CreateVolumeBackup(ctx context.Context, volumeID, displayName, backupType string, tags map[string]string, retryToken string) (CloudVolumeBackup, error)
	ListVolumeBackups(ctx context.Context, volumeID string) ([]CloudVolumeBackup, error)
	// ListCompartmentVolumeBackups lists every backup in the pinned
	// compartment, so backups whose source volume left placement stay
	// reachable for retention.
	ListCompartmentVolumeBackups(ctx context.Context) ([]CloudVolumeBackup, error)
	// VolumeGone reports whether the source volume no longer exists: OCI
	// answers 404 or reports it TERMINATED.
	VolumeGone(ctx context.Context, volumeID string) (bool, error)
	GetVolumeBackup(ctx context.Context, backupID string) (CloudVolumeBackup, error)
	DeleteVolumeBackup(ctx context.Context, backupID, etag string) error
}

// NewInstancePrincipalVolumeBackupProvider builds the region-pinned SDK
// backup seam with instance-principal authentication.
func NewInstancePrincipalVolumeBackupProvider(config RegionConfig, intent RegionIntent) (VolumeBackupProvider, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	return newSDKProvider(config, nil)
}

func (provider *sdkProvider) CreateVolumeBackup(ctx context.Context, volumeID, displayName, backupType string, tags map[string]string, retryToken string) (CloudVolumeBackup, error) {
	kind, ok := core.GetMappingCreateVolumeBackupDetailsTypeEnum(backupType)
	if !ok || volumeID == "" || retryToken == "" {
		return CloudVolumeBackup{}, errors.New("OCI volume backup request is incomplete")
	}
	response, err := provider.storage.CreateVolumeBackup(ctx, core.CreateVolumeBackupRequest{
		CreateVolumeBackupDetails: core.CreateVolumeBackupDetails{
			VolumeId: new(volumeID), DisplayName: new(displayName), Type: kind,
			FreeformTags: cloneStringMap(tags),
		},
		OpcRetryToken: new(retryToken),
	})
	if err != nil {
		return CloudVolumeBackup{}, fmt.Errorf("create OCI volume backup: %w", err)
	}
	return cloudVolumeBackup(response.VolumeBackup, stringValue(response.Etag)), nil
}

func (provider *sdkProvider) ListVolumeBackups(ctx context.Context, volumeID string) ([]CloudVolumeBackup, error) {
	if volumeID == "" {
		return nil, errors.New("OCI volume backup listing requires a volume ID")
	}
	return provider.newestVolumeBackups(ctx, volumeID, maxProviderItems)
}

// newestVolumeBackups lists at most bound backups of one volume, newest
// first. A volume's backup history grows without limit when pruning is off;
// the planner only needs the newest backups (latest, the run since the last
// FULL, and the newest Retain to keep), and pruning walks older ones into
// view on later passes. A long history therefore never stops scheduling.
func (provider *sdkProvider) newestVolumeBackups(ctx context.Context, volumeID string, bound int) ([]CloudVolumeBackup, error) {
	var backups []CloudVolumeBackup
	var page *string
	for {
		response, err := provider.storage.ListVolumeBackups(ctx, core.ListVolumeBackupsRequest{
			CompartmentId: new(provider.config.CompartmentID), VolumeId: new(volumeID), Page: page, Limit: new(100),
			SortBy: core.ListVolumeBackupsSortByTimecreated, SortOrder: core.ListVolumeBackupsSortOrderDesc,
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI volume backups: %w", err)
		}
		for _, backup := range response.Items {
			if len(backups) == bound {
				return backups, nil
			}
			backups = append(backups, cloudVolumeBackup(backup, ""))
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return backups, nil
		}
		page = response.OpcNextPage
	}
}

// maxCompartmentBackups bounds the compartment-wide backup listing.
const maxCompartmentBackups = 8 * maxProviderItems

func (provider *sdkProvider) ListCompartmentVolumeBackups(ctx context.Context) ([]CloudVolumeBackup, error) {
	return provider.listVolumeBackups(ctx, nil, maxCompartmentBackups)
}

func (provider *sdkProvider) listVolumeBackups(ctx context.Context, volumeID *string, bound int) ([]CloudVolumeBackup, error) {
	var backups []CloudVolumeBackup
	var page *string
	for {
		response, err := provider.storage.ListVolumeBackups(ctx, core.ListVolumeBackupsRequest{
			CompartmentId: new(provider.config.CompartmentID), VolumeId: volumeID, Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI volume backups: %w", err)
		}
		for _, backup := range response.Items {
			backups = append(backups, cloudVolumeBackup(backup, ""))
			if len(backups) > bound {
				return nil, errors.New("OCI volume backup list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return backups, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) VolumeGone(ctx context.Context, volumeID string) (bool, error) {
	if volumeID == "" {
		return false, errors.New("OCI volume lookup requires a volume ID")
	}
	volume, err := provider.GetVolume(ctx, volumeID)
	if isNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return volume.LifecycleState == "TERMINATED", nil
}

func (provider *sdkProvider) GetVolumeBackup(ctx context.Context, backupID string) (CloudVolumeBackup, error) {
	response, err := provider.storage.GetVolumeBackup(ctx, core.GetVolumeBackupRequest{VolumeBackupId: new(backupID)})
	if err != nil {
		return CloudVolumeBackup{}, fmt.Errorf("get OCI volume backup: %w", err)
	}
	backup := cloudVolumeBackup(response.VolumeBackup, stringValue(response.Etag))
	if backup.CompartmentID != provider.config.CompartmentID {
		return CloudVolumeBackup{}, ErrForeignResource
	}
	return backup, nil
}

func (provider *sdkProvider) DeleteVolumeBackup(ctx context.Context, backupID, etag string) error {
	if backupID == "" || etag == "" {
		return errors.New("OCI volume backup deletion requires an exact ID and ETag")
	}
	if _, err := provider.storage.DeleteVolumeBackup(ctx, core.DeleteVolumeBackupRequest{
		VolumeBackupId: new(backupID), IfMatch: new(etag),
	}); err != nil {
		return fmt.Errorf("delete OCI volume backup: %w", err)
	}
	return nil
}

func cloudVolumeBackup(backup core.VolumeBackup, etag string) CloudVolumeBackup {
	created := time.Time{}
	if backup.TimeCreated != nil {
		created = backup.TimeCreated.UTC()
	}
	return CloudVolumeBackup{
		ID: stringValue(backup.Id), VolumeID: stringValue(backup.VolumeId),
		CompartmentID: stringValue(backup.CompartmentId), DisplayName: stringValue(backup.DisplayName),
		Type: string(backup.Type), LifecycleState: string(backup.LifecycleState), ETag: etag,
		SizeGB: int64Value(backup.SizeInGBs), CreatedAt: created, FreeformTags: cloneStringMap(backup.FreeformTags),
	}
}
