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
	// VolumeGone persists and reuses a scope-verified TERMINATED observation.
	// OCI 404 can conceal an unreadable resource and is not deletion proof.
	VolumeGone(ctx context.Context, volumeID string) (bool, error)
	GetVolumeBackup(ctx context.Context, backupID string) (CloudVolumeBackup, error)
	DeleteVolumeBackup(ctx context.Context, backupID, etag string) error
}

// NewInstancePrincipalVolumeBackupProvider builds the region-pinned SDK
// backup seam with instance-principal authentication.
func NewInstancePrincipalVolumeBackupProvider(config RegionConfig, intent RegionIntent, journal *KVJournal) (VolumeBackupProvider, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	if journal == nil {
		return nil, errors.New("volume backups require the durable OCI journal")
	}
	provider, err := newSDKProvider(config, nil)
	if err != nil {
		return nil, err
	}
	provider.terminations = journal
	return provider, nil
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
// first. The planner only needs the newest backups (latest, the run since
// the last FULL, and the retained history), and pruning walks older ones into
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
	if provider.terminations == nil {
		return false, errors.New("volume deletion proof requires the durable OCI journal")
	}
	terminated, err := provider.terminations.volumeTerminated(ctx, provider.config, volumeID)
	if err != nil || terminated {
		return terminated, err
	}
	volume, err := provider.GetVolume(ctx, volumeID)
	if err != nil {
		return false, err
	}
	if volume.ID != volumeID || volume.CompartmentID != provider.config.CompartmentID ||
		volume.AvailabilityDomain != provider.config.AvailabilityDomain {
		return false, ErrForeignResource
	}
	if volume.LifecycleState != "TERMINATED" {
		return false, nil
	}
	if err := provider.terminations.RecordVolumeTermination(ctx, provider.config, volumeID); err != nil {
		return false, err
	}
	return true, nil
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

// BackupSchedule is one schedule of an OCI volume backup policy. DayOfWeek
// applies to ONE_WEEK schedules only.
type BackupSchedule struct {
	Type             string // FULL or INCREMENTAL
	Period           string // ONE_DAY or ONE_WEEK
	RetentionSeconds int
	OffsetType       string // STRUCTURED: HourOfDay and DayOfWeek place it
	HourOfDay        int
	DayOfWeek        string
	TimeZone         string // UTC
}

// CloudBackupPolicy is a normalized OCI volume backup policy.
type CloudBackupPolicy struct {
	ID           string
	DisplayName  string
	Schedules    []BackupSchedule
	FreeformTags map[string]string
}

// BackupPolicyProvider is the optional Provider seam for OCI volume backup
// policies: OCI itself then takes and expires the backups on schedule.
type BackupPolicyProvider interface {
	ListVolumeBackupPolicies(ctx context.Context) ([]CloudBackupPolicy, error)
	CreateVolumeBackupPolicy(ctx context.Context, name string, schedules []BackupSchedule, tags map[string]string, retryToken string) (CloudBackupPolicy, error)
	// VolumeBackupPolicyAssignment returns the policy assigned to the
	// volume, or "" when it has none.
	VolumeBackupPolicyAssignment(ctx context.Context, volumeID string) (string, error)
	AssignVolumeBackupPolicy(ctx context.Context, volumeID, policyID string) error
}

func (provider *sdkProvider) ListVolumeBackupPolicies(ctx context.Context) ([]CloudBackupPolicy, error) {
	var policies []CloudBackupPolicy
	var page *string
	for {
		response, err := provider.storage.ListVolumeBackupPolicies(ctx, core.ListVolumeBackupPoliciesRequest{
			CompartmentId: new(provider.config.CompartmentID), Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI volume backup policies: %w", err)
		}
		for _, policy := range response.Items {
			policies = append(policies, cloudBackupPolicy(policy))
			if len(policies) > maxProviderItems {
				return nil, errors.New("OCI volume backup policy list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return policies, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) CreateVolumeBackupPolicy(ctx context.Context, name string, schedules []BackupSchedule, tags map[string]string, retryToken string) (CloudBackupPolicy, error) {
	details := core.CreateVolumeBackupPolicyDetails{
		CompartmentId: new(provider.config.CompartmentID), DisplayName: new(name), FreeformTags: cloneStringMap(tags),
	}
	for _, schedule := range schedules {
		details.Schedules = append(details.Schedules, core.VolumeBackupSchedule{
			BackupType: core.VolumeBackupScheduleBackupTypeEnum(schedule.Type), Period: core.VolumeBackupSchedulePeriodEnum(schedule.Period),
			RetentionSeconds: new(schedule.RetentionSeconds), OffsetType: core.VolumeBackupScheduleOffsetTypeEnum(schedule.OffsetType),
			HourOfDay: new(schedule.HourOfDay), DayOfWeek: core.VolumeBackupScheduleDayOfWeekEnum(schedule.DayOfWeek),
			TimeZone: core.VolumeBackupScheduleTimeZoneEnum(schedule.TimeZone),
		})
	}
	response, err := provider.storage.CreateVolumeBackupPolicy(ctx, core.CreateVolumeBackupPolicyRequest{
		CreateVolumeBackupPolicyDetails: details, OpcRetryToken: new(retryToken),
	})
	if err != nil {
		return CloudBackupPolicy{}, fmt.Errorf("create OCI volume backup policy: %w", err)
	}
	return cloudBackupPolicy(response.VolumeBackupPolicy), nil
}

func (provider *sdkProvider) VolumeBackupPolicyAssignment(ctx context.Context, volumeID string) (string, error) {
	response, err := provider.storage.GetVolumeBackupPolicyAssetAssignment(ctx, core.GetVolumeBackupPolicyAssetAssignmentRequest{AssetId: new(volumeID)})
	if err != nil {
		return "", fmt.Errorf("get OCI volume backup policy assignment: %w", err)
	}
	switch len(response.Items) {
	case 0:
		return "", nil
	case 1:
		return stringValue(response.Items[0].PolicyId), nil
	}
	return "", errors.New("OCI volume has more than one backup policy assignment")
}

func (provider *sdkProvider) AssignVolumeBackupPolicy(ctx context.Context, volumeID, policyID string) error {
	if _, err := provider.storage.CreateVolumeBackupPolicyAssignment(ctx, core.CreateVolumeBackupPolicyAssignmentRequest{
		CreateVolumeBackupPolicyAssignmentDetails: core.CreateVolumeBackupPolicyAssignmentDetails{AssetId: new(volumeID), PolicyId: new(policyID)},
	}); err != nil {
		return fmt.Errorf("assign OCI volume backup policy: %w", err)
	}
	return nil
}

func cloudBackupPolicy(policy core.VolumeBackupPolicy) CloudBackupPolicy {
	cloud := CloudBackupPolicy{ID: stringValue(policy.Id), DisplayName: stringValue(policy.DisplayName), FreeformTags: cloneStringMap(policy.FreeformTags)}
	for _, schedule := range policy.Schedules {
		cloud.Schedules = append(cloud.Schedules, BackupSchedule{Type: string(schedule.BackupType), Period: string(schedule.Period),
			RetentionSeconds: intValue(schedule.RetentionSeconds), OffsetType: string(schedule.OffsetType), HourOfDay: intValue(schedule.HourOfDay),
			DayOfWeek: string(schedule.DayOfWeek), TimeZone: string(schedule.TimeZone)})
	}
	return cloud
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
