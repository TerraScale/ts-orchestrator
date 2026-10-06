package volume

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

// ErrGone marks an OCI volume that OCI reports as not found.
var ErrGone = errors.New("OCI volume does not exist")

// CloudVolume is an OCI block volume as the reconciler sees it.
type CloudVolume struct {
	ID            string
	CompartmentID string
	Zone          string
	SizeGB        int64
	VPUsPerGB     int
	KMSKeyID      string
	// State is the OCI lifecycle state, for example AVAILABLE.
	State string
	ETag  string
	Tags  map[string]string
}

// CreateRequest is one OCI CreateVolume call. RetryToken makes a retried
// create return the volume of the first one.
type CreateRequest struct {
	CompartmentID string
	Zone          string
	DisplayName   string
	SizeGB        int64
	VPUsPerGB     int
	KMSKeyID      string
	Tags          map[string]string
	RetryToken    string
}

// BackupPolicy is an OCI volume backup policy. A managed volume's policy has
// one schedule: a daily incremental backup kept RetentionSeconds.
type BackupPolicy struct {
	ID        string
	Name      string
	Tags      map[string]string
	Schedules []Schedule
}

// Schedule is one schedule of a backup policy.
type Schedule struct {
	Type             string
	Period           string
	RetentionSeconds int
}

// Assignment is a volume's backup policy assignment.
type Assignment struct {
	ID       string
	PolicyID string
}

// Cloud is the OCI Block Volume API the reconciler uses.
type Cloud interface {
	ListVolumes(ctx context.Context, compartmentID, zone string) ([]CloudVolume, error)
	// GetVolume wraps ErrGone when OCI reports the volume not found.
	GetVolume(ctx context.Context, id string) (CloudVolume, error)
	CreateVolume(ctx context.Context, request CreateRequest) (CloudVolume, error)
	ResizeVolume(ctx context.Context, id, etag string, sizeGB int64) error
	SetVolumePerformance(ctx context.Context, id, etag string, vpusPerGB int) error
	ListBackupPolicies(ctx context.Context, compartmentID string) ([]BackupPolicy, error)
	CreateBackupPolicy(ctx context.Context, compartmentID string, policy BackupPolicy, retryToken string) (BackupPolicy, error)
	// PolicyAssignment returns the zero Assignment when none exists.
	PolicyAssignment(ctx context.Context, volumeID string) (Assignment, error)
	AssignPolicy(ctx context.Context, volumeID, policyID string) error
	DeleteAssignment(ctx context.Context, assignmentID string) error
}

const maxCloudItems = 4096

type sdkCloud struct{ storage core.BlockstorageClient }

// NewSDKCloud builds the Block Volume API on the shared rate-limited factory.
func NewSDKCloud(factory *ociclient.Factory) (Cloud, error) {
	storage, err := factory.Blockstorage()
	if err != nil {
		return nil, err
	}
	return sdkCloud{storage: storage}, nil
}

func deref[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}

func cloudVolume(volume core.Volume, etag string) CloudVolume {
	return CloudVolume{ID: deref(volume.Id), CompartmentID: deref(volume.CompartmentId), Zone: deref(volume.AvailabilityDomain),
		SizeGB: deref(volume.SizeInGBs), VPUsPerGB: int(deref(volume.VpusPerGB)), KMSKeyID: deref(volume.KmsKeyId),
		State: string(volume.LifecycleState), ETag: etag, Tags: maps.Clone(volume.FreeformTags)}
}

func (c sdkCloud) ListVolumes(ctx context.Context, compartmentID, zone string) ([]CloudVolume, error) {
	var volumes []CloudVolume
	request := core.ListVolumesRequest{CompartmentId: new(compartmentID), AvailabilityDomain: new(zone), Limit: new(100)}
	for {
		response, err := c.storage.ListVolumes(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("list OCI volumes: %w", err)
		}
		for _, volume := range response.Items {
			volumes = append(volumes, cloudVolume(volume, ""))
		}
		if len(volumes) > maxCloudItems {
			return nil, errors.New("OCI volume list exceeds its safety bound")
		}
		if deref(response.OpcNextPage) == "" {
			return volumes, nil
		}
		request.Page = response.OpcNextPage
	}
}

func (c sdkCloud) GetVolume(ctx context.Context, id string) (CloudVolume, error) {
	response, err := c.storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: new(id)})
	if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
		return CloudVolume{}, fmt.Errorf("get OCI volume %s: %w: %w", id, ErrGone, err)
	}
	if err != nil {
		return CloudVolume{}, fmt.Errorf("get OCI volume %s: %w", id, err)
	}
	return cloudVolume(response.Volume, deref(response.Etag)), nil
}

func (c sdkCloud) CreateVolume(ctx context.Context, request CreateRequest) (CloudVolume, error) {
	response, err := c.storage.CreateVolume(ctx, core.CreateVolumeRequest{
		CreateVolumeDetails: core.CreateVolumeDetails{
			CompartmentId: new(request.CompartmentID), AvailabilityDomain: new(request.Zone),
			DisplayName: new(request.DisplayName), SizeInGBs: new(request.SizeGB), VpusPerGB: new(int64(request.VPUsPerGB)),
			KmsKeyId: new(request.KMSKeyID), FreeformTags: maps.Clone(request.Tags),
		},
		OpcRetryToken: new(request.RetryToken),
	})
	if err != nil {
		return CloudVolume{}, fmt.Errorf("create OCI volume: %w", err)
	}
	return cloudVolume(response.Volume, deref(response.Etag)), nil
}

func (c sdkCloud) ResizeVolume(ctx context.Context, id, etag string, sizeGB int64) error {
	_, err := c.storage.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: new(id), IfMatch: new(etag),
		UpdateVolumeDetails: core.UpdateVolumeDetails{SizeInGBs: new(sizeGB)}})
	if err != nil {
		return fmt.Errorf("grow OCI volume %s: %w", id, err)
	}
	return nil
}

func (c sdkCloud) SetVolumePerformance(ctx context.Context, id, etag string, vpusPerGB int) error {
	_, err := c.storage.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: new(id), IfMatch: new(etag),
		UpdateVolumeDetails: core.UpdateVolumeDetails{VpusPerGB: new(int64(vpusPerGB))}})
	if err != nil {
		return fmt.Errorf("set OCI volume %s performance: %w", id, err)
	}
	return nil
}

func (c sdkCloud) ListBackupPolicies(ctx context.Context, compartmentID string) ([]BackupPolicy, error) {
	var policies []BackupPolicy
	request := core.ListVolumeBackupPoliciesRequest{CompartmentId: new(compartmentID), Limit: new(100)}
	for {
		response, err := c.storage.ListVolumeBackupPolicies(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("list OCI volume backup policies: %w", err)
		}
		for _, item := range response.Items {
			policy := BackupPolicy{ID: deref(item.Id), Name: deref(item.DisplayName), Tags: maps.Clone(item.FreeformTags)}
			for _, schedule := range item.Schedules {
				policy.Schedules = append(policy.Schedules, Schedule{Type: string(schedule.BackupType),
					Period: string(schedule.Period), RetentionSeconds: deref(schedule.RetentionSeconds)})
			}
			policies = append(policies, policy)
		}
		if len(policies) > maxCloudItems {
			return nil, errors.New("OCI volume backup policy list exceeds its safety bound")
		}
		if deref(response.OpcNextPage) == "" {
			return policies, nil
		}
		request.Page = response.OpcNextPage
	}
}

func (c sdkCloud) CreateBackupPolicy(ctx context.Context, compartmentID string, policy BackupPolicy, retryToken string) (BackupPolicy, error) {
	details := core.CreateVolumeBackupPolicyDetails{CompartmentId: new(compartmentID), DisplayName: new(policy.Name),
		FreeformTags: maps.Clone(policy.Tags)}
	for _, schedule := range policy.Schedules {
		details.Schedules = append(details.Schedules, core.VolumeBackupSchedule{
			BackupType: core.VolumeBackupScheduleBackupTypeEnum(schedule.Type), Period: core.VolumeBackupSchedulePeriodEnum(schedule.Period),
			RetentionSeconds: new(schedule.RetentionSeconds), OffsetType: core.VolumeBackupScheduleOffsetTypeStructured,
			HourOfDay: new(3), TimeZone: core.VolumeBackupScheduleTimeZoneUtc,
		})
	}
	response, err := c.storage.CreateVolumeBackupPolicy(ctx, core.CreateVolumeBackupPolicyRequest{
		CreateVolumeBackupPolicyDetails: details, OpcRetryToken: new(retryToken)})
	if err != nil {
		return BackupPolicy{}, fmt.Errorf("create OCI volume backup policy %s: %w", policy.Name, err)
	}
	policy.ID = deref(response.Id)
	return policy, nil
}

func (c sdkCloud) PolicyAssignment(ctx context.Context, volumeID string) (Assignment, error) {
	response, err := c.storage.GetVolumeBackupPolicyAssetAssignment(ctx,
		core.GetVolumeBackupPolicyAssetAssignmentRequest{AssetId: new(volumeID)})
	if err != nil {
		return Assignment{}, fmt.Errorf("get OCI volume %s backup policy assignment: %w", volumeID, err)
	}
	switch len(response.Items) {
	case 0:
		return Assignment{}, nil
	case 1:
		return Assignment{ID: deref(response.Items[0].Id), PolicyID: deref(response.Items[0].PolicyId)}, nil
	}
	return Assignment{}, fmt.Errorf("OCI volume %s has %d backup policy assignments", volumeID, len(response.Items))
}

func (c sdkCloud) AssignPolicy(ctx context.Context, volumeID, policyID string) error {
	_, err := c.storage.CreateVolumeBackupPolicyAssignment(ctx, core.CreateVolumeBackupPolicyAssignmentRequest{
		CreateVolumeBackupPolicyAssignmentDetails: core.CreateVolumeBackupPolicyAssignmentDetails{
			AssetId: new(volumeID), PolicyId: new(policyID)}})
	if err != nil {
		return fmt.Errorf("assign backup policy %s to OCI volume %s: %w", policyID, volumeID, err)
	}
	return nil
}

func (c sdkCloud) DeleteAssignment(ctx context.Context, assignmentID string) error {
	_, err := c.storage.DeleteVolumeBackupPolicyAssignment(ctx,
		core.DeleteVolumeBackupPolicyAssignmentRequest{PolicyAssignmentId: new(assignmentID)})
	if err != nil {
		return fmt.Errorf("delete OCI backup policy assignment %s: %w", assignmentID, err)
	}
	return nil
}
