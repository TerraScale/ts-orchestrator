package regionhost

import (
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/core"
)

const bootBackupPolicy = "ts-boot-weekly-4"

var errBootVolumeNotFound = errors.New("attached boot volume not found")

func (r *run) ensureBootBackup(inst *core.Instance) error {
	if inst == nil {
		return r.report("created", "boot-volume-backup-policy", bootBackupPolicy, "-")
	}
	volume, err := r.bootVolume(inst)
	if err != nil {
		return err
	}
	return r.ensureVolumeBootBackup(volume)
}

func (r *run) ensureVolumeBootBackup(volume string) error {
	policy, err := r.weeklyBootBackupPolicy()
	if err != nil {
		return err
	}
	assigned, err := r.bootBackupAssignment(volume)
	if err != nil {
		return err
	}
	if policy != "" && assigned == policy {
		return r.report("unchanged", "boot-volume-backup-policy", bootBackupPolicy, volume)
	}
	if assigned != "" {
		return fmt.Errorf("boot volume %s already has a different backup policy; refusing to replace it", volume)
	}
	if !r.dry {
		_, err := r.storage.CreateVolumeBackupPolicyAssignment(r.ctx, core.CreateVolumeBackupPolicyAssignmentRequest{
			CreateVolumeBackupPolicyAssignmentDetails: core.CreateVolumeBackupPolicyAssignmentDetails{
				AssetId: &volume, PolicyId: &policy,
			},
		})
		if err != nil {
			return err
		}
		assigned, err = r.bootBackupAssignment(volume)
		if err != nil {
			return err
		}
		if assigned != policy {
			return fmt.Errorf("boot volume %s backup policy did not match after assignment", volume)
		}
	}
	return r.report("created", "boot-volume-backup-policy", bootBackupPolicy, volume)
}

func (r *run) bootVolume(inst *core.Instance) (string, error) {
	req := core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: inst.AvailabilityDomain, CompartmentId: inst.CompartmentId, InstanceId: inst.Id,
	}
	var volumes []string
	for {
		page, err := r.compute.ListBootVolumeAttachments(r.ctx, req)
		if err != nil {
			return "", err
		}
		for _, attachment := range page.Items {
			if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateAttached {
				volumes = append(volumes, deref(attachment.BootVolumeId))
			}
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	if len(volumes) == 0 {
		return "", fmt.Errorf("%s: %w", deref(inst.DisplayName), errBootVolumeNotFound)
	}
	if len(volumes) != 1 || volumes[0] == "" {
		return "", fmt.Errorf("want one attached boot volume for %s, found %d", deref(inst.DisplayName), len(volumes))
	}
	return volumes[0], nil
}

func (r *run) weeklyBootBackupPolicy() (string, error) {
	req := core.ListVolumeBackupPoliciesRequest{CompartmentId: &r.compartment}
	var policies []core.VolumeBackupPolicy
	for {
		page, err := r.storage.ListVolumeBackupPolicies(r.ctx, req)
		if err != nil {
			return "", err
		}
		for _, policy := range page.Items {
			if deref(policy.DisplayName) == bootBackupPolicy {
				policies = append(policies, policy)
			}
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	if len(policies) > 1 {
		return "", fmt.Errorf("want one %s backup policy in the region compartment, found %d", bootBackupPolicy, len(policies))
	}
	if len(policies) == 0 {
		if r.dry {
			return "", r.report("created", "volume-backup-policy", bootBackupPolicy, "-")
		}
		created, err := r.storage.CreateVolumeBackupPolicy(r.ctx, core.CreateVolumeBackupPolicyRequest{
			CreateVolumeBackupPolicyDetails: core.CreateVolumeBackupPolicyDetails{
				CompartmentId: &r.compartment, DisplayName: new(bootBackupPolicy),
				Schedules: []core.VolumeBackupSchedule{{
					BackupType: core.VolumeBackupScheduleBackupTypeIncremental,
					Period:     core.VolumeBackupSchedulePeriodWeek, RetentionSeconds: new(28 * 24 * 60 * 60),
					OffsetType: core.VolumeBackupScheduleOffsetTypeStructured,
					DayOfWeek:  core.VolumeBackupScheduleDayOfWeekSunday, HourOfDay: new(0),
					TimeZone: core.VolumeBackupScheduleTimeZoneUtc,
				}},
			},
		})
		if err != nil {
			return "", err
		}
		policies = append(policies, created.VolumeBackupPolicy)
	}
	policy := policies[0]
	if deref(policy.Id) == "" {
		return "", fmt.Errorf("%s backup policy has no ID", bootBackupPolicy)
	}
	read, err := r.storage.GetVolumeBackupPolicy(r.ctx, core.GetVolumeBackupPolicyRequest{PolicyId: policy.Id})
	if err != nil {
		return "", err
	}
	policy = read.VolumeBackupPolicy
	if deref(policy.Id) == "" || deref(policy.DisplayName) != bootBackupPolicy || deref(policy.CompartmentId) != r.compartment || deref(policy.DestinationRegion) != "" || len(policy.Schedules) != 1 {
		return "", fmt.Errorf("%s backup policy must have one schedule in the region compartment without regional copies", bootBackupPolicy)
	}
	schedule := policy.Schedules[0]
	if schedule.Period != core.VolumeBackupSchedulePeriodWeek || schedule.BackupType != core.VolumeBackupScheduleBackupTypeIncremental || deref(schedule.RetentionSeconds) != 28*24*60*60 {
		return "", fmt.Errorf("%s backup policy must retain only weekly incremental backups for exactly four weeks", bootBackupPolicy)
	}
	return *policy.Id, nil
}

func (r *run) bootBackupAssignment(volume string) (string, error) {
	req := core.GetVolumeBackupPolicyAssetAssignmentRequest{AssetId: &volume}
	var assignments []core.VolumeBackupPolicyAssignment
	for {
		page, err := r.storage.GetVolumeBackupPolicyAssetAssignment(r.ctx, req)
		if err != nil {
			return "", err
		}
		assignments = append(assignments, page.Items...)
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	if len(assignments) == 0 {
		return "", nil
	}
	if len(assignments) != 1 || deref(assignments[0].AssetId) != volume || deref(assignments[0].PolicyId) == "" {
		return "", fmt.Errorf("invalid backup policy assignment for boot volume %s", volume)
	}
	return *assignments[0].PolicyId, nil
}
