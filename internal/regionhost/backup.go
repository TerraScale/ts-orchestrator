package regionhost

import (
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/core"
)

const bootBackupPolicy = "silver"

func (r *run) ensureBootBackup(inst *core.Instance) error {
	if inst == nil {
		return r.report("created", "boot-volume-backup-policy", bootBackupPolicy, "-")
	}
	volume, err := r.bootVolume(inst)
	if err != nil {
		return err
	}
	policy, err := r.oracleBootBackupPolicy()
	if err != nil {
		return err
	}
	assigned, err := r.bootBackupAssignment(volume)
	if err != nil {
		return err
	}
	if assigned == policy {
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
	if len(volumes) != 1 || volumes[0] == "" {
		return "", fmt.Errorf("want one attached boot volume for %s, found %d", deref(inst.DisplayName), len(volumes))
	}
	return volumes[0], nil
}

func (r *run) oracleBootBackupPolicy() (string, error) {
	req := core.ListVolumeBackupPoliciesRequest{}
	var policies []core.VolumeBackupPolicy
	for {
		page, err := r.storage.ListVolumeBackupPolicies(r.ctx, req)
		if err != nil {
			return "", err
		}
		for _, policy := range page.Items {
			if deref(policy.DisplayName) == bootBackupPolicy && deref(policy.CompartmentId) == "" {
				policies = append(policies, policy)
			}
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	if len(policies) != 1 || deref(policies[0].Id) == "" {
		return "", fmt.Errorf("want one Oracle-defined %s backup policy, found %d", bootBackupPolicy, len(policies))
	}
	for _, schedule := range policies[0].Schedules {
		if schedule.Period == core.VolumeBackupSchedulePeriodWeek && deref(schedule.RetentionSeconds) >= 28*24*60*60 {
			return *policies[0].Id, nil
		}
	}
	return "", fmt.Errorf("Oracle-defined %s backup policy lacks weekly backups retained four weeks", bootBackupPolicy)
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
