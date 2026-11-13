package regionhost

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

const dataDevice = "/dev/oracleoci/oraclevdb"
const dataPolicy = "ts-host-data-daily-7d"

func volumeTags(host string) map[string]string {
	return map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-resource": "data-volume", "terrascale-host": host}
}

func (r *run) dataVolume(host string) (*core.Volume, error) {
	var found *core.Volume
	req := core.ListVolumesRequest{CompartmentId: &r.compartment}
	for {
		page, err := r.storage.ListVolumes(r.ctx, req)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Items {
			if v.LifecycleState == core.VolumeLifecycleStateTerminated || v.LifecycleState == core.VolumeLifecycleStateTerminating {
				continue
			}
			if !sameTags(v.FreeformTags, volumeTags(host)) {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("multiple data volumes for %s; refusing to choose", host)
			}
			found = &v
		}
		if page.OpcNextPage == nil {
			return found, nil
		}
		req.Page = page.OpcNextPage
	}
}

func sameTags(actual, want map[string]string) bool {
	for k, v := range want {
		if actual[k] != v {
			return false
		}
	}
	return true
}

func (r *run) ensureDataVolume(host, ad string, volume *core.Volume) (*core.Volume, bool, error) {
	policy, err := r.ensureDataPolicy()
	if err != nil {
		return nil, false, err
	}
	fresh := volume == nil
	verb := "unchanged"
	if fresh {
		verb = "created"
		volume = &core.Volume{Id: new("-"), DisplayName: new(host + "-data"), AvailabilityDomain: &ad}
		if !r.dry {
			created, err := r.storage.CreateVolume(r.ctx, core.CreateVolumeRequest{CreateVolumeDetails: core.CreateVolumeDetails{
				CompartmentId: &r.compartment, AvailabilityDomain: &ad, DisplayName: volume.DisplayName,
				SizeInGBs: new(int64(100)), VpusPerGB: new(int64(10)), FreeformTags: volumeTags(host), BackupPolicyId: &policy,
			}})
			if err != nil {
				return nil, false, err
			}
			volume = &created.Volume
		}
	}
	if !r.dry {
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			g, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
			return g.LifecycleState == core.VolumeLifecycleStateAvailable, err
		}); err != nil {
			return nil, false, err
		}
	}
	if err := r.report(verb, "data-volume", host+"-data", deref(volume.Id)); err != nil {
		return nil, false, err
	}
	if fresh {
		return volume, fresh, r.report("created", "backup-assignment", host+"-data", policy)
	}
	assignments, err := r.storage.GetVolumeBackupPolicyAssetAssignment(r.ctx, core.GetVolumeBackupPolicyAssetAssignmentRequest{AssetId: volume.Id})
	if err != nil {
		return nil, false, err
	}
	if slices.ContainsFunc(assignments.Items, func(a core.VolumeBackupPolicyAssignment) bool { return deref(a.PolicyId) == policy }) {
		return volume, false, r.report("unchanged", "backup-assignment", host+"-data", policy)
	}
	if !r.dry {
		_, err = r.storage.CreateVolumeBackupPolicyAssignment(r.ctx, core.CreateVolumeBackupPolicyAssignmentRequest{
			CreateVolumeBackupPolicyAssignmentDetails: core.CreateVolumeBackupPolicyAssignmentDetails{AssetId: volume.Id, PolicyId: &policy}})
		if err != nil {
			return nil, false, err
		}
	}
	return volume, false, r.report("updated", "backup-assignment", host+"-data", policy)
}

func (r *run) ensureDataPolicy() (string, error) {
	want := []core.VolumeBackupSchedule{{Period: core.VolumeBackupSchedulePeriodDay, BackupType: core.VolumeBackupScheduleBackupTypeIncremental,
		RetentionSeconds: new(7 * 24 * 60 * 60), OffsetType: core.VolumeBackupScheduleOffsetTypeStructured,
		HourOfDay: new(2), TimeZone: core.VolumeBackupScheduleTimeZoneUtc}}
	var found *core.VolumeBackupPolicy
	req := core.ListVolumeBackupPoliciesRequest{CompartmentId: &r.compartment}
	for {
		page, err := r.storage.ListVolumeBackupPolicies(r.ctx, req)
		if err != nil {
			return "", err
		}
		for _, p := range page.Items {
			if deref(p.DisplayName) == dataPolicy && p.FreeformTags["terrascale-managed-by"] == "ts-orchestrator" {
				if found != nil {
					return "", errors.New("multiple managed data backup policies")
				}
				found = &p
			}
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	verb, id := "created", "-"
	if found == nil {
		if !r.dry {
			p, err := r.storage.CreateVolumeBackupPolicy(r.ctx, core.CreateVolumeBackupPolicyRequest{CreateVolumeBackupPolicyDetails: core.CreateVolumeBackupPolicyDetails{
				CompartmentId: &r.compartment, DisplayName: new(dataPolicy), Schedules: want,
				FreeformTags: map[string]string{"terrascale-managed-by": "ts-orchestrator"},
			}})
			if err != nil {
				return "", err
			}
			id = deref(p.Id)
		}
	} else {
		verb, id = "unchanged", deref(found.Id)
		if len(found.Schedules) != 1 || found.Schedules[0].Period != want[0].Period || found.Schedules[0].BackupType != want[0].BackupType ||
			deref(found.Schedules[0].RetentionSeconds) != deref(want[0].RetentionSeconds) {
			verb = "updated"
			if !r.dry {
				_, err := r.storage.UpdateVolumeBackupPolicy(r.ctx, core.UpdateVolumeBackupPolicyRequest{PolicyId: found.Id,
					UpdateVolumeBackupPolicyDetails: core.UpdateVolumeBackupPolicyDetails{Schedules: want}})
				if err != nil {
					return "", err
				}
			}
		}
	}
	return id, r.report(verb, "backup-policy", dataPolicy, id)
}

func (r *run) attachDataVolume(host string, instance *core.Instance, volume *core.Volume) error {
	if r.dry && deref(volume.Id) == "-" {
		return r.report("created", "data-attachment", host, dataDevice)
	}
	attachment, err := r.dataAttachment(instance, volume)
	if err != nil {
		return err
	}
	verb := "unchanged"
	if attachment == nil {
		verb = "created"
		if !r.dry {
			a, err := r.compute.AttachVolume(r.ctx, core.AttachVolumeRequest{AttachVolumeDetails: core.AttachParavirtualizedVolumeDetails{
				InstanceId: instance.Id, VolumeId: volume.Id, Device: new(dataDevice), IsReadOnly: new(false), IsShareable: new(false),
			}})
			if err != nil {
				return err
			}
			attachment = a.VolumeAttachment
		}
	}
	if !r.dry {
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			g, err := r.compute.GetVolumeAttachment(r.ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: attachment.GetId()})
			return g.VolumeAttachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateAttached, err
		}); err != nil {
			return err
		}
	}
	return r.report(verb, "data-attachment", host, dataDevice)
}

func (r *run) dataAttachment(instance *core.Instance, volume *core.Volume) (core.VolumeAttachment, error) {
	req := core.ListVolumeAttachmentsRequest{CompartmentId: &r.compartment, VolumeId: volume.Id}
	var attachment core.VolumeAttachment
	for {
		page, err := r.compute.ListVolumeAttachments(r.ctx, req)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			if a.GetLifecycleState() == core.VolumeAttachmentLifecycleStateDetached {
				continue
			}
			_, pv := a.(core.ParavirtualizedVolumeAttachment)
			if instance == nil || deref(a.GetInstanceId()) != deref(instance.Id) || !pv || deref(a.GetDevice()) != dataDevice || deref(a.GetIsReadOnly()) || deref(a.GetIsShareable()) {
				return nil, fmt.Errorf("data volume %s has a conflicting attachment", deref(volume.DisplayName))
			}
			if attachment != nil {
				return nil, errors.New("multiple live data volume attachments")
			}
			attachment = a
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	return attachment, nil
}

func (r *run) deleteDataVolume(host string, volume *core.Volume) error {
	if !r.dry {
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			a, err := r.dataAttachment(nil, volume)
			return a == nil && err == nil, err
		}); err != nil {
			return err
		}
		if _, err := r.storage.DeleteVolume(r.ctx, core.DeleteVolumeRequest{VolumeId: volume.Id}); err != nil {
			return err
		}
	}
	return r.report("deleted", "data-volume", host+"-data", deref(volume.Id))
}
