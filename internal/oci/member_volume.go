package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Data volumes of C# TerraBase members. Member gru-1-db-N keeps its data on
// the block volume gru-1-db-N-data, created once and attached at
// MemberVolumeDevice to whichever instance holds the member's name, so the
// data survives replacement of the host. This is the operator and autoscaler
// path: it has no controller journal or authority fence, so a volume is
// identified by its static name and the fleet's scope tags, and every effect
// is idempotent and fails closed:
//   - a volume is created only while no active volume of that name exists, in any
//     state; a terminated one holds instead of being replaced by an empty one;
//   - Ensure attaches it only while it has no live attachment, and never
//     detaches it from another instance: OCI detaches it when that instance
//     terminates;
//   - it only grows, under its ETag;
//   - after drain, explicit Retire detaches and retains it with retirement
//     tags; a new member using the name gets a fresh volume and create token;
//   - it carries the cell's OCI backup policy, MemberBackupSchedules, before
//     it is attached, so OCI backs it up without any process of ours.

const (
	// MemberVolumeDevice is the consistent device path of a member's data
	// volume: the first data volume LUN, which a member host leaves free.
	MemberVolumeDevice = "/dev/oracleoci/oraclevdb"
	// maxMemberVolumeGB is OCI's block volume size limit.
	maxMemberVolumeGB int64 = 32768

	resourceMemberBackupPolicy = "member-data-backup-policy"
	resourceMemberRetiredData  = "member-data-retired"
	tagRetiredNode             = "terrascale-retired-node"
	tagRetiredAt               = "terrascale-retired-at"
	tagRetiredInstance         = "terrascale-retired-instance"
)

// MemberBackupSchedules are the OCI backups of every member data volume: a
// daily incremental backup kept 7 days and a weekly full backup kept 4
// weeks. SQLite's WAL makes these crash-consistent volume backups
// restorable; terrabase restore-check proves one.
var MemberBackupSchedules = []BackupSchedule{
	{Type: "INCREMENTAL", Period: "ONE_DAY", RetentionSeconds: 7 * 24 * 3600, OffsetType: "STRUCTURED", HourOfDay: 3, TimeZone: "UTC"},
	{Type: "FULL", Period: "ONE_WEEK", RetentionSeconds: 28 * 24 * 3600, OffsetType: "STRUCTURED", HourOfDay: 4, DayOfWeek: "SUNDAY", TimeZone: "UTC"},
}

// MemberVolumeConfig is the region scope of a cell's member data volumes.
// Volumes and member instances share the compartment and availability domain.
type MemberVolumeConfig struct {
	Region             Region // catalog cell code, for example GRU
	CompartmentID      string
	AvailabilityDomain string
	VPUsPerGB          uint32
}

// MemberVolumes creates, attaches and grows the data volumes of one cell's
// C# TerraBase members.
type MemberVolumes struct {
	fleet *fleet
	// restoreSettle bounds the wait for a volume restored from a backup.
	restoreSettle time.Duration
}

// NewOperatorMemberVolumes uses the operator's OCI config DEFAULT profile,
// like the other operator commands and the cell autoscaler.
func NewOperatorMemberVolumes(config MemberVolumeConfig) (*MemberVolumes, error) {
	regionConfig, err := config.regionConfig()
	if err != nil {
		return nil, err
	}
	ociRegion, _ := config.Region.OCIRegion()
	factory, err := ociclient.OperatorConfig(ociRegion)
	if err != nil {
		return nil, err
	}
	provider, err := sdkProviderFrom(factory, regionConfig, nil)
	if err != nil {
		return nil, err
	}
	return &MemberVolumes{fleet: memberVolumeFleet(regionConfig, memberVolumeProvider{provider}), restoreSettle: restoreSettleTimeout}, nil
}

func newMemberVolumes(config MemberVolumeConfig, provider Provider) (*MemberVolumes, error) {
	regionConfig, err := config.regionConfig()
	if err != nil {
		return nil, err
	}
	return &MemberVolumes{fleet: memberVolumeFleet(regionConfig, provider), restoreSettle: restoreSettleTimeout}, nil
}

// memberVolumeFleet reuses the fleet's volume and attachment reads. It has no
// journal, fencer or image verifier, so only the member volume methods below
// may use it.
func memberVolumeFleet(config RegionConfig, provider Provider) *fleet {
	return &fleet{config: config, provider: provider, now: time.Now, attachmentSettle: attachmentSettleTimeout}
}

// regionConfig scopes the reused fleet reads and tags to the cell: names are
// static, so the volumes belong to the cell and carry generation 1.
func (config MemberVolumeConfig) regionConfig() (RegionConfig, error) {
	ociRegion, err := config.Region.OCIRegion()
	if err != nil {
		return RegionConfig{}, err
	}
	cell, err := naming.RegionCell(string(config.Region)).Name()
	if err != nil {
		return RegionConfig{}, err
	}
	if config.CompartmentID == "" || config.AvailabilityDomain == "" || config.VPUsPerGB%10 != 0 || config.VPUsPerGB > 120 {
		return RegionConfig{}, errors.New("member volumes need a compartment, an availability domain and a VPUs per GB tier of 0 to 120 in steps of 10")
	}
	return RegionConfig{
		Region: config.Region, Generation: 1, Endpoint: "https://iaas." + ociRegion + ".oraclecloud.com",
		CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		DataVolumeVPUsPerGB: config.VPUsPerGB, MaxDataVolumeGB: maxMemberVolumeGB, Owner: cell,
	}, nil
}

// memberVolumeProvider reads an instance as OCI reports it. The fleet
// provider's GetInstance also checks the instance against the fleet's launch
// pins, which member hosts launched by other paths do not share.
type memberVolumeProvider struct{ *sdkProvider }

func (provider memberVolumeProvider) GetInstance(ctx context.Context, id string) (CloudInstance, error) {
	response, err := provider.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(id)})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("get OCI instance: %w", err)
	}
	return cloudInstance(response.Instance, stringValue(response.Etag)), nil
}

// MemberVolumeRequest names a member's data volume and the instance to
// attach it to.
type MemberVolumeRequest struct {
	Member     string // for example gru-1-db-1
	InstanceID string // the running instance named Member
	SizeGB     int64  // size of a volume created now
	// VolumeID is the member's recorded volume, for example plan.json
	// resource_ids.data_volumes. Once a caller has recorded it, Ensure never
	// creates a volume: a missing recorded volume is lost data to restore,
	// not a new member. Empty only for a member's first Ensure.
	VolumeID string
}

// Ensure creates the member's data volume when it has none and none is
// recorded, waits until it is available and attaches it read-write at
// MemberVolumeDevice to the instance. It is idempotent: an existing volume is
// reused at its current size and an existing attachment to the instance is
// returned. After a host replacement it attaches the same volume to the new
// instance once OCI has detached it from the old one; until then it fails
// with ErrRetainedVolumeInUse. Callers record the returned VolumeID.
func (v *MemberVolumes) Ensure(ctx context.Context, request MemberVolumeRequest) (Attachment, error) {
	member, instanceID, sizeGB := request.Member, request.InstanceID, request.SizeGB
	name, err := v.volumeName(member)
	if err != nil {
		return Attachment{}, err
	}
	if sizeGB < minRetainedVolumeSizeGB || sizeGB > maxMemberVolumeGB {
		return Attachment{}, fmt.Errorf("member data volume size must be %d to %d GB", minRetainedVolumeSizeGB, maxMemberVolumeGB)
	}
	f := v.fleet
	instance, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return Attachment{}, err
	}
	if instance.ID != instanceID || instance.DisplayName != member ||
		instance.CompartmentID != f.config.CompartmentID || instance.AvailabilityDomain != f.config.AvailabilityDomain {
		return Attachment{}, fmt.Errorf("%w: instance %s is not member %s in the cell's compartment and availability domain", ErrForeignResource, instanceID, member)
	}
	if instance.LifecycleState != "RUNNING" {
		return Attachment{}, fmt.Errorf("instance %s is %s; its data volume attaches once it runs", instanceID, instance.LifecycleState)
	}
	if instance.ConsistentVolumeNamingEnabled == nil || !*instance.ConsistentVolumeNamingEnabled {
		return Attachment{}, fmt.Errorf("instance %s has no consistent volume naming for %s", instanceID, MemberVolumeDevice)
	}
	volume, err := v.ensureVolume(ctx, name, sizeGB, request.VolumeID)
	if err != nil {
		return Attachment{}, err
	}
	if err := v.ensureBackupPolicy(ctx, volume.ID); err != nil {
		return Attachment{}, fmt.Errorf("data volume %s backup policy: %w", name, err)
	}
	return v.attach(ctx, name, volume.ID, instanceID, MemberVolumeDevice)
}

// Resize requires the member's exact recorded volume ID and grows it online
// to sizeGB. A size at or below the
// current one changes nothing. The member's host grows the filesystem once
// it sees the larger device.
func (v *MemberVolumes) Resize(ctx context.Context, member, recordedID string, sizeGB int64) (RetainedVolume, error) {
	name, err := v.volumeName(member)
	if err != nil {
		return RetainedVolume{}, err
	}
	if sizeGB < minRetainedVolumeSizeGB || sizeGB > maxMemberVolumeGB {
		return RetainedVolume{}, fmt.Errorf("member data volume size must be %d to %d GB", minRetainedVolumeSizeGB, maxMemberVolumeGB)
	}
	if recordedID == "" {
		return RetainedVolume{}, errors.New("member data volume resize requires its recorded volume ID")
	}
	f := v.fleet
	updater, ok := f.provider.(VolumeUpdater)
	if !ok {
		return RetainedVolume{}, ErrVolumeResizeUnsupported
	}
	cloud, identity, found, err := f.findVolumeByCreateKey(ctx, memberVolumeCreateKey(name))
	if err != nil {
		return RetainedVolume{}, err
	}
	if !found {
		return RetainedVolume{}, fmt.Errorf("member %s has no data volume %s", member, name)
	}
	if cloud.ID != recordedID {
		return RetainedVolume{}, fmt.Errorf("%w: data volume %s is %s, not the recorded %s", ErrForeignResource, name, cloud.ID, recordedID)
	}
	if cloud.SizeGB >= sizeGB {
		return retainedVolumeFromCloud(cloud, identity), nil
	}
	if cloud.LifecycleState != "AVAILABLE" {
		return RetainedVolume{}, fmt.Errorf("data volume %s is %s; it grows only while AVAILABLE", name, cloud.LifecycleState)
	}
	if cloud.ETag == "" {
		return RetainedVolume{}, ErrStaleETag
	}
	tags := maps.Clone(cloud.FreeformTags)
	tags[tagVolumeSize] = fmt.Sprint(sizeGB)
	_, updateErr := updater.UpdateVolumeSize(ctx, cloud.ID, cloud.ETag, sizeGB, tags)
	grown, err := v.awaitVolume(ctx, cloud.ID, sizeGB)
	if err != nil {
		return RetainedVolume{}, errors.Join(ErrOutcomeUnknown, updateErr, err)
	}
	_, identity, err = f.reobserveVolume(ctx, grown.ID)
	if err != nil {
		return RetainedVolume{}, err
	}
	return retainedVolumeFromCloud(grown, identity), nil
}

func (v *MemberVolumes) volumeName(member string) (string, error) {
	if !v.fleet.memberName(member, false) {
		return "", fmt.Errorf("%q is not a member name of this cell", member)
	}
	return naming.Data(member)
}

func (v *MemberVolumes) ensureVolume(ctx context.Context, name string, sizeGB int64, recorded string) (CloudVolume, error) {
	f := v.fleet
	cloud, _, found, err := f.findVolumeByCreateKey(ctx, memberVolumeCreateKey(name))
	if err != nil {
		return CloudVolume{}, err
	}
	switch {
	case recorded != "" && !found:
		return CloudVolume{}, fmt.Errorf("recorded data volume %s (%s) is missing; restore it from a backup instead of creating an empty one", name, recorded)
	case recorded != "" && cloud.ID != recorded:
		return CloudVolume{}, fmt.Errorf("%w: data volume %s is %s, not the recorded %s", ErrForeignResource, name, cloud.ID, recorded)
	case !found:
		request := VolumeCreateRequest{Name: name, CreateKey: memberVolumeCreateKey(name), SizeGB: sizeGB, AvailabilityDomain: f.config.AvailabilityDomain}
		// Stable within one incarnation, fresh after retirement: a lost create
		// response replays, but a reused name cannot replay a retired volume.
		retry, err := v.memberCreateToken(ctx, name)
		if err != nil {
			return CloudVolume{}, err
		}
		_, createErr := f.provider.CreateVolume(ctx, request, volumeTags(f.config, request), retry)
		cloud, _, found, err = f.findVolumeByCreateKey(ctx, memberVolumeCreateKey(name))
		if err != nil || !found {
			return CloudVolume{}, errors.Join(ErrOutcomeUnknown, createErr, err,
				fmt.Errorf("data volume %s was not observed after its create", name))
		}
	}
	return v.awaitVolume(ctx, cloud.ID, 0)
}

func (v *MemberVolumes) memberCreateToken(ctx context.Context, name string) (string, error) {
	f := v.fleet
	volumes, err := f.provider.ListVolumes(ctx, f.config.CompartmentID, f.config.AvailabilityDomain)
	if err != nil {
		return "", err
	}
	var retired []string
	for _, listed := range volumes {
		if listed.FreeformTags[tagRetiredNode]+"-data" != name {
			continue
		}
		volume, _, err := f.reobserveVolumeResource(ctx, listed.ID, resourceMemberRetiredData)
		if err != nil {
			return "", err
		}
		if _, err := time.Parse(time.RFC3339Nano, volume.FreeformTags[tagRetiredAt]); err != nil ||
			volume.FreeformTags[tagCreateKey] != retiredMemberCreateKey(volume.ID) || volume.FreeformTags[tagRetiredInstance] == "" {
			return "", fmt.Errorf("%w: volume %s has incomplete retirement tags", ErrForeignResource, volume.ID)
		}
		retired = append(retired, volume.ID)
	}
	slices.Sort(retired)
	return retryToken(strings.Join(append([]string{f.config.Owner, string(f.config.Region), name}, retired...), ":")), nil
}

func memberVolumeCreateKey(name string) string { return entityid.Derive("member-volume", name) }

func retiredMemberCreateKey(volumeID string) string {
	return entityid.Derive("retired-volume", volumeID)
}

// Retire is called after the member has drained and before terminating its
// host. It detaches only the exact recorded volume from that member instance,
// then tags and retains it. Retries preserve the original retirement time;
// Ensure never adopts a retired volume. SizeGB is unused.
func (v *MemberVolumes) Retire(ctx context.Context, request MemberVolumeRequest) (RetainedVolume, error) {
	name, err := v.volumeName(request.Member)
	if err != nil {
		return RetainedVolume{}, err
	}
	if request.VolumeID == "" || request.InstanceID == "" {
		return RetainedVolume{}, errors.New("member retirement requires its recorded volume and instance IDs")
	}
	f := v.fleet
	volume, identity, err := f.reobserveVolumeResource(ctx, request.VolumeID, resourceMemberData, resourceMemberRetiredData)
	if err != nil {
		return RetainedVolume{}, err
	}
	retired := volume.FreeformTags[tagResource] == resourceMemberRetiredData
	if retired {
		if _, err := time.Parse(time.RFC3339Nano, volume.FreeformTags[tagRetiredAt]); err != nil ||
			identity.CreateKey != retiredMemberCreateKey(request.VolumeID) || volume.FreeformTags[tagRetiredNode] != request.Member ||
			volume.FreeformTags[tagRetiredInstance] != request.InstanceID {
			return RetainedVolume{}, fmt.Errorf("%w: recorded volume %s was retired for a different member or instance", ErrForeignResource, request.VolumeID)
		}
	} else if identity.CreateKey != memberVolumeCreateKey(name) || volume.LifecycleState != "AVAILABLE" || volume.ETag == "" {
		return RetainedVolume{}, fmt.Errorf("%w: recorded volume %s is not available data of member %s", ErrForeignResource, request.VolumeID, request.Member)
	}
	updater, ok := f.provider.(VolumeUpdater)
	if !ok && !retired {
		return RetainedVolume{}, errors.New("OCI provider cannot tag retired member volumes")
	}
	records, err := f.findVolumeAttachments(ctx, request.VolumeID)
	if err != nil {
		return RetainedVolume{}, err
	}
	live := liveAttachments(records)
	if len(live) > 1 {
		return RetainedVolume{}, fmt.Errorf("%w: recorded volume %s has multiple live attachments", ErrAttachmentRecoveryHold, request.VolumeID)
	}
	if len(live) == 1 {
		if retired || live[0].InstanceID != request.InstanceID {
			return RetainedVolume{}, ErrRetainedVolumeInUse
		}
		instance, err := f.provider.GetInstance(ctx, request.InstanceID)
		if err != nil {
			return RetainedVolume{}, err
		}
		if instance.ID != request.InstanceID || instance.DisplayName != request.Member || instance.CompartmentID != f.config.CompartmentID ||
			instance.AvailabilityDomain != f.config.AvailabilityDomain {
			return RetainedVolume{}, ErrForeignResource
		}
		attachment, err := f.provider.GetVolumeAttachment(ctx, live[0].ID)
		if err != nil {
			return RetainedVolume{}, err
		}
		if attachment.ID != live[0].ID || attachment.VolumeID != request.VolumeID || attachment.InstanceID != request.InstanceID || attachment.ETag == "" {
			return RetainedVolume{}, ErrForeignResource
		}
		var detachErr error
		if attachment.LifecycleState != attachmentStateDetaching && attachment.LifecycleState != attachmentStateDetached {
			detachErr = f.provider.DetachVolume(ctx, attachment.ID, attachment.ETag)
		}
		settled, err := f.awaitDetached(ctx, attachment.ID)
		if err != nil || !settled {
			return RetainedVolume{}, errors.Join(ErrOutcomeUnknown, detachErr, err, errors.New("member volume retirement detach has not settled"))
		}
	}
	if retired {
		return retainedVolumeFromCloud(volume, identity), nil
	}
	records, err = f.findVolumeAttachments(ctx, request.VolumeID)
	if err != nil {
		return RetainedVolume{}, err
	}
	if len(liveAttachments(records)) != 0 {
		return RetainedVolume{}, ErrRetainedVolumeInUse
	}
	// Re-read the ETag after detach. An interrupted tag write retries the
	// same exact volume; its retired create key frees the static name.
	volume, identity, err = f.reobserveVolume(ctx, request.VolumeID)
	if err != nil || identity.CreateKey != memberVolumeCreateKey(name) || volume.ETag == "" {
		return RetainedVolume{}, errors.Join(err, ErrForeignResource)
	}
	tags := maps.Clone(volume.FreeformTags)
	tags[tagResource], tags[tagCreateKey] = resourceMemberRetiredData, retiredMemberCreateKey(volume.ID)
	tags[tagRetiredNode], tags[tagRetiredInstance], tags[tagRetiredAt] = request.Member, request.InstanceID, f.now().UTC().Format(time.RFC3339Nano)
	_, updateErr := updater.UpdateVolumeSize(ctx, volume.ID, volume.ETag, volume.SizeGB, tags)
	confirmed, confirmedIdentity, err := f.reobserveVolumeResource(ctx, request.VolumeID, resourceMemberRetiredData)
	if err != nil || confirmed.FreeformTags[tagRetiredNode] != request.Member || confirmed.FreeformTags[tagRetiredInstance] != request.InstanceID ||
		confirmed.FreeformTags[tagRetiredAt] != tags[tagRetiredAt] || confirmedIdentity.CreateKey != tags[tagCreateKey] {
		return RetainedVolume{}, errors.Join(ErrOutcomeUnknown, updateErr, err, errors.New("member volume retirement tags were not observed"))
	}
	return retainedVolumeFromCloud(confirmed, confirmedIdentity), nil
}

// awaitVolume waits, bounded by the fleet's attachment settle time, until the
// volume is AVAILABLE with at least sizeGB. A volume in any state other than
// PROVISIONING, RESTORING or AVAILABLE fails: a terminated volume's data is
// gone, and an empty replacement would hide that.
func (v *MemberVolumes) awaitVolume(ctx context.Context, volumeID string, sizeGB int64) (CloudVolume, error) {
	f := v.fleet
	settleCtx, cancel := context.WithTimeout(ctx, f.attachmentSettle)
	defer cancel()
	for {
		cloud, _, err := f.reobserveVolume(settleCtx, volumeID)
		if err != nil {
			return CloudVolume{}, err
		}
		switch cloud.LifecycleState {
		case "AVAILABLE":
			if cloud.SizeGB >= sizeGB {
				return cloud, nil
			}
		case "PROVISIONING", "RESTORING":
		default:
			return CloudVolume{}, fmt.Errorf("data volume %s is %s; restore it from a backup or remove it before a new one is created", volumeID, cloud.LifecycleState)
		}
		select {
		case <-settleCtx.Done():
			return CloudVolume{}, fmt.Errorf("data volume %s is %s at %d GB: %w", volumeID, cloud.LifecycleState, cloud.SizeGB, settleCtx.Err())
		case <-time.After(attachmentSettlePoll):
		}
	}
}

func (v *MemberVolumes) attach(ctx context.Context, name, volumeID, instanceID, device string) (Attachment, error) {
	f := v.fleet
	records, err := f.findVolumeAttachments(ctx, volumeID)
	if err != nil {
		return Attachment{}, err
	}
	live := liveAttachments(records)
	switch {
	case len(live) > 1:
		return Attachment{}, fmt.Errorf("%w: data volume %s has %d live attachments", ErrAttachmentRecoveryHold, name, len(live))
	case len(live) == 1 && live[0].InstanceID != instanceID:
		return Attachment{}, fmt.Errorf("%w: data volume %s is %s on instance %s; it moves only after OCI detaches it from that instance",
			ErrRetainedVolumeInUse, name, live[0].LifecycleState, live[0].InstanceID)
	case len(live) == 1:
		return f.awaitAttached(ctx, live[0].ID, volumeID, instanceID, device)
	}
	devices, err := f.provider.ListInstanceDevices(ctx, instanceID)
	if err != nil {
		return Attachment{}, fmt.Errorf("list OCI instance devices: %w", err)
	}
	if !slices.ContainsFunc(devices, func(candidate CloudDevice) bool {
		return candidate.Name == device && candidate.IsAvailable != nil && *candidate.IsAvailable
	}) {
		return Attachment{}, fmt.Errorf("instance %s has no free %s for data volume %s", instanceID, device, name)
	}
	_, attachErr := f.provider.AttachVolume(ctx, CloudVolumeAttachRequest{
		VolumeID: volumeID, InstanceID: instanceID,
		RetryToken: retryToken(strings.Join([]string{f.config.Owner, string(f.config.Region), name, volumeID, instanceID}, ":")),
		Device:     device, IsReadOnly: retainedVolumeReadOnly, IsShareable: retainedVolumeShareable,
		IsPvEncryptionInTransitEnabled: retainedVolumeEncryptionInTransit,
	})
	records, err = f.findVolumeAttachments(ctx, volumeID)
	live = liveAttachments(records)
	if err != nil || len(live) != 1 || live[0].InstanceID != instanceID {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, attachErr, err,
			fmt.Errorf("data volume %s attachment to %s was not observed", name, instanceID))
	}
	return f.awaitAttached(ctx, live[0].ID, volumeID, instanceID, device)
}

// ensureBackupPolicy assigns the cell's member backup policy, creating it on
// first use, to volumeID. A volume that already carries another policy, or a
// policy of that name whose schedules or tags differ, holds instead of being
// changed.
func (v *MemberVolumes) ensureBackupPolicy(ctx context.Context, volumeID string) error {
	f := v.fleet
	policies, ok := f.provider.(BackupPolicyProvider)
	if !ok {
		return errors.New("OCI provider cannot manage volume backup policies")
	}
	name := f.config.Owner + "-db-data"
	policy, found, err := v.findBackupPolicy(ctx, policies, name)
	if err != nil {
		return err
	}
	if !found {
		tags := map[string]string{tagManagedBy: managedByValue, tagOwner: f.config.Owner,
			tagRegion: string(f.config.Region), tagResource: resourceMemberBackupPolicy}
		retry := retryToken(strings.Join([]string{f.config.Owner, string(f.config.Region), name}, ":"))
		_, createErr := policies.CreateVolumeBackupPolicy(ctx, name, MemberBackupSchedules, tags, retry)
		if policy, found, err = v.findBackupPolicy(ctx, policies, name); err != nil || !found {
			return errors.Join(ErrOutcomeUnknown, createErr, err, fmt.Errorf("backup policy %s was not observed after its create", name))
		}
	}
	current, err := policies.VolumeBackupPolicyAssignment(ctx, volumeID)
	if err != nil || current == policy.ID {
		return err
	}
	if current != "" {
		return fmt.Errorf("%w: volume %s carries backup policy %s, not %s", ErrForeignResource, volumeID, current, policy.ID)
	}
	assignErr := policies.AssignVolumeBackupPolicy(ctx, volumeID, policy.ID)
	if current, err = policies.VolumeBackupPolicyAssignment(ctx, volumeID); err != nil || current != policy.ID {
		return errors.Join(ErrOutcomeUnknown, assignErr, err, fmt.Errorf("backup policy %s is not assigned to volume %s", policy.ID, volumeID))
	}
	return nil
}

func (v *MemberVolumes) findBackupPolicy(ctx context.Context, policies BackupPolicyProvider, name string) (CloudBackupPolicy, bool, error) {
	listed, err := policies.ListVolumeBackupPolicies(ctx)
	if err != nil {
		return CloudBackupPolicy{}, false, err
	}
	var matches []CloudBackupPolicy
	for _, policy := range listed {
		if policy.DisplayName == name {
			matches = append(matches, policy)
		}
	}
	switch {
	case len(matches) == 0:
		return CloudBackupPolicy{}, false, nil
	case len(matches) > 1:
		return CloudBackupPolicy{}, false, fmt.Errorf("%w: backup policy %s", ErrDuplicateCreateKey, name)
	}
	policy, f := matches[0], v.fleet
	if policy.FreeformTags[tagManagedBy] != managedByValue || policy.FreeformTags[tagOwner] != f.config.Owner ||
		policy.FreeformTags[tagResource] != resourceMemberBackupPolicy || len(policy.Schedules) != len(MemberBackupSchedules) ||
		slices.ContainsFunc(MemberBackupSchedules, func(want BackupSchedule) bool { return !slices.Contains(policy.Schedules, want) }) {
		return CloudBackupPolicy{}, false, fmt.Errorf("%w: backup policy %s has other tags or schedules than the member backup policy", ErrForeignResource, name)
	}
	return policy, true, nil
}
