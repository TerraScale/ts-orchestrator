package oci

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testMember       = "gru-1-db-1"
	testMemberVolume = "gru-1-db-1-data"
)

func testMemberVolumeConfig() MemberVolumeConfig {
	return MemberVolumeConfig{Region: "GRU", CompartmentID: "ocid1.compartment.members", AvailabilityDomain: "AD-1", VPUsPerGB: 10}
}

// memberVolumeFixture builds MemberVolumes over the shared fake provider, or
// over provider when one is given. Created volumes become AVAILABLE at once.
func memberVolumeFixture(t *testing.T, provider Provider) (*MemberVolumes, *fakeProvider) {
	t.Helper()
	config := testMemberVolumeConfig()
	regionConfig, err := config.regionConfig()
	if err != nil {
		t.Fatal(err)
	}
	var fake *fakeProvider
	switch typed := provider.(type) {
	case nil:
		fake = newFakeProvider(regionConfig)
		provider = fake
	case *resizeProvider:
		fake = typed.fakeProvider
	default:
		t.Fatalf("unsupported provider %T", provider)
	}
	fake.afterVolumeCreate = func() { setVolumeStates(fake, "PROVISIONING", "AVAILABLE") }
	volumes, err := newMemberVolumes(config, provider)
	if err != nil {
		t.Fatal(err)
	}
	volumes.fleet.attachmentSettle = 50 * time.Millisecond
	return volumes, fake
}

func setVolumeStates(p *fakeProvider, from, to string) {
	for id, volume := range p.volumes {
		if volume.LifecycleState == from {
			volume.LifecycleState = to
			p.volumes[id] = volume
		}
	}
}

func addMemberInstance(p *fakeProvider, id, displayName string) CloudInstance {
	instance := CloudInstance{
		ID: id, DisplayName: displayName, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
		LifecycleState: "RUNNING", ETag: "instance-etag", ConsistentVolumeNamingEnabled: boolPointer(true),
	}
	p.instances[id] = instance
	return instance
}

func onlyVolume(t *testing.T, p *fakeProvider) CloudVolume {
	t.Helper()
	if len(p.volumes) != 1 {
		t.Fatalf("volumes = %d, want 1", len(p.volumes))
	}
	for _, volume := range p.volumes {
		return volume
	}
	return CloudVolume{}
}

func setAttachmentState(p *fakeProvider, id, state string) {
	attachment := p.attachments[id]
	attachment.LifecycleState = state
	p.attachments[id] = attachment
}

func TestMemberVolumeCreatesAndAttachesOnceIdempotently(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)

	attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	volume := onlyVolume(t, p)
	if p.volumeCreates != 1 || volume.SizeGB != 50 || volume.VPUsPerGB != 10 || volume.LifecycleState != "AVAILABLE" ||
		volume.CompartmentID != p.config.CompartmentID || volume.AvailabilityDomain != p.config.AvailabilityDomain {
		t.Fatalf("created volume = %+v (creates %d)", volume, p.volumeCreates)
	}
	for key, want := range map[string]string{
		tagCreateKey: testMemberVolume, tagOwner: "gru-1", tagResource: resourceMemberData, tagVolumeSize: "50",
		tagRegion: "GRU", tagGeneration: "1", tagManagedBy: managedByValue,
	} {
		if got := volume.FreeformTags[key]; got != want {
			t.Fatalf("tag %s = %q, want %q", key, got, want)
		}
	}
	if attachment.VolumeID != volume.ID || attachment.InstanceID != "ocid1.instance.host-1" || attachment.State != "ATTACHED" ||
		attachment.Device != "/dev/oracleoci/oraclevdb" ||
		attachment.IsReadOnly || attachment.IsShareable || !attachment.IsPvEncryptionInTransitEnabled || p.attachCalls != 1 {
		t.Fatalf("attachment = %+v (attach calls %d)", attachment, p.attachCalls)
	}

	again, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != attachment.ID || again.VolumeID != volume.ID || p.volumeCreateCalls != 1 || p.attachCalls != 1 || len(p.volumes) != 1 {
		t.Fatalf("second Ensure = %+v (create calls %d, attach calls %d, volumes %d)", again, p.volumeCreateCalls, p.attachCalls, len(p.volumes))
	}
}

func TestMemberVolumeLostCreateResponseReplaysOneVolume(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)

	// The create succeeds but its response is lost: the fleet sees it anyway.
	p.volumeCreateErrorAfterCreate = errors.New("response lost")
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err != nil {
		t.Fatalf("Ensure after a lost create response: %v", err)
	}
	if p.volumeCreates != 1 || len(p.volumes) != 1 {
		t.Fatalf("creates = %d, volumes = %d", p.volumeCreates, len(p.volumes))
	}

	// The create is not yet listed: Ensure fails with an unknown outcome and a
	// retry replays the same token instead of creating a second volume.
	volumes, p = memberVolumeFixture(t, nil)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)
	hidden := map[string]CloudVolume{}
	p.afterVolumeCreate = func() {
		for id, volume := range p.volumes {
			volume.LifecycleState = "AVAILABLE"
			hidden[id] = volume
			delete(p.volumes, id)
		}
	}
	p.volumeCreateErrorAfterCreate = errors.New("response lost")
	for attempt := range 2 {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("attempt %d: Ensure = %v, want ErrOutcomeUnknown", attempt, err)
		}
	}
	if p.volumeCreateCalls != 2 || p.volumeCreates != 1 || len(p.volumeRetryTokens) != 1 || p.attachCalls != 0 {
		t.Fatalf("create calls %d, creates %d, tokens %d, attach calls %d", p.volumeCreateCalls, p.volumeCreates, len(p.volumeRetryTokens), p.attachCalls)
	}
	for id, volume := range hidden {
		p.volumes[id] = volume
	}
	attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	if volume := onlyVolume(t, p); attachment.VolumeID != volume.ID || p.volumeCreates != 1 || p.volumeCreateCalls != 2 {
		t.Fatalf("attachment %+v to %s (creates %d, create calls %d)", attachment, volume.ID, p.volumeCreates, p.volumeCreateCalls)
	}
}

func TestMemberVolumeReattachesSameVolumeAfterHostReplacement(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	old := addMemberInstance(p, "ocid1.instance.old", testMember)
	first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: old.ID, SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	old.LifecycleState = "TERMINATED"
	p.instances[old.ID] = old
	setAttachmentState(p, first.ID, attachmentStateDetached)

	addMemberInstance(p, "ocid1.instance.new", testMember)
	second, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.new", SizeGB: 100, VolumeID: first.VolumeID})
	if err != nil {
		t.Fatal(err)
	}
	volume := onlyVolume(t, p)
	if second.VolumeID != first.VolumeID || second.VolumeID != volume.ID || second.InstanceID != "ocid1.instance.new" ||
		second.ID == first.ID || second.Device != MemberVolumeDevice || p.volumeCreateCalls != 1 || p.attachCalls != 2 {
		t.Fatalf("reattach = %+v from %+v (create calls %d, attach calls %d)", second, first, p.volumeCreateCalls, p.attachCalls)
	}
	// An existing volume is reused at its size: a larger request does not grow it.
	if volume.SizeGB != 50 {
		t.Fatalf("reattached volume size = %d, want 50", volume.SizeGB)
	}
}

func TestMemberVolumeRefusesToStealLiveAttachment(t *testing.T) {
	for _, state := range []string{"ATTACHED", "DETACHING", "ATTACHING"} {
		t.Run(state, func(t *testing.T) {
			ctx := t.Context()
			volumes, p := memberVolumeFixture(t, nil)
			addMemberInstance(p, "ocid1.instance.old", testMember)
			first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.old", SizeGB: 50})
			if err != nil {
				t.Fatal(err)
			}
			setAttachmentState(p, first.ID, state)
			addMemberInstance(p, "ocid1.instance.new", testMember)

			_, err = volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.new", SizeGB: 50})
			if !errors.Is(err, ErrRetainedVolumeInUse) {
				t.Fatalf("Ensure = %v, want ErrRetainedVolumeInUse", err)
			}
			held, ok := p.attachments[first.ID]
			if p.attachCalls != 1 || len(p.attachments) != 1 || !ok || held.LifecycleState != state || held.InstanceID != "ocid1.instance.old" {
				t.Fatalf("attachments = %+v (attach calls %d)", p.attachments, p.attachCalls)
			}
		})
	}
}

func TestMemberVolumeFailsClosedOnTerminatedVolume(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err != nil {
		t.Fatal(err)
	}
	clear(p.attachments)
	setVolumeStates(p, "AVAILABLE", "TERMINATED")
	addMemberInstance(p, "ocid1.instance.host-2", testMember)

	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-2", SizeGB: 50}); err == nil {
		t.Fatal("Ensure replaced a terminated data volume")
	}
	if p.volumeCreateCalls != 1 || len(p.volumes) != 1 || p.attachCalls != 1 {
		t.Fatalf("create calls %d, volumes %d, attach calls %d", p.volumeCreateCalls, len(p.volumes), p.attachCalls)
	}
}

func TestMemberVolumeRejectsInstancesAndNamesOutsideTheMember(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	mutate := func(id string, change func(*CloudInstance)) {
		instance := addMemberInstance(p, id, testMember)
		change(&instance)
		p.instances[id] = instance
	}
	mutate("ocid1.instance.renamed", func(i *CloudInstance) { i.DisplayName = "gru-1-db-2" })
	mutate("ocid1.instance.compartment", func(i *CloudInstance) { i.CompartmentID = "ocid1.compartment.other" })
	mutate("ocid1.instance.domain", func(i *CloudInstance) { i.AvailabilityDomain = "AD-2" })
	mutate("ocid1.instance.stopped", func(i *CloudInstance) { i.LifecycleState = "STOPPED" })
	mutate("ocid1.instance.provisioning", func(i *CloudInstance) { i.LifecycleState = "PROVISIONING" })
	mutate("ocid1.instance.naming-off", func(i *CloudInstance) { i.ConsistentVolumeNamingEnabled = boolPointer(false) })
	mutate("ocid1.instance.naming-unset", func(i *CloudInstance) { i.ConsistentVolumeNamingEnabled = nil })
	for _, id := range []string{
		"ocid1.instance.renamed", "ocid1.instance.compartment", "ocid1.instance.domain", "ocid1.instance.stopped",
		"ocid1.instance.provisioning", "ocid1.instance.naming-off", "ocid1.instance.naming-unset", "ocid1.instance.missing",
	} {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: id, SizeGB: 50}); err == nil {
			t.Fatalf("Ensure on %s succeeded", id)
		}
	}
	for _, name := range []string{"gru-1-gw-1", "gru-2-db-1", "gru-1-db-1-data", "postgres", ""} {
		addMemberInstance(p, "ocid1.instance."+name, name)
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: name, InstanceID: "ocid1.instance." + name, SizeGB: 50}); err == nil {
			t.Fatalf("Ensure for non-member %q succeeded", name)
		}
	}
	addMemberInstance(p, "ocid1.instance.host-1", testMember)
	for _, size := range []int64{0, 49, maxMemberVolumeGB + 1} {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: size}); err == nil {
			t.Fatalf("Ensure with %d GB succeeded", size)
		}
	}
	if p.volumeCreateCalls != 0 || len(p.volumes) != 0 || p.attachCalls != 0 {
		t.Fatalf("create calls %d, volumes %d, attach calls %d", p.volumeCreateCalls, len(p.volumes), p.attachCalls)
	}
}

func TestMemberVolumeHoldsWhenDeviceIsBusy(t *testing.T) {
	for name, devices := range map[string][]CloudDevice{
		"taken":   {{Name: MemberVolumeDevice, IsAvailable: boolPointer(false)}, {Name: "/dev/oracleoci/oraclevdc", IsAvailable: boolPointer(true)}},
		"unknown": {{Name: MemberVolumeDevice}, {Name: "/dev/oracleoci/oraclevdc", IsAvailable: boolPointer(true)}},
		"missing": {{Name: "/dev/oracleoci/oraclevdc", IsAvailable: boolPointer(true)}},
	} {
		t.Run(name, func(t *testing.T) {
			volumes, p := memberVolumeFixture(t, nil)
			addMemberInstance(p, "ocid1.instance.host-1", testMember)
			p.devices["ocid1.instance.host-1"] = devices
			if _, err := volumes.Ensure(t.Context(), MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err == nil {
				t.Fatal("Ensure attached to a busy device")
			}
			if p.deviceListCalls != 1 || p.attachCalls != 0 || len(p.attachments) != 0 {
				t.Fatalf("device lists %d, attach calls %d, attachments %d", p.deviceListCalls, p.attachCalls, len(p.attachments))
			}
		})
	}
}

func TestMemberVolumeResizeGrowsOnlyUnderETag(t *testing.T) {
	ctx := t.Context()
	regionConfig, err := testMemberVolumeConfig().regionConfig()
	if err != nil {
		t.Fatal(err)
	}
	provider := &resizeProvider{fakeProvider: newFakeProvider(regionConfig)}
	volumes, p := memberVolumeFixture(t, provider)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)
	if _, err := volumes.Resize(ctx, testMember, "ocid1.volume.missing", 100); err == nil {
		t.Fatal("Resize of a member without a data volume succeeded")
	}
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err != nil {
		t.Fatal(err)
	}
	before := onlyVolume(t, p)

	grown, err := volumes.Resize(ctx, testMember, before.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	after := onlyVolume(t, p)
	if grown.ID != before.ID || grown.SizeGB != 100 || grown.State != "AVAILABLE" || grown.CreateKey != testMemberVolume ||
		provider.updates != 1 || after.SizeGB != 100 || after.FreeformTags[tagVolumeSize] != "100" || after.ETag == before.ETag {
		t.Fatalf("Resize = %+v, volume %+v (updates %d)", grown, after, provider.updates)
	}
	for _, size := range []int64{50, 80, 100} {
		same, err := volumes.Resize(ctx, testMember, before.ID, size)
		if err != nil || same.SizeGB != 100 {
			t.Fatalf("Resize to %d = %+v, %v", size, same, err)
		}
	}
	if provider.updates != 1 {
		t.Fatalf("no-op resizes reached OCI: %d updates", provider.updates)
	}
	for _, size := range []int64{49, maxMemberVolumeGB + 1} {
		if _, err := volumes.Resize(ctx, testMember, before.ID, size); err == nil {
			t.Fatalf("Resize to %d GB succeeded", size)
		}
	}
	if _, err := volumes.Resize(ctx, "gru-1-db-2", before.ID, 100); err == nil || provider.updates != 1 {
		t.Fatalf("Resize of a member without a data volume = %v (updates %d)", err, provider.updates)
	}

	// An update OCI rejects is never confirmed as grown.
	provider.updateErr = ErrStaleETag
	if _, err := volumes.Resize(ctx, testMember, before.ID, 200); !errors.Is(err, ErrOutcomeUnknown) || provider.volumes[before.ID].SizeGB != 100 {
		t.Fatalf("Resize under a rejected update = %v (size %d)", err, provider.volumes[before.ID].SizeGB)
	}
	provider.updateErr = nil

	plain, _ := memberVolumeFixture(t, nil)
	if _, err := plain.Resize(ctx, testMember, before.ID, 100); !errors.Is(err, ErrVolumeResizeUnsupported) {
		t.Fatalf("Resize without VolumeUpdater = %v, want ErrVolumeResizeUnsupported", err)
	}
}

func TestMemberVolumeDuplicateCreateKeyHolds(t *testing.T) {
	ctx := t.Context()
	volumes, p := memberVolumeFixture(t, nil)
	addMemberInstance(p, "ocid1.instance.host-1", testMember)
	tags := volumeTags(p.config, VolumeCreateRequest{CreateKey: testMemberVolume, SizeGB: 50})
	for _, id := range []string{"ocid1.volume.a", "ocid1.volume.b"} {
		p.volumes[id] = CloudVolume{
			ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
			SizeGB: 50, VPUsPerGB: 10, LifecycleState: "AVAILABLE", ETag: "volume-etag", FreeformTags: cloneStringMap(tags),
		}
	}
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrDuplicateCreateKey) {
		t.Fatalf("Ensure = %v, want ErrDuplicateCreateKey", err)
	}
	if p.volumeCreateCalls != 0 || p.attachCalls != 0 || len(p.volumes) != 2 {
		t.Fatalf("create calls %d, attach calls %d, volumes %d", p.volumeCreateCalls, p.attachCalls, len(p.volumes))
	}
}

// TestMemberVolumeRecordedVolumeIsNeverRecreated: once a member's volume is
// recorded, a purged volume (no OCI record left at all) is lost data to
// restore, never a reason to create an empty one.
func TestMemberVolumeRecordedVolumeIsNeverRecreated(t *testing.T) {
	ctx := t.Context()
	volumes, fake := memberVolumeFixture(t, nil)
	addMemberInstance(fake, "ocid1.instance.host-1", testMember)
	first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	recorded := MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50, VolumeID: first.VolumeID}
	if again, err := volumes.Ensure(ctx, recorded); err != nil || again.ID != first.ID {
		t.Fatalf("recorded volume = %+v, %v; want the same attachment", again, err)
	}
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50,
		VolumeID: "ocid1.volume.other"}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("a different recorded volume = %v, want ErrForeignResource", err)
	}
	// OCI purged the volume and its attachments: nothing is listed any more.
	clear(fake.volumes)
	clear(fake.attachments)
	addMemberInstance(fake, "ocid1.instance.host-2", testMember)
	recorded.InstanceID = "ocid1.instance.host-2"
	if _, err := volumes.Ensure(ctx, recorded); err == nil {
		t.Fatal("recreated a purged recorded volume")
	}
	if fake.volumeCreates != 1 || len(fake.volumes) != 0 {
		t.Fatalf("creates = %d, volumes = %d; want no new volume", fake.volumeCreates, len(fake.volumes))
	}
}

func (p *fakeProvider) ListVolumeBackupPolicies(context.Context) ([]CloudBackupPolicy, error) {
	return slices.Clone(p.backupPolicies), nil
}

func (p *fakeProvider) CreateVolumeBackupPolicy(_ context.Context, name string, schedules []BackupSchedule, tags map[string]string, retry string) (CloudBackupPolicy, error) {
	if p.backupPolicyRetryTokens == nil {
		p.backupPolicyRetryTokens = make(map[string]string)
	}
	for _, policy := range p.backupPolicies {
		if p.backupPolicyRetryTokens[retry] == policy.ID {
			return policy, nil
		}
	}
	p.backupPolicyCreates++
	policy := CloudBackupPolicy{ID: fmt.Sprintf("ocid1.volumebackuppolicy.created-%d", p.backupPolicyCreates), DisplayName: name,
		Schedules: slices.Clone(schedules), FreeformTags: cloneStringMap(tags)}
	p.backupPolicies = append(p.backupPolicies, policy)
	p.backupPolicyRetryTokens[retry] = policy.ID
	return policy, nil
}

func (p *fakeProvider) VolumeBackupPolicyAssignment(_ context.Context, volumeID string) (string, error) {
	return p.backupPolicyAssignments[volumeID], nil
}

func (p *fakeProvider) AssignVolumeBackupPolicy(_ context.Context, volumeID, policyID string) error {
	if p.backupPolicyAssignments == nil {
		p.backupPolicyAssignments = make(map[string]string)
	}
	// Like OCI, a new assignment replaces the volume's current one.
	p.backupPolicyAssignments[volumeID] = policyID
	return nil
}

// TestMemberVolumeCarriesTheCellBackupPolicy: every member data volume gets
// the cell's one backup policy, a daily backup kept 7 days and a weekly one
// kept 4 weeks, before it is attached.
func TestMemberVolumeCarriesTheCellBackupPolicy(t *testing.T) {
	ctx := t.Context()
	volumes, fake := memberVolumeFixture(t, nil)
	for _, member := range []string{"gru-1-db-1", "gru-1-db-2"} {
		addMemberInstance(fake, "ocid1.instance."+member, member)
		attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: member, InstanceID: "ocid1.instance." + member, SizeGB: 50})
		if err != nil {
			t.Fatal(err)
		}
		if fake.backupPolicyAssignments[attachment.VolumeID] != "ocid1.volumebackuppolicy.created-1" {
			t.Fatalf("%s volume policy = %q", member, fake.backupPolicyAssignments[attachment.VolumeID])
		}
	}
	if fake.backupPolicyCreates != 1 || len(fake.backupPolicies) != 1 {
		t.Fatalf("policies created = %d, want one for the cell", fake.backupPolicyCreates)
	}
	policy := fake.backupPolicies[0]
	daily := BackupSchedule{Type: "INCREMENTAL", Period: "ONE_DAY", RetentionSeconds: 7 * 86400, OffsetType: "STRUCTURED", HourOfDay: 3, TimeZone: "UTC"}
	weekly := BackupSchedule{Type: "FULL", Period: "ONE_WEEK", RetentionSeconds: 4 * 7 * 86400, OffsetType: "STRUCTURED", HourOfDay: 4,
		DayOfWeek: "SUNDAY", TimeZone: "UTC"}
	if policy.DisplayName != "gru-1-db-data" || !slices.Equal(policy.Schedules, []BackupSchedule{daily, weekly}) ||
		policy.FreeformTags[tagOwner] != "gru-1" || policy.FreeformTags[tagResource] != resourceMemberBackupPolicy {
		t.Fatalf("policy = %+v", policy)
	}

	// A volume carrying another policy, or a policy of that name with other
	// schedules, holds the attach instead of being changed.
	held, heldFake := memberVolumeFixture(t, nil)
	addMemberInstance(heldFake, "ocid1.instance.host-1", testMember)
	heldFake.afterVolumeCreate = func() {
		setVolumeStates(heldFake, "PROVISIONING", "AVAILABLE")
		for id := range heldFake.volumes {
			heldFake.backupPolicyAssignments = map[string]string{id: "ocid1.volumebackuppolicy.bronze"}
		}
	}
	if _, err := held.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("volume with another policy = %v, want ErrForeignResource", err)
	}
	if heldFake.attachCalls != 0 {
		t.Fatal("attached a volume without the member backup policy")
	}
	drifted, driftedFake := memberVolumeFixture(t, nil)
	addMemberInstance(driftedFake, "ocid1.instance.host-1", testMember)
	driftedFake.backupPolicies = []CloudBackupPolicy{{ID: "ocid1.volumebackuppolicy.old", DisplayName: "gru-1-db-data",
		Schedules: []BackupSchedule{daily}, FreeformTags: policy.FreeformTags}}
	if _, err := drifted.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("drifted policy = %v, want ErrForeignResource", err)
	}
	if driftedFake.attachCalls != 0 || driftedFake.backupPolicyCreates != 0 {
		t.Fatal("changed or bypassed a drifted backup policy")
	}
	regional := daily
	regional.TimeZone = "REGIONAL_DATA_CENTER_TIME"
	driftedFake.backupPolicies[0].Schedules = []BackupSchedule{regional, weekly}
	if _, err := drifted.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("policy in another time zone = %v, want ErrForeignResource", err)
	}
}

func (p *fakeProvider) ListVolumeBackups(_ context.Context, volumeID string) ([]CloudVolumeBackup, error) {
	var backups []CloudVolumeBackup
	for _, backup := range p.volumeBackups {
		if backup.VolumeID == volumeID {
			backups = append(backups, backup)
		}
	}
	return backups, nil
}

func (p *fakeProvider) GetVolumeBackup(_ context.Context, id string) (CloudVolumeBackup, error) {
	for _, backup := range p.volumeBackups {
		if backup.ID == id {
			return backup, nil
		}
	}
	return CloudVolumeBackup{}, fakeNotFound{}
}

// TestMemberVolumeRestoreDrill restores the newest available backup into a
// new volume on a scratch instance, never on a member host, and leaves the
// member's own volume alone.
func TestMemberVolumeRestoreDrill(t *testing.T) {
	ctx := t.Context()
	volumes, fake := memberVolumeFixture(t, nil)
	volumes.restoreSettle = 50 * time.Millisecond
	addMemberInstance(fake, "ocid1.instance.member", testMember)
	member, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.member", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fake.volumeBackups = []CloudVolumeBackup{
		{ID: "ocid1.volumebackup.old", VolumeID: member.VolumeID, LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now.Add(-48 * time.Hour)},
		{ID: "ocid1.volumebackup.daily", VolumeID: member.VolumeID, LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now.Add(-24 * time.Hour)},
		{ID: "ocid1.volumebackup.running", VolumeID: member.VolumeID, LifecycleState: "CREATING", SizeGB: 50, CreatedAt: now},
		{ID: "ocid1.volumebackup.foreign", VolumeID: "ocid1.volume.other", LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now},
	}
	scratch := addMemberInstance(fake, "ocid1.instance.scratch", "gru-1-restore-drill")
	fake.devices[scratch.ID] = []CloudDevice{{Name: RestoreVolumeDevice, IsAvailable: boolPointer(true)}}
	fake.afterVolumeCreate = func() { setVolumeStates(fake, "PROVISIONING", "AVAILABLE") }
	request := RestoreRequest{Member: testMember, ScratchInstanceID: scratch.ID}
	restored, err := volumes.Restore(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	created := fake.volumeCreateRequests[len(fake.volumeCreateRequests)-1]
	if restored.BackupID != "ocid1.volumebackup.daily" || created.SourceBackupID != "ocid1.volumebackup.daily" ||
		created.Name != "restore-"+testMemberVolume || created.SizeGB != 50 {
		t.Fatalf("restored %+v from create %+v; want the newest AVAILABLE backup", restored, created)
	}
	volume := fake.volumes[restored.VolumeID]
	if restored.InstanceID != scratch.ID || restored.Device != RestoreVolumeDevice || volume.FreeformTags[tagResource] != resourceMemberRestore ||
		fake.backupPolicyAssignments[restored.VolumeID] != "" {
		t.Fatalf("restored volume %+v attached %+v; want a scratch-only copy without a backup policy", volume, restored.Attachment)
	}
	if again, err := volumes.Restore(ctx, request); err != nil || again.VolumeID != restored.VolumeID || fake.volumeCreates != 2 {
		t.Fatalf("rerun = %+v, %v (creates %d); want the same restored volume", again, err, fake.volumeCreates)
	}
	if again, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.member", SizeGB: 50}); err != nil ||
		again.VolumeID != member.VolumeID {
		t.Fatalf("member volume after the drill = %+v, %v", again, err)
	}

	for name, bad := range map[string]RestoreRequest{
		"member host":         {Member: testMember, ScratchInstanceID: "ocid1.instance.member"},
		"other volume backup": {Member: testMember, BackupID: "ocid1.volumebackup.foreign", ScratchInstanceID: scratch.ID},
		"unfinished backup":   {Member: testMember, BackupID: "ocid1.volumebackup.running", ScratchInstanceID: scratch.ID},
		"not a member":        {Member: "gru-1-gw-1", ScratchInstanceID: scratch.ID},
	} {
		if _, err := volumes.Restore(ctx, bad); err == nil {
			t.Fatalf("%s restore was accepted", name)
		}
	}
	if fake.volumeCreates != 2 {
		t.Fatalf("refused restores created volumes: %d", fake.volumeCreates)
	}

	// A scratch instance holding any other volume is refused before the
	// restored volume is created, so restore-check can only mount the copy.
	busy := addMemberInstance(fake, "ocid1.instance.busy", "gru-1-restore-busy")
	readOnly, shareable, encrypted := false, false, true
	fake.attachments["attachment-busy"] = CloudAttachment{ID: "attachment-busy", VolumeID: "ocid1.volume.other", InstanceID: busy.ID,
		LifecycleState: "ATTACHED", ETag: "e", Device: MemberVolumeDevice, IsReadOnly: &readOnly, IsShareable: &shareable,
		IsPvEncryptionInTransitEnabled: &encrypted}
	creates := fake.volumeCreates
	if _, err := volumes.Restore(ctx, RestoreRequest{Member: testMember, BackupID: "ocid1.volumebackup.old", ScratchInstanceID: busy.ID}); err == nil ||
		!strings.Contains(err.Error(), "only the restored volume") || fake.volumeCreates != creates {
		t.Fatalf("scratch instance with another volume = %v, creates %d -> %d", err, creates, fake.volumeCreates)
	}
	delete(fake.attachments, "attachment-busy")

	// The member volume is gone: its backups are found through the recorded
	// volume ID only, and no other volume's backup is accepted.
	delete(fake.volumes, member.VolumeID)
	addMemberInstance(fake, "ocid1.instance.second", "gru-1-restore-drill-2")
	fake.devices["ocid1.instance.second"] = []CloudDevice{{Name: RestoreVolumeDevice, IsAvailable: boolPointer(true)}}
	if _, err := volumes.Restore(ctx, RestoreRequest{Member: testMember, BackupID: "ocid1.volumebackup.old", ScratchInstanceID: "ocid1.instance.second"}); err == nil ||
		!strings.Contains(err.Error(), "no recorded volume ID") {
		t.Fatalf("restore of a gone volume without its recorded ID = %v", err)
	}
	gone := RestoreRequest{Member: testMember, ScratchInstanceID: "ocid1.instance.second", SourceVolumeID: member.VolumeID}
	gone.BackupID = "ocid1.volumebackup.foreign"
	if _, err := volumes.Restore(ctx, gone); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("another volume's backup for a gone volume = %v, want ErrForeignResource", err)
	}
	// The drill volume of that backup stays on its first scratch instance.
	gone.BackupID, gone.ScratchInstanceID = "", scratch.ID
	if restored, err := volumes.Restore(ctx, gone); err != nil || restored.BackupID != "ocid1.volumebackup.daily" {
		t.Fatalf("newest backup of the recorded gone volume = %+v, %v", restored, err)
	}
}
