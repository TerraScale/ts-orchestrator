package oci

import (
	"context"
	"errors"
	"testing"
	"time"
)

type retireProvider struct {
	*resizeProvider
	detaches  int
	deletes   int
	detachErr error
	stayBusy  bool
}

func (p *retireProvider) DetachVolume(ctx context.Context, id, etag string) error {
	p.detaches++
	if p.stayBusy {
		attachment := p.attachments[id]
		attachment.LifecycleState = attachmentStateDetaching
		p.attachments[id] = attachment
		return p.detachErr
	}
	return errors.Join(p.fakeProvider.DetachVolume(ctx, id, etag), p.detachErr)
}

func (p *retireProvider) DeleteVolume(context.Context, string, string) error {
	p.deletes++
	return errors.New("retained member volumes must not be deleted")
}

func retireFixture(t *testing.T) (*MemberVolumes, *retireProvider, MemberVolumeRequest, Attachment) {
	t.Helper()
	config, err := testMemberVolumeConfig().regionConfig()
	if err != nil {
		t.Fatal(err)
	}
	updater := &resizeProvider{fakeProvider: newFakeProvider(config)}
	volumes, fake := memberVolumeFixture(t, updater)
	provider := &retireProvider{resizeProvider: updater}
	volumes.fleet.provider = provider
	addMemberInstance(fake, "ocid1.instance.old", testMember)
	request := MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.old", SizeGB: 50}
	attachment, err := volumes.Ensure(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.VolumeID = attachment.VolumeID
	return volumes, provider, request, attachment
}

func TestMemberVolumeResizeChecksRecordedIDBeforeAnyUpdate(t *testing.T) {
	volumes, provider, request, _ := retireFixture(t)
	for _, recorded := range []string{"", "ocid1.volume.some-other-recorded-volume"} {
		for _, size := range []int64{50, 100} {
			if _, err := volumes.Resize(t.Context(), testMember, recorded, size); err == nil {
				t.Fatalf("Resize accepted recorded ID %q at %d GB", recorded, size)
			}
		}
	}
	if provider.updates != 0 || provider.volumes[request.VolumeID].SizeGB != 50 {
		t.Fatal("recorded ID rejection happened after a volume update")
	}
	delete(provider.volumes, request.VolumeID)
	if _, err := volumes.Resize(t.Context(), testMember, request.VolumeID, 100); err == nil || provider.updates != 0 {
		t.Fatalf("missing recorded data was updated: %v (updates %d)", err, provider.updates)
	}
}

func TestMemberVolumeRetireRetainsAndNameReuseCreatesFreshVolume(t *testing.T) {
	volumes, provider, request, first := retireFixture(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	volumes.fleet.now = func() time.Time { return now }
	retired, err := volumes.Retire(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	old := provider.volumes[first.VolumeID]
	if retired.ID != first.VolumeID || retired.State != "AVAILABLE" || old.SizeGB != 50 ||
		old.FreeformTags[tagResource] != resourceMemberRetiredData || old.FreeformTags[tagRetiredNode] != testMember ||
		old.FreeformTags[tagRetiredInstance] != request.InstanceID || old.FreeformTags[tagRetiredAt] != now.Format(time.RFC3339Nano) ||
		old.FreeformTags[tagCreateKey] == testMemberVolume || provider.detaches != 1 || provider.updates != 1 || provider.deletes != 0 {
		t.Fatalf("retirement did not detach/tag/retain the recorded volume: %+v, provider %+v", old, provider)
	}
	if _, _, err := volumes.fleet.reobserveVolume(t.Context(), retired.ID); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("normal fleet adopted a retired volume: %v", err)
	}
	now = now.Add(time.Hour)
	delete(provider.instances, request.InstanceID)
	if again, err := volumes.Retire(t.Context(), request); err != nil || again.ID != retired.ID || provider.updates != 1 || provider.detaches != 1 ||
		provider.volumes[retired.ID].FreeformTags[tagRetiredAt] != old.FreeformTags[tagRetiredAt] {
		t.Fatalf("retirement retry changed its volume/time or repeated effects: %+v, %v", again, err)
	}

	// Reuse even the same instance ID: attachment tokens bind the new exact
	// volume too, so the old attachment token cannot replay detached data.
	addMemberInstance(provider.fakeProvider, request.InstanceID, testMember)
	if _, err := volumes.Ensure(t.Context(), request); err == nil {
		t.Fatal("Ensure adopted the recorded retired volume")
	}
	fresh := request
	fresh.VolumeID = ""
	second, err := volumes.Ensure(t.Context(), fresh)
	if err != nil {
		t.Fatal(err)
	}
	if second.VolumeID != "ocid1.volume.created-2" || second.VolumeID == first.VolumeID || second.InstanceID != request.InstanceID ||
		provider.volumeCreates != 2 || len(provider.volumeRetryTokens) != 2 || len(provider.volumes) != 2 || provider.attachCalls != 2 || provider.deletes != 0 {
		t.Fatalf("name reuse did not return the exact fresh VolumeID: %+v, retired %+v", second, retired)
	}
	if again, err := volumes.Ensure(t.Context(), fresh); err != nil || again.VolumeID != second.VolumeID || provider.volumeCreates != 2 {
		t.Fatalf("fresh incarnation was not idempotent: %+v, %v", again, err)
	}
	// A second retirement changes the stable history and therefore the token.
	fresh.VolumeID = second.VolumeID
	if _, err := volumes.Retire(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.VolumeID = ""
	third, err := volumes.Ensure(t.Context(), fresh)
	if err != nil || third.VolumeID != "ocid1.volume.created-3" || len(provider.volumeRetryTokens) != 3 || len(provider.volumes) != 3 {
		t.Fatalf("second name reuse replayed old data: %+v, %v", third, err)
	}
}

func TestMemberVolumeRetirementRetriesUnknownOutcomes(t *testing.T) {
	for _, scenario := range []string{"lost detach response", "lost tag response", "rejected tags", "pending detach"} {
		t.Run(scenario, func(t *testing.T) {
			volumes, provider, request, attachment := retireFixture(t)
			switch scenario {
			case "lost detach response":
				provider.detachErr = errors.New("response lost")
			case "lost tag response":
				provider.updateErr, provider.updateApplies = errors.New("response lost"), true
			case "rejected tags":
				provider.updateErr = ErrStaleETag
			case "pending detach":
				provider.stayBusy = true
			}
			_, err := volumes.Retire(t.Context(), request)
			unknown := scenario == "rejected tags" || scenario == "pending detach"
			if unknown && !errors.Is(err, ErrOutcomeUnknown) || !unknown && err != nil {
				t.Fatalf("Retire under %s = %v", scenario, err)
			}
			if scenario == "pending detach" {
				if provider.updates != 0 {
					t.Fatal("tagged retirement before detach was confirmed")
				}
				setAttachmentState(provider.fakeProvider, attachment.ID, attachmentStateDetached)
			}
			provider.updateErr, provider.detachErr, provider.stayBusy = nil, nil, false
			if retired, err := volumes.Retire(t.Context(), request); err != nil || retired.ID != request.VolumeID || provider.detaches != 1 ||
				provider.deletes != 0 || len(provider.volumes) != 1 {
				t.Fatalf("retirement retry failed or repeated detach/deleted data: %+v, %v", retired, err)
			}
		})
	}
}

func TestMemberNameReuseLostCreateResponseReplaysFreshIncarnation(t *testing.T) {
	volumes, provider, request, first := retireFixture(t)
	if _, err := volumes.Retire(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	request.VolumeID = ""
	hidden := map[string]CloudVolume{}
	provider.afterVolumeCreate = func() {
		for id, volume := range provider.volumes {
			if volume.FreeformTags[tagResource] == resourceMemberData {
				volume.LifecycleState = "AVAILABLE"
				hidden[id] = volume
				delete(provider.volumes, id)
			}
		}
	}
	provider.volumeCreateErrorAfterCreate = errors.New("response lost")
	for range 2 {
		if _, err := volumes.Ensure(t.Context(), request); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("hidden fresh incarnation = %v; want ErrOutcomeUnknown", err)
		}
	}
	if provider.volumeCreates != 2 || provider.volumeCreateCalls != 3 || len(provider.volumeRetryTokens) != 2 || provider.attachCalls != 1 {
		t.Fatal("fresh incarnation retries changed tokens or attached retired data")
	}
	for id, volume := range hidden {
		provider.volumes[id] = volume
	}
	fresh, err := volumes.Ensure(t.Context(), request)
	if err != nil || fresh.VolumeID != "ocid1.volume.created-2" || fresh.VolumeID == first.VolumeID || provider.volumeCreates != 2 {
		t.Fatalf("fresh incarnation recovery = %+v, %v", fresh, err)
	}
}

func TestMemberVolumeRetireRefusesOtherLiveAttachmentAndWrongRecordedData(t *testing.T) {
	for _, scenario := range []string{"other instance", "multiple attachments", "wrong recorded ID", "wrong member", "missing recorded ID", "missing recorded data", "foreign instance"} {
		t.Run(scenario, func(t *testing.T) {
			volumes, provider, request, attachment := retireFixture(t)
			switch scenario {
			case "other instance":
				request.InstanceID = "ocid1.instance.new"
				addMemberInstance(provider.fakeProvider, request.InstanceID, testMember)
			case "multiple attachments":
				other := provider.attachments[attachment.ID]
				other.ID, other.InstanceID = "second", "ocid1.instance.other"
				provider.attachments[other.ID] = other
			case "wrong recorded ID":
				request.VolumeID = "ocid1.volume.other"
			case "wrong member":
				request.Member = "gru-1-db-2"
			case "missing recorded ID":
				request.VolumeID = ""
			case "missing recorded data":
				delete(provider.volumes, request.VolumeID)
			case "foreign instance":
				instance := provider.instances[request.InstanceID]
				instance.CompartmentID = "other"
				provider.instances[instance.ID] = instance
			}
			if _, err := volumes.Retire(t.Context(), request); err == nil || provider.detaches != 0 || provider.updates != 0 || provider.deletes != 0 {
				t.Fatalf("unsafe retirement reached a mutation: %v, provider %+v", err, provider)
			}
		})
	}
}
