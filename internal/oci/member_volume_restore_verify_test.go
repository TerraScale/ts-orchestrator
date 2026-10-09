package oci

import (
	"testing"
	"time"
)

func restoreVerifyFixture(t *testing.T) (*MemberVolumes, *retireProvider, RestoredVolume) {
	t.Helper()
	volumes, provider, member, _ := retireFixture(t)
	scratch := addMemberInstance(provider.fakeProvider, "ocid1.instance.scratch", "gru-1-restore-drill")
	provider.devices[scratch.ID] = []CloudDevice{{Name: RestoreVolumeDevice, IsAvailable: boolPointer(true)}}
	provider.volumeBackups = []CloudVolumeBackup{{ID: "ocid1.volumebackup.daily", VolumeID: member.VolumeID,
		LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: time.Now()}}
	restored, err := volumes.Restore(t.Context(), RestoreRequest{Member: testMember, ScratchInstanceID: scratch.ID, SourceVolumeID: member.VolumeID})
	if err != nil {
		t.Fatal(err)
	}
	return volumes, provider, restored
}

func TestVerifyRestoredAttachmentReadsExactScratchCopyWithoutMutatingOCI(t *testing.T) {
	volumes, provider, restored := restoreVerifyFixture(t)
	// Detached history does not turn an exclusive current attachment into
	// another live attachment.
	history := provider.attachments[restored.ID]
	history.ID, history.InstanceID, history.LifecycleState = "detached-history", "ocid1.instance.old-scratch", attachmentStateDetached
	provider.attachments[history.ID] = history
	creates, attaches := provider.volumeCreateCalls, provider.attachCalls
	verified, err := volumes.VerifyRestoredAttachment(t.Context(), restored.InstanceID, restored.VolumeID)
	if err != nil || verified != restored.Attachment || provider.volumeCreateCalls != creates || provider.attachCalls != attaches ||
		provider.updates != 0 || provider.detaches != 0 || provider.deletes != 0 {
		t.Fatalf("read-only verification = %+v, %v; want exact %+v without OCI writes", verified, err, restored.Attachment)
	}
}

func TestVerifyRestoredAttachmentFailsClosedOnWrongVolumeScopeStateAndAttachments(t *testing.T) {
	for _, scenario := range []string{
		"member data volume", "missing volume", "wrong returned volume ID", "wrong compartment", "wrong domain", "wrong tier", "wrong size tag",
		"wrong resource tag", "wrong owner tag", "wrong region tag", "wrong generation tag", "wrong managed tag", "wrong create key", "unfinished restore",
		"wrong device", "wrong returned attachment ID", "wrong instance", "read-only", "shareable", "unencrypted", "detaching", "missing attachment",
		"second scratch volume", "duplicate scratch attachment", "second volume attachment", "member instance", "foreign scratch", "stopped scratch",
	} {
		t.Run(scenario, func(t *testing.T) {
			volumes, provider, restored := restoreVerifyFixture(t)
			volume := provider.volumes[restored.VolumeID]
			attachment := provider.attachments[restored.ID]
			switch scenario {
			case "member data volume":
				restored.VolumeID = "ocid1.volume.created-1"
			case "missing volume":
				delete(provider.volumes, restored.VolumeID)
			case "wrong returned volume ID":
				volume.ID = "ocid1.volume.other"
			case "wrong compartment":
				volume.CompartmentID = "0000000000V4MRM46HP1SNGDYW"
			case "wrong domain":
				volume.AvailabilityDomain = "0000000000V4MRM46HP1SNGDYW"
			case "wrong tier":
				volume.VPUsPerGB = 20
			case "wrong size tag":
				volume.FreeformTags[tagVolumeSize] = "100"
			case "wrong resource tag":
				volume.FreeformTags[tagResource] = resourceMemberData
			case "wrong owner tag":
				volume.FreeformTags[tagOwner] = "0000000000V4MRM46HP1SNGDYW"
			case "wrong region tag":
				volume.FreeformTags[tagRegion] = "SFO"
			case "wrong generation tag":
				volume.FreeformTags[tagGeneration] = "2"
			case "wrong managed tag":
				volume.FreeformTags[tagManagedBy] = "0000000000V4MRM46HP1SNGDYW"
			case "wrong create key":
				volume.FreeformTags[tagCreateKey] = memberVolumeCreateKey(testMemberVolume)
			case "unfinished restore":
				volume.LifecycleState = "RESTORING"
			case "wrong device":
				attachment.Device = MemberVolumeDevice
			case "wrong returned attachment ID":
				attachment.ID = "0000000000V4MRM46HP1SNGDYW"
			case "wrong instance":
				attachment.InstanceID = "0000000000V4MRM46HP1SNGDYW"
			case "read-only":
				attachment.IsReadOnly = boolPointer(true)
			case "shareable":
				attachment.IsShareable = boolPointer(true)
			case "unencrypted":
				attachment.IsPvEncryptionInTransitEnabled = boolPointer(false)
			case "detaching":
				attachment.LifecycleState = attachmentStateDetaching
			case "missing attachment":
				delete(provider.attachments, restored.ID)
			case "second scratch volume", "duplicate scratch attachment", "second volume attachment":
				other := attachment
				other.ID = "extra"
				if scenario == "second scratch volume" {
					other.VolumeID = "ocid1.volume.other"
				}
				if scenario == "second volume attachment" {
					other.InstanceID = "ocid1.instance.other"
				}
				provider.attachments[other.ID] = other
			case "member instance", "foreign scratch", "stopped scratch":
				instance := provider.instances[restored.InstanceID]
				if scenario == "member instance" {
					instance.DisplayName = testMember
				}
				if scenario == "foreign scratch" {
					instance.CompartmentID = "0000000000V4MRM46HP1SNGDYW"
				}
				if scenario == "stopped scratch" {
					instance.LifecycleState = "STOPPED"
				}
				provider.instances[restored.InstanceID] = instance
			}
			if scenario != "missing volume" && scenario != "member data volume" {
				provider.volumes[restored.VolumeID] = volume
			}
			if scenario != "missing attachment" {
				provider.attachments[restored.ID] = attachment
			}
			creates, attaches := provider.volumeCreateCalls, provider.attachCalls
			if verified, err := volumes.VerifyRestoredAttachment(t.Context(), restored.InstanceID, restored.VolumeID); err == nil ||
				provider.volumeCreateCalls != creates || provider.attachCalls != attaches || provider.updates != 0 || provider.detaches != 0 || provider.deletes != 0 {
				t.Fatalf("%s passed verification or mutated OCI: %+v, %v", scenario, verified, err)
			}
		})
	}
}
