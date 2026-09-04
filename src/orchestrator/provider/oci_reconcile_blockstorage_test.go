package provider

import (
	"context"
	"errors"
	"testing"
)

// fakeBlockGateway models volumes and attachments.
type fakeBlockGateway struct {
	volumes     []ObservedVolume
	attachments []ObservedAttachment
	nextID      int
	createErr   error
	expandErr   error
	attachErr   error
	detachErr   error
	calls       []string
}

func (f *fakeBlockGateway) ListVolumes(ctx context.Context) ([]ObservedVolume, error) {
	return f.volumes, nil
}

func (f *fakeBlockGateway) CreateVolume(ctx context.Context, spec VolumeSpec) (ObservedVolume, error) {
	f.calls = append(f.calls, "create")
	if f.createErr != nil {
		return ObservedVolume{}, f.createErr
	}
	f.nextID++
	created := ObservedVolume{ID: "ocid1.volume.oc1.x." + string(rune('a'+f.nextID)), DisplayName: spec.DisplayName, SizeGiB: spec.SizeGiB, VPUsPerGiB: spec.VPUsPerGiB, LifecycleState: "AVAILABLE", AvailabilityDomain: spec.AvailabilityDomain, KMSKeyID: spec.KMSKeyID, FreeformTags: volumeOwnershipTags(spec.DisplayName)}
	f.volumes = append(f.volumes, created)
	return created, nil
}

func (f *fakeBlockGateway) ExpandVolume(ctx context.Context, volumeID string, sizeGiB uint64) error {
	f.calls = append(f.calls, "expand")
	if f.expandErr != nil {
		return f.expandErr
	}
	for i := range f.volumes {
		if f.volumes[i].ID == volumeID {
			f.volumes[i].SizeGiB = sizeGiB
		}
	}
	return nil
}

func (f *fakeBlockGateway) ListAttachments(ctx context.Context) ([]ObservedAttachment, error) {
	return f.attachments, nil
}

func (f *fakeBlockGateway) AttachVolume(ctx context.Context, instanceID, volumeID, displayName string) (ObservedAttachment, error) {
	f.calls = append(f.calls, "attach")
	if f.attachErr != nil {
		return ObservedAttachment{}, f.attachErr
	}
	f.nextID++
	created := ObservedAttachment{ID: "ocid1.volumeattachment.oc1.x." + string(rune('a'+f.nextID)), InstanceID: instanceID, VolumeID: volumeID, LifecycleState: "ATTACHED", Managed: true}
	f.attachments = append(f.attachments, created)
	return created, nil
}

func (f *fakeBlockGateway) DetachAttachment(ctx context.Context, attachmentID string) error {
	f.calls = append(f.calls, "detach")
	if f.detachErr != nil {
		return f.detachErr
	}
	remaining := f.attachments[:0]
	for _, attachment := range f.attachments {
		if attachment.ID != attachmentID {
			remaining = append(remaining, attachment)
		}
	}
	f.attachments = remaining
	return nil
}

func testBlockObserved(members ...ObservedMember) BlockStorageObserved {
	return BlockStorageObserved{Members: members}
}

func testOwnedVolume(region string, index int, id string, size uint64, state, availabilityDomain string) ObservedVolume {
	return ObservedVolume{
		ID: id, DisplayName: DataVolumeName(region, index), SizeGiB: size,
		VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: state,
		AvailabilityDomain: availabilityDomain, FreeformTags: volumeOwnershipTags(DataVolumeName(region, index)),
	}
}

func testOwnedAttachment(id, instanceID, volumeID, state string) ObservedAttachment {
	return ObservedAttachment{ID: id, InstanceID: instanceID, VolumeID: volumeID, LifecycleState: state, Managed: true}
}

func TestBlockStorageReconcilePlans(t *testing.T) {
	declared := testComputeRegion()
	member1 := testOwnedMember("gru", 1, "VM.Standard.A1.Flex", "RUNNING", "AD-1")
	member2 := testOwnedMember("gru", 2, "VM.Standard.A1.Flex", "RUNNING", "AD-2")
	cases := []struct {
		name      string
		observed  BlockStorageObserved
		wantKinds []OCIActionKind
		wantErr   bool
	}{
		{
			name:      "two members no volumes plans two balanced volumes",
			observed:  testBlockObserved(member1, member2),
			wantKinds: []OCIActionKind{OCIActionCreateVolume, OCIActionCreateVolume},
		},
		{
			name: "converged volumes plan nothing",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 200, "AVAILABLE", "AD-1"),
					testOwnedVolume("gru", 2, "ocid1.volume.oc1.x.2", 200, "AVAILABLE", "AD-2"),
				}
				observed.Attachments = []ObservedAttachment{
					testOwnedAttachment("ocid1.volumeattachment.oc1.x.1", member1.ID, "ocid1.volume.oc1.x.1", "ATTACHED"),
					testOwnedAttachment("ocid1.volumeattachment.oc1.x.2", member2.ID, "ocid1.volume.oc1.x.2", "ATTACHED"),
				}
				return observed
			}(),
			wantKinds: nil,
		},
		{
			name: "undersized volume plans an expand",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 50, "AVAILABLE", "AD-1"),
				}
				return observed
			}(),
			wantKinds: []OCIActionKind{OCIActionExpandVolume, OCIActionAttachVolume, OCIActionCreateVolume},
		},
		{
			name: "oversized volume is refused",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 500, "AVAILABLE", "AD-1"),
				}
				return observed
			}(),
			wantErr: true,
		},
		{
			name: "volume on the wrong performance tier is refused",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 200, "AVAILABLE", "AD-1"),
				}
				observed.Volumes[0].VPUsPerGiB = 20
				return observed
			}(),
			wantErr: true,
		},
		{
			name: "attachment to the wrong instance is replanned",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 200, "AVAILABLE", "AD-1"),
				}
				observed.Attachments = []ObservedAttachment{
					testOwnedAttachment("ocid1.volumeattachment.oc1.x.1", member2.ID, "ocid1.volume.oc1.x.1", "ATTACHED"),
				}
				return observed
			}(),
			wantKinds: []OCIActionKind{OCIActionDetachAttachment, OCIActionAttachVolume, OCIActionCreateVolume},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &BlockStorageReconciler{Block: &fakeBlockGateway{}, Compute: &fakeComputeGateway{}}
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Reconcile() = %v, want drift error", plan.Kinds())
				}
				return
			}
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
		})
	}
}

func TestBlockStorageApplyConvergesIdempotently(t *testing.T) {
	declared := testComputeRegion()
	block := &fakeBlockGateway{}
	compute := &fakeComputeGateway{}
	compute.addMember("ocid1.instance.oc1.x.1", 1, "VM.Standard.A1.Flex", "RUNNING")
	compute.addMember("ocid1.instance.oc1.x.2", 2, "VM.Standard.A1.Flex", "RUNNING")
	reconciler := &BlockStorageReconciler{Block: block, Compute: compute}
	ctx := context.Background()
	creates := 0
	for pass := 0; pass < 4; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("observe failed: %v", err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		if plan.Empty() {
			if len(block.volumes) != 2 || len(block.attachments) != 2 {
				t.Fatalf("volumes = %d, attachments = %d, want 2 and 2", len(block.volumes), len(block.attachments))
			}
			for _, volume := range block.volumes {
				if volume.SizeGiB != 200 || volume.VPUsPerGiB != BalancedVPUsPerGiB {
					t.Fatalf("volume %s = %+v, want 200 GiB Balanced", volume.DisplayName, volume)
				}
			}
			if creates != 2 {
				t.Fatalf("create volume calls = %d, want exactly 2 (idempotent)", creates)
			}
			return
		}
		creates += countKinds(plan, OCIActionCreateVolume)
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
	}
	t.Fatal("block storage did not converge in four passes")
}

func TestBlockStoragePendingFailedAndDuplicateResources(t *testing.T) {
	declared := testComputeRegion()
	member1 := testOwnedMember("gru", 1, declared.Members.PrimaryShape, "RUNNING", "AD-1")
	member2 := testOwnedMember("gru", 2, declared.Members.PrimaryShape, "RUNNING", "AD-2")
	reconciler := &BlockStorageReconciler{Block: &fakeBlockGateway{}, Compute: &fakeComputeGateway{}}
	observed := testBlockObserved(member1, member2)
	observed.Volumes = []ObservedVolume{
		testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 200, "CREATING", "AD-1"),
		testOwnedVolume("gru", 2, "ocid1.volume.oc1.x.2", 200, "CREATING", "AD-2"),
	}
	plan, err := reconciler.Reconcile(context.Background(), declared, observed)
	if err != nil || !plan.Empty() {
		t.Fatalf("pending volume reconcile = %v, %v; want empty retry plan", plan.Kinds(), err)
	}
	converged, err := reconciler.bootstrapConverged(observed, declared)
	if err != nil || converged {
		t.Fatalf("pending volume convergence = %v, %v; want false", converged, err)
	}
	failed := observed
	failed.Volumes[0].LifecycleState = "FAILED"
	if _, err := reconciler.Reconcile(context.Background(), declared, failed); err == nil {
		t.Fatal("failed volume accepted")
	}
	duplicate := observed
	duplicate.Volumes = append(duplicate.Volumes, duplicate.Volumes[0])
	if _, err := reconciler.Reconcile(context.Background(), declared, duplicate); err == nil {
		t.Fatal("duplicate volume accepted")
	}
}

func TestBlockStorageFullVolumePlansBoundedExpansion(t *testing.T) {
	declared := testComputeRegion()
	member := testOwnedMember("gru", 1, declared.Members.PrimaryShape, "RUNNING", "AD-1")
	observed := testBlockObserved(member)
	observed.Volumes = []ObservedVolume{testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.full", 200, "AVAILABLE", "AD-1")}
	observed.Volumes[0].UtilizationPercent = 99
	plan, err := (&BlockStorageReconciler{Block: &fakeBlockGateway{}, Compute: &fakeComputeGateway{}}).Reconcile(context.Background(), declared, observed)
	if err != nil {
		t.Fatalf("full volume reconcile failed: %v", err)
	}
	if len(plan.Actions) != 2 || plan.Actions[0].Kind() != OCIActionExpandVolume || plan.Actions[1].Kind() != OCIActionAttachVolume {
		t.Fatalf("full volume plan = %v, want bounded expansion then attach", plan.Kinds())
	}
	if got := plan.Actions[0].(ExpandVolumeAction).NewSizeGiB; got != 400 {
		t.Fatalf("full volume target = %d, want 400 GiB", got)
	}

	observed.Volumes[0].SizeGiB = DefaultMaxVolumeGiB
	if _, err := (&BlockStorageReconciler{Block: &fakeBlockGateway{}, Compute: &fakeComputeGateway{}}).Reconcile(context.Background(), declared, observed); err == nil {
		t.Fatal("full volume at bound was accepted")
	}
}

func TestBlockStorageUnhealthyVolumeRequiresProvenReplacement(t *testing.T) {
	declared := testComputeRegion()
	member := testOwnedMember("gru", 1, declared.Members.PrimaryShape, "RUNNING", "AD-1")
	observed := testBlockObserved(member)
	observed.Volumes = []ObservedVolume{testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.bad", 200, "ERROR", "AD-1")}
	observed.Volumes[0].KMSKeyID = "ocid1.key.oc1.x.key"
	observed.Volumes[0].BackupVerified = true
	observed.Volumes[0].ReplicaCount = 2
	observed.Attachments = []ObservedAttachment{testOwnedAttachment("ocid1.volumeattachment.oc1.x.old", member.ID, observed.Volumes[0].ID, "ATTACHED")}
	block := &fakeBlockGateway{volumes: observed.Volumes, attachments: observed.Attachments}
	compute := &fakeComputeGateway{members: []ObservedMember{member}}
	reconciler := &BlockStorageReconciler{Block: block, Compute: compute, Policy: BlockStoragePolicy{AllowReplacement: true}}
	plan, err := reconciler.Reconcile(context.Background(), declared, observed)
	if err != nil {
		t.Fatalf("replacement reconcile failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind() != OCIActionCreateVolume {
		t.Fatalf("replacement plan = %v, want one replacement action", plan.Kinds())
	}
	replacement := plan.Actions[0].(ReplaceVolumeAction)
	if replacement.OldVolumeID != observed.Volumes[0].ID || replacement.OldAttachmentID != observed.Attachments[0].ID || replacement.Spec.AvailabilityDomain != "AD-1" || replacement.Spec.KMSKeyID != observed.Volumes[0].KMSKeyID {
		t.Fatalf("replacement lost identity/residency: %+v", replacement)
	}
	if err := reconciler.Apply(context.Background(), declared, observed, plan); err != nil {
		t.Fatalf("replacement apply failed: %v", err)
	}
	block = reconciler.Block.(*fakeBlockGateway)
	if got, want := block.calls, []string{"create", "attach", "detach"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("replacement calls = %v, want create/attach/detach", got)
	}
}

func TestBlockStorageApplyPreservesUnownedAndStaleAttachments(t *testing.T) {
	declared := testComputeRegion()
	member := testOwnedMember("gru", 1, declared.Members.PrimaryShape, "RUNNING", "AD-1")
	volume := testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 200, "AVAILABLE", "AD-1")
	expected := testOwnedAttachment("ocid1.volumeattachment.oc1.x.old", member.ID, volume.ID, "ATTACHED")
	foreign := expected
	foreign.Managed = false
	block := &fakeBlockGateway{volumes: []ObservedVolume{volume}, attachments: []ObservedAttachment{foreign}}
	compute := &fakeComputeGateway{members: []ObservedMember{member}}
	reconciler := &BlockStorageReconciler{Block: block, Compute: compute}
	plan := OCIPlan{Actions: []OCIAction{DetachAttachmentAction{AttachmentID: expected.ID}}}
	err := reconciler.Apply(context.Background(), declared, BlockStorageObserved{
		Members: []ObservedMember{member}, Volumes: []ObservedVolume{volume}, Attachments: []ObservedAttachment{expected},
	}, plan)
	if err == nil {
		t.Fatal("unowned attachment detach was accepted")
	}
	if len(block.calls) != 0 {
		t.Fatalf("unowned detach calls = %v, want none", block.calls)
	}

	block.calls = nil
	block.attachments = []ObservedAttachment{expected}
	stale := expected
	stale.LifecycleState = "DETACHED"
	err = reconciler.Apply(context.Background(), declared, BlockStorageObserved{
		Members: []ObservedMember{member}, Volumes: []ObservedVolume{volume}, Attachments: []ObservedAttachment{stale},
	}, plan)
	if err == nil {
		t.Fatal("stale attachment detach was accepted")
	}
	if len(block.calls) != 0 {
		t.Fatalf("stale detach calls = %v, want none", block.calls)
	}
}

func TestBlockStorageUnknownMutationOutcomeStopsPlan(t *testing.T) {
	declared := testComputeRegion()
	member := testOwnedMember("gru", 1, declared.Members.PrimaryShape, "RUNNING", "AD-1")
	volume := testOwnedVolume("gru", 1, "ocid1.volume.oc1.x.1", 50, "AVAILABLE", "AD-1")
	block := &fakeBlockGateway{expandErr: &ProviderOutcomeUnknownError{Message: "accepted by OCI"}}
	reconciler := &BlockStorageReconciler{Block: block, Compute: &fakeComputeGateway{}}
	plan, err := reconciler.Reconcile(context.Background(), declared, testBlockObserved(member))
	if err != nil {
		t.Fatal(err)
	}
	// Use a plan containing a mutating operation followed by attach: Apply must
	// stop at the indeterminate operation and never risk a second mutation.
	plan.Actions = []OCIAction{ExpandVolumeAction{VolumeID: volume.ID, NewSizeGiB: 200}, AttachVolumeAction{InstanceID: member.ID, VolumeID: volume.ID}}
	observed := testBlockObserved(member)
	observed.Volumes = []ObservedVolume{volume}
	err = reconciler.Apply(context.Background(), declared, observed, plan)
	var unknown *ProviderOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("unknown mutation error = %v, want ProviderOutcomeUnknownError", err)
	}
	if len(block.calls) != 1 || block.calls[0] != "expand" {
		t.Fatalf("calls after unknown outcome = %v, want only expand", block.calls)
	}
}

func countKinds(plan OCIPlan, kind OCIActionKind) int {
	total := 0
	for _, action := range plan.Actions {
		if action.Kind() == kind {
			total++
		}
	}
	return total
}
