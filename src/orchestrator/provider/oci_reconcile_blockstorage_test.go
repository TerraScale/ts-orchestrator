package provider

import (
	"context"
	"testing"
)

// fakeBlockGateway models volumes and attachments.
type fakeBlockGateway struct {
	volumes     []ObservedVolume
	attachments []ObservedAttachment
	nextID      int
}

func (f *fakeBlockGateway) ListVolumes(ctx context.Context) ([]ObservedVolume, error) {
	return f.volumes, nil
}

func (f *fakeBlockGateway) CreateVolume(ctx context.Context, spec VolumeSpec) (ObservedVolume, error) {
	f.nextID++
	created := ObservedVolume{ID: "ocid1.volume.oc1.x." + string(rune('a'+f.nextID)), DisplayName: spec.DisplayName, SizeGiB: spec.SizeGiB, VPUsPerGiB: spec.VPUsPerGiB, LifecycleState: "AVAILABLE", AvailabilityDomain: spec.AvailabilityDomain}
	f.volumes = append(f.volumes, created)
	return created, nil
}

func (f *fakeBlockGateway) ExpandVolume(ctx context.Context, volumeID string, sizeGiB uint64) error {
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
	f.nextID++
	created := ObservedAttachment{ID: "ocid1.volumeattachment.oc1.x." + string(rune('a'+f.nextID)), InstanceID: instanceID, VolumeID: volumeID, LifecycleState: "ATTACHED"}
	f.attachments = append(f.attachments, created)
	return created, nil
}

func (f *fakeBlockGateway) DetachAttachment(ctx context.Context, attachmentID string) error {
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

func TestBlockStorageReconcilePlans(t *testing.T) {
	declared := testComputeRegion()
	member1 := ObservedMember{ID: "ocid1.instance.oc1.x.1", Index: 1, Shape: "VM.Standard.A1.Flex", LifecycleState: "RUNNING", AvailabilityDomain: "AD-1"}
	member2 := ObservedMember{ID: "ocid1.instance.oc1.x.2", Index: 2, Shape: "VM.Standard.A1.Flex", LifecycleState: "RUNNING", AvailabilityDomain: "AD-2"}
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
					{ID: "ocid1.volume.oc1.x.1", DisplayName: "terrascale-gru-1-data", SizeGiB: 200, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "AVAILABLE"},
					{ID: "ocid1.volume.oc1.x.2", DisplayName: "terrascale-gru-2-data", SizeGiB: 200, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "AVAILABLE"},
				}
				observed.Attachments = []ObservedAttachment{
					{ID: "ocid1.volumeattachment.oc1.x.1", InstanceID: member1.ID, VolumeID: "ocid1.volume.oc1.x.1", LifecycleState: "ATTACHED"},
					{ID: "ocid1.volumeattachment.oc1.x.2", InstanceID: member2.ID, VolumeID: "ocid1.volume.oc1.x.2", LifecycleState: "ATTACHED"},
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
					{ID: "ocid1.volume.oc1.x.1", DisplayName: "terrascale-gru-1-data", SizeGiB: 50, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "AVAILABLE"},
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
					{ID: "ocid1.volume.oc1.x.1", DisplayName: "terrascale-gru-1-data", SizeGiB: 500, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "AVAILABLE"},
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
					{ID: "ocid1.volume.oc1.x.1", DisplayName: "terrascale-gru-1-data", SizeGiB: 200, VPUsPerGiB: 20, LifecycleState: "AVAILABLE"},
				}
				return observed
			}(),
			wantErr: true,
		},
		{
			name: "attachment to the wrong instance is replanned",
			observed: func() BlockStorageObserved {
				observed := testBlockObserved(member1, member2)
				observed.Volumes = []ObservedVolume{
					{ID: "ocid1.volume.oc1.x.1", DisplayName: "terrascale-gru-1-data", SizeGiB: 200, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "AVAILABLE"},
				}
				observed.Attachments = []ObservedAttachment{
					{ID: "ocid1.volumeattachment.oc1.x.1", InstanceID: member2.ID, VolumeID: "ocid1.volume.oc1.x.1", LifecycleState: "ATTACHED"},
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
	member1 := ObservedMember{ID: "ocid1.instance.oc1.x.1", Index: 1, Shape: declared.Members.PrimaryShape, LifecycleState: "RUNNING", AvailabilityDomain: "AD-1"}
	member2 := ObservedMember{ID: "ocid1.instance.oc1.x.2", Index: 2, Shape: declared.Members.PrimaryShape, LifecycleState: "RUNNING", AvailabilityDomain: "AD-2"}
	reconciler := &BlockStorageReconciler{Block: &fakeBlockGateway{}, Compute: &fakeComputeGateway{}}
	observed := testBlockObserved(member1, member2)
	observed.Volumes = []ObservedVolume{
		{ID: "ocid1.volume.oc1.x.1", DisplayName: DataVolumeName("gru", 1), SizeGiB: 200, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "CREATING"},
		{ID: "ocid1.volume.oc1.x.2", DisplayName: DataVolumeName("gru", 2), SizeGiB: 200, VPUsPerGiB: BalancedVPUsPerGiB, LifecycleState: "CREATING"},
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

func countKinds(plan OCIPlan, kind OCIActionKind) int {
	total := 0
	for _, action := range plan.Actions {
		if action.Kind() == kind {
			total++
		}
	}
	return total
}
