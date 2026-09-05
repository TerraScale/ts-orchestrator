//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualsuite"
)

func TestRecoveryDataDrivePlanPreservesVMDiskContract(t *testing.T) {
	digest := strings.Repeat("a", 64)
	plan := vmdisk.BootPlan{
		RunID:                       "qualification-run",
		DriveID:                     "gru-member-2",
		Generation:                  7,
		Activation:                  vmdisk.ActivationNextBoot,
		RequiresStoppedGuest:        true,
		Attachment:                  vmdisk.AttachmentAttached,
		Path:                        "/var/lib/terrascale/drives/gru-member-2/data-7.ext4",
		Size:                        64 << 20,
		SHA256:                      digest,
		ReadOnly:                    true,
		RequiresGuestFilesystemFill: false,
		Filesystem:                  vmdisk.DefaultFilesystem(),
	}
	got, err := recoveryDataDrivePlan(plan, plan.RunID, plan.DriveID)
	if err != nil {
		t.Fatal(err)
	}
	want := sandboxvm.DataDrivePlan{
		DriveID: plan.DriveID, Generation: plan.Generation, Attached: true,
		Path: plan.Path, Size: plan.Size, SHA256: plan.SHA256, ReadOnly: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("translated plan = %+v, want %+v", got, want)
	}

	plan.Attachment = vmdisk.AttachmentDetached
	plan.Path, plan.SHA256, plan.ReadOnly = "", "", false
	got, err = recoveryDataDrivePlan(plan, plan.RunID, plan.DriveID)
	if err != nil {
		t.Fatal(err)
	}
	want = sandboxvm.DataDrivePlan{DriveID: plan.DriveID, Generation: plan.Generation, Size: plan.Size}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("translated detached plan = %+v, want %+v", got, want)
	}
}

func TestRecoveryDataDrivePlanRejectsInconsistentRequirements(t *testing.T) {
	valid := vmdisk.BootPlan{
		RunID: "qualification-run", DriveID: "gru-member-2", Generation: 2,
		Activation: vmdisk.ActivationNextBoot, RequiresStoppedGuest: true,
		Attachment: vmdisk.AttachmentAttached, Path: "/data.ext4", Size: 64 << 20,
		SHA256: strings.Repeat("b", 64), Filesystem: vmdisk.DefaultFilesystem(),
	}
	cases := map[string]func(*vmdisk.BootPlan){
		"foreign run":     func(plan *vmdisk.BootPlan) { plan.RunID = "other-run" },
		"live activation": func(plan *vmdisk.BootPlan) { plan.RequiresStoppedGuest = false },
		"missing digest":  func(plan *vmdisk.BootPlan) { plan.SHA256 = "" },
		"fault adapter":   func(plan *vmdisk.BootPlan) { plan.RequiresRuntimeFaultAdapter = true },
		"fill action":     func(plan *vmdisk.BootPlan) { plan.FillToENOSPC = true },
		"detached read-only": func(plan *vmdisk.BootPlan) {
			plan.Attachment, plan.Path, plan.SHA256, plan.ReadOnly = vmdisk.AttachmentDetached, "", "", true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			plan := valid
			mutate(&plan)
			if _, err := recoveryDataDrivePlan(plan, valid.RunID, valid.DriveID); err == nil {
				t.Fatalf("inconsistent plan was accepted: %+v", plan)
			}
		})
	}
}

func TestRecoveryExpansionTargetIsBoundedByDiskBudget(t *testing.T) {
	if got, err := recoveryExpansionTarget(64<<20, 384<<20, 8<<30); err != nil || got != 128<<20 {
		t.Fatalf("default expansion target = %d, err=%v", got, err)
	}
	if got, err := recoveryExpansionTarget(64<<20, 120<<20, 132<<20); err != nil || got != 76<<20 {
		t.Fatalf("budget-limited expansion target = %d, err=%v", got, err)
	}
	if _, err := recoveryExpansionTarget(64<<20, 120<<20, 124<<20); err == nil {
		t.Fatal("sub-minimum expansion budget was accepted")
	}
}

func TestRecoveryStorageEvidenceRequiresGuestDeviceAndWrite(t *testing.T) {
	observe := vmguest.StorageObservation{
		Action: vmguest.StorageActionObserve, Device: recoveryDataDevice,
		MountPath: recoveryDataMount, Filesystem: vmdisk.FilesystemExt4,
		Mounted: true, TotalBytes: 64 << 20, Healthy: true,
	}
	if !recoveryHealthyStorage(observe) {
		t.Fatalf("healthy storage was rejected: %+v", observe)
	}
	observe.Device = "/dev/vdc"
	if recoveryHealthyStorage(observe) {
		t.Fatal("foreign guest device was accepted")
	}
}

func TestRecoveryShapeFallbackUsesOCIReconcilerAndHTTPProvider(t *testing.T) {
	observation, err := (&firecrackerFactory{}).ExhaustA1AndFallback(context.Background(), vmqual.Guest{
		ID: "gru-member-2", Region: vmnet.GRU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observation.Attempts, []string{recoveryPrimaryShape, recoveryFallbackShape}) {
		t.Fatalf("shape attempts = %v", observation.Attempts)
	}
	if !observation.A1CapacityExhausted || observation.SelectedShape != recoveryFallbackShape ||
		observation.SelectedArchitecture != "amd64" || !observation.ReplacementReady {
		t.Fatalf("shape fallback observation = %+v", observation)
	}
	if err := vmqualsuite.ValidateShapeFallback(observation); err != nil {
		t.Fatalf("validated fallback: %v", err)
	}
}

func TestRecoveryCertificateUsesExpiredRenewalAndTLSReadback(t *testing.T) {
	observation, err := exerciseCertificateRotation(context.Background(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	if observation.ExpiredSerial == observation.RotatedSerial || !observation.ExpiredRejected ||
		!observation.RotatedAccepted || !observation.ServiceHealthy {
		t.Fatalf("certificate rotation observation = %+v", observation)
	}
	if err := vmqualsuite.ValidateCertificateRotation(observation); err != nil {
		t.Fatalf("validated certificate rotation: %v", err)
	}
}

func TestRecoveryClockFailsClosedWithoutTerraBaseEvidence(t *testing.T) {
	observation, err := (&firecrackerFactory{}).SkewClockAndRepair(context.Background(), vmqual.Guest{})
	if !errors.Is(err, errRecoveryClockUnavailable) {
		t.Fatalf("clock error = %v", err)
	}
	if observation.WritesFenced || observation.WritesAdmittedAfter || observation.SuspectHLCMinted {
		t.Fatalf("unobserved clock claims = %+v", observation)
	}
}
