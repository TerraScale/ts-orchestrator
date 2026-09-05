//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"

	sandboxoci "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/oci"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

const (
	recoveryPrimaryShape  = "VM.Standard.A1.Flex"
	recoveryFallbackShape = "VM.Standard.E5.Flex"
	recoveryOCIRegion     = "sa-saopaulo-1"
	recoveryDataDevice    = "/dev/vdb"
	recoveryDataMount     = "/var/lib/terrascale"
	recoveryExpansionStep = int64(64 << 20)
	recoveryMinExpansion  = int64(8 << 20)
	recoveryFillStep      = uint64(64 << 20)
	recoveryExt4Magic     = int64(1024 + 56)
)

var (
	errRecoveryCatchUpUnavailable = errors.New("vmqual: TerraBase exposes no guest-bound replication commit or catch-up observation")
	errRecoveryClockUnavailable   = errors.New("vmqual: TerraBase exposes no guest-bound write fence or HLC observation")
	errRecoveryIOFaultUnavailable = errors.New("vmqual: no real Firecracker data-drive I/O-failure adapter is configured")
)

// KillReplaceAndCatchUp proves the lifecycle and durable-volume prerequisites
// of host replacement. The current TerraBase artifact does not expose a
// replication commit or catch-up observation, so this method keeps the final
// catch-up claim false and returns a typed fail-closed error after collecting
// the evidence that is available.
func (factory *firecrackerFactory) KillReplaceAndCatchUp(ctx context.Context, guest vmqual.Guest) (vmqual.HostRecoveryObservation, error) {
	observation := vmqual.HostRecoveryObservation{FailedVMID: guest.ID}
	vm, err := factory.recoveryVM(guest)
	if err != nil {
		return observation, err
	}
	before, err := vm.Inspect(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect recovery target before stop: %w", err)
	}
	if !before.Running || !before.Ready || before.Process.PID <= 0 || before.Process.StartTimeTicks == 0 {
		return observation, errors.New("vmqual: recovery target is not a ready observed Firecracker process")
	}
	commit := uint64(time.Now().UTC().UnixNano())
	if commit == 0 {
		commit = 1
	}
	marker := make([]byte, 8+16)
	for shift := uint(0); shift < 64; shift += 8 {
		marker[shift/8] = byte(commit >> (56 - shift))
	}
	if _, err := rand.Read(marker[8:]); err != nil {
		return observation, fmt.Errorf("vmqual: create recovery marker: %w", err)
	}
	if err := vm.DataWrite(ctx, "recovery/commit", marker); err != nil {
		return observation, fmt.Errorf("vmqual: persist recovery marker: %w", err)
	}
	observation.CatchUpTarget = commit
	if err := vm.Stop(ctx); err != nil {
		return observation, fmt.Errorf("vmqual: stop failed recovery target: %w", err)
	}
	stopped, err := vm.Inspect(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect stopped recovery target: %w", err)
	}
	observation.FailedVMStopped = !stopped.Running
	if !observation.FailedVMStopped {
		return observation, errors.New("vmqual: failed recovery target remained running")
	}
	if err := vm.StartReady(ctx); err != nil {
		return observation, fmt.Errorf("vmqual: start replacement process: %w", err)
	}
	after, err := vm.Inspect(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect replacement process: %w", err)
	}
	if after.Process.PID <= 0 || after.Process.StartTimeTicks == 0 ||
		(after.Process.PID == before.Process.PID && after.Process.StartTimeTicks == before.Process.StartTimeTicks) {
		return observation, errors.New("vmqual: replacement did not have a new observed process incarnation")
	}
	observation.ReplacementVMID = fmt.Sprintf("%s@%d:%d", guest.ID, after.Process.PID, after.Process.StartTimeTicks)
	observation.ReplacementRunning = after.Running
	observation.ReplacementReady = after.Ready
	recovered, err := vm.DataRead(ctx, "recovery/commit")
	if err != nil {
		return observation, fmt.Errorf("vmqual: read replacement recovery marker: %w", err)
	}
	if !bytes.Equal(recovered, marker) {
		return observation, errors.New("vmqual: replacement did not retain the durable recovery marker")
	}
	observation.ReplacementCommit = commit
	// A durable local marker is not replication catch-up. Keep the field false
	// until TerraBase exposes the remote commit index observed by this guest.
	observation.ReplacementCaughtUp = false
	return observation, errRecoveryCatchUpUnavailable
}

// SkewClockAndRepair fails closed because neither ts-node nor TerraBase
// exposes a guest-bound write refusal and HLC identity. Hostagent's chrony
// heartbeat alone cannot prove that the engine rejected a write without
// minting an HLC.
func (*firecrackerFactory) SkewClockAndRepair(context.Context, vmqual.Guest) (vmqual.ClockFenceObservation, error) {
	return vmqual.ClockFenceObservation{}, errRecoveryClockUnavailable
}

func (factory *firecrackerFactory) recoveryVM(guest vmqual.Guest) (*sandboxVM, error) {
	if factory == nil || guest.ID == "" {
		return nil, errors.New("vmqual: recovery factory or guest is missing")
	}
	factory.activeMu.Lock()
	vm := factory.active[guest.ID]
	factory.activeMu.Unlock()
	if vm == nil || vm.guest != guest {
		return nil, fmt.Errorf("vmqual: recovery guest %s is not owned by the factory", guest.ID)
	}
	return vm, nil
}

// ExerciseDiskFault consumes vmdisk's next-boot contract through the live
// Firecracker provider and derives every result from the guest storage
// diagnostic. The I/O-failure mode stays unavailable until the provider is
// constructed with a real faulting block-device adapter.
func (factory *firecrackerFactory) ExerciseDiskFault(ctx context.Context, guest vmqual.Guest, mode vmqual.DiskFaultMode) (vmqual.DiskFaultObservation, error) {
	observation := vmqual.DiskFaultObservation{VMID: guest.ID, Mode: mode}
	if ctx == nil {
		return observation, errors.New("vmqual: disk fault context is nil")
	}
	vm, err := factory.recoveryVM(guest)
	if err != nil {
		return observation, err
	}
	if vm.provider == nil || vm.disks == nil {
		return observation, errors.New("vmqual: recovery data-drive ownership is not configured")
	}
	before, err := recoveryReadyVM(ctx, vm)
	if err != nil {
		return observation, err
	}
	baseline, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionObserve, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: observe healthy data drive before %s: %w", mode, err)
	}
	if !recoveryHealthyStorage(baseline) {
		return observation, fmt.Errorf("vmqual: data drive is not healthy before %s: %+v", mode, baseline)
	}

	switch mode {
	case vmqual.DiskFaultENOSPC:
		return exerciseRecoveryENOSPC(ctx, vm, before, baseline, observation)
	case vmqual.DiskFaultIOFailure:
		observation.Disposition = vmqual.FaultDispositionFailClosed
		observation.FailClosed = true
		return observation, errRecoveryIOFaultUnavailable
	case vmqual.DiskFaultReadOnly:
		return exerciseRecoveryReadOnly(ctx, vm, before, observation)
	case vmqual.DiskFaultMissingAtBoot:
		return exerciseRecoveryMissing(ctx, vm, before, observation)
	case vmqual.DiskFaultExpansion:
		return exerciseRecoveryExpansion(ctx, vm, before, baseline, observation)
	case vmqual.DiskFaultCorruption:
		return exerciseRecoveryCorruption(ctx, vm, before, observation)
	default:
		return observation, fmt.Errorf("vmqual: unsupported disk fault mode %q", mode)
	}
}

func exerciseRecoveryENOSPC(ctx context.Context, vm *sandboxVM, before vmqual.VMObservation, baseline vmguest.StorageObservation, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareFaultPlan(ctx, vm.id, vmdisk.FaultPlan{FillAll: true}); err != nil {
		return observation, fmt.Errorf("vmqual: prepare ENOSPC next-boot plan: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true, fill: true}); err != nil {
		return observation, err
	}
	faultVM, err := recoveryStartVM(ctx, vm, before, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: start ENOSPC guest: %w", err)
	}
	observation.RestartObserved = recoveryProcessChanged(before, faultVM)
	filled, err := recoveryFillToENOSPC(ctx, vm, baseline.AvailableBytes)
	if err != nil {
		return observation, err
	}
	observation.GuestVisible = recoveryMountedStorage(filled)
	observation.FailureObserved = filled.Errno == vmguest.StorageErrnoENOSPC && filled.AttemptedBytes > 0
	if !observation.GuestVisible || !observation.FailureObserved {
		return observation, fmt.Errorf("vmqual: guest did not observe ENOSPC: %+v", filled)
	}
	observation.RepairAttempted = true
	cleared, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionClearFill, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: clear guest ENOSPC fill: %w", err)
	}
	if !recoveryMountedStorage(cleared) || cleared.Errno != vmguest.StorageErrnoNone {
		return observation, fmt.Errorf("vmqual: guest ENOSPC fill was not cleared: %+v", cleared)
	}
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareClearFaults(ctx, vm.id); err != nil {
		return observation, fmt.Errorf("vmqual: clear ENOSPC next-boot intent: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	if _, err := recoveryStartVM(ctx, vm, faultVM, true); err != nil {
		return observation, fmt.Errorf("vmqual: start repaired ENOSPC guest: %w", err)
	}
	observation.CapacityBeforeBytes = baseline.TotalBytes
	return recoveryFinishDiskRepair(ctx, vm, observation)
}

func exerciseRecoveryReadOnly(ctx context.Context, vm *sandboxVM, before vmqual.VMObservation, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareFaultPlan(ctx, vm.id, vmdisk.FaultPlan{ReadOnly: true}); err != nil {
		return observation, fmt.Errorf("vmqual: prepare read-only next-boot plan: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true, readOnly: true}); err != nil {
		return observation, err
	}
	faultVM, err := recoveryStartVM(ctx, vm, before, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: start read-only guest: %w", err)
	}
	observation.RestartObserved = recoveryProcessChanged(before, faultVM)
	observed, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionObserve, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: observe read-only data drive: %w", err)
	}
	probe, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionProbeWrite, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: probe read-only data drive: %w", err)
	}
	observation.GuestVisible = recoveryMountedStorage(observed) && observed.ReadOnly && recoveryMountedStorage(probe)
	observation.FailureObserved = probe.Errno == vmguest.StorageErrnoEROFS && probe.AttemptedBytes > 0 && probe.WrittenBytes == 0
	if !observation.GuestVisible || !observation.FailureObserved {
		return observation, fmt.Errorf("vmqual: guest did not observe a read-only write refusal: observe=%+v probe=%+v", observed, probe)
	}
	observation.RepairAttempted = true
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareClearFaults(ctx, vm.id); err != nil {
		return observation, fmt.Errorf("vmqual: clear read-only next-boot intent: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	if _, err := recoveryStartVM(ctx, vm, faultVM, true); err != nil {
		return observation, fmt.Errorf("vmqual: start repaired read-only guest: %w", err)
	}
	return recoveryFinishDiskRepair(ctx, vm, observation)
}

func exerciseRecoveryMissing(ctx context.Context, vm *sandboxVM, before vmqual.VMObservation, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareAttachment(ctx, vm.id, false); err != nil {
		return observation, fmt.Errorf("vmqual: prepare detached next-boot plan: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{}); err != nil {
		return observation, err
	}
	faultVM, err := recoveryStartVM(ctx, vm, before, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: start guest without data drive: %w", err)
	}
	observation.RestartObserved = recoveryProcessChanged(before, faultVM)
	missing, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionObserve, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: observe missing data drive: %w", err)
	}
	observation.GuestVisible = recoveryStorageIdentity(missing) && !missing.Mounted
	observation.FailureObserved = missing.Errno == vmguest.StorageErrnoENODEV
	if !observation.GuestVisible || !observation.FailureObserved || !observation.RestartObserved {
		return observation, fmt.Errorf("vmqual: missing data drive was not observed on a new boot: %+v", missing)
	}
	observation.RepairAttempted = true
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareAttachment(ctx, vm.id, true); err != nil {
		return observation, fmt.Errorf("vmqual: prepare data-drive reattachment: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	if _, err := recoveryStartVM(ctx, vm, faultVM, true); err != nil {
		return observation, fmt.Errorf("vmqual: start guest after data-drive reattachment: %w", err)
	}
	return recoveryFinishDiskRepair(ctx, vm, observation)
}

func exerciseRecoveryExpansion(ctx context.Context, vm *sandboxVM, before vmqual.VMObservation, baseline vmguest.StorageObservation, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	drive, err := vm.disks.Get(ctx, vm.id)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect data drive before expansion: %w", err)
	}
	usage, err := vm.disks.Usage(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect disk budget before expansion: %w", err)
	}
	target, err := recoveryExpansionTarget(drive.Size, usage.Bytes, vm.factory.config.MaxDiskBytes)
	if err != nil {
		return observation, err
	}
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareExpansion(ctx, vm.id, target); err != nil {
		return observation, fmt.Errorf("vmqual: prepare expanded next-boot plan: %w", err)
	}
	plan, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true, grow: true})
	if err != nil {
		return observation, err
	}
	expandedVM, err := recoveryStartVM(ctx, vm, before, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: start guest with expanded data drive: %w", err)
	}
	observation.RestartObserved = recoveryProcessChanged(before, expandedVM)
	observation.RepairAttempted = true
	grown, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionGrow, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: grow guest data filesystem: %w", err)
	}
	observation.GuestVisible = recoveryMountedStorage(grown)
	observation.CapacityBeforeBytes = baseline.TotalBytes
	observation.CapacityAfterBytes = grown.TotalBytes
	if !observation.GuestVisible || grown.Errno != vmguest.StorageErrnoNone || grown.ExitCode != 0 || !grown.Healthy || observation.CapacityAfterBytes <= observation.CapacityBeforeBytes {
		return observation, fmt.Errorf("vmqual: guest filesystem capacity did not grow: before=%d result=%+v", baseline.TotalBytes, grown)
	}
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if err := recoveryAcknowledgeFilesystemGrow(ctx, vm, plan.Generation); err != nil {
		return observation, err
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	if _, err := recoveryStartVM(ctx, vm, expandedVM, true); err != nil {
		return observation, fmt.Errorf("vmqual: start guest after acknowledging filesystem growth: %w", err)
	}
	return recoveryFinishDiskRepair(ctx, vm, observation)
}

func exerciseRecoveryCorruption(ctx context.Context, vm *sandboxVM, before vmqual.VMObservation, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	snapshot, err := vm.disks.Snapshot(ctx, vm.id)
	if err != nil {
		return observation, fmt.Errorf("vmqual: snapshot clean data drive: %w", err)
	}
	corruption := vmdisk.Corruption{Offset: recoveryExt4Magic, Length: 2, Pattern: 0}
	if _, err := vm.disks.PrepareFaultPlan(ctx, vm.id, vmdisk.FaultPlan{Corruptions: []vmdisk.Corruption{corruption}}); err != nil {
		return observation, fmt.Errorf("vmqual: prepare corrupt next-boot plan: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	faultVM, err := recoveryStartVM(ctx, vm, before, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: start guest with corrupt data drive: %w", err)
	}
	observation.RestartObserved = recoveryProcessChanged(before, faultVM)
	observed, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionObserve, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: observe corrupt data drive: %w", err)
	}
	checked, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionFSCKCheck, true)
	if err != nil {
		return observation, fmt.Errorf("vmqual: check corrupt data drive: %w", err)
	}
	observation.GuestVisible = recoveryStorageIdentity(observed) && recoveryStorageIdentity(checked) && !observed.Mounted
	observation.CorruptionDetected = checked.CorruptionDetected
	observation.FailureObserved = !observed.Mounted && observed.Errno == vmguest.StorageErrnoENODEV && checked.CorruptionDetected && !checked.Healthy && checked.ExitCode != 0
	if !observation.GuestVisible || !observation.FailureObserved {
		return observation, fmt.Errorf("vmqual: guest did not detect ext4 corruption: observe=%+v fsck=%+v", observed, checked)
	}
	observation.RepairAttempted = true
	if err := recoveryStopVM(ctx, vm); err != nil {
		return observation, err
	}
	if _, err := vm.disks.PrepareRestore(ctx, vm.id, snapshot); err != nil {
		return observation, fmt.Errorf("vmqual: restore clean data-drive snapshot: %w", err)
	}
	if _, err := recoveryApplyDataPlan(ctx, vm, recoveryPlanExpectation{attached: true}); err != nil {
		return observation, err
	}
	if _, err := recoveryStartVM(ctx, vm, faultVM, true); err != nil {
		return observation, fmt.Errorf("vmqual: start guest after corruption repair: %w", err)
	}
	return recoveryFinishDiskRepair(ctx, vm, observation)
}

type recoveryPlanExpectation struct {
	attached bool
	readOnly bool
	ioFault  bool
	fill     bool
	grow     bool
}

func recoveryApplyDataPlan(ctx context.Context, vm *sandboxVM, expected recoveryPlanExpectation) (vmdisk.BootPlan, error) {
	plan, err := vm.disks.NextBoot(ctx, vm.id)
	if err != nil {
		return vmdisk.BootPlan{}, fmt.Errorf("vmqual: resolve current data-drive plan: %w", err)
	}
	translated, err := recoveryDataDrivePlan(plan, vm.disks.RunID(), vm.id)
	if err != nil {
		return vmdisk.BootPlan{}, err
	}
	attached := plan.Attachment == vmdisk.AttachmentAttached
	if attached != expected.attached || plan.ReadOnly != expected.readOnly || plan.IOFailure != expected.ioFault ||
		plan.RequiresGuestFilesystemFill != expected.fill || plan.RequiresGuestFilesystemGrow != expected.grow {
		return vmdisk.BootPlan{}, fmt.Errorf("vmqual: data-drive plan does not match the selected guest action: %+v", plan)
	}
	if err := vm.provider.ApplyDataDrivePlan(ctx, vm.id, translated); err != nil {
		return vmdisk.BootPlan{}, fmt.Errorf("vmqual: apply data-drive generation %d: %w", plan.Generation, err)
	}
	return plan, nil
}

func recoveryDataDrivePlan(plan vmdisk.BootPlan, runID, vmID string) (sandboxvm.DataDrivePlan, error) {
	if plan.RunID != runID || plan.DriveID != vmID || plan.Generation == 0 || plan.Activation != vmdisk.ActivationNextBoot || !plan.RequiresStoppedGuest {
		return sandboxvm.DataDrivePlan{}, errors.New("vmqual: vmdisk next-boot identity or activation is invalid")
	}
	if plan.Size <= 0 || plan.Filesystem.Type != vmdisk.FilesystemExt4 {
		return sandboxvm.DataDrivePlan{}, errors.New("vmqual: vmdisk next-boot size or filesystem is invalid")
	}
	attached := false
	switch plan.Attachment {
	case vmdisk.AttachmentAttached:
		attached = true
		if plan.Path == "" || !vmqual.ValidPinnedSHA256(plan.SHA256) {
			return sandboxvm.DataDrivePlan{}, errors.New("vmqual: attached vmdisk next-boot artifact is incomplete")
		}
	case vmdisk.AttachmentDetached:
		if plan.Path != "" || plan.SHA256 != "" || plan.ReadOnly || plan.IOFailure {
			return sandboxvm.DataDrivePlan{}, errors.New("vmqual: detached vmdisk next-boot plan retained attachment state")
		}
	default:
		return sandboxvm.DataDrivePlan{}, errors.New("vmqual: vmdisk next-boot attachment state is invalid")
	}
	if plan.RequiresRuntimeFaultAdapter != (attached && plan.IOFailure) {
		return sandboxvm.DataDrivePlan{}, errors.New("vmqual: vmdisk runtime fault-adapter requirement is inconsistent")
	}
	wantsFill := attached && (plan.FillBytes > 0 || plan.FillToENOSPC)
	if plan.RequiresGuestFilesystemFill != wantsFill || plan.RequiresGuestFilesystemGrow && !attached {
		return sandboxvm.DataDrivePlan{}, errors.New("vmqual: vmdisk guest-filesystem action requirement is inconsistent")
	}
	return sandboxvm.DataDrivePlan{
		DriveID: plan.DriveID, Generation: plan.Generation, Attached: attached,
		Path: plan.Path, Size: plan.Size, SHA256: plan.SHA256,
		ReadOnly: plan.ReadOnly, IOFailure: plan.IOFailure,
	}, nil
}

func recoveryReadyVM(ctx context.Context, vm *sandboxVM) (vmqual.VMObservation, error) {
	observation, err := vm.Inspect(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect disk-fault target: %w", err)
	}
	if !observation.Running || !observation.Ready || observation.Process.PID <= 0 || observation.Process.StartTimeTicks == 0 {
		return observation, errors.New("vmqual: disk-fault target is not a ready observed Firecracker process")
	}
	return observation, nil
}

func recoveryStopVM(ctx context.Context, vm *sandboxVM) error {
	if err := vm.Stop(ctx); err != nil {
		return fmt.Errorf("vmqual: stop disk-fault target: %w", err)
	}
	stopped, err := vm.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("vmqual: inspect stopped disk-fault target: %w", err)
	}
	if stopped.Running {
		return errors.New("vmqual: disk-fault target remained running")
	}
	return nil
}

func recoveryStartVM(ctx context.Context, vm *sandboxVM, previous vmqual.VMObservation, requireReady bool) (vmqual.VMObservation, error) {
	if requireReady {
		if err := vm.StartReady(ctx); err != nil {
			return vmqual.VMObservation{}, err
		}
	} else {
		if err := vm.provider.Start(ctx, vm.id); err != nil {
			return vmqual.VMObservation{}, err
		}
		bootstrapper, ok := vm.executor.(interface{ Bootstrap(context.Context) error })
		if !ok {
			_ = vm.provider.Stop(context.Background(), vm.id)
			return vmqual.VMObservation{}, errors.New("vmqual: degraded guest control bootstrap is not configured")
		}
		if err := bootstrapper.Bootstrap(ctx); err != nil {
			_ = vm.provider.Stop(context.Background(), vm.id)
			return vmqual.VMObservation{}, fmt.Errorf("wait for degraded guest control: %w", err)
		}
	}
	started, err := vm.Inspect(ctx)
	if err != nil {
		return vmqual.VMObservation{}, err
	}
	if !started.Running || started.Process.PID <= 0 || started.Process.StartTimeTicks == 0 || !recoveryProcessChanged(previous, started) {
		return vmqual.VMObservation{}, errors.New("vmqual: disk-fault restart did not create a new observed Firecracker process")
	}
	if requireReady && !started.Ready {
		return vmqual.VMObservation{}, errors.New("vmqual: repaired disk-fault guest is not ready")
	}
	return started, nil
}

func recoveryProcessChanged(before, after vmqual.VMObservation) bool {
	return before.Process.PID > 0 && before.Process.StartTimeTicks > 0 && after.Process.PID > 0 && after.Process.StartTimeTicks > 0 &&
		(before.Process.PID != after.Process.PID || before.Process.StartTimeTicks != after.Process.StartTimeTicks)
}

func recoveryStorageRequest(ctx context.Context, vm *sandboxVM, action vmguest.StorageAction, degraded bool) (vmguest.StorageObservation, error) {
	request := vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationStorage, Action: action}
	var response vmguest.Response
	var err error
	if degraded {
		requester, ok := vm.executor.(interface {
			Request(context.Context, vmguest.Request) (vmguest.Response, error)
		})
		if !ok {
			return vmguest.StorageObservation{}, errors.New("vmqual: degraded guest request channel is not configured")
		}
		response, err = requester.Request(ctx, request)
	} else {
		response, err = vm.guestRequest(ctx, request)
	}
	if err != nil {
		return vmguest.StorageObservation{}, err
	}
	if response.Storage == nil || response.Storage.Action != action {
		return vmguest.StorageObservation{}, errors.New("vmqual: guest storage response is missing or has the wrong action")
	}
	return *response.Storage, nil
}

func recoveryStorageIdentity(observation vmguest.StorageObservation) bool {
	return observation.Device == recoveryDataDevice
}

func recoveryMountedStorage(observation vmguest.StorageObservation) bool {
	return recoveryStorageIdentity(observation) && observation.Mounted && observation.MountPath == recoveryDataMount && observation.Filesystem == vmdisk.FilesystemExt4 && observation.TotalBytes > 0
}

func recoveryHealthyStorage(observation vmguest.StorageObservation) bool {
	return observation.Action == vmguest.StorageActionObserve && recoveryMountedStorage(observation) && !observation.ReadOnly && observation.Errno == vmguest.StorageErrnoNone && observation.Healthy
}

func recoveryFinishDiskRepair(ctx context.Context, vm *sandboxVM, observation vmqual.DiskFaultObservation) (vmqual.DiskFaultObservation, error) {
	probe, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionProbeWrite, false)
	if err != nil {
		return observation, fmt.Errorf("vmqual: probe repaired data drive: %w", err)
	}
	admitted := recoveryMountedStorage(probe) && !probe.ReadOnly && probe.Errno == vmguest.StorageErrnoNone && probe.AttemptedBytes > 0 && probe.WrittenBytes == probe.AttemptedBytes && probe.Healthy
	observation.HealthyAfterRepair = admitted
	observation.WritesAdmittedAfter = admitted
	observation.FailClosed = false
	observation.Disposition = vmqual.FaultDispositionRepaired
	if !admitted {
		return observation, fmt.Errorf("vmqual: repaired data drive did not admit a verified write: %+v", probe)
	}
	return observation, nil
}

func recoveryFillToENOSPC(ctx context.Context, vm *sandboxVM, available uint64) (vmguest.StorageObservation, error) {
	if available == 0 {
		return vmguest.StorageObservation{}, errors.New("vmqual: healthy data drive reported no space before ENOSPC injection")
	}
	maxRequests := available/recoveryFillStep + 2
	var last vmguest.StorageObservation
	for requestNumber := uint64(0); requestNumber < maxRequests; requestNumber++ {
		observation, err := recoveryStorageRequest(ctx, vm, vmguest.StorageActionFillENOSPC, false)
		if err != nil {
			return observation, fmt.Errorf("vmqual: fill guest data filesystem: %w", err)
		}
		last = observation
		if !recoveryMountedStorage(observation) {
			return observation, fmt.Errorf("vmqual: ENOSPC fill lost the mounted data-drive identity: %+v", observation)
		}
		if observation.Errno == vmguest.StorageErrnoENOSPC {
			return observation, nil
		}
		if observation.Errno != vmguest.StorageErrnoNone || observation.AttemptedBytes == 0 || observation.WrittenBytes == 0 {
			return observation, fmt.Errorf("vmqual: ENOSPC fill made no verified progress: %+v", observation)
		}
	}
	return last, fmt.Errorf("vmqual: data filesystem did not report ENOSPC within %d bounded fill requests", maxRequests)
}

func recoveryExpansionTarget(size, used, limit int64) (int64, error) {
	if size <= 0 || used < size || limit <= used {
		return 0, errors.New("vmqual: disk budget cannot accommodate a guest-visible expansion")
	}
	available := limit - used
	step := min(recoveryExpansionStep, available)
	step -= step % 4096
	if step < recoveryMinExpansion || size > int64(^uint64(0)>>1)-step {
		return 0, errors.New("vmqual: disk budget cannot accommodate the minimum guest-visible expansion")
	}
	return size + step, nil
}

func recoveryAcknowledgeFilesystemGrow(ctx context.Context, vm *sandboxVM, generation uint64) error {
	plan, err := vm.disks.AcknowledgeFilesystemGrow(ctx, vm.id, generation)
	if err != nil {
		return fmt.Errorf("vmqual: acknowledge guest filesystem growth: %w", err)
	}
	if plan.Generation <= generation || plan.RequiresGuestFilesystemGrow || plan.Transition.Kind != vmdisk.TransitionAcknowledgeGrow {
		return fmt.Errorf("vmqual: vmdisk did not clear acknowledged filesystem growth: %+v", plan)
	}
	return nil
}

// ExhaustA1AndFallback runs the exported compute reconciler through its real
// OCI HTTP gateway. The first local endpoint launch returns OCI's capacity
// error, the reconciler retries the E5 image, and a provider readback plus a
// start action proves the selected instance reached RUNNING.
func (factory *firecrackerFactory) ExhaustA1AndFallback(ctx context.Context, guest vmqual.Guest) (vmqual.ShapeFallbackObservation, error) {
	observation := vmqual.ShapeFallbackObservation{}
	if ctx == nil {
		return observation, errors.New("vmqual: shape fallback context is nil")
	}
	if guest.ID == "" || guest.Region == "" {
		return observation, errors.New("vmqual: shape fallback guest is invalid")
	}
	cloudInit, err := factory.recoveryHostCloudInit(guest)
	if err != nil {
		return observation, err
	}
	endpoint := sandboxoci.New(sandboxoci.Config{Faults: []sandboxoci.Fault{{
		Method: http.MethodPost,
		Path:   "/20160918/instances",
		Steps: []sandboxoci.FaultStep{{
			Status: http.StatusInternalServerError,
			Code:   "OutOfHostCapacity",
			Body: map[string]any{
				"code":    "OutOfHostCapacity",
				"message": "out of host capacity",
			},
		}},
	}}})
	server := httptest.NewServer(endpoint)
	defer server.Close()
	defer endpoint.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		return observation, err
	}
	transport := &recoveryOCIRewriteTransport{endpoint: serverURL, next: server.Client().Transport}
	config, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceCore, recoveryOCIRegion, "https://iaas."+recoveryOCIRegion+".oraclecloud.com")
	if err != nil {
		return observation, err
	}
	config.MaxRetries = 0
	ociTransport, err := provider.NewOCIHTTPTransport(config, &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil)
	if err != nil {
		return observation, err
	}
	gateway, err := ocireconcile.NewOCIMemberGateway(ociTransport, "ocid1.compartment.oc1.local.vmqual", "ocid1.image.oc1.local.arm64")
	if err != nil {
		return observation, err
	}
	reconciler := &ocireconcile.ComputeReconciler{Compute: gateway}
	declared := ocireconcile.ComputeDeclared{Region: estate.Region{Code: strings.ToLower(string(guest.Region))}}
	spec := ocireconcile.MemberLaunchSpec{
		DisplayName:        "terrascale-" + strings.ToLower(string(guest.Region)) + "-recovery",
		Index:              1,
		Shape:              recoveryPrimaryShape,
		FallbackShape:      recoveryFallbackShape,
		ImageID:            "ocid1.image.oc1.local.arm64",
		FallbackImageID:    "ocid1.image.oc1.local.amd64",
		OCPUs:              1,
		MemoryGiB:          8,
		SubnetID:           "ocid1.subnet.oc1.local.vmqual",
		AvailabilityDomain: "AD-1",
		CloudInitBase64:    cloudInit,
	}
	plan := ocireconcile.OCIPlan{Actions: []ocireconcile.OCIAction{ocireconcile.LaunchMemberAction{Region: declared.Region, Spec: spec}}}
	if err := reconciler.Apply(ctx, declared, ocireconcile.ComputeObserved{}, plan); err != nil {
		return observation, fmt.Errorf("vmqual: apply A1-to-E5 compute plan: %w", err)
	}
	observation.Attempts = transport.launchShapes()
	observation.A1CapacityExhausted = len(observation.Attempts) > 0 && observation.Attempts[0] == recoveryPrimaryShape
	members, err := gateway.ListMembers(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: read fallback instance: %w", err)
	}
	if len(members) != 1 {
		return observation, fmt.Errorf("vmqual: provider retained %d fallback instances", len(members))
	}
	selected := members[0]
	if err := gateway.StartMember(ctx, selected.ID); err != nil {
		return observation, fmt.Errorf("vmqual: start fallback instance: %w", err)
	}
	members, err = gateway.ListMembers(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: read started fallback instance: %w", err)
	}
	if len(members) != 1 || members[0].ID != selected.ID {
		return observation, errors.New("vmqual: fallback instance identity changed before readiness")
	}
	observation.SelectedShape = members[0].Shape
	architecture, _ := ocireconcile.ShapeArch(observation.SelectedShape)
	observation.SelectedArchitecture = architecture
	observation.ReplacementReady = members[0].LifecycleState == "RUNNING"
	return observation, nil
}

// recoveryHostCloudInit forwards admitted public launch inputs into the HTTP
// shape probe. Private credentials remain on the existing guest root disk;
// provider RUNNING is not evidence of service admission on a replacement host.
func (factory *firecrackerFactory) recoveryHostCloudInit(guest vmqual.Guest) (string, error) {
	if factory == nil || factory.services == nil {
		return "", errors.New("vmqual: recovery requires admitted guest bootstrap material")
	}
	seed, artifacts, err := factory.services.Bootstrap(guest)
	if err != nil {
		return "", err
	}
	if seed.Controller != nil {
		defer seed.Controller.Clear()
	}
	defer clear(seed.MembershipIdentityPrivateKey)
	defer seed.Engine.Clear()
	if seed.NATSIdentity == nil || seed.InitialGrant == nil || seed.Config.NodeID != guest.ID {
		return "", errors.New("vmqual: recovery guest seed is incomplete")
	}
	defer clear(seed.NATSIdentity.NKeySeed)
	defer clear(seed.NATSIdentity.TLSPrivateKey)
	return vmimage.TSNodeRecoveryCloudInit(seed, artifacts)
}

type recoveryOCIRewriteTransport struct {
	mu       sync.Mutex
	endpoint *url.URL
	next     http.RoundTripper
	shapes   []string
}

func (transport *recoveryOCIRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport == nil || transport.endpoint == nil || transport.next == nil {
		return nil, errors.New("vmqual: recovery OCI transport is not configured")
	}
	clone := request.Clone(request.Context())
	clone.URL.Scheme = transport.endpoint.Scheme
	clone.URL.Host = transport.endpoint.Host
	clone.Host = transport.endpoint.Host
	if request.Method == http.MethodPost && request.URL.Path == "/20160918/instances" {
		body, err := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		if err != nil {
			return nil, err
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		clone.Body = io.NopCloser(bytes.NewReader(body))
		var document struct {
			Shape string `json:"shape"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		// Observe the shape while forwarding the complete production launch
		// request, which also contains networking, image, and ownership fields.
		if err := decoder.Decode(&document); err != nil || document.Shape == "" {
			return nil, errors.New("vmqual: compute launch body did not contain a shape")
		}
		transport.mu.Lock()
		transport.shapes = append(transport.shapes, document.Shape)
		transport.mu.Unlock()
	}
	return transport.next.RoundTrip(clone)
}

func (transport *recoveryOCIRewriteTransport) launchShapes() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.shapes...)
}

// ExpireAndRotateCertificate runs the production certificate reconciler over
// an issuer that creates real Ed25519 X.509 versions. TLS handshakes prove the
// expired leaf is rejected and the renewed leaf is accepted; the participating
// Firecracker guest must remain ready across the repair.
func (factory *firecrackerFactory) ExpireAndRotateCertificate(ctx context.Context, guest vmqual.Guest) (vmqual.CertificateRotationObservation, error) {
	observation := vmqual.CertificateRotationObservation{}
	vm, err := factory.recoveryVM(guest)
	if err != nil {
		return observation, err
	}
	before, err := vm.Inspect(ctx)
	if err != nil || !before.Running || !before.Ready {
		return observation, fmt.Errorf("vmqual: certificate target is not ready: %w", err)
	}
	result, err := exerciseCertificateRotation(ctx, strings.ToLower(string(guest.Region)))
	if err != nil {
		return observation, err
	}
	after, err := vm.Inspect(ctx)
	if err != nil {
		return observation, fmt.Errorf("vmqual: inspect certificate target after rotation: %w", err)
	}
	result.ServiceHealthy = result.ServiceHealthy && after.Running && after.Ready && after.ID == before.ID
	return result, nil
}

func exerciseCertificateRotation(ctx context.Context, region string) (vmqual.CertificateRotationObservation, error) {
	observation := vmqual.CertificateRotationObservation{}
	if ctx == nil {
		return observation, errors.New("vmqual: certificate rotation context is nil")
	}
	now := time.Now().UTC()
	hostname := region + ".api.terrascale.tech"
	displayName := ocireconcile.CertDisplayName(region, "member-control")
	gateway, roots, err := newRecoveryCertificateGateway(now, displayName, hostname)
	if err != nil {
		return observation, err
	}
	defer gateway.close()
	expired := gateway.certificate()
	observation.ExpiredSerial = expired.Leaf.SerialNumber.String()
	observation.ExpiredNotAfter = expired.Leaf.NotAfter
	observation.ObservedAt = now
	if err := probeRecoveryTLS(ctx, expired, roots, hostname); err == nil {
		return observation, errors.New("vmqual: expired certificate completed a TLS handshake")
	}
	observation.ExpiredRejected = true
	declared := estate.Region{Code: region, Certificates: []estate.Certificate{{
		Name: "member-control", Purpose: "member-control", DNSNames: []string{hostname}, RenewBeforeHours: 24 * 30,
	}}}
	reconciler := &ocireconcile.CertReconciler{Gateway: gateway, Now: func() time.Time { return now }}
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		return observation, fmt.Errorf("vmqual: observe expired certificate: %w", err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil {
		return observation, fmt.Errorf("vmqual: plan expired certificate repair: %w", err)
	}
	if len(plan.Actions) != 1 {
		return observation, fmt.Errorf("vmqual: expired certificate planned %d actions", len(plan.Actions))
	}
	renewal, ok := plan.Actions[0].(ocireconcile.RenewCertificateAction)
	if !ok || renewal.Reason != ocireconcile.RenewReasonExpired {
		return observation, errors.New("vmqual: certificate reconciler did not plan an expired-version renewal")
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		return observation, fmt.Errorf("vmqual: apply expired certificate repair: %w", err)
	}
	rotated := gateway.certificate()
	observation.RotatedSerial = rotated.Leaf.SerialNumber.String()
	observation.RotatedNotAfter = rotated.Leaf.NotAfter
	if err := probeRecoveryTLS(ctx, rotated, roots, hostname); err != nil {
		return observation, fmt.Errorf("vmqual: rotated certificate TLS handshake: %w", err)
	}
	observation.RotatedAccepted = true
	// A second independent handshake is the service-health readback. The first
	// proves version acceptance; the second proves the endpoint still serves.
	observation.ServiceHealthy = probeRecoveryTLS(ctx, rotated, roots, hostname) == nil
	return observation, nil
}

type recoveryCertificateGateway struct {
	mu                sync.Mutex
	ca                *x509.Certificate
	caPrivate         ed25519.PrivateKey
	activeCertificate tls.Certificate
	observed          ocireconcile.ObservedCert
	now               time.Time
}

func newRecoveryCertificateGateway(now time.Time, displayName, hostname string) (*recoveryCertificateGateway, *x509.CertPool, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := recoveryCertificateSerial()
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "TerraScale recovery qualification CA"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return nil, nil, err
	}
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if len(caPEM) == 0 || !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("vmqual: load recovery certificate authority")
	}
	gateway := &recoveryCertificateGateway{ca: parsedCA, caPrivate: caPrivate, now: now}
	certificate, err := gateway.issue(hostname, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		gateway.close()
		return nil, nil, err
	}
	gateway.activeCertificate = certificate
	gateway.observed = ocireconcile.ObservedCert{
		ID: "ocid1.certificate.oc1.local.vmqual", DisplayName: displayName,
		LifecycleState: "ACTIVE", DNSNames: []string{hostname}, ExpiresAtUnix: certificate.Leaf.NotAfter.Unix(),
	}
	return gateway, roots, nil
}

func (gateway *recoveryCertificateGateway) ListCertificates(ctx context.Context) ([]ocireconcile.ObservedCert, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	copy := gateway.observed
	copy.DNSNames = append([]string(nil), copy.DNSNames...)
	return []ocireconcile.ObservedCert{copy}, nil
}

func (*recoveryCertificateGateway) CreateCertificate(context.Context, string, []string) (ocireconcile.ObservedCert, error) {
	return ocireconcile.ObservedCert{}, errors.New("vmqual: recovery certificate already exists")
}

func (gateway *recoveryCertificateGateway) RenewCertificate(ctx context.Context, id string, names []string) (ocireconcile.ObservedCert, error) {
	if err := ctx.Err(); err != nil {
		return ocireconcile.ObservedCert{}, err
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if id != gateway.observed.ID || len(names) != 1 || names[0] != gateway.observed.DNSNames[0] {
		return ocireconcile.ObservedCert{}, errors.New("vmqual: recovery certificate identity changed")
	}
	certificate, err := gateway.issue(names[0], gateway.now.Add(-time.Minute), gateway.now.Add(12*time.Hour))
	if err != nil {
		return ocireconcile.ObservedCert{}, err
	}
	if private, ok := gateway.activeCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		zeroBytes(private)
	}
	gateway.activeCertificate = certificate
	gateway.observed.ExpiresAtUnix = certificate.Leaf.NotAfter.Unix()
	copy := gateway.observed
	copy.DNSNames = append([]string(nil), copy.DNSNames...)
	return copy, nil
}

func (gateway *recoveryCertificateGateway) issue(hostname string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := recoveryCertificateSerial()
	if err != nil {
		zeroBytes(private)
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, gateway.ca, public, gateway.caPrivate)
	if err != nil {
		zeroBytes(private)
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		zeroBytes(private)
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, gateway.ca.Raw}, PrivateKey: private, Leaf: leaf}, nil
}

func (gateway *recoveryCertificateGateway) certificate() tls.Certificate {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	return gateway.activeCertificate
}

func (gateway *recoveryCertificateGateway) close() {
	if gateway == nil {
		return
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if private, ok := gateway.activeCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		zeroBytes(private)
	}
	zeroBytes(gateway.caPrivate)
	gateway.activeCertificate = tls.Certificate{}
	gateway.caPrivate = nil
}

func recoveryCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func probeRecoveryTLS(ctx context.Context, certificate tls.Certificate, roots *x509.CertPool, hostname string) error {
	if ctx == nil {
		return errors.New("vmqual: TLS probe context is nil")
	}
	serverConn, clientConn := net.Pipe()
	server := tls.Server(serverConn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	client := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: hostname})
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.HandshakeContext(ctx) }()
	clientErr := client.HandshakeContext(ctx)
	_ = clientConn.Close()
	_ = serverConn.Close()
	serverErr := <-serverResult
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}
