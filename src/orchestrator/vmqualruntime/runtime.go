package vmqualruntime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type sandboxVM struct {
	provider  *sandboxvm.Provider
	disks     *vmdisk.Store
	factory   *firecrackerFactory
	guest     vmqual.Guest
	id        string
	executor  sandboxvm.CommandRunner
	seedDir   string
	rootDrive string
	resources vmqual.VMResourceIdentity
	deleteMu  sync.Mutex
	deleted   bool
}

type qualificationServices interface {
	Start(context.Context) error
	Close(context.Context) error
	VerifyStopped() error
	Bootstrap(vmqual.Guest) (vmimage.TSNodeBootstrap, []vmimage.GuestArtifact, error)
}

func (v *sandboxVM) StartReady(ctx context.Context) error {
	if v == nil || v.provider == nil {
		return errors.New("vmqual: VM provider is not configured")
	}
	if ctx == nil {
		return errors.New("vmqual: VM context is nil")
	}
	if err := v.provider.Start(ctx, v.id); err != nil {
		return err
	}
	if bootstrapper, ok := v.executor.(interface{ Bootstrap(context.Context) error }); ok {
		if err := bootstrapper.Bootstrap(ctx); err != nil {
			return v.failStartup(ctx, fmt.Errorf("vmqual: bootstrap guest artifacts: %w", err))
		}
	}
	if v.factory != nil {
		if err := v.factory.activateGuest(ctx, v.id); err != nil {
			return v.failStartup(ctx, fmt.Errorf("vmqual: activate guest services: %w", err))
		}
	}
	if err := v.provider.WaitReady(ctx, v.id); err != nil {
		return v.failStartup(ctx, err)
	}
	return nil
}
func (v *sandboxVM) Stop(ctx context.Context) error {
	if v == nil || v.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return v.provider.Stop(ctx, v.id)
}
func (v *sandboxVM) Delete(ctx context.Context) error {
	if v == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	v.deleteMu.Lock()
	defer v.deleteMu.Unlock()
	if v.deleted {
		return nil
	}
	// Cleanup is deliberately independent of the caller's deadline. A
	// cancelled qualification must not strand a VMM jail or its drive.
	cleanCtx := context.WithoutCancel(ctx)
	var providerErr, diskErr, stateErr error
	if v.provider != nil {
		providerErr = v.provider.Delete(cleanCtx, v.id)
	}
	if v.disks != nil {
		diskErr = v.disks.Delete(cleanCtx, v.id)
	}
	if v.seedDir != "" {
		stateErr = removePreparedVMState(v.seedDir, v.id)
	}
	if err := errors.Join(providerErr, diskErr, stateErr); err != nil {
		return err
	}
	if destroyer, ok := v.executor.(interface{ Destroy() }); ok {
		destroyer.Destroy()
	}
	v.deleted = true
	if v.factory != nil {
		v.factory.release(v.id, v)
	}
	return nil
}
func (v *sandboxVM) Inspect(ctx context.Context) (vmqual.VMObservation, error) {
	if v == nil || v.provider == nil {
		return vmqual.VMObservation{}, errors.New("vmqual: VM provider is not configured")
	}
	if ctx == nil {
		return vmqual.VMObservation{}, errors.New("vmqual: VM context is nil")
	}
	info, err := v.provider.Inspect(ctx, v.id)
	if err != nil {
		return vmqual.VMObservation{}, err
	}
	process := vmqual.VMProcessIdentity{}
	if info.PID > 0 || info.ProcessStartTime > 0 {
		process = vmqual.VMProcessIdentity{PID: info.PID, StartTimeTicks: info.ProcessStartTime, Executable: info.Executable}
	}
	resources := v.resources
	if info.Paths.Cgroup != resources.CgroupPath || info.Paths.JailerCgroup != resources.JailerCgroupPath {
		return vmqual.VMObservation{}, errors.New("vmqual: observed VM cgroups differ from the cleanup plan")
	}
	resources.Process = process
	return vmqual.VMObservation{ID: v.id, Region: v.guest.Region, Running: info.State == sandboxvm.StateRunning, Ready: info.Ready, MemoryMiB: info.Config.MemoryMiB, RSSBytes: info.RSSBytes, IdleCPU: info.IdleCPU, CPUSampled: info.CPUSampled, Process: process, Resources: resources}, nil
}

// Execute is intentionally exposed only on the real VM adapter. It lets the
// smoke path prove a guest systemd boundary without adding execution to the
// narrow VM lifecycle contract used by unit-test fakes.
func (v *sandboxVM) Execute(ctx context.Context, command sandboxvm.Command) error {
	if v == nil || v.provider == nil {
		return errors.New("vmqual: VM provider is not configured")
	}
	if ctx == nil {
		return errors.New("vmqual: VM context is nil")
	}
	if v.executor == nil {
		return errors.New("vmqual: guest execution channel is not configured")
	}
	return v.provider.ExecuteCommand(ctx, v.id, v.executor, command)
}

// Put copies one bounded artifact into the guest's qualification inbox. It
// does not install or activate the artifact; that remains ts-node's job.
func (v *sandboxVM) Put(ctx context.Context, relativePath string, data []byte, mode uint32) error {
	_, err := v.guestRequest(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationPut, Path: relativePath, Data: data, Mode: mode})
	return err
}

func (v *sandboxVM) DataWrite(ctx context.Context, relativePath string, data []byte) error {
	_, err := v.guestRequest(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationDataWrite, Path: relativePath, Data: data})
	return err
}

func (v *sandboxVM) DataRead(ctx context.Context, relativePath string) ([]byte, error) {
	response, err := v.guestRequest(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationDataRead, Path: relativePath})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), response.Data...), nil
}

func (v *sandboxVM) NetworkExchange(ctx context.Context, endpoint string, challenge []byte) ([]byte, error) {
	response, err := v.guestRequest(ctx, vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationNetwork, Path: endpoint, Data: challenge})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), response.Data...), nil
}

func (v *sandboxVM) HostDiskUsageBytes(ctx context.Context) (uint64, error) {
	if v == nil || v.disks == nil {
		return 0, errors.New("vmqual: VM disk ownership is not configured")
	}
	drive, err := v.disks.Get(ctx, v.id)
	if err != nil {
		return 0, err
	}
	paths := []string{v.rootDrive, drive.Path}
	return allocatedPathBytes(paths...)
}

func (v *sandboxVM) VerifyNoOwnedResources(ctx context.Context) error {
	if v == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("vmqual: VM cleanup verification context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var errs []error
	if v.provider != nil {
		if _, err := v.provider.Inspect(ctx, v.id); err == nil {
			errs = append(errs, errors.New("vmqual: deleted VM remains registered"))
		} else if !errors.Is(err, sandboxvm.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	if v.disks != nil {
		if _, err := v.disks.Get(ctx, v.id); err == nil {
			errs = append(errs, errors.New("vmqual: deleted VM data drive remains"))
		} else if !errors.Is(err, vmdisk.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	for _, path := range []string{v.resources.StateDir, v.resources.DriveDir, v.resources.SeedDir, v.resources.CgroupPath, v.resources.JailerCgroupPath} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			errs = append(errs, fmt.Errorf("vmqual: deleted VM resource remains: %s", path))
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (v *sandboxVM) guestRequest(ctx context.Context, request vmguest.Request) (vmguest.Response, error) {
	if v == nil || v.provider == nil || v.executor == nil {
		return vmguest.Response{}, errors.New("vmqual: guest execution channel is not configured")
	}
	if ctx == nil {
		return vmguest.Response{}, errors.New("vmqual: VM context is nil")
	}
	if err := request.Validate(); err != nil {
		return vmguest.Response{}, err
	}
	info, err := v.provider.Inspect(ctx, v.id)
	if err != nil {
		return vmguest.Response{}, err
	}
	if info.State != sandboxvm.StateRunning || !info.Ready {
		return vmguest.Response{}, sandboxvm.ErrNotReady
	}
	requester, ok := v.executor.(interface {
		Request(context.Context, vmguest.Request) (vmguest.Response, error)
	})
	if !ok {
		return vmguest.Response{}, errors.New("vmqual: guest request channel is not configured")
	}
	return requester.Request(ctx, request)
}

type firecrackerFactory struct {
	provider   *sandboxvm.Provider
	image      vmqual.ImageResult
	diskRoot   string
	createMu   sync.Mutex
	diskMu     sync.Mutex
	disks      *vmdisk.Store
	diskRunID  string
	activeMu   sync.Mutex
	active     map[string]*sandboxVM
	closed     bool
	services   qualificationServices
	network    *networkController
	config     vmqual.Config
	mkfsPath   string
	cgroupRoot string
}

// NewFirecrackerFactory is the production command-side factory. The tagged
// runtime binds it to the official SDK; unit tests should inject VMFactory
// instead of calling this constructor.
func NewFirecrackerFactory(config vmqual.Config, image vmqual.ImageResult) (vmqual.VMFactory, error) {
	return newFirecrackerFactory(config, image, nil)
}

// NewProductionComponents binds one canonical network plan, its embedded
// services, and the Firecracker factory to the same runtime ownership.
func NewProductionComponents(config vmqual.Config, image vmqual.ImageResult, networkConfig vmnet.Config, runner vmnet.Runner, networkJournalPath string) (vmqual.VMFactory, vmqual.NetworkController, error) {
	if config.JailerUID <= 0 || config.JailerGID <= 0 {
		return nil, nil, errors.New("vmqual: resolve a non-root jailer identity before planning production components")
	}
	if !vmqual.CanonicalAbsolute(config.Root) || filepath.Clean(config.Root) == string(filepath.Separator) {
		return nil, nil, errors.New("vmqual: production root must be an absolute owned directory")
	}
	// Host resources can collide across qualification directories. Use vmnet's
	// single host lock directory, never a lock directory scoped to this run.
	if networkConfig.CoordinationRoot != "" {
		return nil, nil, errors.New("vmqual: production network must use the default host coordination root")
	}
	if networkConfig.TAPUID == 0 && networkConfig.TAPGID == 0 {
		networkConfig.TAPUID, networkConfig.TAPGID = uint32(config.JailerUID), uint32(config.JailerGID)
	}
	if networkConfig.TAPUID != uint32(config.JailerUID) || networkConfig.TAPGID != uint32(config.JailerGID) {
		return nil, nil, errors.New("vmqual: TAP and jailer ownership must use the same UID/GID")
	}
	if networkJournalPath == "" {
		return nil, nil, errors.New("vmqual: production network requires a durable cleanup journal")
	}
	network, err := NewNetworkController(networkConfig, runner, networkJournalPath)
	if err != nil {
		return nil, nil, err
	}
	controller := network.(*networkController)
	config.NetworkPlan = controller.Plan()
	services, err := newQualificationServices(config, config.NetworkPlan, image.Manifest.Architecture)
	if err != nil {
		return nil, nil, err
	}
	factory, err := newFirecrackerFactory(config, image, services)
	if err != nil {
		_ = services.Close(context.Background())
		return nil, nil, err
	}
	controller.services = services
	factory.(*firecrackerFactory).network = controller
	return factory, controller, nil
}

func newFirecrackerFactory(config vmqual.Config, image vmqual.ImageResult, services qualificationServices) (vmqual.VMFactory, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateInstalledImage(image); err != nil {
		return nil, err
	}
	if image.Installed.Dir == "" {
		return nil, errors.New("vmqual: installed image is required")
	}
	mkfsPath, err := resolveHostExecutable("mkfs.ext4", "mke2fs")
	if err != nil {
		return nil, fmt.Errorf("vmqual: ext4 formatter: %w", err)
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("vmqual: read cgroup mounts: %w", err)
	}
	cgroupRoot, err := vmqual.UnifiedCgroupMount(string(mountInfo))
	if err != nil {
		return nil, fmt.Errorf("vmqual: resolve unified cgroup mount: %w", err)
	}
	provider, err := newSandboxVMProvider(config)
	if err != nil {
		return nil, err
	}
	return &firecrackerFactory{provider: provider, image: image, diskRoot: filepath.Join(config.Root, "drives"), active: make(map[string]*sandboxVM), services: services, config: config, mkfsPath: mkfsPath, cgroupRoot: cgroupRoot}, nil
}
func (f *firecrackerFactory) Create(ctx context.Context, guest vmqual.Guest) (vmqual.VM, error) {
	if f == nil || f.provider == nil || f.diskRoot == "" {
		return nil, errors.New("vmqual: Firecracker factory is not configured")
	}
	if ctx == nil {
		return nil, errors.New("vmqual: VM context is nil")
	}
	f.createMu.Lock()
	defer f.createMu.Unlock()
	f.activeMu.Lock()
	if f.closed {
		f.activeMu.Unlock()
		return nil, errors.New("vmqual: Firecracker factory is closed")
	}
	if f.active[guest.ID] != nil {
		f.activeMu.Unlock()
		return nil, fmt.Errorf("vmqual: guest %s already exists", guest.ID)
	}
	f.activeMu.Unlock()
	if guest.ID == "" || strings.ContainsAny(guest.ID, `/\\\x00`) || guest.Region == "" || guest.VCPU != 1 || guest.MemoryMiB < 256 || guest.MemoryMiB > vmqual.MaxGuestMemoryMiB {
		return nil, fmt.Errorf("vmqual: invalid guest %q", guest.ID)
	}
	resources, err := f.PlanResources(ctx, guest)
	if err != nil {
		return nil, err
	}
	rootDrive, rootDigest, err := cloneRootDrive(ctx, f.image.Installed.RootFS, resources.SeedDir, f.config.MaxDiskBytes)
	if err != nil {
		return nil, err
	}
	prepared := true
	defer func() {
		if prepared {
			_ = removePreparedVMState(resources.SeedDir, guest.ID)
		}
	}()
	if !strings.EqualFold(rootDigest, f.config.ExpectedRootFSSHA256) {
		return nil, errors.New("vmqual: cloned rootfs checksum differs from the pinned image")
	}
	if err := secureJailerDrive(rootDrive, f.config.JailerUID, f.config.JailerGID); err != nil {
		return nil, fmt.Errorf("vmqual: hand off root drive to jailer: %w", err)
	}
	if err := f.enforceDiskBudget(resources.SeedDir); err != nil {
		return nil, err
	}
	disks, err := f.diskStore(ctx)
	if err != nil {
		return nil, err
	}
	driveBytes := int64(64 << 20)
	if sizing, ok := f.services.(interface {
		DataDriveBytes(vmqual.Guest) (int64, error)
	}); ok {
		driveBytes, err = sizing.DataDriveBytes(guest)
		if err != nil {
			return nil, err
		}
	}
	drive, err := disks.Preallocate(ctx, guest.ID, driveBytes)
	if err != nil {
		return nil, err
	}
	driveCreated := true
	defer func() {
		if driveCreated {
			_ = disks.Delete(context.Background(), guest.ID)
		}
	}()
	if err := formatPersistentDataDrive(ctx, f.mkfsPath, drive.Path, guest.ID); err != nil {
		return nil, err
	}
	if err := secureJailerDrive(drive.Path, f.config.JailerUID, f.config.JailerGID); err != nil {
		return nil, fmt.Errorf("vmqual: hand off data drive to jailer: %w", err)
	}
	if err := f.enforceDiskBudget(resources.SeedDir); err != nil {
		return nil, err
	}
	paths := sandboxPaths(f.config, guest.ID)
	uid, gid := f.config.JailerUID, f.config.JailerGID
	vmConfig := sandboxvm.Config{ID: guest.ID, Region: string(guest.Region), VCPU: guest.VCPU, MemoryMiB: guest.MemoryMiB, KernelImage: f.image.Installed.Kernel, RootDrive: rootDrive, DataDrive: drive.Path, StateRoot: f.config.StateRoot, CgroupRoot: f.cgroupRoot, JailerChrootBaseDir: f.config.StateRoot, JailerUID: &uid, JailerGID: &gid, SocketPath: paths.socket, KernelArgs: qualificationKernelArgs, LogPath: paths.log, MetricsPath: paths.metrics, FirecrackerBinary: f.config.FirecrackerPath, JailerBinary: f.config.JailerPath, ExpectedVersion: f.config.ExpectedVersion, ExpectedKernelSHA256: f.config.ExpectedKernelSHA256, ExpectedRootDriveSHA256: rootDigest, ExpectedDataDriveSHA256: "", ExpectedFirecrackerSHA256: f.config.ExpectedFirecrackerSHA256, ExpectedJailerSHA256: f.config.ExpectedJailerSHA256, ReadinessTimeout: f.config.ReadinessTimeout, StopTimeout: f.config.StopTimeout}
	seedDigest, err := f.prepareGuest(ctx, guest, &vmConfig)
	if err != nil {
		return nil, err
	}
	if err := f.enforceDiskBudget(resources.SeedDir); err != nil {
		return nil, err
	}
	// Data disks are generated by the pinned vmdisk provider, so their digest
	// is not a static artifact pin. The VM provider still requires a digest;
	// obtain it from the immutable file before creating the VMM.
	if digest, digestErr := fileSHA256(drive.Path); digestErr != nil {
		return nil, digestErr
	} else {
		vmConfig.ExpectedDataDriveSHA256 = digest
	}
	executor := newGuestExecutor(vmConfig)
	if executor == nil {
		return nil, errors.New("vmqual: guest execution channel is not configured")
	}
	executorOwned := true
	defer func() {
		if executorOwned {
			if destroyer, ok := executor.(interface{ Destroy() }); ok {
				destroyer.Destroy()
			}
		}
	}()
	if _, err := f.provider.Create(ctx, vmConfig); err != nil {
		return nil, err
	}
	f.provider.RegisterGuest(vmConfig, seedDigest)
	vm := &sandboxVM{provider: f.provider, disks: disks, factory: f, guest: guest, id: guest.ID, executor: executor, seedDir: resources.SeedDir, rootDrive: rootDrive, resources: resources}
	f.activeMu.Lock()
	if f.closed || f.active[guest.ID] != nil {
		f.activeMu.Unlock()
		_ = f.provider.Delete(context.Background(), guest.ID)
		return nil, errors.New("vmqual: Firecracker factory ownership changed during create")
	}
	f.active[guest.ID] = vm
	f.activeMu.Unlock()
	prepared, driveCreated, executorOwned = false, false, false
	return vm, nil
}

func (f *firecrackerFactory) diskStore(ctx context.Context) (*vmdisk.Store, error) {
	runID, _ := vmqual.RunIDFromContext(ctx)
	f.diskMu.Lock()
	defer f.diskMu.Unlock()
	if f.disks != nil {
		if runID != "" && f.diskRunID != runID {
			return nil, errors.New("vmqual: disk store belongs to a different qualification run")
		}
		return f.disks, nil
	}
	store, err := vmdisk.New(vmdisk.Config{Root: f.diskRoot, RunID: runID, Ownership: &vmdisk.Ownership{UID: f.config.JailerUID, GID: f.config.JailerGID}, MaxBytes: f.config.MaxDiskBytes, MaxDrives: 6})
	if err != nil {
		return nil, err
	}
	f.disks, f.diskRunID = store, store.RunID()
	return store, nil
}

func (f *firecrackerFactory) release(id string, vm *sandboxVM) {
	if f == nil {
		return
	}
	f.activeMu.Lock()
	if f.active[id] == vm {
		delete(f.active, id)
	}
	f.activeMu.Unlock()
}

func (f *firecrackerFactory) SupportsSmokeProfile(ctx context.Context, profile vmqual.SmokeProfile) (bool, error) {
	if f == nil || f.provider == nil {
		return false, errors.New("vmqual: Firecracker factory is not configured")
	}
	if ctx == nil {
		return false, errors.New("vmqual: smoke profile context is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch profile.Name {
	case "control-only":
		if profile.Guest.VCPU != 1 || profile.Guest.MemoryMiB != vmqual.SmokeControlMemoryMiB || !profile.Guest.Control || profile.Guest.Service {
			return false, errors.New("vmqual: control-only smoke profile is invalid")
		}
	case "service":
		if profile.Guest.VCPU != 1 || profile.Guest.MemoryMiB != vmqual.DefaultMemoryMiB || !profile.Guest.Control || !profile.Guest.Service {
			return false, errors.New("vmqual: service smoke profile is invalid")
		}
	default:
		return false, fmt.Errorf("vmqual: unknown smoke profile %q", profile.Name)
	}
	return true, nil
}

func (f *firecrackerFactory) VerifyNoOwnedResources(ctx context.Context) error {
	if f == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("vmqual: factory cleanup verification context is nil")
	}
	f.createMu.Lock()
	defer f.createMu.Unlock()
	f.activeMu.Lock()
	f.closed = true
	active := make([]string, 0, len(f.active))
	for id := range f.active {
		active = append(active, id)
	}
	f.activeMu.Unlock()
	if len(active) != 0 {
		return fmt.Errorf("vmqual: Firecracker factory still owns %d VM handles", len(active))
	}

	var errs []error
	f.diskMu.Lock()
	store := f.disks
	if store != nil {
		if _, err := os.Lstat(store.Identity().Root); errors.Is(err, os.ErrNotExist) {
			f.disks = nil
		} else if err != nil {
			errs = append(errs, err)
		} else {
			usage, err := store.Usage(ctx)
			if err != nil {
				errs = append(errs, err)
			} else if usage.Bytes != 0 || usage.Drives != 0 || usage.Snapshots != 0 {
				errs = append(errs, fmt.Errorf("vmqual: disk store still owns %d bytes in %d drives and %d snapshots", usage.Bytes, usage.Drives, usage.Snapshots))
			} else if err := store.CloseAndRemove(ctx); err != nil {
				errs = append(errs, err)
			} else {
				f.disks = nil
			}
		}
	}
	f.diskMu.Unlock()
	if err := releaseGuestTransport(f.config.StateRoot); err != nil {
		errs = append(errs, err)
	}
	if _, err := os.Lstat(f.diskRoot); err == nil {
		errs = append(errs, errors.New("vmqual: disk store root remains after cleanup"))
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (f *firecrackerFactory) enforceDiskBudget(extraRoots ...string) error {
	if f == nil || f.config.MaxDiskBytes <= 0 {
		return errors.New("vmqual: disk budget is not configured")
	}
	f.activeMu.Lock()
	roots := make([]string, 0, len(f.active)+len(extraRoots)+1)
	roots = append(roots, f.diskRoot)
	for _, vm := range f.active {
		roots = append(roots, vm.seedDir)
	}
	f.activeMu.Unlock()
	roots = append(roots, extraRoots...)
	allocated, err := allocatedTreeBytes(roots...)
	if err != nil {
		return fmt.Errorf("vmqual: measure allocated disk bytes: %w", err)
	}
	if allocated > uint64(f.config.MaxDiskBytes) {
		return fmt.Errorf("vmqual: aggregate allocated disk budget exceeded: %d > %d", allocated, f.config.MaxDiskBytes)
	}
	return nil
}

type diskInode struct {
	device uint64
	inode  uint64
}

func allocatedPathBytes(paths ...string) (uint64, error) {
	seen := make(map[diskInode]struct{}, len(paths))
	var total uint64
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) {
			return 0, errors.New("vmqual: allocated file path must be absolute")
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return 0, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink == 0 || stat.Blocks < 0 {
			return 0, fmt.Errorf("vmqual: allocated path is not a regular file: %s", path)
		}
		key := diskInode{device: uint64(stat.Dev), inode: stat.Ino}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		allocated := uint64(stat.Blocks) * 512
		if allocated/512 != uint64(stat.Blocks) || ^uint64(0)-total < allocated {
			return 0, errors.New("vmqual: allocated disk byte count overflowed")
		}
		total += allocated
	}
	return total, nil
}

func allocatedTreeBytes(roots ...string) (uint64, error) {
	seenRoots := make(map[string]struct{}, len(roots))
	seenFiles := make(map[diskInode]struct{})
	var total uint64
	for _, root := range roots {
		if root == "" {
			continue
		}
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return 0, errors.New("vmqual: allocated disk root must be clean and absolute")
		}
		if _, duplicate := seenRoots[root]; duplicate {
			continue
		}
		seenRoots[root] = struct{}{}
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return 0, err
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("vmqual: disk ownership tree contains a symlink: %s", path)
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("vmqual: disk ownership tree contains a non-regular entry: %s", path)
			}
			var stat unix.Stat_t
			if err := unix.Lstat(path, &stat); err != nil {
				return err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink == 0 || stat.Blocks < 0 {
				return fmt.Errorf("vmqual: cannot measure allocated bytes for %s", path)
			}
			key := diskInode{device: uint64(stat.Dev), inode: stat.Ino}
			if _, duplicate := seenFiles[key]; duplicate {
				return nil
			}
			seenFiles[key] = struct{}{}
			allocated := uint64(stat.Blocks) * 512
			if allocated/512 != uint64(stat.Blocks) || ^uint64(0)-total < allocated {
				return errors.New("vmqual: allocated disk byte count overflowed")
			}
			total += allocated
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func secureJailerDrive(path string, uid, gid int) error {
	if path == "" || !filepath.IsAbs(path) || uid <= 0 || gid <= 0 {
		return errors.New("drive path and jailer identity must be explicit")
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return errors.New("drive must be a single-link regular file")
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if after.Mode&unix.S_IFMT != unix.S_IFREG || after.Nlink != 1 || int(after.Uid) != uid || int(after.Gid) != gid || after.Mode&0o7777 != 0o600 || after.Dev != before.Dev || after.Ino != before.Ino {
		return errors.New("drive ownership changed during jailer handoff")
	}
	return nil
}

const qualificationKernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootfstype=ext4 systemd.mask=boot.mount systemd.mask=boot-efi.mount"

type resolvedSandboxPaths struct{ stateDir, jailRoot, socket, log, metrics, runtime string }

// PlanResources returns the exact paths used by Create without touching the
// filesystem. Stack writes this plan to its cleanup journal before creation.
func (f *firecrackerFactory) PlanResources(ctx context.Context, guest vmqual.Guest) (vmqual.VMResourceIdentity, error) {
	if f == nil || f.diskRoot == "" {
		return vmqual.VMResourceIdentity{}, errors.New("vmqual: Firecracker factory is not configured")
	}
	if guest.ID == "" || strings.ContainsAny(guest.ID, `/\\\x00`) {
		return vmqual.VMResourceIdentity{}, errors.New("vmqual: resource guest id is invalid")
	}
	paths := sandboxPaths(f.config, guest.ID)
	seedDir := filepath.Join(f.config.StateRoot, guest.ID)
	drivePaths, err := vmdisk.PlanPaths(f.diskRoot, guest.ID, 1)
	if err != nil {
		return vmqual.VMResourceIdentity{}, err
	}
	runID, _ := vmqual.RunIDFromContext(ctx)
	return vmqual.VMResourceIdentity{
		RunID:                runID,
		StateDir:             paths.stateDir,
		SandboxOwnershipPath: filepath.Join(paths.stateDir, "ownership.json"),
		RunMarkerPath:        filepath.Join(paths.stateDir, vmqual.RunMarkerName),
		RuntimePath:          paths.runtime,
		JailRoot:             paths.jailRoot,
		SocketPath:           paths.socket,
		LogPath:              paths.log,
		MetricsPath:          paths.metrics,
		CgroupRoot:           f.cgroupRoot,
		CgroupPath:           filepath.Join(f.cgroupRoot, "terrascale-sandboxvm", guest.ID),
		JailerCgroupPath:     filepath.Join(f.cgroupRoot, filepath.Base(f.config.FirecrackerPath), guest.ID),
		FirecrackerPath:      filepath.Join(paths.jailRoot, filepath.Base(f.config.FirecrackerPath)),
		DriveDir:             drivePaths.DriveDir,
		DrivePath:            drivePaths.Artifact,
		DriveMetadataPath:    drivePaths.Metadata,
		DriveOwnershipPath:   drivePaths.Ownership,
		SeedDir:              seedDir,
	}, nil
}

func (f *firecrackerFactory) PlanDiskStore(ctx context.Context) (vmdisk.StoreIdentity, error) {
	if f == nil || f.diskRoot == "" {
		return vmdisk.StoreIdentity{}, errors.New("vmqual: Firecracker disk store is not configured")
	}
	if ctx == nil {
		return vmdisk.StoreIdentity{}, errors.New("vmqual: disk store context is nil")
	}
	runID, ok := vmqual.RunIDFromContext(ctx)
	if !ok {
		return vmdisk.StoreIdentity{}, errors.New("vmqual: disk store run identity is missing")
	}
	return vmdisk.PlanStoreIdentity(f.diskRoot, runID, vmdisk.Ownership{UID: f.config.JailerUID, GID: f.config.JailerGID})
}

func (f *firecrackerFactory) FinalizeDiskStore(ctx context.Context, identity vmdisk.StoreIdentity) error {
	if f == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("vmqual: disk store cleanup context is nil")
	}
	f.diskMu.Lock()
	defer f.diskMu.Unlock()
	if f.disks == nil {
		return vmdisk.RemoveStore(ctx, identity)
	}
	actual := f.disks.Identity()
	if actual.Root != identity.Root || actual.RunID != identity.RunID || actual.Ownership != identity.Ownership || actual.Tombstone != identity.Tombstone {
		return errors.New("vmqual: live disk store identity differs from the cleanup journal")
	}
	usage, err := f.disks.Usage(ctx)
	if err != nil {
		return err
	}
	if usage.Bytes != 0 || usage.Drives != 0 || usage.Snapshots != 0 {
		return fmt.Errorf("vmqual: disk store still owns %d bytes in %d drives and %d snapshots", usage.Bytes, usage.Drives, usage.Snapshots)
	}
	if err := f.disks.CloseAndRemove(ctx); err != nil {
		return err
	}
	f.disks = nil
	return nil
}

func sandboxStateDir(config vmqual.Config, id string) string {
	return filepath.Join(config.StateRoot, filepath.Base(config.FirecrackerPath), id)
}

func sandboxPaths(config vmqual.Config, id string) resolvedSandboxPaths {
	stateDir := sandboxStateDir(config, id)
	jailRoot := filepath.Join(stateDir, "root")
	return resolvedSandboxPaths{
		stateDir: stateDir,
		jailRoot: jailRoot,
		socket:   filepath.Join(jailRoot, "api.sock"),
		log:      filepath.Join(stateDir, "firecracker.log"),
		metrics:  filepath.Join(stateDir, "firecracker.metrics"),
		runtime:  filepath.Join(stateDir, "runtime.json"),
	}
}

func resolveHostExecutable(names ...string) (string, error) {
	var failures []error
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		info, err := os.Lstat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
			failures = append(failures, fmt.Errorf("%s is not a regular executable", resolved))
			continue
		}
		return filepath.Clean(resolved), nil
	}
	if len(failures) == 0 {
		return "", errors.New("no executable name was supplied")
	}
	return "", errors.Join(failures...)
}

func cloneRootDrive(ctx context.Context, source, stateDir string, maximum int64) (string, string, error) {
	if ctx == nil {
		return "", "", errors.New("vmqual: rootfs clone context is nil")
	}
	if source == "" || !filepath.IsAbs(source) || stateDir == "" || !filepath.IsAbs(stateDir) || filepath.Base(stateDir) == "." {
		return "", "", errors.New("vmqual: rootfs clone paths must be absolute")
	}
	if err := regularImmutableFile(source); err != nil {
		return "", "", fmt.Errorf("vmqual: rootfs clone source: %w", err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return "", "", err
	}
	if info.Size() <= 0 || maximum <= 0 || info.Size() > maximum {
		return "", "", errors.New("vmqual: rootfs clone exceeds the configured disk budget")
	}
	if err := os.MkdirAll(filepath.Dir(stateDir), 0o700); err != nil {
		return "", "", err
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		return "", "", fmt.Errorf("vmqual: create VM state directory: %w", err)
	}
	target := filepath.Join(stateDir, "rootfs.ext4")
	staging := filepath.Join(stateDir, ".rootfs.ext4.tmp")
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(staging)
		}
	}()
	sourceFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", "", fmt.Errorf("vmqual: open rootfs source: %w", err)
	}
	sourceFile := os.NewFile(uintptr(sourceFD), source)
	defer sourceFile.Close()
	destinationFD, err := unix.Open(staging, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("vmqual: create rootfs clone: %w", err)
	}
	destination := os.NewFile(uintptr(destinationFD), staging)
	destinationOpen := true
	defer func() {
		if destinationOpen {
			_ = destination.Close()
		}
	}()
	if err := unix.IoctlFileClone(int(destination.Fd()), int(sourceFile.Fd())); err != nil {
		if !reflinkUnsupported(err) {
			return "", "", fmt.Errorf("vmqual: reflink rootfs: %w", err)
		}
		if err := copySparseFile(ctx, sourceFile, destination, info.Size()); err != nil {
			return "", "", fmt.Errorf("vmqual: sparse-copy rootfs: %w", err)
		}
	}
	if err := destination.Truncate(info.Size()); err != nil {
		return "", "", err
	}
	if err := destination.Sync(); err != nil {
		return "", "", err
	}
	if err := destination.Close(); err != nil {
		return "", "", err
	}
	destinationOpen = false
	if err := os.Rename(staging, target); err != nil {
		return "", "", err
	}
	if err := vmqual.SyncDirectory(stateDir); err != nil {
		return "", "", err
	}
	digest, err := fileSHA256(target)
	if err != nil {
		return "", "", err
	}
	complete = true
	return target, digest, nil
}

func copySparseFile(ctx context.Context, source, destination *os.File, size int64) error {
	if source == nil || destination == nil || size <= 0 {
		return errors.New("invalid sparse-copy input")
	}
	if err := destination.Truncate(size); err != nil {
		return err
	}
	buffer := make([]byte, 1<<20)
	for cursor := int64(0); cursor < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		dataOffset, err := unix.Seek(int(source.Fd()), cursor, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("source filesystem does not support SEEK_DATA: %w", err)
		}
		if dataOffset < cursor || dataOffset >= size {
			return errors.New("source returned an invalid data extent")
		}
		holeOffset, err := unix.Seek(int(source.Fd()), dataOffset, unix.SEEK_HOLE)
		if err != nil {
			return fmt.Errorf("source filesystem does not support SEEK_HOLE: %w", err)
		}
		if holeOffset <= dataOffset {
			return errors.New("source returned an invalid hole extent")
		}
		if holeOffset > size {
			holeOffset = size
		}
		for offset := dataOffset; offset < holeOffset; {
			if err := ctx.Err(); err != nil {
				return err
			}
			part := int64(len(buffer))
			if remaining := holeOffset - offset; remaining < part {
				part = remaining
			}
			read, readErr := source.ReadAt(buffer[:part], offset)
			if readErr != nil && !(errors.Is(readErr, io.EOF) && int64(read) == part) {
				return readErr
			}
			written, writeErr := destination.WriteAt(buffer[:read], offset)
			if writeErr != nil {
				return writeErr
			}
			if written != read || int64(read) != part {
				return io.ErrShortWrite
			}
			offset += int64(read)
		}
		cursor = holeOffset
	}
	return nil
}

func reflinkUnsupported(err error) bool {
	return errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL)
}

func formatPersistentDataDrive(ctx context.Context, formatter, path, id string) error {
	if ctx == nil {
		return errors.New("vmqual: data formatter context is nil")
	}
	if formatter == "" || !filepath.IsAbs(formatter) || path == "" || !filepath.IsAbs(path) {
		return errors.New("vmqual: data formatter and drive paths must be absolute")
	}
	if err := regularImmutableFile(path); err != nil {
		return fmt.Errorf("vmqual: data drive: %w", err)
	}
	command := exec.CommandContext(ctx, formatter, "-F", "-q", "-t", "ext4", "-L", "terrascale-data", "-U", deterministicDiskUUID(id), "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0", path)
	command.Env = hostToolEnvironment()
	command.WaitDelay = 2 * time.Second
	var output limitedHostOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("vmqual: format persistent data disk: %w: %s", err, output.String())
	}
	if err := regularImmutableFile(path); err != nil {
		return errors.New("vmqual: data formatter replaced the drive with an unsafe file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	magic := make([]byte, 2)
	if _, err := file.ReadAt(magic, 1024+56); err != nil || binary.LittleEndian.Uint16(magic) != 0xef53 {
		return errors.New("vmqual: data formatter did not create an ext4 filesystem")
	}
	return nil
}

func deterministicDiskUUID(id string) string {
	sum := sha256.Sum256([]byte("terrascale-vmqual-data\x00" + id))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	value := hex.EncodeToString(sum[:16])
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}

type limitedHostOutput struct{ data []byte }

func (output *limitedHostOutput) Write(data []byte) (int, error) {
	n := len(data)
	if len(output.data) < 64<<10 {
		output.data = append(output.data, data[:min(len(data), 64<<10-len(output.data))]...)
	}
	return n, nil
}

func (output *limitedHostOutput) String() string { return strings.TrimSpace(string(output.data)) }

func removePreparedVMState(stateDir, id string) error {
	if stateDir == "" || !filepath.IsAbs(stateDir) || filepath.Base(stateDir) != id || id == "" || strings.ContainsAny(id, `/\\\x00`) {
		return errors.New("vmqual: refusing to remove invalid VM state path")
	}
	info, err := os.Lstat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: refusing to remove unsafe VM state path")
	}
	return os.RemoveAll(stateDir)
}

func validateInstalledImage(image vmqual.ImageResult) error {
	installed := image.Installed
	if installed.Dir == "" || !filepath.IsAbs(installed.Dir) {
		return errors.New("vmqual: installed image directory must be absolute")
	}
	if installed.Kernel == "" || installed.RootFS == "" || !filepath.IsAbs(installed.Kernel) || !filepath.IsAbs(installed.RootFS) {
		return errors.New("vmqual: installed image kernel and rootfs are required")
	}
	if !vmqual.PathWithin(installed.Dir, installed.Kernel) || !vmqual.PathWithin(installed.Dir, installed.RootFS) {
		return errors.New("vmqual: installed image artifacts must remain below its directory")
	}
	if installed.Kernel == installed.RootFS {
		return errors.New("vmqual: kernel and rootfs must be distinct")
	}
	if err := regularImmutableFile(installed.Kernel); err != nil {
		return fmt.Errorf("vmqual: installed kernel: %w", err)
	}
	if err := regularImmutableFile(installed.RootFS); err != nil {
		return fmt.Errorf("vmqual: installed rootfs: %w", err)
	}
	// MaterializeImage already verifies the pair. Revalidate the immutable
	// manifest here because callers can construct ImageResult directly.
	if err := image.Manifest.Validate(); err != nil {
		return fmt.Errorf("vmqual: installed image manifest: %w", err)
	}
	if installed.Manifest.SchemaVersion != 0 {
		left, leftErr := installed.Manifest.CanonicalJSON()
		right, rightErr := image.Manifest.CanonicalJSON()
		if leftErr != nil || rightErr != nil || string(left) != string(right) {
			return errors.New("vmqual: installed image manifest differs from image result")
		}
	}
	return nil
}

func regularImmutableFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("artifact is not a regular non-symlink file")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
