package vmqual

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
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

type sandboxVM struct {
	provider *sandboxvm.Provider
	disks    *vmdisk.Store
	guest    Guest
	id       string
	executor sandboxvm.CommandRunner
	seedDir  string
	resources VMResourceIdentity
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
			_ = v.provider.Stop(context.Background(), v.id)
			return fmt.Errorf("vmqual: bootstrap guest artifacts: %w", err)
		}
	}
	if err := v.provider.WaitReady(ctx, v.id); err != nil {
		_ = v.provider.Stop(context.Background(), v.id)
		return err
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
	// Cleanup is deliberately independent of the caller's deadline. A
	// cancelled qualification must not strand a VMM jail or its drive.
	cleanCtx := context.WithoutCancel(ctx)
	if destroyer, ok := v.executor.(interface{ Destroy() }); ok {
		defer destroyer.Destroy()
	}
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
	return errors.Join(providerErr, diskErr, stateErr)
}
func (v *sandboxVM) Inspect(ctx context.Context) (VMObservation, error) {
	if v == nil || v.provider == nil {
		return VMObservation{}, errors.New("vmqual: VM provider is not configured")
	}
	if ctx == nil {
		return VMObservation{}, errors.New("vmqual: VM context is nil")
	}
	info, err := v.provider.Inspect(ctx, v.id)
	if err != nil {
		return VMObservation{}, err
	}
	process := VMProcessIdentity{}
	if info.PID > 0 || info.ProcessStartTime > 0 {
		process = VMProcessIdentity{PID: info.PID, StartTimeTicks: info.ProcessStartTime, Executable: info.Config.FirecrackerBinary}
	}
	resources := v.resources
	resources.Process = process
	return VMObservation{ID: v.id, Region: v.guest.Region, Running: info.State == sandboxvm.StateRunning, Ready: info.Ready, MemoryMiB: info.Config.MemoryMiB, RSSBytes: info.RSSBytes, IdleCPU: info.IdleCPU, Process: process, Resources: resources}, nil
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
	provider *sandboxvm.Provider
	image    ImageResult
	disks    *vmdisk.Store
	config   Config
	mkfsPath string
}

// NewFirecrackerFactory is the production command-side factory. The tagged
// runtime binds it to the official SDK; unit tests should inject VMFactory
// instead of calling this constructor.
func NewFirecrackerFactory(config Config, image ImageResult) (VMFactory, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateInstalledImage(image); err != nil {
		return nil, err
	}
	if image.Installed.Dir == "" {
		return nil, errors.New("vmqual: installed image is required")
	}
	provider, err := newSandboxVMProvider(config)
	if err != nil {
		return nil, err
	}
	disks, err := vmdisk.NewStore(filepath.Join(config.Root, "drives"))
	if err != nil {
		return nil, err
	}
	mkfsPath, err := resolveHostExecutable("mkfs.ext4", "mke2fs")
	if err != nil {
		return nil, fmt.Errorf("vmqual: ext4 formatter: %w", err)
	}
	return &firecrackerFactory{provider: provider, image: image, disks: disks, config: config, mkfsPath: mkfsPath}, nil
}
func (f *firecrackerFactory) Create(ctx context.Context, guest Guest) (VM, error) {
	if f == nil || f.provider == nil || f.disks == nil {
		return nil, errors.New("vmqual: Firecracker factory is not configured")
	}
	if ctx == nil {
		return nil, errors.New("vmqual: VM context is nil")
	}
	if guest.ID == "" || strings.ContainsAny(guest.ID, `/\\\x00`) || guest.Region == "" || guest.VCPU != 1 || guest.MemoryMiB < 256 || guest.MemoryMiB > MaxGuestMemoryMiB {
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
	drive, err := f.disks.Preallocate(ctx, guest.ID, 64<<20)
	if err != nil {
		return nil, err
	}
	driveCreated := true
	defer func() {
		if driveCreated {
			_ = f.disks.Delete(context.Background(), guest.ID)
		}
	}()
	if err := formatPersistentDataDrive(ctx, f.mkfsPath, drive.Path, guest.ID); err != nil {
		return nil, err
	}
	paths := sandboxPaths(f.config, guest.ID)
	vmConfig := sandboxvm.Config{ID: guest.ID, Region: string(guest.Region), VCPU: guest.VCPU, MemoryMiB: guest.MemoryMiB, KernelImage: f.image.Installed.Kernel, RootDrive: rootDrive, DataDrive: drive.Path, StateRoot: f.config.StateRoot, JailerChrootBaseDir: f.config.StateRoot, SocketPath: paths.socket, KernelArgs: qualificationKernelArgs, LogPath: paths.log, MetricsPath: paths.metrics, FirecrackerBinary: f.config.FirecrackerPath, JailerBinary: f.config.JailerPath, ExpectedVersion: f.config.ExpectedVersion, ExpectedKernelSHA256: f.config.ExpectedKernelSHA256, ExpectedRootDriveSHA256: rootDigest, ExpectedDataDriveSHA256: "", ExpectedFirecrackerSHA256: f.config.ExpectedFirecrackerSHA256, ExpectedJailerSHA256: f.config.ExpectedJailerSHA256, ReadinessTimeout: f.config.ReadinessTimeout, StopTimeout: f.config.StopTimeout}
	seedDigest, err := f.prepareGuest(ctx, guest, &vmConfig)
	if err != nil {
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
	prepared, driveCreated, executorOwned = false, false, false
	return &sandboxVM{provider: f.provider, disks: f.disks, guest: guest, id: guest.ID, executor: executor, seedDir: resources.SeedDir, resources: resources}, nil
}

const qualificationKernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootfstype=ext4 systemd.mask=boot.mount systemd.mask=boot-efi.mount"

type resolvedSandboxPaths struct{ stateDir, jailRoot, socket, log, metrics, runtime string }

// PlanResources returns the exact paths used by Create without touching the
// filesystem. Stack writes this plan to its cleanup journal before creation.
func (f *firecrackerFactory) PlanResources(ctx context.Context, guest Guest) (VMResourceIdentity, error) {
	if f == nil || f.disks == nil {
		return VMResourceIdentity{}, errors.New("vmqual: Firecracker factory is not configured")
	}
	if guest.ID == "" || strings.ContainsAny(guest.ID, `/\\\x00`) {
		return VMResourceIdentity{}, errors.New("vmqual: resource guest id is invalid")
	}
	paths := sandboxPaths(f.config, guest.ID)
	seedDir := filepath.Join(f.config.StateRoot, guest.ID)
	driveDir := filepath.Join(f.disks.Root(), "drives", guest.ID)
	runID, _ := RunIDFromContext(ctx)
	return VMResourceIdentity{
		RunID:                runID,
		StateDir:             paths.stateDir,
		SandboxOwnershipPath: filepath.Join(paths.stateDir, "ownership.json"),
		RunMarkerPath:        filepath.Join(paths.stateDir, runMarkerName),
		RuntimePath:          paths.runtime,
		JailRoot:             paths.jailRoot,
		SocketPath:           paths.socket,
		LogPath:              paths.log,
		MetricsPath:          paths.metrics,
		DriveDir:             driveDir,
		DrivePath:            filepath.Join(driveDir, "disk.img"),
		DriveMetadataPath:    filepath.Join(driveDir, "metadata.json"),
		SeedDir:              seedDir,
		SeedDrivePath:        filepath.Join(seedDir, "seed.img"),
	}, nil
}

func sandboxStateDir(config Config, id string) string {
	return filepath.Join(config.StateRoot, filepath.Base(config.FirecrackerPath), id)
}

func sandboxPaths(config Config, id string) resolvedSandboxPaths {
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
		if _, err := sourceFile.Seek(0, io.SeekStart); err != nil {
			return "", "", err
		}
		if _, err := destination.Seek(0, io.SeekStart); err != nil {
			return "", "", err
		}
		copied, err := io.CopyBuffer(destination, &contextReader{ctx: ctx, reader: io.LimitReader(sourceFile, info.Size()+1)}, make([]byte, 1<<20))
		if err != nil {
			return "", "", fmt.Errorf("vmqual: copy rootfs: %w", err)
		}
		if copied != info.Size() {
			return "", "", errors.New("vmqual: rootfs changed while it was cloned")
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
	if err := syncDirectory(stateDir); err != nil {
		return "", "", err
	}
	digest, err := fileSHA256(target)
	if err != nil {
		return "", "", err
	}
	complete = true
	return target, digest, nil
}

func reflinkUnsupported(err error) bool {
	return errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
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
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
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

func validateInstalledImage(image ImageResult) error {
	installed := image.Installed
	if installed.Dir == "" || !filepath.IsAbs(installed.Dir) {
		return errors.New("vmqual: installed image directory must be absolute")
	}
	if installed.Kernel == "" || installed.RootFS == "" || !filepath.IsAbs(installed.Kernel) || !filepath.IsAbs(installed.RootFS) {
		return errors.New("vmqual: installed image kernel and rootfs are required")
	}
	if !pathWithin(installed.Dir, installed.Kernel) || !pathWithin(installed.Dir, installed.RootFS) {
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
