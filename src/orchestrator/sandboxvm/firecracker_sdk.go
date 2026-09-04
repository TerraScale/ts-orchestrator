//go:build sandboxvm

package sandboxvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/fifo"
	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"golang.org/x/sys/unix"
)

const captureMetricsHandlerName = "terrascale.CaptureMetrics"

const (
	attachCgroupHandlerName = "terrascale.AttachOwnedCgroup"
	cgroupPeriodMicros      = int64(100000)
	cgroupPIDsMax           = int64(64)
	cgroupMemoryOverheadMiB = int64(128)
)

// NewSDKMachineFactory binds the lifecycle boundary to the pinned official
// Firecracker Go SDK. It is available only to the explicit qualification build
// and therefore cannot be pulled into a production binary.
func NewSDKMachineFactory() MachineFactory {
	return func(ctx context.Context, cfg Config) (Machine, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sdkCfg, diagnostics, err := newSDKConfig(cfg)
		if err != nil {
			return nil, err
		}
		lifecycleCtx, cancel := context.WithCancel(context.Background())
		// JailerCfg is deliberately the only process-launch configuration. Passing
		// WithProcessRunner here would replace the jailer command constructed by
		// the SDK after it has adapted all paths into the chroot.
		machine, err := firecracker.NewMachine(lifecycleCtx, sdkCfg)
		if err != nil {
			cancel()
			diagnostics.Close()
			return nil, fmt.Errorf("new jailed Firecracker machine: %w", err)
		}
		executable := filepath.Join(sdkCfg.JailerCfg.ChrootBaseDir, filepath.Base(sdkCfg.JailerCfg.ExecFile), sdkCfg.VMID, "root", filepath.Base(sdkCfg.JailerCfg.ExecFile))
		strategy := sdkCfg.JailerCfg.ChrootStrategy.(*jailerChrootStrategy)
		return &sdkMachine{machine: machine, diagnostics: diagnostics, cgroup: strategy.cgroup, lifecycleCtx: lifecycleCtx, cancel: cancel, expectedExecutable: executable, expectedSHA256: cfg.ExpectedFirecrackerSHA256}, nil
	}
}

func buildSDKConfig(cfg Config) (firecracker.Config, error) {
	sdkCfg, _, err := newSDKConfig(cfg)
	return sdkCfg, err
}

func newSDKConfig(cfg Config) (firecracker.Config, *diagnosticCapture, error) {
	normalized, paths, err := normalizeConfig(cfg)
	if err != nil {
		return firecracker.Config{}, nil, err
	}
	cfg = normalized
	root, writable, readOnly := true, false, true
	kernelArgs := cfg.KernelArgs
	if kernelArgs == "" {
		kernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw"
	}
	drives := []models.Drive{{DriveID: firecracker.String("rootfs"), PathOnHost: &cfg.RootDrive, IsRootDevice: &root, IsReadOnly: &writable}}
	if cfg.DataDrive != "" {
		dataReadOnly := cfg.DataDriveReadOnly
		drives = append(drives, models.Drive{DriveID: firecracker.String("data"), PathOnHost: &cfg.DataDrive, IsRootDevice: &writable, IsReadOnly: &dataReadOnly})
	}
	if cfg.SeedDrive != "" {
		drives = append(drives, models.Drive{DriveID: firecracker.String("seed"), PathOnHost: &cfg.SeedDrive, IsRootDevice: &writable, IsReadOnly: &readOnly})
	}
	diagnostics, err := newDiagnosticCapture(paths)
	if err != nil {
		return firecracker.Config{}, nil, err
	}
	logFIFO := filepath.Join(paths.StateDir, "firecracker-log.fifo")
	metricsFIFO := filepath.Join(paths.StateDir, "firecracker-metrics.fifo")
	strategy := &jailerChrootStrategy{
		kernelImage: cfg.KernelImage,
		metricsFIFO: metricsFIFO,
		diagnostics: diagnostics,
		cgroup:      newOwnedCgroup(cfg.CgroupRoot, cfg),
		dataBlock:   cfg.dataDriveBlock,
		blockOps:    realBlockNodeOperations(),
	}
	sdkConfig := firecracker.Config{
		// This path is interpreted from inside the jail. NewMachine rewrites its
		// own client path to the corresponding absolute host path.
		SocketPath:      jailerSocketPath,
		LogFifo:         logFIFO,
		LogLevel:        "Warning",
		MetricsFifo:     metricsFIFO,
		FifoLogWriter:   diagnostics.log,
		KernelImagePath: cfg.KernelImage,
		KernelArgs:      kernelArgs,
		VMID:            cfg.ID,
		NetNS:           cfg.NetworkNamespace,
		MachineCfg:      models.MachineConfiguration{VcpuCount: &cfg.VCPU, MemSizeMib: &cfg.MemoryMiB},
		Drives:          drives,
		// Enabled=true preserves Firecracker's built-in seccomp filter. The SDK's
		// zero value would explicitly launch with --no-seccomp.
		Seccomp: firecracker.SeccompConfig{Enabled: true},
		JailerCfg: &firecracker.JailerConfig{
			ID:             cfg.ID,
			UID:            cfg.JailerUID,
			GID:            cfg.JailerGID,
			NumaNode:       cfg.JailerNumaNode,
			ExecFile:       cfg.FirecrackerBinary,
			JailerBinary:   cfg.JailerBinary,
			ChrootBaseDir:  cfg.JailerChrootBaseDir,
			CgroupVersion:  "2",
			ChrootStrategy: strategy,
			Stdout:         diagnostics.log,
			Stderr:         diagnostics.log,
		},
	}
	if cfg.TapName != "" {
		sdkConfig.NetworkInterfaces = []firecracker.NetworkInterface{{StaticConfiguration: &firecracker.StaticNetworkConfiguration{
			HostDevName: cfg.TapName,
			MacAddress:  cfg.GuestMAC,
		}}}
	}
	return sdkConfig, diagnostics, nil
}

// jailerChrootStrategy stages ordinary artifacts with hard links and maps a
// fault adapter's device-mapper target to a private block node in the jail.
// It also adds the metrics reader that the SDK's built-in strategy omits.
type jailerChrootStrategy struct {
	kernelImage string
	metricsFIFO string
	diagnostics *diagnosticCapture
	cgroup      *ownedCgroup
	dataBlock   *blockDeviceIdentity
	blockOps    blockNodeOperations
}

func (s *jailerChrootStrategy) AdaptHandlers(handlers *firecracker.Handlers) error {
	if s == nil || s.kernelImage == "" || s.diagnostics == nil || s.cgroup == nil || !s.blockOps.valid() {
		return errors.New("sandboxvm: incomplete jailer chroot strategy")
	}
	if !handlers.FcInit.Has(firecracker.CreateLogFilesHandlerName) {
		return firecracker.ErrRequiredHandlerMissing
	}
	linkHandler := firecracker.Handler{Name: firecracker.LinkFilesToRootFSHandlerName, Fn: s.stageJailFiles}
	handlers.FcInit = handlers.FcInit.AppendAfter(firecracker.CreateLogFilesHandlerName, linkHandler)
	attach := firecracker.Handler{Name: attachCgroupHandlerName, Fn: func(_ context.Context, machine *firecracker.Machine) error {
		pid, err := machine.PID()
		if err != nil {
			return fmt.Errorf("read Firecracker PID for cgroup attachment: %w", err)
		}
		return s.cgroup.Attach(pid)
	}}
	handlers.FcInit = handlers.FcInit.AppendAfter(firecracker.StartVMMHandlerName, attach)
	handler := firecracker.Handler{Name: captureMetricsHandlerName, Fn: func(ctx context.Context, _ *firecracker.Machine) error {
		info, err := os.Lstat(s.metricsFIFO)
		if err != nil {
			return fmt.Errorf("inspect Firecracker metrics FIFO: %w", err)
		}
		if info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Firecracker metrics path is not an owned FIFO")
		}
		reader, err := fifo.OpenFifo(ctx, s.metricsFIFO, syscall.O_RDONLY|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return fmt.Errorf("open Firecracker metrics FIFO: %w", err)
		}
		s.diagnostics.addReader(reader)
		go func() {
			_, _ = io.Copy(s.diagnostics.metrics, reader)
			_ = reader.Close()
		}()
		return nil
	}}
	handlers.FcInit = handlers.FcInit.AppendAfter(firecracker.LinkFilesToRootFSHandlerName, handler)
	return nil
}

type blockNodeOperations struct {
	mknod   func(string, uint32, int) error
	chown   func(string, int, int) error
	chmod   func(string, os.FileMode) error
	inspect func(string, int, int) (blockDeviceIdentity, error)
	remove  func(string) error
}

func realBlockNodeOperations() blockNodeOperations {
	return blockNodeOperations{
		mknod:   unix.Mknod,
		chown:   os.Chown,
		chmod:   os.Chmod,
		inspect: inspectPrivateBlockDevice,
		remove:  os.Remove,
	}
}

func (ops blockNodeOperations) valid() bool {
	return ops.mknod != nil && ops.chown != nil && ops.chmod != nil && ops.inspect != nil && ops.remove != nil
}

func (s *jailerChrootStrategy) stageJailFiles(_ context.Context, machine *firecracker.Machine) (err error) {
	if machine == nil || machine.Cfg.JailerCfg == nil || machine.Cfg.JailerCfg.UID == nil || machine.Cfg.JailerCfg.GID == nil {
		return firecracker.ErrMissingJailerConfig
	}
	root := filepath.Join(
		machine.Cfg.JailerCfg.ChrootBaseDir,
		filepath.Base(machine.Cfg.JailerCfg.ExecFile),
		machine.Cfg.JailerCfg.ID,
		"root",
	)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("sandboxvm: jail root is not a real directory")
	}
	uid, gid := *machine.Cfg.JailerCfg.UID, *machine.Cfg.JailerCfg.GID
	created := make([]string, 0, 3+len(machine.Cfg.Drives))
	defer func() {
		if err == nil {
			return
		}
		for index := len(created) - 1; index >= 0; index-- {
			_ = os.Remove(created[index])
		}
	}()

	kernelInfo, err := os.Lstat(machine.Cfg.KernelImagePath)
	if err != nil || !kernelInfo.Mode().IsRegular() || kernelInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(errors.New("sandboxvm: kernel image changed before jail staging"), err)
	}
	kernelName := filepath.Base(s.kernelImage)
	kernelDestination := filepath.Join(root, kernelName)
	if err = linkExactFile(machine.Cfg.KernelImagePath, kernelDestination, kernelInfo); err != nil {
		return err
	}
	created = append(created, kernelDestination)
	machine.Cfg.KernelImagePath = kernelName

	if machine.Cfg.InitrdPath != "" {
		initrdInfo, statErr := os.Lstat(machine.Cfg.InitrdPath)
		if statErr != nil || !initrdInfo.Mode().IsRegular() || initrdInfo.Mode()&os.ModeSymlink != 0 {
			return errors.Join(errors.New("sandboxvm: initrd changed before jail staging"), statErr)
		}
		initrdName := filepath.Base(machine.Cfg.InitrdPath)
		initrdDestination := filepath.Join(root, initrdName)
		if err = linkExactFile(machine.Cfg.InitrdPath, initrdDestination, initrdInfo); err != nil {
			return err
		}
		created = append(created, initrdDestination)
		machine.Cfg.InitrdPath = initrdName
	}

	foundBlockData := false
	for index := range machine.Cfg.Drives {
		drive := &machine.Cfg.Drives[index]
		hostPath := firecracker.StringValue(drive.PathOnHost)
		if hostPath == "" {
			return errors.New("sandboxvm: drive has an empty host path")
		}
		driveID := firecracker.StringValue(drive.DriveID)
		if s.dataBlock != nil && driveID == "data" {
			if foundBlockData || filepath.Clean(hostPath) != s.dataBlock.Path {
				return errors.New("sandboxvm: fault data-drive identity is inconsistent")
			}
			current, resolveErr := resolvePrivateBlockDevice(hostPath, uid, gid)
			if resolveErr != nil || !s.dataBlock.matches(current) {
				return errors.Join(errors.New("sandboxvm: fault block device changed before jail staging"), resolveErr)
			}
			destination := filepath.Join(root, faultDataDriveJailName)
			if err = createJailBlockDevice(destination, uid, gid, current, s.blockOps); err != nil {
				return err
			}
			created = append(created, destination)
			drive.PathOnHost = firecracker.String(faultDataDriveJailName)
			foundBlockData = true
			continue
		}
		driveInfo, validateErr := validatePrivateJailerFile(hostPath, uid, gid)
		if validateErr != nil {
			return fmt.Errorf("validate drive before jail staging: %w", validateErr)
		}
		driveName := filepath.Base(hostPath)
		destination := filepath.Join(root, driveName)
		if err = linkExactFile(hostPath, destination, driveInfo); err != nil {
			return err
		}
		created = append(created, destination)
		drive.PathOnHost = firecracker.String(driveName)
	}
	if s.dataBlock != nil && !foundBlockData {
		return errors.New("sandboxvm: fault block device has no data drive")
	}

	for _, fifoPath := range []*string{&machine.Cfg.LogFifo, &machine.Cfg.MetricsFifo} {
		if fifoPath == nil || *fifoPath == "" {
			continue
		}
		fifoInfo, statErr := os.Lstat(*fifoPath)
		if statErr != nil || fifoInfo.Mode()&os.ModeNamedPipe == 0 || fifoInfo.Mode()&os.ModeSymlink != 0 {
			return errors.Join(errors.New("sandboxvm: diagnostic FIFO changed before jail staging"), statErr)
		}
		fileName := filepath.Base(*fifoPath)
		destination := filepath.Join(root, fileName)
		if err = linkExactFile(*fifoPath, destination, fifoInfo); err != nil {
			return err
		}
		created = append(created, destination)
		if err = os.Chown(destination, uid, gid); err != nil {
			return err
		}
		*fifoPath = fileName
	}
	return nil
}

func linkExactFile(source, destination string, expected os.FileInfo) error {
	if expected == nil || expected.Mode()&os.ModeSymlink != 0 {
		return errors.New("sandboxvm: invalid jail hard-link source")
	}
	if err := os.Link(source, destination); err != nil {
		return err
	}
	destinationInfo, err := os.Lstat(destination)
	if err != nil || destinationInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, destinationInfo) {
		_ = os.Remove(destination)
		return errors.Join(errors.New("sandboxvm: jail hard link did not preserve source identity"), err)
	}
	return nil
}

func createJailBlockDevice(path string, uid, gid int, source blockDeviceIdentity, ops blockNodeOperations) (err error) {
	if !ops.valid() || !filepath.IsAbs(path) || filepath.Base(path) != faultDataDriveJailName {
		return errors.New("sandboxvm: invalid jail block-device request")
	}
	device := int(source.Rdev)
	if uint64(device) != source.Rdev {
		return errors.New("sandboxvm: block-device number exceeds host integer width")
	}
	if err := ops.mknod(path, uint32(unix.S_IFBLK|0600), device); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = ops.remove(path)
		}
	}()
	if err = ops.chown(path, uid, gid); err != nil {
		return err
	}
	if err = ops.chmod(path, 0600); err != nil {
		return err
	}
	created, inspectErr := ops.inspect(path, uid, gid)
	if inspectErr != nil || created.Rdev != source.Rdev {
		return errors.Join(errors.New("sandboxvm: jailed block-device identity is incorrect"), inspectErr)
	}
	return nil
}

type boundedDiagnosticWriter struct {
	mu        sync.Mutex
	path      string
	limit     int64
	file      *os.File
	bytes     int64
	truncated bool
	closed    bool
}

func newBoundedDiagnosticWriter(path string, limit int64) (*boundedDiagnosticWriter, error) {
	if !filepath.IsAbs(path) || limit <= 0 {
		return nil, errors.New("sandboxvm: invalid bounded diagnostic path or limit")
	}
	writer := &boundedDiagnosticWriter{path: path, limit: limit}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return writer, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, fmt.Errorf("sandboxvm: unsafe existing diagnostic file %s", path)
	}
	writer.bytes = info.Size()
	writer.truncated = info.Size() == limit
	return writer, nil
}

func (w *boundedDiagnosticWriter) open() error {
	if w.file != nil {
		return nil
	}
	info, err := os.Lstat(w.path)
	if errors.Is(err, os.ErrNotExist) {
		file, openErr := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return openErr
		}
		w.file = file
		w.bytes = 0
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() > w.limit {
		return fmt.Errorf("sandboxvm: unsafe existing diagnostic file %s", w.path)
	}
	file, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0600 || openedInfo.Size() > w.limit {
		_ = file.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("sandboxvm: diagnostic file changed while opening %s", w.path)
	}
	w.file = file
	w.bytes = openedInfo.Size()
	w.truncated = w.truncated || openedInfo.Size() == w.limit
	return nil
}

func (w *boundedDiagnosticWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(data)
	if w.closed {
		return 0, os.ErrClosed
	}
	if err := w.open(); err != nil {
		return 0, err
	}
	remaining := w.limit - w.bytes
	if remaining <= 0 {
		w.truncated = true
		return original, nil
	}
	toWrite := data
	if int64(len(toWrite)) > remaining {
		toWrite = toWrite[:remaining]
		w.truncated = true
	}
	written, err := w.file.Write(toWrite)
	w.bytes += int64(written)
	if err != nil {
		return written, err
	}
	if written != len(toWrite) {
		return written, io.ErrShortWrite
	}
	// Report the input as consumed after the admitted prefix is durable so a
	// chatty VMM cannot turn the deliberate bound into a lifecycle failure.
	return original, nil
}

func (w *boundedDiagnosticWriter) observation() DiagnosticFileObservation {
	w.mu.Lock()
	defer w.mu.Unlock()
	return DiagnosticFileObservation{Path: w.path, Bytes: w.bytes, Truncated: w.truncated}
}

func (w *boundedDiagnosticWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	return errors.Join(w.file.Sync(), w.file.Close())
}

type diagnosticCapture struct {
	mu      sync.Mutex
	readers []io.Closer
	log     *boundedDiagnosticWriter
	metrics *boundedDiagnosticWriter
	once    sync.Once
}

var cgroupSetupMu sync.Mutex

type ownedCgroup struct {
	mu           sync.Mutex
	root         string
	parent       string
	path         string
	jailerParent string
	jailerPath   string
	cpus         string
	mems         string
	numaNode     int
	cpuMax       string
	memoryMax    string
	pidsMax      string
	attachedPID  int
	setupStarted bool
}

func newOwnedCgroup(root string, cfg Config) *ownedCgroup {
	parent := filepath.Join(root, cgroupParentName)
	return &ownedCgroup{
		root:         root,
		parent:       parent,
		path:         filepath.Join(parent, cfg.ID),
		jailerParent: filepath.Join(root, filepath.Base(cfg.FirecrackerBinary)),
		jailerPath:   filepath.Join(root, filepath.Base(cfg.FirecrackerBinary), cfg.ID),
		numaNode:     *cfg.JailerNumaNode,
		cpuMax:       fmt.Sprintf("%d %d", cfg.VCPU*cgroupPeriodMicros, cgroupPeriodMicros),
		memoryMax:    strconv.FormatInt((cfg.MemoryMiB+cgroupMemoryOverheadMiB)<<20, 10),
		pidsMax:      strconv.FormatInt(cgroupPIDsMax, 10),
	}
}

func (g *ownedCgroup) Attach(pid int) error {
	if g == nil || pid <= 0 || validateCgroup2Mount(g.root) != nil || !pathWithinRoot(g.root, g.path) || !pathWithinRoot(g.root, g.jailerPath) {
		return errors.New("sandboxvm: invalid owned cgroup configuration")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cgroupSetupMu.Lock()
	defer cgroupSetupMu.Unlock()
	g.setupStarted = true
	var fs syscall.Statfs_t
	if err := syscall.Statfs(g.root, &fs); err != nil {
		return err
	}
	if uint64(fs.Type) != uint64(0x63677270) {
		return errors.New("sandboxvm: host cgroup root is not cgroup v2")
	}
	controllers, err := readCgroupFile(filepath.Join(g.root, "cgroup.controllers"))
	if err != nil {
		return err
	}
	for _, controller := range []string{"cpu", "memory", "pids", "cpuset"} {
		if !fieldPresent(controllers, controller) {
			return fmt.Errorf("sandboxvm: cgroup v2 controller %q is unavailable", controller)
		}
	}
	rootCPUs, err := readCgroupFile(filepath.Join(g.root, "cpuset.cpus.effective"))
	if err != nil || rootCPUs == "" {
		return errors.Join(errors.New("sandboxvm: cgroup v2 effective CPU set is unavailable"), err)
	}
	rootMems, err := readCgroupFile(filepath.Join(g.root, "cpuset.mems.effective"))
	if err != nil || rootMems == "" {
		return errors.Join(errors.New("sandboxvm: cgroup v2 effective memory-node set is unavailable"), err)
	}
	g.cpus, err = readSmallFile(fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", g.numaNode))
	if err != nil || g.cpus == "" {
		return errors.Join(fmt.Errorf("sandboxvm: NUMA node %d CPU list is unavailable", g.numaNode), err)
	}
	g.mems = strconv.Itoa(g.numaNode)
	if !cpuSetContains(rootCPUs, g.cpus) || !cpuSetContains(rootMems, g.mems) {
		return fmt.Errorf("sandboxvm: NUMA node %d is outside the effective cgroup cpuset", g.numaNode)
	}
	if err := requireCgroupControllersEnabled(g.root); err != nil {
		return err
	}
	if err := mkdirCgroup(g.parent, true); err != nil {
		return err
	}
	if err := writeCgroupFile(filepath.Join(g.parent, "cpuset.cpus"), rootCPUs); err != nil {
		return err
	}
	if err := writeCgroupFile(filepath.Join(g.parent, "cpuset.mems"), rootMems); err != nil {
		return err
	}
	if err := enableCgroupControllers(g.parent); err != nil {
		return err
	}
	if err := mkdirCgroup(g.path, false); err != nil {
		return err
	}
	settings := map[string]string{
		"cpuset.cpus":     g.cpus,
		"cpuset.mems":     g.mems,
		"cpu.max":         g.cpuMax,
		"memory.max":      g.memoryMax,
		"memory.swap.max": "0",
		"pids.max":        g.pidsMax,
	}
	for name, value := range settings {
		if err := writeCgroupFile(filepath.Join(g.path, name), value); err != nil {
			return fmt.Errorf("configure cgroup %s: %w", name, err)
		}
	}
	if err := writeCgroupFile(filepath.Join(g.path, "cgroup.procs"), strconv.Itoa(pid)); err != nil {
		return fmt.Errorf("attach Firecracker to owned cgroup: %w", err)
	}
	for name, value := range settings {
		got, err := readCgroupFile(filepath.Join(g.path, name))
		if err != nil || got != value {
			return fmt.Errorf("verify cgroup %s: got %q, want %q: %w", name, got, value, err)
		}
	}
	membership, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return err
	}
	wantMembership := "0::" + strings.TrimPrefix(g.path, g.root)
	if !fieldLinePresent(string(membership), wantMembership) {
		return fmt.Errorf("sandboxvm: Firecracker PID %d is not in owned cgroup %s", pid, g.path)
	}
	g.attachedPID = pid
	if err := removeEmptyCgroup(g.jailerPath, false); err != nil {
		return fmt.Errorf("remove empty jailer cgroup: %w", err)
	}
	if err := removeEmptyCgroup(g.jailerParent, true); err != nil {
		return fmt.Errorf("remove empty jailer cgroup parent: %w", err)
	}
	return nil
}

func (g *ownedCgroup) Cleanup() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cgroupSetupMu.Lock()
	defer cgroupSetupMu.Unlock()
	if g.setupStarted {
		if err := removeEmptyCgroup(g.path, false); err != nil {
			return err
		}
	}
	// The jailer creates its own cgroup before the post-start attachment
	// handler runs. A startup failure can therefore leave this leaf behind even
	// when setupStarted is false.
	if err := removeEmptyCgroup(g.jailerPath, false); err != nil {
		return err
	}
	if err := removeEmptyCgroup(g.jailerParent, true); err != nil {
		return err
	}
	if g.setupStarted {
		if err := removeEmptyCgroup(g.parent, true); err != nil {
			return err
		}
	}
	g.setupStarted = false
	g.attachedPID = 0
	return nil
}

func (g *ownedCgroup) Validate(pid int) error {
	if g == nil || pid <= 0 {
		return errors.New("sandboxvm: invalid cgroup validation request")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.setupStarted || g.attachedPID != pid {
		return errors.New("sandboxvm: Firecracker cgroup was not attached by this machine")
	}
	settings := map[string]string{
		"cpuset.cpus":     g.cpus,
		"cpuset.mems":     g.mems,
		"cpu.max":         g.cpuMax,
		"memory.max":      g.memoryMax,
		"memory.swap.max": "0",
		"pids.max":        g.pidsMax,
	}
	for name, value := range settings {
		got, err := readCgroupFile(filepath.Join(g.path, name))
		if err != nil || got != value {
			return fmt.Errorf("verify cgroup %s: got %q, want %q: %w", name, got, value, err)
		}
	}
	membership, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return err
	}
	wantMembership := "0::" + strings.TrimPrefix(g.path, g.root)
	if !fieldLinePresent(string(membership), wantMembership) {
		return fmt.Errorf("sandboxvm: Firecracker PID %d left owned cgroup %s", pid, g.path)
	}
	return nil
}

func enableCgroupControllers(path string) error {
	const enabled = "+cpu +memory +pids +cpuset"
	if err := writeCgroupFile(filepath.Join(path, "cgroup.subtree_control"), enabled); err != nil {
		return fmt.Errorf("enable cgroup v2 controllers below %s: %w", path, err)
	}
	current, err := readCgroupFile(filepath.Join(path, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	for _, controller := range []string{"cpu", "memory", "pids", "cpuset"} {
		if !fieldPresent(current, controller) {
			return fmt.Errorf("sandboxvm: cgroup v2 controller %q was not enabled below %s", controller, path)
		}
	}
	return nil
}

func requireCgroupControllersEnabled(path string) error {
	current, err := readCgroupFile(filepath.Join(path, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	for _, controller := range []string{"cpu", "memory", "pids", "cpuset"} {
		if !fieldPresent(current, controller) {
			return fmt.Errorf("sandboxvm: cgroup v2 controller %q is not delegated below %s", controller, path)
		}
	}
	return nil
}

func mkdirCgroup(path string, allowExisting bool) error {
	err := os.Mkdir(path, 0755)
	if err == nil {
		return nil
	}
	if !allowExisting || !errors.Is(err, os.ErrExist) {
		return err
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return statErr
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("sandboxvm: existing cgroup parent is unsafe")
	}
	return nil
}

func readCgroupFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<10 {
		return "", fmt.Errorf("sandboxvm: unsafe cgroup control file %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) > 64<<10 {
		return "", fmt.Errorf("sandboxvm: oversized cgroup control file %s", path)
	}
	return strings.TrimSpace(string(data)), nil
}

func readSmallFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<10 {
		return "", fmt.Errorf("sandboxvm: unsafe host topology file %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func cpuSetContains(outer, inner string) bool {
	outerSet, ok := parseCPUSet(outer)
	if !ok {
		return false
	}
	innerSet, ok := parseCPUSet(inner)
	if !ok || len(innerSet) == 0 {
		return false
	}
	for value := range innerSet {
		if _, exists := outerSet[value]; !exists {
			return false
		}
	}
	return true
}

func parseCPUSet(value string) (map[int]struct{}, bool) {
	result := make(map[int]struct{})
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return nil, false
		}
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 0 {
			return nil, false
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first || last-first > 1<<20 {
				return nil, false
			}
		}
		for current := first; current <= last; current++ {
			result[current] = struct{}{}
		}
	}
	return result, true
}

func writeCgroupFile(path, value string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sandboxvm: unsafe cgroup control file %s", path)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, value)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func removeEmptyCgroup(path string, shared bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sandboxvm: refusing unsafe cgroup path %s", path)
	}
	processes, err := readCgroupFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return err
	}
	if processes != "" {
		return fmt.Errorf("sandboxvm: refusing to remove populated cgroup %s", path)
	}
	err = os.Remove(path)
	if shared && (errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EBUSY)) {
		return nil
	}
	return err
}

func fieldPresent(value, field string) bool {
	for _, candidate := range strings.Fields(value) {
		if candidate == field {
			return true
		}
	}
	return false
}

func fieldLinePresent(value, line string) bool {
	for _, candidate := range strings.Split(strings.TrimSpace(value), "\n") {
		if strings.TrimSpace(candidate) == line {
			return true
		}
	}
	return false
}

func newDiagnosticCapture(paths Paths) (*diagnosticCapture, error) {
	logWriter, err := newBoundedDiagnosticWriter(paths.Log, DiagnosticLimitBytes)
	if err != nil {
		return nil, err
	}
	metricsWriter, err := newBoundedDiagnosticWriter(paths.Metrics, DiagnosticLimitBytes)
	if err != nil {
		return nil, err
	}
	return &diagnosticCapture{log: logWriter, metrics: metricsWriter}, nil
}

func (d *diagnosticCapture) addReader(reader io.Closer) {
	d.mu.Lock()
	d.readers = append(d.readers, reader)
	d.mu.Unlock()
}

func (d *diagnosticCapture) observation() DiagnosticObservation {
	if d == nil {
		return DiagnosticObservation{}
	}
	return DiagnosticObservation{LimitBytes: DiagnosticLimitBytes, Log: d.log.observation(), Metrics: d.metrics.observation()}
}

func (d *diagnosticCapture) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.mu.Lock()
		readers := append([]io.Closer(nil), d.readers...)
		d.mu.Unlock()
		for _, reader := range readers {
			_ = reader.Close()
		}
		_ = d.log.Close()
		_ = d.metrics.Close()
	})
}

type sdkMachine struct {
	mu                 sync.Mutex
	machine            *firecracker.Machine
	diagnostics        *diagnosticCapture
	cgroup             *ownedCgroup
	lifecycleCtx       context.Context
	cancel             context.CancelFunc
	expectedExecutable string
	expectedSHA256     string
	executableInfo     os.FileInfo
	pid                int
	processStartTime   uint64
}

func (m *sdkMachine) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	startupDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			m.cancel()
		case <-startupDone:
		}
	}()
	startErr := m.machine.Start(m.lifecycleCtx)
	close(startupDone)
	identityErr := m.captureProcessIdentity()
	if startErr != nil {
		return errors.Join(startErr, identityErr)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, identityErr)
	}
	return identityErr
}

func (m *sdkMachine) captureProcessIdentity() error {
	pid, err := m.machine.PID()
	if err != nil {
		return err
	}
	process, err := observeProcess(pid)
	if err != nil {
		return fmt.Errorf("observe Firecracker process identity: %w", err)
	}
	m.mu.Lock()
	m.pid, m.processStartTime = pid, process.StartTime
	m.mu.Unlock()
	if !process.Alive || process.StartTime == 0 {
		return errors.New("Firecracker process is not alive")
	}
	matched, err := sameProcessExecutable(m.expectedExecutable, pid, process.Executable)
	if err != nil {
		return fmt.Errorf("verify jailed Firecracker executable identity: %w", err)
	}
	if !matched {
		return fmt.Errorf("running executable is %q, want jail copy %q", process.Executable, m.expectedExecutable)
	}
	if err := validateArtifact(Artifact{Kind: "firecracker", Path: m.expectedExecutable, SHA256: m.expectedSHA256}); err != nil {
		return fmt.Errorf("verify jailed Firecracker executable digest: %w", err)
	}
	info, err := os.Stat(m.expectedExecutable)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.executableInfo = info
	m.mu.Unlock()
	return nil
}

func (m *sdkMachine) Shutdown(ctx context.Context) error { return m.machine.Shutdown(ctx) }
func (m *sdkMachine) StopVMM() error {
	err := m.machine.StopVMM()
	m.cancel()
	return err
}
func (m *sdkMachine) Wait(ctx context.Context) error {
	// A handler may fail before the SDK starts a process. In that case its
	// exit channel never closes, so waiting on it would consume the whole
	// controller stop timeout for a process that never existed.
	if _, err := m.machine.PID(); err != nil {
		m.cancel()
		m.diagnostics.Close()
		return nil
	}
	err := m.machine.Wait(ctx)
	if ctx.Err() == nil {
		m.cancel()
		m.diagnostics.Close()
	}
	return err
}

func (m *sdkMachine) ExitConfirmed() (bool, error) {
	m.mu.Lock()
	pid, start := m.pid, m.processStartTime
	m.mu.Unlock()
	if pid <= 0 {
		var err error
		pid, err = m.machine.PID()
		if err != nil {
			if cleanupErr := m.cgroup.Cleanup(); cleanupErr != nil {
				return false, cleanupErr
			}
			return true, nil
		}
	}
	process, err := observeProcess(pid)
	if errors.Is(err, os.ErrNotExist) {
		if cleanupErr := m.cgroup.Cleanup(); cleanupErr != nil {
			return false, cleanupErr
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if start == 0 {
		m.mu.Lock()
		m.pid, m.processStartTime = pid, process.StartTime
		m.mu.Unlock()
		return !process.Alive, nil
	}
	exited := !process.Alive || process.StartTime != start
	if exited {
		if cleanupErr := m.cgroup.Cleanup(); cleanupErr != nil {
			return false, cleanupErr
		}
	}
	return exited, nil
}

func (m *sdkMachine) Close() {
	m.cancel()
	m.diagnostics.Close()
}

func (m *sdkMachine) Version(ctx context.Context) (string, error) {
	version, err := m.machine.GetFirecrackerVersion(ctx)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", errors.New("Firecracker returned an empty version")
	}
	return version, nil
}

func (m *sdkMachine) Inspect(ctx context.Context) (Inspection, error) {
	m.mu.Lock()
	pid, start, executableInfo := m.pid, m.processStartTime, m.executableInfo
	m.mu.Unlock()
	inspection := Inspection{PID: pid, ProcessStartTime: start, Diagnostics: m.diagnostics.observation()}
	if pid <= 0 || start == 0 {
		return inspection, errors.New("Firecracker has no recorded process identity")
	}
	process, err := observeProcess(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			inspection.State = StateStopped
			return inspection, nil
		}
		return inspection, err
	}
	executableMatches, _ := sameProcessExecutable(m.expectedExecutable, pid, process.Executable)
	if executableMatches && executableInfo != nil {
		currentInfo, statErr := os.Stat(m.expectedExecutable)
		executableMatches = statErr == nil && os.SameFile(executableInfo, currentInfo)
	} else {
		executableMatches = false
	}
	inspection.Executable = process.Executable
	inspection.ExecutableValid = executableMatches
	inspection.CgroupValid = m.cgroup.Validate(pid) == nil
	inspection.ProcessAlive = process.Alive && process.StartTime == start
	inspection.RSSBytes = process.RSSBytes
	inspection.SocketReady = SocketReady(m.machine.Cfg.SocketPath)
	if !inspection.ProcessAlive {
		inspection.State = StateStopped
		return inspection, nil
	}
	if !inspection.ExecutableValid || !inspection.CgroupValid || !inspection.SocketReady {
		inspection.State = StateStarting
		return inspection, nil
	}
	info, err := m.machine.DescribeInstanceInfo(ctx)
	if err != nil {
		return inspection, err
	}
	if info.State != nil {
		inspection.State = State(strings.ToLower(*info.State))
	}
	if info.VmmVersion != nil {
		inspection.Version = *info.VmmVersion
	}
	return inspection, nil
}
