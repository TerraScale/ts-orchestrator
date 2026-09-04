//go:build sandboxvm

package sandboxvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/fifo"
	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

const captureMetricsHandlerName = "terrascale.CaptureMetrics"

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
		return &sdkMachine{machine: machine, diagnostics: diagnostics, lifecycleCtx: lifecycleCtx, cancel: cancel, expectedExecutable: cfg.FirecrackerBinary}, nil
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
	drives := []models.Drive{
		{DriveID: firecracker.String("rootfs"), PathOnHost: &cfg.RootDrive, IsRootDevice: &root, IsReadOnly: &writable},
		{DriveID: firecracker.String("data"), PathOnHost: &cfg.DataDrive, IsRootDevice: &writable, IsReadOnly: &writable},
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
		base:        firecracker.NewNaiveChrootStrategy(cfg.KernelImage),
		metricsFIFO: metricsFIFO,
		diagnostics: diagnostics,
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

// jailerChrootStrategy delegates kernel and drive staging to the SDK and adds
// the metrics reader that its built-in strategy omits. Both FIFOs are linked
// into the jail by NewNaiveChrootStrategy before Firecracker receives them.
type jailerChrootStrategy struct {
	base        firecracker.HandlersAdapter
	metricsFIFO string
	diagnostics *diagnosticCapture
}

func (s *jailerChrootStrategy) AdaptHandlers(handlers *firecracker.Handlers) error {
	if s == nil || s.base == nil || s.diagnostics == nil {
		return errors.New("sandboxvm: incomplete jailer chroot strategy")
	}
	if err := s.base.AdaptHandlers(handlers); err != nil {
		return err
	}
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
	lifecycleCtx       context.Context
	cancel             context.CancelFunc
	expectedExecutable string
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
	err := m.machine.Start(m.lifecycleCtx)
	close(startupDone)
	if err != nil {
		m.cancel()
		m.diagnostics.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = m.machine.StopVMM()
		m.cancel()
		return err
	}
	pid, err := m.machine.PID()
	if err != nil {
		_ = m.machine.StopVMM()
		return err
	}
	process, err := observeProcess(pid)
	if err != nil || !process.Alive || process.StartTime == 0 {
		_ = m.machine.StopVMM()
		if err == nil {
			err = errors.New("Firecracker process is not alive")
		}
		return fmt.Errorf("record Firecracker process identity: %w", err)
	}
	matched, err := sameExecutable(m.expectedExecutable, process.Executable)
	if err != nil || !matched {
		_ = m.machine.StopVMM()
		m.cancel()
		if err == nil {
			err = fmt.Errorf("running executable is %q, want %q", process.Executable, m.expectedExecutable)
		}
		return fmt.Errorf("record Firecracker executable identity: %w", err)
	}
	m.mu.Lock()
	m.pid, m.processStartTime = pid, process.StartTime
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
	pid, start := m.pid, m.processStartTime
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
	executableMatches, _ := sameExecutable(m.expectedExecutable, process.Executable)
	inspection.Executable = process.Executable
	inspection.ProcessAlive = process.Alive && process.StartTime == start && executableMatches
	inspection.RSSBytes = process.RSSBytes
	inspection.SocketReady = SocketReady(m.machine.Cfg.SocketPath)
	if !inspection.ProcessAlive || !inspection.SocketReady {
		inspection.State = StateStopped
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
