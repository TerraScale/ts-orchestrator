package sandboxvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeMachine struct {
	mu                                            sync.Mutex
	start, shutdown, stop, wait, version, inspect int
	shutdownBlock                                 <-chan struct{}
	waitBlock                                     <-chan struct{}
	startErr, waitErr, exitConfirmedErr           error
	inspectErr                                    error
	omitInspectionVersion                         bool
	shutdownLeavesAlive, stopLeavesAlive          bool
	versionValue                                  string
	pid                                           int
	processStartTime                              uint64
	executable                                    string
	processAlive                                  bool
	socketReady                                   bool
	state                                         State
	dead                                          bool
}

func (m *fakeMachine) Start(context.Context) error {
	m.mu.Lock()
	m.start++
	m.dead = false
	m.state = StateRunning
	m.processAlive = true
	m.socketReady = true
	err := m.startErr
	m.mu.Unlock()
	return err
}
func (m *fakeMachine) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.shutdown++
	block := m.shutdownBlock
	m.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	if !m.shutdownLeavesAlive {
		m.dead = true
		m.state = StateStopped
		m.processAlive = false
		m.socketReady = false
	}
	m.mu.Unlock()
	return nil
}
func (m *fakeMachine) StopVMM() error {
	m.mu.Lock()
	m.stop++
	if !m.stopLeavesAlive {
		m.dead = true
		m.state = StateStopped
		m.processAlive = false
		m.socketReady = false
	}
	m.mu.Unlock()
	return nil
}
func (m *fakeMachine) Wait(ctx context.Context) error {
	m.mu.Lock()
	m.wait++
	block := m.waitBlock
	m.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	err := m.waitErr
	m.mu.Unlock()
	return err
}
func (m *fakeMachine) ExitConfirmed() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.processAlive, m.exitConfirmedErr
}
func (m *fakeMachine) Version(context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version++
	if m.versionValue == "" {
		return "1.0", nil
	}
	return m.versionValue, nil
}
func (m *fakeMachine) Inspect(context.Context) (Inspection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inspect++
	pid, start, state, dead := m.pid, m.processStartTime, m.state, m.dead
	if pid == 0 {
		pid = 42
	}
	if start == 0 {
		start = 100
	}
	if state == "" {
		state = StateRunning
	}
	version, executable := m.versionValue, m.executable
	if version == "" && !m.omitInspectionVersion {
		version = "1.0"
	}
	alive, socket := m.processAlive, m.socketReady
	if dead {
		state, alive, socket = StateStopped, false, false
	} else if !alive && !socket && state == StateRunning {
		alive, socket = true, true
	}
	return Inspection{State: state, PID: pid, ProcessStartTime: start, Executable: executable, ExecutableValid: true, CgroupValid: true, ProcessAlive: alive, SocketReady: socket, Version: version}, m.inspectErr
}

type fakeAPI struct {
	mu      sync.Mutex
	patches []string
}

func (a *fakeAPI) Version(context.Context) (string, error) { return "1.0", nil }
func (a *fakeAPI) Inspect(context.Context) (Inspection, error) {
	return Inspection{SocketReady: true}, nil
}
func (a *fakeAPI) PatchVM(_ context.Context, state string) error {
	a.mu.Lock()
	a.patches = append(a.patches, state)
	a.mu.Unlock()
	return nil
}

type fakeProbe struct {
	mu     sync.Mutex
	result Readiness
	calls  int
}

func (p *fakeProbe) Probe(context.Context, string) (Readiness, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.result, nil
}

type fakeRunner struct {
	mu       sync.Mutex
	commands []Command
}

type fakeDataDriveFaultAdapter struct {
	attachment *fakeDataDriveFaultAttachment
	err        error
	request    DataDriveFaultRequest
}

func (a *fakeDataDriveFaultAdapter) Prepare(_ context.Context, request DataDriveFaultRequest) (DataDriveFaultAttachment, error) {
	a.request = request
	return a.attachment, a.err
}

type fakeDataDriveFaultAttachment struct {
	path      string
	cleaned   bool
	activated bool
}

func (a *fakeDataDriveFaultAttachment) Path() string { return a.path }
func (a *fakeDataDriveFaultAttachment) Cleanup(context.Context) error {
	a.cleaned = true
	return nil
}
func (a *fakeDataDriveFaultAttachment) Activate(context.Context) error {
	a.activated = true
	return nil
}

func (r *fakeRunner) Run(_ context.Context, c Command) error {
	r.mu.Lock()
	r.commands = append(r.commands, c)
	r.mu.Unlock()
	return nil
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	stateRoot, err := os.MkdirTemp("", "sandboxvm-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateRoot) })
	paths := map[string][]byte{"kernel": []byte("kernel"), "root": []byte("root"), "data": []byte("data"), "firecracker": []byte("firecracker"), "jailer": []byte("jailer")}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 || gid == 0 {
		uid, gid = 1000, 1000
	}
	files := make(map[string]string)
	for name, content := range paths {
		path := filepath.Join(root, name)
		mode := os.FileMode(0700)
		if name == "kernel" {
			mode = 0644
		} else if name == "root" || name == "data" {
			mode = 0600
		}
		if err := os.WriteFile(path, content, mode); err != nil {
			t.Fatal(err)
		}
		if (name == "root" || name == "data") && (os.Getuid() != uid || os.Getgid() != gid) {
			if err := os.Chown(path, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
		files[name] = path
	}
	return Config{ID: "gru-member-1", Region: "GRU", VCPU: 1, MemoryMiB: 256, KernelImage: files["kernel"], RootDrive: files["root"], DataDrive: files["data"], StateRoot: stateRoot, JailerUID: &uid, JailerGID: &gid, FirecrackerBinary: files["firecracker"], JailerBinary: files["jailer"], ExpectedVersion: "1.0", ExpectedKernelSHA256: digest(paths["kernel"]), ExpectedRootDriveSHA256: digest(paths["root"]), ExpectedDataDriveSHA256: digest(paths["data"]), ExpectedFirecrackerSHA256: digest(paths["firecracker"]), ExpectedJailerSHA256: digest(paths["jailer"]), ReadinessTimeout: 300 * time.Millisecond, StopTimeout: time.Second}
}

func testProvider(t *testing.T, machine *fakeMachine, probe *fakeProbe, runner CommandRunner) *Provider {
	t.Helper()
	p, err := New(Options{MachineFactory: func(_ context.Context, cfg Config) (Machine, error) {
		machine.mu.Lock()
		machine.executable = filepath.Join(cfg.JailerChrootBaseDir, filepath.Base(cfg.FirecrackerBinary), cfg.ID, "root", filepath.Base(cfg.FirecrackerBinary))
		machine.mu.Unlock()
		return machine, nil
	}, OpenAPIFactory: func(Config) (OpenAPI, error) { return &fakeAPI{}, nil }, Probe: probe, CommandRunner: runner})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLifecycleReadinessExecuteRebootAndDelete(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: "1.0", pid: 42}
	probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
	runner := &fakeRunner{}
	p := testProvider(t, machine, probe, runner)
	info, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != StateCreated || info.Paths.StateDir != filepath.Join(cfg.StateRoot, "firecracker", cfg.ID) {
		t.Fatalf("unexpected create result: %+v", info)
	}
	if err := p.StartAndWaitReady(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateProcess(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Execute(context.Background(), cfg.ID, Command{Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Reboot(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(info.Paths.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory remains: %v", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.start != 1 || machine.shutdown != 1 || machine.wait != 1 {
		t.Fatalf("unexpected machine calls: %+v", machine)
	}
}

func TestStopThenStartBuildsFreshRuntimeAndPreservesDiagnostics(t *testing.T) {
	cfg := testConfig(t)
	probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
	var machines []*fakeMachine
	p, err := New(Options{
		MachineFactory: func(_ context.Context, machineConfig Config) (Machine, error) {
			machine := &fakeMachine{
				versionValue:     machineConfig.ExpectedVersion,
				pid:              42 + len(machines),
				processStartTime: uint64(100 + len(machines)),
				executable:       filepath.Join(machineConfig.JailerChrootBaseDir, filepath.Base(machineConfig.FirecrackerBinary), machineConfig.ID, "root", filepath.Base(machineConfig.FirecrackerBinary)),
			}
			machines = append(machines, machine)
			return machine, nil
		},
		OpenAPIFactory: func(Config) (OpenAPI, error) { return &fakeAPI{}, nil },
		Probe:          probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if created.Paths.Cgroup != filepath.Join(created.Config.CgroupRoot, cgroupParentName, cfg.ID) || created.Paths.JailerCgroup != filepath.Join(created.Config.CgroupRoot, filepath.Base(cfg.FirecrackerBinary), cfg.ID) {
		t.Fatalf("owned cgroup paths = %q / %q", created.Paths.Cgroup, created.Paths.JailerCgroup)
	}
	if err := os.WriteFile(created.Paths.Log, []byte("first boot\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.StartAndWaitReady(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DataDrive, []byte("guest-mutated-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RootDrive, []byte("guest-mutated-root"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.StartAndWaitReady(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(created.Paths.Log)
	if err != nil || string(data) != "first boot\n" {
		t.Fatalf("diagnostic log after restart = %q, %v", data, err)
	}
	if len(machines) != 2 {
		t.Fatalf("machine factory calls = %d, want 2", len(machines))
	}
	for index, machine := range machines {
		machine.mu.Lock()
		starts := machine.start
		machine.mu.Unlock()
		if starts != 1 {
			t.Fatalf("machine %d starts = %d, want 1", index, starts)
		}
	}
}

func TestApplyDataDrivePlanRebuildsStoppedMachine(t *testing.T) {
	cfg := testConfig(t)
	writeDrive := func(name, contents string) string {
		path := filepath.Join(filepath.Dir(cfg.DataDrive), name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if os.Getuid() != *cfg.JailerUID || os.Getgid() != *cfg.JailerGID {
			if err := os.Chown(path, *cfg.JailerUID, *cfg.JailerGID); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	replacement := writeDrive("replacement-data", "replacement")
	faultPath := writeDrive("fault-data", "fault-adapter")
	attachment := &fakeDataDriveFaultAttachment{path: faultPath}
	adapter := &fakeDataDriveFaultAdapter{attachment: attachment}
	var configs []Config
	p, err := New(Options{
		MachineFactory: func(_ context.Context, machineConfig Config) (Machine, error) {
			configs = append(configs, machineConfig)
			return &fakeMachine{
				pid:              42 + len(configs),
				processStartTime: uint64(100 + len(configs)),
				versionValue:     machineConfig.ExpectedVersion,
				executable:       filepath.Join(machineConfig.JailerChrootBaseDir, filepath.Base(machineConfig.FirecrackerBinary), machineConfig.ID, "root", filepath.Base(machineConfig.FirecrackerBinary)),
			}, nil
		},
		OpenAPIFactory: func(Config) (OpenAPI, error) { return &fakeAPI{}, nil },
		Probe:          &fakeProbe{},
		DataDriveFault: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, DataDrivePlan{DriveID: cfg.ID, Generation: 1, Attached: false}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("running ApplyDataDrivePlan() error = %v", err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	plan := DataDrivePlan{DriveID: cfg.ID, Generation: 1, Attached: true, Path: replacement, Size: int64(len("replacement")), SHA256: digest([]byte("replacement")), ReadOnly: true}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err != nil {
		t.Fatal(err)
	}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("replayed generation error = %v", err)
	}
	zeroGeneration := plan
	zeroGeneration.Generation = 0
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, zeroGeneration); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("zero generation error = %v", err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[1].DataDrive != replacement || !configs[1].DataDriveReadOnly {
		t.Fatalf("replacement start config = %+v", configs)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	plan.Generation = 2
	plan.ReadOnly = false
	plan.IOFailure = true
	p.resolveDataFault = func(path string, uid, gid int) (blockDeviceIdentity, error) {
		if path != faultPath || uid != *cfg.JailerUID || gid != *cfg.JailerGID {
			t.Fatalf("fault resolver = %q %d:%d", path, uid, gid)
		}
		return blockDeviceIdentity{Path: path, Device: 11, Inode: 12, Rdev: 13}, nil
	}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err != nil {
		t.Fatal(err)
	}
	if adapter.request.Generation != plan.Generation || adapter.request.VMID != cfg.ID || adapter.request.SourcePath != replacement {
		t.Fatalf("fault adapter request = %+v", adapter.request)
	}
	i, err := p.get(cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	gotFaultPath := i.cfg.DataDrive
	i.mu.Unlock()
	if gotFaultPath != faultPath {
		t.Fatalf("fault adapter path = %q", gotFaultPath)
	}
	if err := p.ActivateDataDriveFault(context.Background(), cfg.ID, plan.Generation); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("stopped ActivateDataDriveFault() error = %v", err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.ActivateDataDriveFault(context.Background(), cfg.ID, plan.Generation-1); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("stale activation error = %v", err)
	}
	if err := p.ActivateDataDriveFault(context.Background(), cfg.ID, plan.Generation); err != nil {
		t.Fatal(err)
	}
	if !attachment.activated {
		t.Fatal("fault attachment was not activated")
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	plan.Generation = 3
	plan.IOFailure = false
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err != nil {
		t.Fatal(err)
	}
	if !attachment.cleaned {
		t.Fatal("previous fault adapter was not cleaned")
	}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, DataDrivePlan{DriveID: cfg.ID, Generation: 4, Attached: false}); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if len(configs) != 4 || configs[3].DataDrive != "" {
		t.Fatalf("detached start config = %+v", configs)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	p.dataFault = nil
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, DataDrivePlan{DriveID: cfg.ID, Generation: 5, Attached: true, Path: replacement, Size: int64(len("replacement")), SHA256: digest([]byte("replacement")), IOFailure: true}); err == nil || !strings.Contains(err.Error(), "requires a real runtime fault adapter") {
		t.Fatalf("unsupported I/O failure error = %v", err)
	}
}

func TestDataDriveFaultPreparationRollsBackAndDeleteCleansAttachment(t *testing.T) {
	cfg := testConfig(t)
	faultPath := filepath.Join(filepath.Dir(cfg.DataDrive), "fault-device")
	failedAttachment := &fakeDataDriveFaultAttachment{path: faultPath}
	adapter := &fakeDataDriveFaultAdapter{attachment: failedAttachment, err: errors.New("prepare failed")}
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	p, err := New(Options{
		MachineFactory: func(_ context.Context, machineConfig Config) (Machine, error) {
			machine.executable = filepath.Join(machineConfig.JailerChrootBaseDir, filepath.Base(machineConfig.FirecrackerBinary), machineConfig.ID, "root", filepath.Base(machineConfig.FirecrackerBinary))
			return machine, nil
		},
		OpenAPIFactory: func(Config) (OpenAPI, error) { return &fakeAPI{}, nil },
		Probe:          &fakeProbe{},
		DataDriveFault: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	plan := DataDrivePlan{DriveID: cfg.ID, Generation: 1, Attached: true, Path: cfg.DataDrive, Size: int64(len("data")), SHA256: cfg.ExpectedDataDriveSHA256, IOFailure: true}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err == nil || !strings.Contains(err.Error(), "prepare failed") {
		t.Fatalf("failed Prepare() error = %v", err)
	}
	if !failedAttachment.cleaned {
		t.Fatal("partially prepared attachment was not cleaned")
	}
	i, err := p.get(cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	generation, dataPath := i.dataGeneration, i.cfg.DataDrive
	i.mu.Unlock()
	if generation != 0 || dataPath != cfg.DataDrive {
		t.Fatalf("failed preparation changed config: generation=%d path=%q", generation, dataPath)
	}

	activeAttachment := &fakeDataDriveFaultAttachment{path: faultPath}
	adapter.attachment, adapter.err = activeAttachment, nil
	p.resolveDataFault = func(path string, _, _ int) (blockDeviceIdentity, error) {
		return blockDeviceIdentity{Path: path, Device: 21, Inode: 22, Rdev: 23}, nil
	}
	if err := p.ApplyDataDrivePlan(context.Background(), cfg.ID, plan); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if !activeAttachment.cleaned {
		t.Fatal("Delete did not clean the active fault attachment")
	}
}

func TestReadinessCancellationStopsVM(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{}
	probe := &fakeProbe{}
	p := testProvider(t, machine, probe, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if err := p.StartAndWaitReady(ctx, cfg.ID); err == nil {
		t.Fatal("expected cancellation")
	}
	machine.mu.Lock()
	stopped := machine.shutdown > 0
	machine.mu.Unlock()
	if !stopped {
		t.Fatal("cancellation did not stop VM")
	}
}

func TestReadinessFailureReturnsUnconfirmedStopError(t *testing.T) {
	cfg := testConfig(t)
	cfg.ReadinessTimeout = 20 * time.Millisecond
	cfg.StopTimeout = 10 * time.Millisecond
	machine := &fakeMachine{shutdownLeavesAlive: true, stopLeavesAlive: true, waitErr: errors.New("early SDK wait")}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	err := p.StartAndWaitReady(context.Background(), cfg.ID)
	if err == nil || !strings.Contains(err.Error(), "not ready") || !strings.Contains(err.Error(), "exit was not confirmed") {
		t.Fatalf("StartAndWaitReady() error = %v", err)
	}
}

func TestCanceledStopStillForcesAndConfirmsExit(t *testing.T) {
	cfg := testConfig(t)
	never := make(chan struct{})
	machine := &fakeMachine{shutdownBlock: never}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Stop(ctx, cfg.ID); err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	forced := machine.stop
	machine.mu.Unlock()
	if forced != 1 {
		t.Fatalf("forced stops = %d, want 1", forced)
	}
}

func TestVersionMismatchAbortsBeforeReadinessProbe(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: "2.0"}
	probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
	p := testProvider(t, machine, probe, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.StartAndWaitReady(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Fatalf("StartAndWaitReady() error = %v", err)
	}
	machine.mu.Lock()
	start, stop, wait := machine.start, machine.stop, machine.wait
	machine.mu.Unlock()
	probe.mu.Lock()
	probeCalls := probe.calls
	probe.mu.Unlock()
	if start != 1 || stop != 1 || wait != 1 {
		t.Fatalf("start/abort calls = %d/%d/%d", start, stop, wait)
	}
	if probeCalls != 0 {
		t.Fatalf("readiness probe called %d times", probeCalls)
	}
}

func TestStartRevalidatesAnAlreadyRunningMachine(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	machine.dead = true
	machine.mu.Unlock()
	if err := p.Start(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "not alive") {
		t.Fatalf("second Start() error = %v", err)
	}
	machine.mu.Lock()
	starts := machine.start
	machine.mu.Unlock()
	if starts != 1 {
		t.Fatalf("dead machine was started through a sticky state: %d calls", starts)
	}
}

func TestInspectRejectsDeadOrChangedProcessIdentity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutate    func(*fakeMachine)
		wantState State
	}{
		{name: "dead process", mutate: func(machine *fakeMachine) { machine.dead = true }, wantState: StateStopped},
		{name: "changed PID", mutate: func(machine *fakeMachine) { machine.pid++ }, wantState: StateRunning},
		{name: "changed start time", mutate: func(machine *fakeMachine) { machine.processStartTime++ }, wantState: StateRunning},
		{name: "changed executable", mutate: func(machine *fakeMachine) { machine.executable = "/bin/sh" }, wantState: StateRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
			probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
			p := testProvider(t, machine, probe, nil)
			if _, err := p.Create(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := p.StartAndWaitReady(context.Background(), cfg.ID); err != nil {
				t.Fatal(err)
			}
			machine.mu.Lock()
			tc.mutate(machine)
			machine.mu.Unlock()
			info, err := p.Inspect(context.Background(), cfg.ID)
			if err != nil {
				t.Fatal(err)
			}
			if info.State != tc.wantState || info.Ready {
				t.Fatalf("inspection trusted stale lifecycle state: %+v", info)
			}
		})
	}
}

func TestInspectLostSocketKeepsLiveMachineStoppable(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	machine.socketReady = false
	machine.mu.Unlock()
	info, err := p.Inspect(context.Background(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != StateRunning || info.Ready {
		t.Fatalf("lost-socket inspection = %+v", info)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	shutdown, wait := machine.shutdown, machine.wait
	machine.mu.Unlock()
	if shutdown != 1 || wait == 0 {
		t.Fatalf("stop calls after lost socket = shutdown %d, wait %d", shutdown, wait)
	}
}

func TestConcurrentStopIsIdempotent(t *testing.T) {
	cfg := testConfig(t)
	release := make(chan struct{})
	machine := &fakeMachine{shutdownBlock: release}
	probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
	p := testProvider(t, machine, probe, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.StartAndWaitReady(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- p.Stop(context.Background(), cfg.ID) }()
	time.Sleep(10 * time.Millisecond)
	second := make(chan error, 1)
	go func() { second <- p.Stop(context.Background(), cfg.ID) }()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.shutdown != 1 {
		t.Fatalf("stop was not idempotent: %d calls", machine.shutdown)
	}
}

func TestDeleteBlocksConcurrentStartUntilStateRemoval(t *testing.T) {
	cfg := testConfig(t)
	release := make(chan struct{})
	machine := &fakeMachine{}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	machine.mu.Lock()
	machine.shutdownBlock = release
	machine.mu.Unlock()
	deleted := make(chan error, 1)
	go func() { deleted <- p.Delete(context.Background(), cfg.ID) }()
	deadline := time.Now().Add(time.Second)
	for {
		machine.mu.Lock()
		shutdown := machine.shutdown
		machine.mu.Unlock()
		if shutdown > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Delete did not enter Stop")
		}
		time.Sleep(time.Millisecond)
	}
	if err := p.Start(context.Background(), cfg.ID); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("concurrent Start() error = %v", err)
	}
	close(release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
}

func TestStopTimeoutRemainsRetryableAndBlocksDelete(t *testing.T) {
	cfg := testConfig(t)
	cfg.StopTimeout = 10 * time.Millisecond
	never := make(chan struct{})
	machine := &fakeMachine{waitBlock: never, shutdownLeavesAlive: true, stopLeavesAlive: true}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "exit was not confirmed") {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := p.Delete(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "exit was not confirmed") {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(created.Paths.StateDir); err != nil {
		t.Fatalf("indeterminate process state was deleted: %v", err)
	}
}

func TestStartFailurePreservesLiveRuntimeUntilExitConfirmed(t *testing.T) {
	cfg := testConfig(t)
	cfg.StopTimeout = 10 * time.Millisecond
	machine := &fakeMachine{
		startErr:              errors.New("SDK socket startup failed"),
		waitErr:               errors.New("SDK exit channel closed early"),
		inspectErr:            errors.New("API unavailable"),
		omitInspectionVersion: true,
		shutdownLeavesAlive:   true,
		stopLeavesAlive:       true,
	}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "exit was not confirmed") {
		t.Fatalf("Start() error = %v", err)
	}
	record, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateRunning || record.PID == 0 || record.ProcessStartTime == 0 || record.Firecracker != "" {
		t.Fatalf("live startup-failure record = %+v", record)
	}
	if err := p.Delete(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "exit was not confirmed") {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(created.Paths.StateDir); err != nil {
		t.Fatalf("live startup-failure state was removed: %v", err)
	}
	machine.mu.Lock()
	machine.processAlive = false
	machine.dead = true
	machine.mu.Unlock()
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUnownedStateCannotBeDeleted(t *testing.T) {
	cfg := testConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.StateRoot, cfg.ID), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.StateRoot, cfg.ID, "ownership.json"), []byte(`{"marker":"other","id":"gru-member-1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedState(filepath.Join(cfg.StateRoot, cfg.ID), cfg.ID); !errors.Is(err, ErrUnowned) {
		t.Fatalf("expected ownership error, got %v", err)
	}
}

func TestResetRejectsUnexpectedTransientPath(t *testing.T) {
	cfg := testConfig(t)
	p := testProvider(t, &fakeMachine{}, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	unexpected := filepath.Join(created.Paths.StateDir, "firecracker-log.fifo")
	if err := os.WriteFile(unexpected, []byte("not a fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "unexpected transient path") {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestConfigValidationRejectsUnsafeValues(t *testing.T) {
	cfg := testConfig(t)
	cfg.ID = "../escape"
	if err := cfg.Validate(); err == nil {
		t.Fatal("path traversal id accepted")
	}
	cfg = testConfig(t)
	cfg.MemoryMiB = 128
	if err := cfg.Validate(); err == nil {
		t.Fatal("undersized memory accepted")
	}
	cfg = testConfig(t)
	cfg.ExpectedDataDriveSHA256 = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bad checksum accepted")
	}
}

func TestJailerIdentityResolution(t *testing.T) {
	uid1001, gid1002, zero := 1001, 1002, 0
	tests := []struct {
		name                         string
		explicitUID, explicitGID     *int
		currentUID, currentGID, euid int
		sudoUID, sudoGID             string
		wantUID, wantGID             int
		wantErr                      string
	}{
		{name: "explicit", explicitUID: &uid1001, explicitGID: &gid1002, currentUID: 0, currentGID: 0, euid: 0, wantUID: 1001, wantGID: 1002},
		{name: "explicit pair required", explicitUID: &uid1001, currentUID: 1001, currentGID: 1002, euid: 1001, wantErr: "configured together"},
		{name: "explicit root rejected", explicitUID: &zero, explicitGID: &gid1002, wantErr: "non-root account"},
		{name: "current non-root identity", currentUID: 1001, currentGID: 1002, euid: 1001, wantUID: 1001, wantGID: 1002},
		{name: "real identity under setuid root", currentUID: 1001, currentGID: 1002, euid: 0, wantUID: 1001, wantGID: 1002},
		{name: "sudo identity", currentUID: 0, currentGID: 0, euid: 0, sudoUID: "1001", sudoGID: "1002", wantUID: 1001, wantGID: 1002},
		{name: "root without sudo identity", currentUID: 0, currentGID: 0, euid: 0, wantErr: "explicit non-root"},
		{name: "malformed sudo identity", currentUID: 0, currentGID: 0, euid: 0, sudoUID: "user", sudoGID: "1002", wantErr: "explicit non-root"},
		{name: "root sudo identity", currentUID: 0, currentGID: 0, euid: 0, sudoUID: "0", sudoGID: "0", wantErr: "explicit non-root"},
		{name: "oversized sudo identity", currentUID: 0, currentGID: 0, euid: 0, sudoUID: "4294967296", sudoGID: "1002", wantErr: "explicit non-root"},
		{name: "non-root user with root group", currentUID: 1001, currentGID: 0, euid: 1001, wantErr: "non-root account"},
	}
	if strconv.IntSize > 32 {
		overflow := int(uint64(1) << 32)
		tests = append(tests, struct {
			name                         string
			explicitUID, explicitGID     *int
			currentUID, currentGID, euid int
			sudoUID, sudoGID             string
			wantUID, wantGID             int
			wantErr                      string
		}{name: "oversized explicit identity", explicitUID: &overflow, explicitGID: &gid1002, wantErr: "unsigned 32-bit"})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid, err := resolveJailerIdentity(tc.explicitUID, tc.explicitGID, tc.currentUID, tc.currentGID, tc.euid, tc.sudoUID, tc.sudoGID)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveJailerIdentity() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || uid != tc.wantUID || gid != tc.wantGID {
				t.Fatalf("resolveJailerIdentity() = %d, %d, %v", uid, gid, err)
			}
		})
	}
}

func TestNormalizeConfigRejectsMismatchedAndOverlongJailPaths(t *testing.T) {
	cfg := testConfig(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "socket", mutate: func(cfg *Config) { cfg.SocketPath = filepath.Join(cfg.StateRoot, "other.sock") }},
		{name: "log", mutate: func(cfg *Config) { cfg.LogPath = filepath.Join(cfg.StateRoot, "other.log") }},
		{name: "metrics", mutate: func(cfg *Config) { cfg.MetricsPath = filepath.Join(cfg.StateRoot, "other.metrics") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cfg
			tc.mutate(&candidate)
			if _, _, err := normalizeConfig(candidate); err == nil || !strings.Contains(err.Error(), "must match") {
				t.Fatalf("normalizeConfig() error = %v", err)
			}
		})
	}
	cfg.StateRoot = filepath.Join(t.TempDir(), strings.Repeat("x", maxUnixSocketPathBytes))
	if _, _, err := normalizeConfig(cfg); err == nil || !strings.Contains(err.Error(), "Linux permits at most") {
		t.Fatalf("normalizeConfig() overlong socket error = %v", err)
	}
}

func TestCreateRequiresPrivateJailerDriveOwnership(t *testing.T) {
	cfg := testConfig(t)
	if err := os.Chmod(cfg.RootDrive, 0640); err != nil {
		t.Fatal(err)
	}
	p := testProvider(t, &fakeMachine{}, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("Create() mode error = %v", err)
	}
	if _, err := validatePrivateJailerFile(cfg.DataDrive, *cfg.JailerUID+1, *cfg.JailerGID); err == nil || !strings.Contains(err.Error(), "file owner") {
		t.Fatalf("validatePrivateJailerFile() owner error = %v", err)
	}
}

func TestRestartRejectsReplacedDriveInode(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	if _, err := p.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(cfg.RootDrive), "replacement-root")
	if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != *cfg.JailerUID || os.Getgid() != *cfg.JailerGID {
		if err := os.Chown(replacement, *cfg.JailerUID, *cfg.JailerGID); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(replacement, cfg.RootDrive); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err == nil || !strings.Contains(err.Error(), "inode changed") {
		t.Fatalf("restart with replaced root drive error = %v", err)
	}
}

func TestRuntimeRecordRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	record, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.PID != 42 || record.ProcessStartTime != 100 || record.Firecracker != cfg.ExpectedVersion || record.SocketPath != created.Paths.Socket || record.LogPath != created.Paths.Log || record.MetricsPath != created.Paths.Metrics || record.State != StateRunning {
		t.Fatalf("runtime record = %+v", record)
	}
	if record.StoppedAt != nil {
		t.Fatalf("running runtime record has stopped timestamp %v", record.StoppedAt)
	}
	if err := p.Stop(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	record, err = ReadRuntimeRecord(created.Paths.StateDir, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateStopped || record.StoppedAt == nil || !record.StoppedAt.Equal(record.ObservedAt) {
		t.Fatalf("stopped runtime record = %+v", record)
	}
	predatingStop := record.ObservedAt.Add(-time.Second)
	record.StoppedAt = &predatingStop
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created.Paths.RuntimeState, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID); err == nil || !strings.Contains(err.Error(), "stop timestamp predates") {
		t.Fatalf("ReadRuntimeRecord() error = %v", err)
	}
}

func TestRuntimeRecordRejectsTimestampBeforeOwnership(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	record, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.ObservedAt = time.Unix(1, 0).UTC()
	if err := writeRuntimeRecord(created.Paths.RuntimeState, record); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID); err == nil || !strings.Contains(err.Error(), "predates its ownership marker") {
		t.Fatalf("ReadRuntimeRecord() error = %v", err)
	}
}

func TestRuntimeRecordRejectsNonCanonicalOwnedPath(t *testing.T) {
	cfg := testConfig(t)
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	p := testProvider(t, machine, &fakeProbe{}, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	record, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.SocketPath = filepath.Join(created.Paths.StateDir, "other.sock")
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created.Paths.RuntimeState, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRuntimeRecord(created.Paths.StateDir, cfg.ID); err == nil {
		t.Fatal("runtime record with a non-canonical owned path was accepted")
	}
}

func TestProcessMeasurementMarksARealZeroSample(t *testing.T) {
	now := time.Now()
	idleCPU, sampled := cpuCoreUsage(42, 42, now, now.Add(time.Second))
	if idleCPU != 0 || !sampled {
		t.Fatalf("process sample = idle CPU %f, sampled %t", idleCPU, sampled)
	}
}

func TestRuntimeRecordVerifiesPIDStartIdentityAndSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fc.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observation, err := observeProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	record := RuntimeRecord{State: StateRunning, PID: os.Getpid(), ProcessStartTime: observation.StartTime, SocketPath: socketPath}
	if err := record.VerifyRunningProcess(observation.Executable); err != nil {
		t.Fatal(err)
	}
	if err := record.VerifyRunningProcess(filepath.Join(t.TempDir(), "other")); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("VerifyRunningProcess() wrong executable error = %v", err)
	}
	record.ProcessStartTime++
	if err := record.VerifyRunningProcess(observation.Executable); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("VerifyRunningProcess() altered start error = %v", err)
	}
}

func TestUnixSocketOpenAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fc.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"firecracker_version":"1.7.0"}`))
		case "/instance-info":
			_, _ = w.Write([]byte(`{"state":"Running","vmm_version":"1.7.0"}`))
		case "/vm":
			if r.Method != http.MethodPatch {
				t.Errorf("method = %s", r.Method)
			}
			_, _ = w.Write([]byte{})
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	client, err := NewUnixSocketOpenAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	version, err := client.Version(context.Background())
	if err != nil || version != "1.7.0" {
		t.Fatalf("version = %q, err = %v", version, err)
	}
	inspection, err := client.Inspect(context.Background())
	if err != nil || !inspection.SocketReady {
		t.Fatalf("inspection = %+v, err = %v", inspection, err)
	}
	if err := client.PatchVM(context.Background(), "Reboot"); err != nil {
		t.Fatal(err)
	}
	if err := client.PatchVM(context.Background(), "invalid"); err == nil {
		t.Fatal("invalid VM patch accepted")
	}
}

func TestSocketReadyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: target, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if !SocketReady(target) {
		t.Fatal("real Unix socket was not ready")
	}
	if SocketReady(link) {
		t.Fatal("symlinked Unix socket was accepted")
	}
}
