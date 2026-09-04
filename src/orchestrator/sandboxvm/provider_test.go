package sandboxvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	m.mu.Unlock()
	return nil
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
	m.dead = true
	m.state = StateStopped
	m.processAlive = false
	m.socketReady = false
	m.mu.Unlock()
	return nil
}
func (m *fakeMachine) StopVMM() error {
	m.mu.Lock()
	m.stop++
	m.dead = true
	m.state = StateStopped
	m.processAlive = false
	m.socketReady = false
	m.mu.Unlock()
	return nil
}
func (m *fakeMachine) Wait(context.Context) error { m.mu.Lock(); m.wait++; m.mu.Unlock(); return nil }
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
	if version == "" {
		version = "1.0"
	}
	alive, socket := m.processAlive, m.socketReady
	if dead {
		state, alive, socket = StateStopped, false, false
	} else if !alive && !socket && state == StateRunning {
		alive, socket = true, true
	}
	return Inspection{State: state, PID: pid, ProcessStartTime: start, Executable: executable, ProcessAlive: alive, SocketReady: socket, Version: version}, nil
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
	files := make(map[string]string)
	for name, content := range paths {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0700); err != nil {
			t.Fatal(err)
		}
		files[name] = path
	}
	uid, gid := 1000, 1000
	return Config{ID: "gru-member-1", Region: "GRU", VCPU: 1, MemoryMiB: 256, KernelImage: files["kernel"], RootDrive: files["root"], DataDrive: files["data"], StateRoot: stateRoot, JailerUID: &uid, JailerGID: &gid, FirecrackerBinary: files["firecracker"], JailerBinary: files["jailer"], ExpectedVersion: "1.0", ExpectedKernelSHA256: digest(paths["kernel"]), ExpectedRootDriveSHA256: digest(paths["root"]), ExpectedDataDriveSHA256: digest(paths["data"]), ExpectedFirecrackerSHA256: digest(paths["firecracker"]), ExpectedJailerSHA256: digest(paths["jailer"]), ReadinessTimeout: 300 * time.Millisecond, StopTimeout: time.Second}
}

func testProvider(t *testing.T, machine *fakeMachine, probe *fakeProbe, runner CommandRunner) *Provider {
	t.Helper()
	p, err := New(Options{MachineFactory: func(_ context.Context, cfg Config) (Machine, error) {
		machine.mu.Lock()
		machine.executable = cfg.FirecrackerBinary
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
	machine := &fakeMachine{versionValue: cfg.ExpectedVersion, pid: 42, processStartTime: 100}
	probe := &fakeProbe{result: Readiness{Systemd: true, DataDiskMounted: true, Network: true, TSNodeHealthy: true, ServiceHealthy: true}}
	p := testProvider(t, machine, probe, nil)
	created, err := p.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
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
	machine.mu.Lock()
	starts := machine.start
	machine.mu.Unlock()
	if starts != 2 {
		t.Fatalf("machine starts = %d, want 2", starts)
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

func TestInspectRejectsDeadOrChangedProcessIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeMachine)
	}{
		{name: "dead process", mutate: func(machine *fakeMachine) { machine.dead = true }},
		{name: "changed PID", mutate: func(machine *fakeMachine) { machine.pid++ }},
		{name: "changed start time", mutate: func(machine *fakeMachine) { machine.processStartTime++ }},
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
			if info.State != StateStopped || info.Ready {
				t.Fatalf("inspection trusted stale lifecycle state: %+v", info)
			}
		})
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
	if err := record.VerifyRunningProcess(); err == nil || !strings.Contains(err.Error(), "identity") {
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
