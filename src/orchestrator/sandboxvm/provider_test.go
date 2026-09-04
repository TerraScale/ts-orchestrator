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
}

func (m *fakeMachine) Start(context.Context) error { m.mu.Lock(); m.start++; m.mu.Unlock(); return nil }
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
	return nil
}
func (m *fakeMachine) StopVMM() error             { m.mu.Lock(); m.stop++; m.mu.Unlock(); return nil }
func (m *fakeMachine) Wait(context.Context) error { m.mu.Lock(); m.wait++; m.mu.Unlock(); return nil }
func (m *fakeMachine) Version(context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version++
	return m.versionValue, nil
}
func (m *fakeMachine) Inspect(context.Context) (Inspection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inspect++
	return Inspection{PID: m.pid, SocketReady: true}, nil
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
	paths := map[string][]byte{"kernel": []byte("kernel"), "root": []byte("root"), "data": []byte("data"), "firecracker": []byte("firecracker"), "jailer": []byte("jailer")}
	files := make(map[string]string)
	for name, content := range paths {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0700); err != nil {
			t.Fatal(err)
		}
		files[name] = path
	}
	return Config{ID: "gru-member-1", Region: "GRU", VCPU: 1, MemoryMiB: 256, KernelImage: files["kernel"], RootDrive: files["root"], DataDrive: files["data"], StateRoot: filepath.Join(root, "state"), SocketPath: filepath.Join(root, "state", "gru-member-1.sock"), FirecrackerBinary: files["firecracker"], JailerBinary: files["jailer"], ExpectedVersion: "1.0", ExpectedKernelSHA256: digest(paths["kernel"]), ExpectedRootDriveSHA256: digest(paths["root"]), ExpectedDataDriveSHA256: digest(paths["data"]), ExpectedFirecrackerSHA256: digest(paths["firecracker"]), ExpectedJailerSHA256: digest(paths["jailer"]), ReadinessTimeout: 300 * time.Millisecond, StopTimeout: time.Second}
}

func testProvider(t *testing.T, machine *fakeMachine, probe *fakeProbe, runner CommandRunner) *Provider {
	t.Helper()
	p, err := New(Options{MachineFactory: func(context.Context, Config) (Machine, error) { return machine, nil }, OpenAPIFactory: func(Config) (OpenAPI, error) { return &fakeAPI{}, nil }, Probe: probe, CommandRunner: runner})
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
	if info.State != StateCreated || info.Paths.StateDir != filepath.Join(cfg.StateRoot, cfg.ID) {
		t.Fatalf("unexpected create result: %+v", info)
	}
	if err := p.ValidateVersion(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
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
	if _, err := os.Stat(filepath.Join(cfg.StateRoot, cfg.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory remains: %v", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.start != 1 || machine.shutdown != 1 || machine.wait != 1 {
		t.Fatalf("unexpected machine calls: %+v", machine)
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
