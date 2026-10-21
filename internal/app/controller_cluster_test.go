package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Local process scenarios keep the real JWT broker gate and replace only cloud admission.
func stubAuthenticatedController(t *testing.T, cfg *Config) {
	t.Helper()
	previousRuntime, previousMarker := controllerRuntimeProduction, controllerMarkerPresent
	previousBaked, previousAdmission := controllerBakedInputsPresent, controllerBootstrapProduction
	previousFounder, previousClock := controllerFounderProduction, controllerBrokerClockProbe
	previousSeed := rolloutSeedSlot
	controllerRuntimeProduction = func(ctx context.Context, cfg Config, _ func() error) (*natscell.Runtime, error) {
		return natscell.Start(ctx, cfg.NATS)
	}
	controllerMarkerPresent = func() (bool, error) { return false, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerBootstrapProduction = func(context.Context, Config) error { return nil }
	controllerFounderProduction = func(context.Context) error { return nil }
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	rolloutSeedSlot = func(Config) (string, error) { return cfg.NATS.Instance, nil }
	t.Cleanup(func() {
		controllerRuntimeProduction, controllerMarkerPresent = previousRuntime, previousMarker
		controllerBakedInputsPresent, controllerBootstrapProduction = previousBaked, previousAdmission
		controllerFounderProduction, controllerBrokerClockProbe = previousFounder, previousClock
		rolloutSeedSlot = previousSeed
	})
	newAcceptedSpecTrust(t, cfg)
}

func TestControllerBootstrapRetriesOnlyTransientErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{context.DeadlineExceeded, true},
		{nats.ErrNoResponders, true},
		{fmt.Errorf("%w: %w", delivery.ErrStoreNotReady, jetstream.ErrStreamNotFound), true},
		{fmt.Errorf("%w: %w", host.ErrStateNotReady, jetstream.ErrStreamNotFound), true},
		{jetstream.ErrStreamNotFound, false},
		{&jetstream.APIError{Code: 400, ErrorCode: 10005, Description: "no suitable peers for placement"}, true},
		{jetstream.ErrJetStreamNotEnabled, false},
		{nats.ErrAuthorization, false},
		{&jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeBadRequest}, false},
	} {
		if got := transientControllerBootstrapError(test.err); got != test.want {
			t.Errorf("transientControllerBootstrapError(%v) = %t, want %t", test.err, got, test.want)
		}
	}
}

// TestControllerChildProcess is the controller that startControllerChild
// runs in a separate test process.
func TestControllerChildProcess(t *testing.T) {
	configPath := os.Getenv("TS_ORCH_TEST_CONTROLLER_CHILD_CONFIG")
	if configPath == "" {
		t.Skip("runs only as a controller child process")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	stubAuthenticatedController(t, &cfg)
	configPath = testJSONFile(t, t.TempDir(), "controller.json", cfg)
	if err := Run(ctx, []string{"run", "--config", configPath}, os.Stdout); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}

type controllerChild struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error // Read only after done is closed.
	logPath string
	started time.Time
}

func reserveControllerPort(t *testing.T) int {
	t.Helper()
	return reserveControllerPorts(t, 1)[0]
}

func reserveControllerPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			if err := listener.Close(); err != nil {
				t.Errorf("close reserved controller port: %v", err)
			}
		}
	}()
	ports := make([]int, count)
	for index := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports[index] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports
}

func TestReserveControllerPortsDistinct(t *testing.T) {
	ports := reserveControllerPorts(t, 6)
	seen := make(map[int]bool, len(ports))
	for _, port := range ports {
		if seen[port] {
			t.Fatalf("reserved controller port %d more than once", port)
		}
		seen[port] = true
	}
}

func startControllerChild(t *testing.T, ctx context.Context, root, config string, boot, index int) *controllerChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, fmt.Sprintf("boot%d-peer%d.log", boot, index))
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestControllerChildProcess$")
	cmd.Env = append(os.Environ(), "TS_ORCH_TEST_CONTROLLER_CHILD_CONFIG="+config)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	child := &controllerChild{cmd: cmd, done: make(chan struct{}), logPath: logPath, started: time.Now()}
	go func() {
		child.err = cmd.Wait()
		logFile.Close()
		close(child.done)
	}()
	t.Cleanup(func() {
		select {
		case <-child.done:
			return
		default:
		}
		_ = cmd.Process.Kill()
		// Reap even failed fixtures before the next lab test starts. Reading
		// Cmd.ProcessState while Wait writes it also races under -race.
		select {
		case <-child.done:
		case <-time.After(controllerStopBudget):
			t.Errorf("controller cleanup did not reap child: %s", child.logPath)
		}
	})
	return child
}

func assertControllerChildRunning(t *testing.T, child *controllerChild) {
	t.Helper()
	select {
	case <-child.done:
		data, _ := os.ReadFile(child.logPath)
		t.Fatalf("controller exited before quorum: %v; log %s\n%s", child.err, child.logPath, data)
	default:
	}
}

func waitControllerChildReady(t *testing.T, ctx context.Context, child *controllerChild) {
	t.Helper()
	ctx, cancel := context.WithDeadline(ctx, child.started.Add(controllerStartupBudget(t)))
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		assertControllerChildRunning(t, child)
		data, _ := os.ReadFile(child.logPath)
		if strings.Contains(string(data), " ready in cell ") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("controller readiness: %v; log %s\n%s", ctx.Err(), child.logPath, data)
		case <-ticker.C:
		}
	}
}

func controllerStartupBudget(t *testing.T) time.Duration {
	t.Helper()
	// Use the deployed bootstrap admission budget for forming a fresh lab
	// cell, including embedded NATS startup and provisioning retries.
	data, err := os.ReadFile("../../deploy/systemd/terrascale-orchestrator-bootstrap.service")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "TimeoutStartSec="); ok {
			budget, err := time.ParseDuration(value)
			if err != nil || budget <= 0 {
				t.Fatalf("invalid bootstrap startup budget %q: %v", value, err)
			}
			return budget
		}
	}
	t.Fatal("bootstrap unit has no startup budget")
	return 0
}

// controllerStopBudget matches TimeoutStopSec in the controller unit.
const controllerStopBudget = 60 * time.Second
