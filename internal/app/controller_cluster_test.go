package app

import (
	"context"
	"encoding/base64"
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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// Each child executes the real run command with a persistent embedded broker.
// A delayed founder and a complete restart exercise the bootstrap path that
// systemd uses on separate hosts.
func TestControllerThreeProcessBootstrapAndRestart(t *testing.T) {
	if configPath := os.Getenv("TS_ORCH_TEST_CONTROLLER_CHILD_CONFIG"); configPath != "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := Run(ctx, []string{"run", "--config", configPath}, os.Stdout); err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	root := t.TempDir()
	public, _ := testEd25519(t, root, "response.key")
	clientPorts := make([]int, 3)
	routePorts := make([]int, 3)
	for index := range clientPorts {
		clientPorts[index] = reserveControllerPort(t)
		routePorts[index] = reserveControllerPort(t)
	}
	routes := make([]string, 3)
	for index, port := range routePorts {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", port)
	}
	configs := make([]string, 3)
	for index := range configs {
		instance := fmt.Sprintf("peer%d", index)
		configs[index] = testJSONFile(t, root, instance+".json", Config{
			NATS: natscell.Config{Cell: "lab", Instance: instance, Replicas: 3, Lab: true,
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: clientPorts[index],
					RouteHost: "127.0.0.1", RoutePort: routePorts[index], Routes: routes,
					StoreDir: filepath.Join(root, instance), StoreMaxBytes: 2 << 30}},
			Controller: ControllerConfig{CandidateID: instance, ResponseKeyFile: filepath.Join(root, "response.key"),
				ArtifactStoreMaxBytes: 64 << 20,
				TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public),
					Roles: []string{"terrabase"}, Environments: []string{"test"}}},
				Workloads: map[string]WorkloadProfile{"terrabase": {Resources: placement.Resources{
					CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}}},
		})
	}
	for boot := 1; boot <= 2; boot++ {
		children := make([]*controllerChild, 3)
		for index := 0; index < 2; index++ {
			children[index] = startControllerChild(t, ctx, root, configs[index], boot, index)
		}
		if boot == 1 {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(3 * time.Second):
			}
			for _, child := range children[:2] {
				assertControllerChildRunning(t, child)
			}
		}
		children[2] = startControllerChild(t, ctx, root, configs[2], boot, 2)
		for _, child := range children {
			waitControllerChildReady(t, ctx, child)
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
		probe, err := natscell.Start(probeCtx, natscell.Config{Cell: "lab", Instance: "probe", Replicas: 3,
			Lab: true, URL: fmt.Sprintf("nats://127.0.0.1:%d", clientPorts[0])})
		if err != nil {
			probeCancel()
			t.Fatal(err)
		}
		stream, err := probe.JetStream().Stream(probeCtx, authority.ControlStreamName)
		if err == nil {
			streamInfo, infoErr := stream.Info(probeCtx)
			if infoErr != nil {
				err = infoErr
			} else if streamInfo.Config.Replicas != 3 || streamInfo.Config.AllowDirect {
				err = fmt.Errorf("authority stream has replicas=%d allow_direct=%t", streamInfo.Config.Replicas, streamInfo.Config.AllowDirect)
			}
			if err == nil && boot == 1 {
				leaseSubject := "ts.control.lab.lease"
				before, readErr := stream.GetLastMsgForSubject(probeCtx, leaseSubject)
				if readErr != nil {
					err = readErr
				} else {
					select {
					case <-ctx.Done():
						err = ctx.Err()
					case <-time.After(21 * time.Second):
						// The authority's successful startup context must outlive
						// its 20-second provisioning attempt timer.
						after, readErr := stream.GetLastMsgForSubject(ctx, leaseSubject)
						if readErr != nil {
							err = readErr
						} else if after.Sequence <= before.Sequence {
							err = fmt.Errorf("authority lease did not renew after startup: %d -> %d", before.Sequence, after.Sequence)
						}
					}
				}
			}
		}
		for _, child := range children {
			assertControllerChildRunning(t, child)
		}
		_ = probe.Close()
		probeCancel()
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range children {
			stopControllerChild(t, child)
		}
	}
}

type controllerChild struct {
	cmd     *exec.Cmd
	done    chan error
	logPath string
}

func reserveControllerPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
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
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestControllerThreeProcessBootstrapAndRestart$")
	cmd.Env = append(os.Environ(), "TS_ORCH_TEST_CONTROLLER_CHILD_CONFIG="+config)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	child := &controllerChild{cmd: cmd, done: make(chan error, 1), logPath: logPath}
	go func() {
		child.done <- cmd.Wait()
		logFile.Close()
	}()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
	})
	return child
}

func assertControllerChildRunning(t *testing.T, child *controllerChild) {
	t.Helper()
	select {
	case err := <-child.done:
		data, _ := os.ReadFile(child.logPath)
		t.Fatalf("controller exited before quorum: %v; log %s\n%s", err, child.logPath, data)
	default:
	}
}

func waitControllerChildReady(t *testing.T, ctx context.Context, child *controllerChild) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		assertControllerChildRunning(t, child)
		data, _ := os.ReadFile(child.logPath)
		if strings.Contains(string(data), " ready in cell lab ") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("controller readiness: %v; log %s\n%s", ctx.Err(), child.logPath, data)
		case <-ticker.C:
		}
	}
}

func stopControllerChild(t *testing.T, child *controllerChild) {
	t.Helper()
	if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		data, _ := os.ReadFile(child.logPath)
		t.Fatalf("controller signal: %v; log %s\n%s", err, child.logPath, data)
	}
	select {
	case err := <-child.done:
		if err != nil {
			data, _ := os.ReadFile(child.logPath)
			t.Fatalf("controller shutdown: %v; log %s\n%s", err, child.logPath, data)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("controller did not stop: %s", child.logPath)
	}
}
