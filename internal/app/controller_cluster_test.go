package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
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

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

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
	tier.Integration(t)
	// Each startup and shutdown has its own budget. A deadline shared by
	// both boots can kill a healthy child during its graceful shutdown.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	root := t.TempDir()
	public, _ := testEd25519(t, root, "response.key")
	const peers = 3
	ports := reserveControllerPorts(t, 2*peers)
	clientPorts, routePorts := ports[:peers], ports[peers:]
	routes := make([]string, 3)
	for index, port := range routePorts {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", port)
	}
	specTrust := authorityTestSpecTrust(t, root, "lab")
	configs := make([]string, 3)
	for index := range configs {
		instance := fmt.Sprintf("peer%d", index)
		configs[index] = testJSONFile(t, root, instance+".json", Config{Version: ConfigVersion,
			NATS: natscell.Config{Cell: "lab", Instance: instance, Replicas: 3, Lab: true,
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: clientPorts[index],
					RouteHost: "127.0.0.1", RoutePort: routePorts[index], Routes: natscell.PeerRoutes(routes, routes[index]),
					StoreDir: filepath.Join(root, instance), StoreMaxBytes: 4 << 30}},
			Controller: ControllerConfig{SpecTrust: specTrust, CandidateID: entityid.Derive("test-controller", instance), ResponseKeyFile: filepath.Join(root, "response.key"),
				ArtifactStoreMaxBytes: 64 << 20,
				TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public),
					Roles: []string{"terrabase"}, Environments: []string{"test"}}},
				Workloads: map[string]WorkloadProfile{"terrabase": {Resources: placement.Resources{
					CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}}},
		})
	}
	var durableLeaseSequence uint64
	var durableLeasePayload []byte
	var durableLeaseEpoch uint64
	for boot := 1; boot <= 2; boot++ {
		children := make([]*controllerChild, 3)
		for index := 0; index < 2; index++ {
			children[index] = startControllerChild(t, ctx, root, configs[index], boot, index)
		}
		if boot == 1 {
			for index, child := range children[:2] {
				waitControllerChildListening(t, ctx, child, clientPorts[index], routePorts[index])
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
		var holder authority.Snapshot
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
				if err == nil {
					holder, err = authority.Observe(ctx, probe.JetStream(), "lab")
				}
				if err == nil {
					entry, readErr := stream.GetLastMsgForSubject(ctx, leaseSubject)
					if readErr != nil {
						err = fmt.Errorf("read durable authority lease before shutdown: %w", readErr)
					} else {
						lease, readErr := controllerLeaseRecordFromData(entry.Data)
						if readErr != nil {
							err = fmt.Errorf("decode durable authority lease before shutdown: %w", readErr)
						} else if entry.Subject != leaseSubject || lease.Epoch != holder.Epoch ||
							lease.CandidateID != holder.CandidateID || lease.OwnerID != holder.OwnerID || lease.Released {
							err = fmt.Errorf("durable authority lease does not match observed holder: subject=%q lease=%+v holder=%+v",
								entry.Subject, lease, holder)
						} else {
							durableLeaseEpoch = lease.Epoch
							durableLeaseSequence = entry.Sequence
							durableLeasePayload = bytes.Clone(entry.Data)
						}
					}
				}
			} else if err == nil && boot == 2 {
				leaseSubject := "ts.control.lab.lease"
				if durableLeaseSequence == 0 || len(durableLeasePayload) == 0 || durableLeaseEpoch == 0 {
					err = fmt.Errorf("first boot did not capture a durable authority lease")
				} else {
					persisted, readErr := stream.GetMsg(probeCtx, durableLeaseSequence)
					if readErr != nil {
						err = fmt.Errorf("reread authority lease sequence %d after restart: %w", durableLeaseSequence, readErr)
					} else if persisted.Sequence != durableLeaseSequence || persisted.Subject != leaseSubject ||
						!bytes.Equal(persisted.Data, durableLeasePayload) {
						err = fmt.Errorf("authority lease changed across restart at sequence %d: subject=%q payload_equal=%t",
							durableLeaseSequence, persisted.Subject, bytes.Equal(persisted.Data, durableLeasePayload))
					} else if persistedLease, decodeErr := controllerLeaseRecordFromData(persisted.Data); decodeErr != nil ||
						persistedLease.Epoch != durableLeaseEpoch {
						err = fmt.Errorf("authority lease epoch changed across restart at sequence %d: lease=%+v want_epoch=%d err=%v",
							durableLeaseSequence, persistedLease, durableLeaseEpoch, decodeErr)
					} else if latest, latestErr := stream.GetLastMsgForSubject(probeCtx, leaseSubject); latestErr != nil {
						err = fmt.Errorf("read authority lease after restart: %w", latestErr)
					} else if latest.Sequence <= durableLeaseSequence {
						err = fmt.Errorf("authority lease did not make durable write progress after restart: sequence=%d captured=%d",
							latest.Sequence, durableLeaseSequence)
					} else if latestLease, decodeErr := controllerLeaseRecordFromData(latest.Data); decodeErr != nil ||
						latestLease.Epoch <= durableLeaseEpoch || latestLease.Released {
						err = fmt.Errorf("authority lease epoch did not advance after restart: lease=%+v captured_epoch=%d err=%v",
							latestLease, durableLeaseEpoch, decodeErr)
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
		failedPeer := 0
		if boot == 1 {
			found := false
			for index := range children {
				if holder.CandidateID == controllerChildCandidateID(t, children[index]) {
					failedPeer, found = index, true
					break
				}
			}
			if !found || !holder.Ready || holder.Epoch == 0 {
				t.Fatalf("unexpected authority holder after startup: %+v", holder)
			}
			crashControllerChild(t, children[failedPeer])
			waitSurvivingAuthority(t, ctx, clientPorts[(failedPeer+1)%3], holder.Epoch)
		} else {
			stopControllerChild(t, children[failedPeer])
		}
		// An R3 region must retain both surviving controllers and their
		// embedded brokers when one controller is lost.
		waitSurvivingAuthority(t, ctx, clientPorts[(failedPeer+1)%3], 0)
		for index, child := range children {
			if index == failedPeer {
				continue
			}
			assertControllerChildRunning(t, child)
			signalControllerChild(t, child)
		}
		for index, child := range children {
			if index == failedPeer {
				continue
			}
			waitControllerChildStopped(t, child)
		}
	}
}

type controllerLeaseRecordForTest struct {
	Scope       string `json:"scope"`
	CandidateID string `json:"candidate_id"`
	OwnerID     string `json:"owner_id"`
	Epoch       uint64 `json:"epoch"`
	Released    bool   `json:"released"`
}

func controllerLeaseRecordFromData(data []byte) (controllerLeaseRecordForTest, error) {
	var lease controllerLeaseRecordForTest
	if err := json.Unmarshal(data, &lease); err != nil {
		return lease, err
	}
	if lease.Scope != "lab" || lease.CandidateID == "" || lease.OwnerID == "" || lease.Epoch == 0 {
		return lease, fmt.Errorf("invalid lease identity/scope/epoch: %q/%q/%q/%d",
			lease.Scope, lease.CandidateID, lease.OwnerID, lease.Epoch)
	}
	return lease, nil
}

type controllerChild struct {
	cmd      *exec.Cmd
	done     chan struct{}
	err      error // Read only after done is closed.
	logPath  string
	started  time.Time
	stopping time.Time
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
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestControllerThreeProcessBootstrapAndRestart$")
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

// The founder is deliberately absent here. Wait for both listeners instead
// of assuming that a three-second sleep lets the other processes start.
func waitControllerChildListening(t *testing.T, ctx context.Context, child *controllerChild, ports ...int) {
	t.Helper()
	ctx, cancel := context.WithDeadline(ctx, child.started.Add(controllerStartupBudget(t)))
	defer cancel()
	var lastErr error
	for ctx.Err() == nil {
		assertControllerChildRunning(t, child)
		listening := true
		for _, port := range ports {
			conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				lastErr, listening = err, false
				break
			}
			conn.Close()
		}
		if listening {
			assertControllerChildRunning(t, child)
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	data, _ := os.ReadFile(child.logPath)
	t.Fatalf("controller listeners: %v; last error %v; log %s\n%s", ctx.Err(), lastErr, child.logPath, data)
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

func stopControllerChild(t *testing.T, child *controllerChild) {
	t.Helper()
	signalControllerChild(t, child)
	waitControllerChildStopped(t, child)
}

func signalControllerChild(t *testing.T, child *controllerChild) {
	t.Helper()
	child.stopping = time.Now()
	if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		data, _ := os.ReadFile(child.logPath)
		t.Fatalf("controller signal: %v; log %s\n%s", err, child.logPath, data)
	}
}

func crashControllerChild(t *testing.T, child *controllerChild) {
	t.Helper()
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("crashed controller did not exit: %s", child.logPath)
	}
}

func waitSurvivingAuthority(t *testing.T, ctx context.Context, port int, priorEpoch uint64) {
	t.Helper()
	probeCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	probe, err := natscell.Start(probeCtx, natscell.Config{Cell: "lab", Instance: "failover-probe", Replicas: 3,
		Lab: true, URL: fmt.Sprintf("nats://127.0.0.1:%d", port)})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var last authority.Snapshot
	var lastErr error
	for probeCtx.Err() == nil {
		attempt, stop := context.WithTimeout(probeCtx, 2*time.Second)
		last, lastErr = authority.Observe(attempt, probe.JetStream(), "lab")
		stop()
		if lastErr == nil && last.Ready && last.Epoch > priorEpoch {
			return
		}
		select {
		case <-probeCtx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("authority did not take over after leader crash: previous epoch=%d last=%+v err=%v", priorEpoch, last, lastErr)
}

// controllerStopBudget matches TimeoutStopSec in the controller unit. The
// last controller of a stopping cell has no JetStream quorum, so its graceful
// shutdown waits out in-flight request timeouts.
const controllerStopBudget = 60 * time.Second

func waitControllerChildStopped(t *testing.T, child *controllerChild) {
	t.Helper()
	select {
	case <-child.done:
		if child.err != nil {
			data, _ := os.ReadFile(child.logPath)
			t.Fatalf("controller shutdown: %v; log %s\n%s", child.err, child.logPath, data)
		}
	case <-time.After(time.Until(child.stopping.Add(controllerStopBudget))):
		data, _ := os.ReadFile(child.logPath)
		t.Fatalf("controller did not stop within %s: %s\n%s", controllerStopBudget, child.logPath, data)
	}
}

func controllerChildCandidateID(t *testing.T, child *controllerChild) string {
	t.Helper()
	data, err := os.ReadFile(child.logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		// Under journald each record starts with its syslog priority, such as <5>.
		if len(line) > 3 && line[0] == '<' && line[2] == '>' {
			line = line[3:]
		}
		var record struct {
			CandidateID string `json:"candidate_id"`
		}
		if json.Unmarshal([]byte(line), &record) == nil && entityid.Valid(record.CandidateID) {
			return record.CandidateID
		}
	}
	t.Fatalf("controller candidate identity missing from %s", child.logPath)
	return ""
}
