//go:build live_autoscaler_role

package live

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

func TestAutoscalerRoleAuthenticatedLifecycle(t *testing.T) {
	if os.Getenv("TS_ORCH_LIVE_AUTOSCALER_ROLE") != "1" {
		t.Skip("set TS_ORCH_LIVE_AUTOSCALER_ROLE=1 and build with -tags live_autoscaler_role")
	}
	required := []string{
		"TS_ORCH_LIVE_ORCHESTRATOR_BINARY", "TS_ORCH_AUTOSCALER_AGENT_BINARY",
		"TS_ORCH_NATS_URL", "TS_ORCH_NATS_NKEY_FILE", "TS_ORCH_NATS_TLS_CA_FILE",
		"TS_ORCH_NATS_TLS_CERT_FILE", "TS_ORCH_NATS_TLS_KEY_FILE",
		"TS_ORCH_AUTOSCALER_NODE_NATS_CREDENTIAL_DIRECTORY",
		"TS_ORCH_OCI_ESTATE_FILE", "TS_ORCH_OCI_KEY_ID", "TS_ORCH_OCI_PRIVATE_KEY_FILE",
	}
	for _, name := range required {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Fatalf("%s is required for this live lane", name)
		}
	}
	if os.Getuid() == 0 {
		t.Fatal("the live role must run as a non-root user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	role := exec.CommandContext(ctx, os.Getenv("TS_ORCH_LIVE_ORCHESTRATOR_BINARY"), "autoscaler")
	role.Env = liveRoleEnvironment(os.Environ())
	role.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var roleOutput synchronizedBuffer
	role.Stdout, role.Stderr = &roleOutput, &roleOutput
	if err := role.Start(); err != nil {
		t.Fatalf("start autoscaler role: %v", err)
	}
	roleDone := make(chan error, 1)
	go func() { roleDone <- role.Wait() }()

	// The baseline node is a real ts-node process. This keeps the live lane's
	// heartbeat input authenticated and avoids granting the controller identity
	// permission to forge node heartbeats.
	directory := os.Getenv("TS_ORCH_AUTOSCALER_NODE_NATS_CREDENTIAL_DIRECTORY")
	baseline := exec.CommandContext(ctx, os.Getenv("TS_ORCH_AUTOSCALER_AGENT_BINARY"),
		"--node-id", "baseline-node", "--node-class", "worker-medium",
		"--nats-url", os.Getenv("TS_ORCH_NATS_URL"),
		"--nats-nkey-file", filepath.Join(directory, "baseline-node.seed"),
		"--nats-tls-ca-file", filepath.Join(directory, "baseline-node.ca.pem"),
		"--nats-tls-cert-file", filepath.Join(directory, "baseline-node.pem"),
		"--nats-tls-key-file", filepath.Join(directory, "baseline-node.key"),
		"--heartbeat-interval", "1s")
	baseline.Env = role.Env
	var baselineOutput bytes.Buffer
	baseline.Stdout, baseline.Stderr = &baselineOutput, &baselineOutput
	if err := baseline.Start(); err != nil {
		t.Fatalf("start baseline node: %v", err)
	}
	baselineDone := make(chan error, 1)
	go func() { baselineDone <- baseline.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-baselineDone:
		case <-time.After(5 * time.Second):
			_ = baseline.Process.Kill()
			<-baselineDone
		}
		select {
		case <-roleDone:
		case <-time.After(5 * time.Second):
			_ = role.Process.Kill()
			<-roleDone
		}
		if roleOutput.Len() > 0 {
			t.Logf("autoscaler output: %s", roleOutput.String())
		}
		if baselineOutput.Len() > 0 {
			t.Logf("baseline output: %s", baselineOutput.String())
		}
	})

	connection := liveRoleConnection(t, ctx)
	defer connection.Close()
	heartbeats := make(chan hostagent.NodeHeartbeat, 32)
	subscription, err := connection.Subscribe(hostagent.NatsSubjectNodePrefix+".*."+hostagent.NatsSubjectLeafHeartbeat,
		func(message *nats.Msg) {
			var heartbeat hostagent.NodeHeartbeat
			if json.Unmarshal(message.Data, &heartbeat) == nil {
				select {
				case heartbeats <- heartbeat:
				default:
				}
			}
		})
	if err != nil {
		t.Fatalf("heartbeat subscription: %v", err)
	}
	defer subscription.Unsubscribe()
	if err := connection.Flush(); err != nil {
		t.Fatalf("heartbeat subscription flush: %v", err)
	}

	demandResources, err := autoscaling.NewNodeResources(2<<30, 200, 64)
	if err != nil {
		t.Fatal(err)
	}
	demand, err := autoscaling.NewAllocationDemand("dashboard-role-live", "dashboard", false, demandResources)
	if err != nil {
		t.Fatal(err)
	}
	child := waitForRoleChild(t, ctx, connection, heartbeats, demand)
	childProcess := waitForRoleChildProcess(t, ctx, role.Process.Pid,
		os.Getenv("TS_ORCH_AUTOSCALER_AGENT_BINARY"), child.NodeId.String())
	if !childProcess.alive() {
		t.Fatalf("role child %s was not alive after its authenticated heartbeat", child.NodeId)
	}
	// Establish a live pre-retirement observation. A child that crashed before
	// the retire action must not satisfy this lifecycle test.
	preRetirementDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(preRetirementDeadline) {
		if !childProcess.alive() {
			t.Fatalf("role child %s exited before the retire action", child.NodeId)
		}
		assertRoleRunning(t, roleDone)
		time.Sleep(100 * time.Millisecond)
	}
	retireOutput := "autoscaler action=RetireNode node=" + child.NodeId.String()
	childExitedBeforeAction := atomic.Bool{}
	childExitObserved := make(chan struct{})
	stopChildMonitor := make(chan struct{})
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !childProcess.alive() {
					childExitedBeforeAction.Store(!strings.Contains(roleOutput.String(), retireOutput))
					close(childExitObserved)
					return
				}
			case <-stopChildMonitor:
				return
			}
		}
	}()
	defer close(stopChildMonitor)

	feed, err := autoscaling.NewAutoscalerObservationFeed(
		autoscaling.AutoscalerFeedSchemaVersion, time.Now().Unix(), nil, true,
		[]autoscaling.AutoscalerNodePlacement{{NodeId: "baseline-node"}, {NodeId: child.NodeId.String()}}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	lastChild := time.Now()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		assertRoleRunning(t, roleDone)
		if err := connection.Publish(autoscaling.AutoscalerObservationSubject, payload); err != nil {
			t.Fatal(err)
		}
		if err := connection.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case heartbeat := <-heartbeats:
			if heartbeat.NodeId.String() == child.NodeId.String() {
				lastChild = time.Now()
			}
		case <-time.After(250 * time.Millisecond):
		}
		if time.Since(lastChild) >= 2*time.Second {
			break
		}
	}
	if time.Since(lastChild) < 2*time.Second {
		t.Fatal("role did not retire the real child within the live bound")
	}
	exitDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(exitDeadline) && childProcess.alive() {
		assertRoleRunning(t, roleDone)
		time.Sleep(100 * time.Millisecond)
	}
	if !childProcess.alive() && !strings.Contains(roleOutput.String(), retireOutput) {
		t.Fatalf("role child pid %d exited before the retire action was reported", childProcess.pid)
	}
	if !childProcess.alive() {
		select {
		case <-childExitObserved:
		case <-time.After(500 * time.Millisecond):
		}
		if childExitedBeforeAction.Load() {
			t.Fatalf("role child pid %d exited without a preceding retire action", childProcess.pid)
		}
	}
	if childProcess.alive() {
		t.Fatalf("retire action left role child pid %d running", childProcess.pid)
	}
	if !strings.Contains(roleOutput.String(), retireOutput) {
		t.Fatalf("autoscaler output did not prove the retire action: %q", roleOutput.String())
	}
	assertRoleRunning(t, roleDone)
}

type synchronizedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

func (b *synchronizedBuffer) Len() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Len()
}

type observedRoleProcess struct {
	pid       int
	parentPid int
	cmdline   string
}

func waitForRoleChildProcess(t *testing.T, ctx context.Context, parentPid int, binaryPath string, nodeId string) observedRoleProcess {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if process, ok := findRoleChildProcess(parentPid, binaryPath, nodeId); ok {
			return process
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("could not find the live role child process for node %s", nodeId)
	return observedRoleProcess{}
}

func findRoleChildProcess(parentPid int, binaryPath string, nodeId string) (observedRoleProcess, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return observedRoleProcess{}, false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(cmdlineBytes) == 0 {
			continue
		}
		parts := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
		if len(parts) == 0 || parts[0] != binaryPath {
			continue
		}
		for index := 1; index+1 < len(parts); index++ {
			if parts[index] == "--node-id" && parts[index+1] == nodeId {
				process := observedRoleProcess{pid: pid, parentPid: parentPid, cmdline: string(cmdlineBytes)}
				if process.alive() {
					return process, true
				}
			}
		}
	}
	return observedRoleProcess{}, false
}

func (p observedRoleProcess) alive() bool {
	if p.pid <= 0 {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.pid), "cmdline"))
	if err != nil || string(cmdline) != p.cmdline || syscall.Kill(p.pid, 0) != nil {
		return false
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.pid), "status"))
	if err != nil {
		return false
	}
	zombie := false
	observedParent := 0
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "State:") {
			zombie = strings.Contains(line, "\tZ")
		}
		if strings.HasPrefix(line, "PPid:") && p.parentPid > 0 {
			observedParent, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			if err != nil {
				return false
			}
		}
	}
	return !zombie && observedParent == p.parentPid
}

func assertRoleRunning(t *testing.T, roleDone chan error) {
	t.Helper()
	select {
	case err := <-roleDone:
		roleDone <- err
		t.Fatalf("autoscaler role exited before lifecycle proof completed: %v", err)
	default:
	}
}

func liveRoleEnvironment(base []string) []string {
	overrides := map[string]string{
		"TS_ORCH_AUTOSCALER_PROVIDER": "local-dev", "TS_ORCH_AUTOSCALER_TICK_INTERVAL": "100ms",
		"TS_ORCH_AUTOSCALER_MIN_NODES": "1", "TS_ORCH_AUTOSCALER_MAX_NODES": "2",
		"TS_ORCH_AUTOSCALER_SCALE_UP_HEADROOM_PERCENT": "20", "TS_ORCH_AUTOSCALER_SCALE_DOWN_HEADROOM_PERCENT": "30",
		"TS_ORCH_AUTOSCALER_SCALE_UP_CONFIRM_TICKS": "1", "TS_ORCH_AUTOSCALER_SCALE_DOWN_CONFIRM_TICKS": "1",
		"TS_ORCH_AUTOSCALER_MAX_CONCURRENT_PROVISIONS": "1", "TS_ORCH_AUTOSCALER_FLAP_SUPPRESSION_TICKS": "1",
		"TS_ORCH_AUTOSCALER_DRAIN_MAX_LAG_BYTES": "1048576",
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, replaced := overrides[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func liveRoleConnection(t *testing.T, ctx context.Context) *nats.Conn {
	t.Helper()
	authentication, err := control.NatsAuthenticationFilesFromNKeyFile(os.Getenv("TS_ORCH_NATS_NKEY_FILE"))
	if err != nil {
		t.Fatalf("NATS authentication: %v", err)
	}
	tlsFiles, err := control.NatsTlsFilesResolve(os.Getenv("TS_ORCH_NATS_TLS_CA_FILE"), os.Getenv("TS_ORCH_NATS_TLS_CERT_FILE"), os.Getenv("TS_ORCH_NATS_TLS_KEY_FILE"), "live NATS TLS")
	if err != nil {
		t.Fatalf("NATS TLS: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		connection, connectErr := control.NatsConnect(ctx, control.NatsConnectionConfiguration{URL: os.Getenv("TS_ORCH_NATS_URL"), Authentication: authentication, TLS: tlsFiles, Timeout: time.Second, MaxReconnects: 0})
		if connectErr == nil {
			return connection
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("could not connect to NATS within startup bound")
	return nil
}

func waitForRoleChild(t *testing.T, ctx context.Context, connection *nats.Conn, heartbeats <-chan hostagent.NodeHeartbeat, demand autoscaling.AllocationDemand) hostagent.NodeHeartbeat {
	t.Helper()
	feed, err := autoscaling.NewAutoscalerObservationFeed(autoscaling.AutoscalerFeedSchemaVersion, time.Now().Unix(), []autoscaling.AllocationDemand{demand}, true, []autoscaling.AutoscalerNodePlacement{{NodeId: "baseline-node"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := connection.Publish(autoscaling.AutoscalerObservationSubject, payload); err != nil {
			t.Fatal(err)
		}
		if err := connection.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case heartbeat := <-heartbeats:
			if heartbeat.NodeId.String() == "as-node-1" {
				return heartbeat
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("role did not provision a real child within the live bound")
	return hostagent.NodeHeartbeat{}
}
