package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The R1 caller test cannot exercise a host whose request can be routed to
// three controller subscribers. This test keeps the real signed operator and
// host protocols active across the loss of the broker the host is using.
func TestAuthenticatedOperatorToHostDeliveryWithControllerLoss(t *testing.T) {
	testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, false, false)
}

// Legacy static NKeys remain an explicit TLS lab regression; production JWT
// admission is exercised separately through the broker bridge.
func TestLabTLSHostSessionSurvivesControllerLoss(t *testing.T) {
	for _, test := range []struct {
		name      string
		blackhole bool
	}{
		{name: "clean_kill"},
		{name: "blackholed_socket", blackhole: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, true, test.blackhole)
		})
	}
}

func testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t *testing.T, production, blackhole bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 165*time.Second)
	defer cancel()
	root := t.TempDir()
	var tlsFiles natscell.TLSFiles
	var routePasswordFile string
	if production {
		tlsFiles, routePasswordFile = testR3TLSMaterial(t, root)
	}
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	controllerSeeds := make([]string, 3)
	grants := make([]natscell.NKeyGrant, 0, 5)
	for index := range controllerSeeds {
		public, seed := testNKey(t)
		controllerSeeds[index] = seed
		grants = append(grants, natscell.NKeyGrant{PublicKey: public, Role: "controller"})
	}
	operatorNKey, operatorSeed := testNKey(t)
	hostNKey, hostSeed := testNKey(t)
	grants = append(grants, natscell.NKeyGrant{PublicKey: operatorNKey, Role: "operator"},
		natscell.NKeyGrant{PublicKey: hostNKey, Role: "host", Node: "node-a"})
	clientPorts := make([]int, 3)
	routePorts := make([]int, 3)
	for index := range clientPorts {
		clientPorts[index] = reserveControllerPort(t)
		routePorts[index] = reserveControllerPort(t)
	}
	routes := make([]string, 3)
	urls := make([]string, 3)
	for index := range routes {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", routePorts[index])
		urls[index] = fmt.Sprintf("nats://127.0.0.1:%d", clientPorts[index])
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRegisterHosts: true}
	configs := make([]string, 3)
	for index := range configs {
		instance := fmt.Sprintf("peer%d", index)
		configs[index] = testJSONFile(t, root, instance+".json", Config{
			NATS: natscell.Config{Cell: "lab", Instance: instance, Replicas: 3, Lab: true,
				NKeySeedFile: controllerSeeds[index], TLS: tlsFiles, Embedded: &natscell.Embedded{
					Host: "127.0.0.1", Port: clientPorts[index], RouteHost: "127.0.0.1", RoutePort: routePorts[index],
					Routes: routes, StoreDir: filepath.Join(root, instance), StoreMaxBytes: 2 << 30, Users: grants,
					TLS: tlsFiles, RouteTLS: tlsFiles, RouteUser: r3RouteUser(production), RoutePasswordFile: routePasswordFile}},
			Controller: ControllerConfig{CandidateID: instance, ResponseKeyFile: filepath.Join(root, "controller.key"),
				ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
				Workloads: map[string]WorkloadProfile{"terrabase": {Resources: placement.Resources{
					CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}}},
		})
	}
	children := make([]*controllerChild, 3)
	for index := range children {
		children[index] = startControllerChild(t, ctx, root, configs[index], 1, index)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		logDir, err := os.MkdirTemp("", "ts-orch-r3-host-caller-logs-")
		if err != nil {
			t.Logf("preserve controller logs: %v", err)
			return
		}
		for index, child := range children {
			data, err := os.ReadFile(child.logPath)
			if err != nil {
				t.Logf("read controller %d log: %v", index, err)
				continue
			}
			if err := os.WriteFile(filepath.Join(logDir, fmt.Sprintf("peer%d.log", index)), data, 0o600); err != nil {
				t.Logf("preserve controller %d log: %v", index, err)
			}
		}
		t.Logf("controller logs: %s", logDir)
	})
	for _, child := range children {
		waitControllerChildReady(t, ctx, child)
	}
	probe, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "authority-probe", Replicas: 3,
		Lab: true, URL: strings.Join(urls, ","), NKeySeedFile: controllerSeeds[0], TLS: tlsFiles})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	operatorConfig := testJSONFile(t, root, "operator.json", Config{
		NATS: natscell.Config{Cell: "lab", Instance: "operator", Replicas: 3, Lab: true,
			URL: strings.Join(urls, ","), NKeySeedFile: operatorSeed, TLS: tlsFiles},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")},
	})
	registration := host.Registration{Cell: "lab", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), Generation: 1,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}}
	registrationPath := testJSONFile(t, root, "registration.json", registration)
	if _, err := callR3Operator(ctx, operatorConfig, "host-register", "--registration", registrationPath); err != nil {
		t.Fatalf("signed host registration: %v", err)
	}
	hostURLs := urls
	var proxies []*r3BlackholeProxy
	if blackhole {
		hostURLs = make([]string, len(urls))
		for index := range urls {
			proxies = append(proxies, newR3BlackholeProxy(t, fmt.Sprintf("127.0.0.1:%d", clientPorts[index])))
			hostURLs[index] = "nats://" + proxies[index].listener.Addr().String()
		}
	}
	hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "node-a", Replicas: 3,
		Lab: true, URL: strings.Join(hostURLs, ","), NKeySeedFile: hostSeed, ClientRole: "host", TLS: tlsFiles})
	if err != nil {
		t.Fatal(err)
	}
	defer hostRuntime.Close()
	runner := &inMemoryRunner{}
	var agentRunner host.Runner = runner
	if production {
		agentRunner = &r3StopOnCloseRunner{inMemoryRunner: runner}
	}
	agent, err := host.NewAgent(host.AgentConfig{WorkloadIdentity: host.WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, Cell: "lab", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		Conn: hostRuntime.Conn(), Identity: hostPrivate, ControllerPublicKey: controllerPublic, Runner: agentRunner,
		InstallRoot: filepath.Join(root, "install"), StateRoot: filepath.Join(root, "state"), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	defer stopAgent()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(agentCtx) }()
	firstSession := waitR3HostSession(t, ctx, operatorConfig, agentDone, time.Time{})
	firstDigest := deployR3Workload(t, ctx, root, operatorConfig, runner, 1)
	connected := hostRuntime.Conn().ConnectedUrl()
	failedPeer := -1
	for index, url := range hostURLs {
		if connected == url {
			failedPeer = index
			break
		}
	}
	if failedPeer < 0 {
		t.Fatalf("host connected to unexpected NATS URL %q", connected)
	}
	before := waitR3Authority(t, ctx, probe, 0, -1)
	t.Logf("crashing peer%d host_url=%s authority=%+v", failedPeer, connected, before)
	if blackhole {
		proxies[failedPeer].blocked.Store(true)
	}
	crashControllerChild(t, children[failedPeer])
	_ = waitR3HostSession(t, ctx, operatorConfig, agentDone, firstSession.SessionExpiresAt, probe)
	if !hostRuntime.Conn().IsConnected() || hostRuntime.Conn().ConnectedUrl() == connected {
		t.Fatalf("host did not reconnect away from crashed controller %q; current %q", connected, hostRuntime.Conn().ConnectedUrl())
	}
	for index, child := range children {
		if index != failedPeer {
			assertControllerChildRunning(t, child)
		}
	}
	priorEpoch := uint64(0)
	if strings.HasPrefix(before.CandidateID, fmt.Sprintf("peer%d-", failedPeer)) {
		priorEpoch = before.Epoch
	}
	after := waitR3Authority(t, ctx, probe, priorEpoch, failedPeer)
	t.Logf("host_url=%s authority_after=%+v", hostRuntime.Conn().ConnectedUrl(), after)
	operatorProbe, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "operator-probe", Replicas: 3,
		Lab: true, URL: strings.Join(urls, ","), NKeySeedFile: operatorSeed, TLS: tlsFiles})
	if err != nil {
		t.Fatal(err)
	}
	defer operatorProbe.Close()
	secondDigest := deployR3Workload(t, ctx, root, operatorConfig, runner, 2,
		&r3CallerDiagnostics{probe: probe, operatorProbe: operatorProbe, agentDone: agentDone})
	if firstDigest == secondDigest {
		t.Fatal("replacement workload did not change artifact digest")
	}
	if production && blackhole {
		lastSession := waitR3HostSession(t, ctx, operatorConfig, agentDone, firstSession.SessionExpiresAt)
		for index, child := range children {
			if index != failedPeer {
				crashControllerChild(t, child)
				break
			}
		}
		select {
		case err := <-agentDone:
			if err == nil || errors.Is(err, context.Canceled) {
				t.Fatalf("host did not fail closed on quorum loss: %v", err)
			}
			if !time.Now().Before(lastSession.SessionExpiresAt.Add(-5 * time.Second)) {
				t.Fatalf("host failed after session execution reserve: expiry=%s err=%v", lastSession.SessionExpiresAt, err)
			}
			observed, observeErr := runner.Observe(ctx, "terrabase")
			if observeErr != nil || observed.Running {
				t.Fatalf("host retained workload after session loss: observed=%+v err=%v", observed, observeErr)
			}
		case <-ctx.Done():
			t.Fatalf("host did not fail closed after quorum loss: %v", ctx.Err())
		}
		return
	}
	stopAgent()
	if err := <-agentDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host agent shutdown: %v", err)
	}
	for index, child := range children {
		if index != failedPeer {
			stopControllerChild(t, child)
		}
	}
}

func waitR3Authority(t *testing.T, ctx context.Context, probe *natscell.Runtime, priorEpoch uint64, failedPeer int) authority.Snapshot {
	t.Helper()
	checkCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var last authority.Snapshot
	var lastErr error
	for checkCtx.Err() == nil {
		attempt, stop := context.WithTimeout(checkCtx, 2*time.Second)
		last, lastErr = authority.Observe(attempt, probe.JetStream(), "lab")
		stop()
		if lastErr == nil && last.Ready && last.Epoch > priorEpoch && last.ExpiresAt.After(time.Now().Add(5*time.Second)) &&
			(failedPeer < 0 || !strings.HasPrefix(last.CandidateID, fmt.Sprintf("peer%d-", failedPeer))) {
			return last
		}
		select {
		case <-checkCtx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("authority not ready after peer%d loss: prior epoch=%d last=%+v err=%v probe_url=%s: %v",
		failedPeer, priorEpoch, last, lastErr, probe.Conn().ConnectedUrl(), checkCtx.Err())
	return authority.Snapshot{}
}

func callR3Operator(ctx context.Context, config, operation string, args ...string) ([]byte, error) {
	var output bytes.Buffer
	command := append([]string{"operator", operation, "--config", config}, args...)
	err := Run(ctx, command, &output)
	return output.Bytes(), err
}

func waitR3HostSession(t *testing.T, ctx context.Context, config string, agentDone <-chan error, after time.Time, probe ...*natscell.Runtime) host.HostStatus {
	t.Helper()
	var lastErr error
	for ctx.Err() == nil {
		attempt, stop := context.WithTimeout(ctx, 8*time.Second)
		data, err := callR3Operator(attempt, config, "hosts")
		stop()
		if err == nil {
			var statuses []host.HostStatus
			err = json.Unmarshal(data, &statuses)
			if err == nil && len(statuses) == 1 && statuses[0].SessionExpiresAt.After(after) &&
				statuses[0].SessionExpiresAt.After(time.Now().Add(5*time.Second)) {
				return statuses[0]
			}
		}
		lastErr = err
		select {
		case err := <-agentDone:
			if len(probe) != 0 {
				attempt, stop := context.WithTimeout(ctx, 2*time.Second)
				snapshot, observeErr := authority.Observe(attempt, probe[0].JetStream(), "lab")
				stop()
				t.Logf("authority on host session failure: %+v, observe error: %v, probe_url=%s", snapshot, observeErr, probe[0].Conn().ConnectedUrl())
			}
			t.Fatalf("host agent exited before session renewal: %v", err)
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	t.Fatalf("host session did not renew after controller loss: %v; last error %v", ctx.Err(), lastErr)
	return host.HostStatus{}
}

type r3CallerDiagnostics struct {
	probe         *natscell.Runtime
	operatorProbe *natscell.Runtime
	agentDone     <-chan error
}

func deployR3Workload(t *testing.T, ctx context.Context, root, config string, runner *inMemoryRunner, generation uint64, diagnostics ...*r3CallerDiagnostics) string {
	t.Helper()
	path := filepath.Join(root, fmt.Sprintf("workload-%d", generation))
	if err := os.WriteFile(path, []byte(fmt.Sprintf("#!/bin/sh\n# generation %d\nsleep 30\n", generation)), 0o755); err != nil {
		t.Fatal(err)
	}
	source := delivery.ArtifactSource{Repository: "https://example.com/terrascale/r3-caller",
		Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}
	var stopAdmissionMonitor chan struct{}
	var admissionMonitorDone chan struct{}
	if len(diagnostics) != 0 {
		stopAdmissionMonitor = make(chan struct{})
		admissionMonitorDone = make(chan struct{})
		go func() {
			defer close(admissionMonitorDone)
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopAdmissionMonitor:
					return
				case <-ticker.C:
					logR3AdmissionState(t, t.Context(), diagnostics[0].probe, diagnostics[0].operatorProbe)
				}
			}
		}()
	}
	pushStarted := time.Now()
	data, err := callR3Operator(ctx, config, "artifact-push", "--file", path,
		"--repository", source.Repository, "--commit", source.Commit, "--tree-digest", source.TreeDigest,
		"--role", "terrabase", "--environment", "test")
	if stopAdmissionMonitor != nil {
		close(stopAdmissionMonitor)
		<-admissionMonitorDone
		t.Logf("generation-%d artifact push elapsed=%s error=%v", generation, time.Since(pushStarted), err)
	}
	if err != nil {
		if len(diagnostics) != 0 {
			logR3AdmissionState(t, t.Context(), diagnostics[0].probe, diagnostics[0].operatorProbe)
		}
		t.Fatalf("push artifact generation %d: %v", generation, err)
	}
	var record delivery.ArtifactRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion,
		OperationID: fmt.Sprintf("r3-workload-%d", generation), Source: source,
		ArtifactDigest: record.Digest, ManifestDigest: record.ManifestDigest,
		Cell: "lab", Role: "terrabase", Environment: "test", Generation: generation,
		DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(nil, nil)}
	intentPath := testJSONFile(t, root, fmt.Sprintf("intent-%d.json", generation), intent)
	data, err = callR3Operator(ctx, config, "deploy", "--intent", intentPath)
	if err != nil {
		t.Fatalf("submit workload generation %d: %v", generation, err)
	}
	var submitted struct {
		OperationID string `json:"operationId"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &submitted); err != nil || submitted.OperationID == "" || submitted.Fingerprint == "" {
		t.Fatalf("invalid submit receipt: %v: %s", err, data)
	}
	var lastStatus string
	for ctx.Err() == nil {
		attempt, stop := context.WithTimeout(ctx, 8*time.Second)
		data, err := callR3Operator(attempt, config, "status", "--operation-id", submitted.OperationID,
			"--fingerprint", submitted.Fingerprint)
		stop()
		if err == nil {
			var receipt delivery.Receipt
			err = json.Unmarshal(data, &receipt)
			if err == nil {
				lastStatus = receipt.Status
				if receipt.Status == "accepted" {
					break
				}
				if receipt.Status == "rejected" || receipt.Status == "held" {
					t.Fatalf("workload generation %d became %s: %s", generation, receipt.Status, receipt.Error)
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("workload generation %d not accepted: %v; last status %s", generation, err, lastStatus)
	}
	nextDiagnostic := time.Now().Add(15 * time.Second)
	for ctx.Err() == nil {
		observed, _ := runner.Observe(ctx, "terrabase")
		if observed.Running && observed.Digest == record.Digest {
			return record.Digest
		}
		if len(diagnostics) != 0 {
			select {
			case agentErr := <-diagnostics[0].agentDone:
				logR3CallerState(t, ctx, config, runner, diagnostics[0].probe)
				t.Fatalf("host agent exited before workload generation %d applied: %v", generation, agentErr)
			default:
			}
			if !time.Now().Before(nextDiagnostic) {
				logR3CallerState(t, ctx, config, runner, diagnostics[0].probe)
				nextDiagnostic = time.Now().Add(15 * time.Second)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	t.Fatalf("host did not apply workload generation %d: %v", generation, ctx.Err())
	return ""
}

func logR3CallerState(t *testing.T, ctx context.Context, config string, runner *inMemoryRunner, probe *natscell.Runtime) {
	t.Helper()
	observed, observeErr := runner.Observe(ctx, "terrabase")
	t.Logf("generation-2 runner: %+v err=%v", observed, observeErr)
	attempt, stop := context.WithTimeout(ctx, 2*time.Second)
	data, err := callR3Operator(attempt, config, "hosts")
	stop()
	if err == nil {
		var statuses []host.HostStatus
		err = json.Unmarshal(data, &statuses)
		if err == nil {
			for _, status := range statuses {
				t.Logf("generation-2 host %s: session_expires=%s reports=%+v", status.Registration.Node,
					status.SessionExpiresAt.Format(time.RFC3339Nano), status.Reports)
			}
		}
	}
	if err != nil {
		t.Logf("generation-2 hosts read: %v", err)
	}
	legacy, err := probe.Conn().JetStream()
	if err != nil {
		t.Logf("generation-2 cycle reader: %v", err)
		return
	}
	attempt, stop = context.WithTimeout(ctx, 2*time.Second)
	message, err := legacy.GetLastMsg("KV_TS_HOST_STATE", "$KV.TS_HOST_STATE.cycle.lab.node-a.terrabase", nats.Context(attempt))
	stop()
	if err != nil {
		t.Logf("generation-2 cycle read: %v", err)
		return
	}
	var cycle struct {
		Generation     uint64    `json:"generation"`
		AuthorityEpoch uint64    `json:"authority_epoch"`
		State          string    `json:"state"`
		Failures       int       `json:"failures"`
		NotBefore      time.Time `json:"not_before"`
	}
	if err := json.Unmarshal(message.Data, &cycle); err != nil {
		t.Logf("generation-2 cycle decode: %v", err)
		return
	}
	t.Logf("generation-2 cycle: seq=%d state=%s generation=%d authority_epoch=%d failures=%d not_before=%s",
		message.Sequence, cycle.State, cycle.Generation, cycle.AuthorityEpoch, cycle.Failures, cycle.NotBefore.Format(time.RFC3339Nano))
}

func logR3AdmissionState(t *testing.T, ctx context.Context, probe, operatorProbe *natscell.Runtime) {
	t.Helper()
	attempt, stop := context.WithTimeout(ctx, 2*time.Second)
	account, err := probe.JetStream().AccountInfo(attempt)
	stop()
	if err != nil {
		t.Logf("admission controller account: %v", err)
	} else {
		t.Logf("admission controller account: %+v", account.API)
	}
	for _, name := range []string{authority.ControlStreamName, "KV_TS_DELIVERY_ADMISSIONS", "OBJ_TS_ARTIFACTS"} {
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		stream, err := probe.JetStream().Stream(attempt, name)
		if err == nil {
			var info *jetstream.StreamInfo
			info, err = stream.Info(attempt)
			if err == nil {
				t.Logf("admission stream %s: cluster=%+v messages=%d bytes=%d consumers=%d last_seq=%d",
					name, info.Cluster, info.State.Msgs, info.State.Bytes, info.State.Consumers, info.State.LastSeq)
			}
		}
		stop()
		if err != nil {
			t.Logf("admission stream %s: %v", name, err)
		}
	}
	attempt, stop = context.WithTimeout(ctx, 2*time.Second)
	snapshot, err := authority.Observe(attempt, probe.JetStream(), "lab")
	stop()
	t.Logf("admission authority=%+v err=%v probe_url=%s", snapshot, err, probe.Conn().ConnectedUrl())
	attempt, stop = context.WithTimeout(ctx, 2*time.Second)
	account, err = operatorProbe.JetStream().AccountInfo(attempt)
	stop()
	if err != nil {
		t.Logf("admission operator account: %v", err)
	} else {
		t.Logf("admission operator account: %+v", account.API)
	}
	attempt, stop = context.WithTimeout(ctx, 2*time.Second)
	_, err = operatorProbe.JetStream().ObjectStore(attempt, delivery.ArtifactBucket)
	stop()
	t.Logf("admission operator artifact bind: err=%v operator_url=%s", err, operatorProbe.Conn().ConnectedUrl())
}
