package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, false, false, false)
}

// Legacy static NKeys remain an explicit TLS lab regression; production JWT
// admission is exercised separately through the broker bridge.
func TestLabTLSHostSessionRecoversAfterControllerLoss(t *testing.T) {
	testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, true, false, false)
}

func TestLabTLSHostSessionRecoversAfterBlackholedController(t *testing.T) {
	testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, true, true, false)
}

func TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss(t *testing.T) {
	testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t, true, true, true)
}

func testAuthenticatedOperatorToHostDeliveryWithControllerLoss(t *testing.T, production, blackhole, forceRestart bool) {
	// Controller startup and shutdown must not consume the host scenario's
	// deadline or cause CommandContext to kill a gracefully stopping child.
	controllerCtx, cancel := context.WithCancel(t.Context())
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
	const peers = 3
	ports := reserveControllerPorts(t, 2*peers)
	clientPorts, routePorts := ports[:peers], ports[peers:]
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
		children[index] = startControllerChild(t, controllerCtx, root, configs[index], 1, index)
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
			// The CI runner discards its container filesystem after a failed job.
			// Include the controller stages in the retained test log as well.
			t.Logf("controller peer%d log:\n%s", index, data)
		}
		t.Logf("controller logs: %s", logDir)
	})
	for _, child := range children {
		waitControllerChildReady(t, controllerCtx, child)
	}
	ctx, cancelScenario := context.WithTimeout(controllerCtx, 165*time.Second)
	defer cancelScenario()
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
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey, Generation: 1,
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
	hostConn := hostRuntime.Conn()
	if forceRestart {
		// Keep every host connection on the controllable proxies. The normal
		// lab client may learn direct broker URLs from NATS INFO messages.
		options := hostConn.Opts
		options.IgnoreDiscoveredServers = true
		hostConn, err = options.Connect()
		if err != nil {
			t.Fatalf("connect isolated host through proxies: %v", err)
		}
		defer hostConn.Close()
	}
	runner := &inMemoryRunner{}
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	var agentRunner host.Runner = runner
	var stopRunner *r3TimedStopRunner
	var acceptedSessions r3AcceptedSessionTrace
	if production {
		baseRunner := &r3StopOnCloseRunner{inMemoryRunner: runner}
		agentRunner = baseRunner
		if blackhole {
			stopRunner = &r3TimedStopRunner{r3StopOnCloseRunner: baseRunner}
			agentRunner = stopRunner
			originalLogger := slog.Default()
			slog.SetDefault(slog.New(r3AcceptedSessionHandler{next: slog.NewTextHandler(os.Stderr, nil), sessions: &acceptedSessions}))
			defer slog.SetDefault(originalLogger)
		}
	}
	agentConfig := host.AgentConfig{WorkloadIdentity: testHostWorkloadIdentity(), Cell: "lab", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		Conn: hostConn, Identity: hostPrivate, NATSUserPublicKey: hostNKey, ControllerPublicKey: controllerPublic, Runner: agentRunner,
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), PollInterval: 100 * time.Millisecond,
		ClockCheck: controllerClockCheck(clock), SessionTrace: production && blackhole}
	agent, err := host.NewAgent(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(controllerCtx)
	defer stopAgent()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(agentCtx) }()
	firstSession := waitR3HostSession(t, ctx, operatorConfig, agentDone, time.Time{})
	firstDigest := deployR3Workload(t, ctx, root, operatorConfig, runner, 1)
	// Controller readiness does not prove that every host/delivery stream has
	// two current followers. Inject loss only after the whole caller's durable
	// state can survive it, including signed sessions in the control log.
	waitR3CallerStreamQuorum(t, ctx, probe, -1)
	connected := hostConn.ConnectedUrl()
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
	var postCrashExpiry int64
	var postCrashAdvancements uint64
	if blackhole {
		postCrashExpiry, postCrashAdvancements = acceptedSessions.snapshot()
		if postCrashExpiry == 0 {
			t.Fatal("host session trace did not capture the accepted pre-failure session")
		}
	}
	reconnectDeadline := time.NewTimer(15 * time.Second)
	reconnectPoll := time.NewTicker(50 * time.Millisecond)
	defer reconnectDeadline.Stop()
	defer reconnectPoll.Stop()
	for !hostConn.IsConnected() || hostConn.ConnectedUrl() == connected {
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before reconnecting away from crashed controller: %v", err)
		case <-reconnectDeadline.C:
			t.Fatalf("host did not reconnect away from crashed controller %q within session headroom; current %q", connected, hostConn.ConnectedUrl())
		case <-ctx.Done():
			t.Fatalf("host reconnect interrupted after controller loss: %v", ctx.Err())
		case <-reconnectPoll.C:
		}
	}
	if production && blackhole {
		var stoppedErr error
		var stopped bool
		if forceRestart {
			// Hide both surviving broker links until the old signed execution
			// reserve expires. This exercises the supervisor restart path even
			// when the controller backend recovers promptly in the lab.
			for index := range proxies {
				if index != failedPeer {
					proxies[index].blocked.Store(true)
				}
			}
			select {
			case stoppedErr = <-agentDone:
				stopped = true
			case <-ctx.Done():
				t.Fatalf("host did not fence while session links were blocked: %v", ctx.Err())
			}
		} else {
			_, stoppedErr, stopped = observeR3HostSession(ctx, operatorConfig, agentDone, firstSession.SessionExpiresAt)
			if stoppedErr == nil {
				stoppedErr, stopped = observeR3HostReconnect(ctx, hostConn, hostURLs, urls, failedPeer,
					&acceptedSessions, postCrashExpiry, postCrashAdvancements, agentDone)
			}
		}
		if stopped {
			// A surviving NATS connection does not prove the JetStream session
			// backend recovered before the old signed lease ran out. This is the
			// host's fail-closed branch, followed by supervised restart.
			assertR3HostFenced(t, ctx, runner, stopRunner, &acceptedSessions, stoppedErr)
			t.Logf("host fenced during controller recovery: %v", stoppedErr)
			oldSession, ok := acceptedSessions.latest()
			if !ok {
				t.Fatal("host did not trace the fenced signed session")
			}
			if forceRestart {
				for index := range proxies {
					if index != failedPeer {
						proxies[index].blocked.Store(false)
					}
				}
			}
			agent, err = host.NewAgent(agentConfig)
			if err != nil {
				t.Fatal(err)
			}
			agentCtx, stopAgent = context.WithCancel(controllerCtx)
			defer stopAgent()
			agentDone = make(chan error, 1)
			go func() { agentDone <- agent.Run(agentCtx) }()
			_ = waitR3RestartedSession(t, ctx, operatorConfig, hostConn, hostURLs, urls, failedPeer,
				&acceptedSessions, oldSession, agentDone)
		} else if stoppedErr != nil {
			t.Fatalf("host recovery observation failed: %v", stoppedErr)
		}
	} else {
		_ = waitR3HostSession(t, ctx, operatorConfig, agentDone, firstSession.SessionExpiresAt, probe)
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
	t.Logf("host_url=%s authority_after=%+v", hostConn.ConnectedUrl(), after)
	operatorProbe, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "operator-probe", Replicas: 3,
		Lab: true, URL: strings.Join(urls, ","), NKeySeedFile: operatorSeed, TLS: tlsFiles})
	if err != nil {
		t.Fatal(err)
	}
	defer operatorProbe.Close()
	secondDigest := deployR3Workload(t, ctx, root, operatorConfig, runner, 2,
		&r3CallerDiagnostics{probe: probe, operatorProbe: operatorProbe, agentDone: agentDone})
	waitR3CallerStreamQuorum(t, ctx, probe, failedPeer)
	if firstDigest == secondDigest {
		t.Fatal("replacement workload did not change artifact digest")
	}
	if production && blackhole {
		lastSession := waitR3HostSession(t, ctx, operatorConfig, agentDone, firstSession.SessionExpiresAt)
		stopRunner.stoppedAt.Store(0)
		for index, child := range children {
			if index != failedPeer {
				crashControllerChild(t, child)
				break
			}
		}
		// Earlier startup, reconnect and restart waits cannot shorten the
		// signed session's remaining execution reserve. Keep the absolute
		// before-expiry assertion in assertR3HostFenced.
		acceptedUntil, _ := acceptedSessions.snapshot()
		fenceDeadline := time.NewTimer(time.Until(time.Unix(0, acceptedUntil)))
		defer fenceDeadline.Stop()
		select {
		case err := <-agentDone:
			assertR3HostFenced(t, controllerCtx, runner, stopRunner, &acceptedSessions, err)
			t.Logf("host fenced before accepted expiry after quorum loss: observed_expiry=%s", lastSession.SessionExpiresAt)
		case <-fenceDeadline.C:
			t.Fatal("host did not fail closed before accepted signed session expiry after quorum loss")
		}
		return
	}
	stopAgent()
	if err := <-agentDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host agent shutdown: %v", err)
	}
	for index, child := range children {
		if index != failedPeer {
			signalControllerChild(t, child)
		}
	}
	for index, child := range children {
		if index != failedPeer {
			waitControllerChildStopped(t, child)
		}
	}
}

type r3TimedStopRunner struct {
	*r3StopOnCloseRunner
	stoppedAt atomic.Int64
}

func (r *r3TimedStopRunner) Close(ctx context.Context) error {
	err := r.r3StopOnCloseRunner.Close(ctx)
	if err == nil {
		r.stoppedAt.CompareAndSwap(0, time.Now().UnixNano())
	}
	return err
}

type r3AcceptedSessionHandler struct {
	next     slog.Handler
	sessions *r3AcceptedSessionTrace
}

type r3AcceptedSessionTrace struct {
	mu           sync.Mutex
	expiry       int64
	advancements uint64
	events       []r3AcceptedSessionEvent
}

type r3AcceptedSessionEvent struct {
	sequence      uint64
	phase         string
	sessionIDHash string
	expiresAt     time.Time
}

func (trace *r3AcceptedSessionTrace) record(event r3AcceptedSessionEvent) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	event.sequence = uint64(len(trace.events) + 1)
	trace.events = append(trace.events, event)
	expiry := event.expiresAt.UnixNano()
	if expiry > trace.expiry {
		trace.expiry = expiry
		trace.advancements++
	}
}

func (trace *r3AcceptedSessionTrace) snapshot() (expiry int64, advancements uint64) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.expiry, trace.advancements
}

func (trace *r3AcceptedSessionTrace) latest() (r3AcceptedSessionEvent, bool) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.events) == 0 {
		return r3AcceptedSessionEvent{}, false
	}
	return trace.events[len(trace.events)-1], true
}

func (trace *r3AcceptedSessionTrace) eventsAfter(sequence uint64) []r3AcceptedSessionEvent {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if sequence >= uint64(len(trace.events)) {
		return nil
	}
	return slices.Clone(trace.events[sequence:])
}

func (h r3AcceptedSessionHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h r3AcceptedSessionHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "host session accepted" {
		var event r3AcceptedSessionEvent
		record.Attrs(func(attr slog.Attr) bool {
			switch attr.Key {
			case "phase":
				event.phase = attr.Value.String()
			case "session_id_hash":
				event.sessionIDHash = attr.Value.String()
			case "expires_at":
				event.expiresAt, _ = time.Parse(time.RFC3339Nano, attr.Value.String())
			}
			return true
		})
		if event.phase != "" && event.sessionIDHash != "" && !event.expiresAt.IsZero() {
			h.sessions.record(event)
		}
	}
	return h.next.Handle(ctx, record)
}

func (h r3AcceptedSessionHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return r3AcceptedSessionHandler{next: h.next.WithAttrs(attrs), sessions: h.sessions}
}

func (h r3AcceptedSessionHandler) WithGroup(name string) slog.Handler {
	return r3AcceptedSessionHandler{next: h.next.WithGroup(name), sessions: h.sessions}
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

func waitR3CallerStreamQuorum(t *testing.T, ctx context.Context, probe *natscell.Runtime, failedPeer int) {
	t.Helper()
	started := time.Now()
	checkCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	streams := []string{authority.ControlStreamName, delivery.IntentStream,
		"OBJ_" + delivery.ArtifactBucket, "KV_" + delivery.AdmissionBucket,
		"KV_" + delivery.OperationBucket, "KV_TS_HOST_STATE"}
	var lastStream string
	var lastCluster *jetstream.ClusterInfo
	var lastErr error
	for checkCtx.Err() == nil {
		quorate := true
		for _, name := range streams {
			attempt, stop := context.WithTimeout(checkCtx, 2*time.Second)
			stream, err := probe.JetStream().Stream(attempt, name)
			var info *jetstream.StreamInfo
			if err == nil {
				info, err = stream.Info(attempt)
			}
			stop()
			if err != nil || !r3CallerStreamQuorate(info, failedPeer) {
				lastStream, lastErr, lastCluster = name, err, nil
				if info != nil {
					lastCluster = info.Cluster
				}
				quorate = false
				break
			}
		}
		if quorate {
			t.Logf("all %d caller streams have a current quorum after peer%d loss: wait=%s", len(streams), failedPeer, time.Since(started))
			return
		}
		select {
		case <-checkCtx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("caller stream %s lacks a current surviving quorum after peer%d loss: cluster=%+v err=%v: %v",
		lastStream, failedPeer, lastCluster, lastErr, checkCtx.Err())
}

func r3CallerStreamQuorate(info *jetstream.StreamInfo, failedPeer int) bool {
	if info == nil || info.Config.Replicas != 3 || info.Cluster == nil ||
		info.Cluster.Leader == "" || len(info.Cluster.Replicas) != 2 {
		return false
	}
	failedName := fmt.Sprintf("lab-peer%d", failedPeer)
	if info.Cluster.Leader == failedName {
		return false
	}
	current := map[string]bool{info.Cluster.Leader: true}
	for _, peer := range info.Cluster.Replicas {
		if peer == nil || current[peer.Name] {
			return false
		}
		if peer.Name != failedName {
			current[peer.Name] = peer.Current && !peer.Offline && !peer.Pending
		}
	}
	for index := range 3 {
		name := fmt.Sprintf("lab-peer%d", index)
		if index == failedPeer {
			continue
		}
		if !current[name] {
			return false
		}
	}
	return true
}

func TestR3CallerStreamQuorumRequiresEverySurvivingReplica(t *testing.T) {
	for _, test := range []struct {
		name       string
		failedPeer int
		leader     string
		replicas   []*jetstream.PeerInfo
		want       bool
	}{
		{"ready before loss", -1, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true}, {Name: "lab-peer2", Current: true}}, true},
		{"lagging before loss", -1, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true}, {Name: "lab-peer2"}}, false},
		{"ready after loss", 2, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true}, {Name: "lab-peer2", Offline: true}}, true},
		{"surviving follower lagging", 2, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1"}, {Name: "lab-peer2", Offline: true}}, false},
		{"surviving follower pending", 2, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true, Pending: true}, {Name: "lab-peer2", Offline: true}}, false},
		{"surviving follower offline", 2, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true, Offline: true}, {Name: "lab-peer2", Offline: true}}, false},
		{"failed leader", 2, "lab-peer2", []*jetstream.PeerInfo{
			{Name: "lab-peer0", Current: true}, {Name: "lab-peer1", Current: true}}, false},
		{"duplicate follower", -1, "lab-peer0", []*jetstream.PeerInfo{
			{Name: "lab-peer1", Current: true}, {Name: "lab-peer1", Current: true}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := &jetstream.StreamInfo{Config: jetstream.StreamConfig{Replicas: 3},
				Cluster: &jetstream.ClusterInfo{Leader: test.leader, Replicas: test.replicas}}
			if got := r3CallerStreamQuorate(info, test.failedPeer); got != test.want {
				t.Fatalf("stream fixture ready=%t, want %t: %+v", got, test.want, info.Cluster)
			}
		})
	}
}

func callR3Operator(ctx context.Context, config, operation string, args ...string) ([]byte, error) {
	var output bytes.Buffer
	command := append([]string{"operator", operation, "--config", config}, args...)
	err := Run(ctx, command, &output)
	return output.Bytes(), err
}

func waitR3HostSession(t *testing.T, ctx context.Context, config string, agentDone <-chan error, after time.Time, probe ...*natscell.Runtime) host.HostStatus {
	t.Helper()
	status, err, stopped := observeR3HostSession(ctx, config, agentDone, after)
	if stopped {
		if len(probe) != 0 {
			attempt, stop := context.WithTimeout(ctx, 2*time.Second)
			snapshot, observeErr := authority.Observe(attempt, probe[0].JetStream(), "lab")
			stop()
			t.Logf("authority on host session failure: %+v, observe error: %v, probe_url=%s", snapshot, observeErr, probe[0].Conn().ConnectedUrl())
		}
		t.Fatalf("host agent exited before session renewal: %v", err)
	}
	if err != nil {
		t.Fatalf("host session did not renew after controller loss: %v", err)
	}
	return status
}

func observeR3HostSession(ctx context.Context, config string, agentDone <-chan error, after time.Time) (host.HostStatus, error, bool) {
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
				select {
				case agentErr := <-agentDone:
					return host.HostStatus{}, agentErr, true
				default:
				}
				return statuses[0], nil, false
			}
		}
		lastErr = err
		select {
		case agentErr := <-agentDone:
			return host.HostStatus{}, agentErr, true
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	return host.HostStatus{}, fmt.Errorf("%w; last error %v", ctx.Err(), lastErr), false
}

func waitR3RestartedSession(t *testing.T, ctx context.Context, config string, conn *nats.Conn,
	hostURLs, urls []string, failedPeer int, acceptedSessions *r3AcceptedSessionTrace,
	oldSession r3AcceptedSessionEvent, agentDone <-chan error) host.HostStatus {
	t.Helper()
	var lastStatus host.HostStatus
	var lastErr error
	for ctx.Err() == nil {
		var acquired, renewed r3AcceptedSessionEvent
		for _, event := range acceptedSessions.eventsAfter(oldSession.sequence) {
			if event.phase == "acquire" && event.sessionIDHash != oldSession.sessionIDHash {
				acquired = event
				renewed = r3AcceptedSessionEvent{}
			}
			if acquired.sequence != 0 && event.phase == "renew" &&
				event.sequence > acquired.sequence && event.sessionIDHash == acquired.sessionIDHash &&
				event.expiresAt.After(acquired.expiresAt) && event.expiresAt.After(time.Now().Add(5*time.Second)) {
				renewed = event
			}
		}
		if renewed.sequence != 0 && conn.IsConnected() &&
			r3ConnectedToSurvivor(conn.ConnectedUrl(), hostURLs, urls, failedPeer) {
			attempt, stop := context.WithTimeout(ctx, 2*time.Second)
			data, err := callR3Operator(attempt, config, "hosts")
			stop()
			if err == nil {
				var statuses []host.HostStatus
				err = json.Unmarshal(data, &statuses)
				if err == nil && len(statuses) == 1 {
					lastStatus = statuses[0]
					if !lastStatus.SessionExpiresAt.Before(renewed.expiresAt) &&
						lastStatus.SessionExpiresAt.After(time.Now().Add(5*time.Second)) {
						select {
						case agentErr := <-agentDone:
							t.Fatalf("restarted host agent exited after signed acquire and renew: %v", agentErr)
						default:
						}
						t.Logf("restarted host accepted fresh signed session: old_hash=%s new_hash=%s acquire_expiry=%s renew_expiry=%s status_expiry=%s",
							oldSession.sessionIDHash, acquired.sessionIDHash, acquired.expiresAt, renewed.expiresAt, lastStatus.SessionExpiresAt)
						return lastStatus
					}
				}
			}
			lastErr = err
		}
		select {
		case agentErr := <-agentDone:
			t.Fatalf("restarted host agent exited before fresh signed acquire and renew: %v", agentErr)
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	t.Fatalf("restarted host did not accept a distinct signed acquisition and renewal on a surviving endpoint: old_hash=%s status_expiry=%s last_error=%v: %v",
		oldSession.sessionIDHash, lastStatus.SessionExpiresAt, lastErr, ctx.Err())
	return host.HostStatus{}
}

func assertR3HostFenced(t *testing.T, ctx context.Context, runner *inMemoryRunner, stopRunner *r3TimedStopRunner,
	acceptedSessions *r3AcceptedSessionTrace, err error) {
	t.Helper()
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("host did not fail closed on session loss: %v", err)
	}
	if !strings.Contains(err.Error(), "host session execution reserve exhausted") {
		t.Fatalf("host stopped for a reason other than signed lease reserve: %v", err)
	}
	stoppedAt := stopRunner.stoppedAt.Load()
	acceptedUntil, _ := acceptedSessions.snapshot()
	if stoppedAt == 0 || acceptedUntil == 0 || !time.Unix(0, stoppedAt).Before(time.Unix(0, acceptedUntil)) {
		t.Fatalf("host workload stop missed accepted signed expiry: stopped_at=%s accepted_expiry=%s err=%v",
			time.Unix(0, stoppedAt), time.Unix(0, acceptedUntil), err)
	}
	observed, observeErr := runner.Observe(ctx, "terrabase")
	if observeErr != nil || observed.Running {
		t.Fatalf("host retained workload after session loss: observed=%+v err=%v", observed, observeErr)
	}
}

func observeR3HostReconnect(ctx context.Context, conn *nats.Conn, hostURLs, urls []string,
	failedPeer int, acceptedSessions *r3AcceptedSessionTrace, priorExpiry int64, priorAdvancements uint64,
	agentDone <-chan error) (error, bool) {
	if priorExpiry == 0 {
		return errors.New("host session trace did not capture the accepted pre-failure session"), false
	}
	for ctx.Err() == nil {
		connectedToSurvivor := conn.IsConnected() && r3ConnectedToSurvivor(conn.ConnectedUrl(), hostURLs, urls, failedPeer)
		currentExpiry, currentAdvancements := acceptedSessions.snapshot()
		if connectedToSurvivor && currentAdvancements >= priorAdvancements+2 &&
			time.Unix(0, currentExpiry).After(time.Now().Add(5*time.Second)) {
			select {
			case err := <-agentDone:
				return err, true
			default:
			}
			return nil, false
		}
		select {
		case err := <-agentDone:
			return err, true
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	currentExpiry, currentAdvancements := acceptedSessions.snapshot()
	return fmt.Errorf("host did not reconnect to a surviving controller and accept renewed valid sessions: connected_to_survivor=%t prior_expiry=%s current_expiry=%s prior_advancements=%d current_advancements=%d: %w",
		conn.IsConnected() && r3ConnectedToSurvivor(conn.ConnectedUrl(), hostURLs, urls, failedPeer),
		time.Unix(0, priorExpiry).Format(time.RFC3339Nano), time.Unix(0, currentExpiry).Format(time.RFC3339Nano),
		priorAdvancements, currentAdvancements, ctx.Err()), false
}

func r3ConnectedToSurvivor(currentURL string, hostURLs, urls []string, failedPeer int) bool {
	currentEndpoint, ok := r3NATSEndpointHostPort(currentURL)
	if !ok {
		return false
	}
	for index := range urls {
		if index == failedPeer {
			continue
		}
		if index < len(hostURLs) {
			if hostEndpoint, valid := r3NATSEndpointHostPort(hostURLs[index]); valid && currentEndpoint == hostEndpoint {
				return true
			}
		}
		if brokerEndpoint, valid := r3NATSEndpointHostPort(urls[index]); valid && currentEndpoint == brokerEndpoint {
			return true
		}
	}
	return false
}

func r3NATSEndpointHostPort(rawURL string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "nats" && parsed.Scheme != "tls") ||
		parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", false
	}
	return parsed.Host, true
}

func TestR3ConnectedToSurvivorNormalizesTLSURLSchemeAndExcludesFailedPeer(t *testing.T) {
	hostURLs := []string{
		"nats://127.0.0.1:38017",
		"nats://127.0.0.1:38019",
		"nats://127.0.0.1:38021",
	}
	urls := []string{
		"nats://127.0.0.1:37417",
		"nats://127.0.0.1:44427",
		"nats://127.0.0.1:44241",
	}
	tests := []struct {
		name       string
		currentURL string
		want       bool
	}{
		{name: "discovered TLS broker URL matches survivor", currentURL: "tls://127.0.0.1:37417", want: true},
		{name: "configured NATS proxy URL matches survivor", currentURL: hostURLs[0], want: true},
		{name: "failed broker is excluded", currentURL: "tls://127.0.0.1:44427"},
		{name: "failed proxy is excluded", currentURL: hostURLs[1]},
		{name: "foreign scheme is rejected", currentURL: "https://127.0.0.1:37417"},
		{name: "malformed URL is rejected", currentURL: "tls://:37417"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := r3ConnectedToSurvivor(test.currentURL, hostURLs, urls, 1); got != test.want {
				t.Fatalf("r3ConnectedToSurvivor(%q) = %t, want %t", test.currentURL, got, test.want)
			}
		})
	}
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
		if len(diagnostics) != 0 {
			logR3AdmissionState(t, t.Context(), diagnostics[0].probe, diagnostics[0].operatorProbe)
		}
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
	for _, name := range []string{authority.ControlStreamName, delivery.IntentStream,
		"KV_TS_DELIVERY_ADMISSIONS", "OBJ_TS_ARTIFACTS"} {
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
