package mesh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

func stopNode(node *Node) {
	if err := node.Close(); err != nil {
		node.ForceClose()
	}
}

var fleetMuted atomic.Bool

const FleetAdvertiseEvery = 250 * time.Millisecond

func FleetMuteAnnouncements(muted bool) { fleetMuted.Store(muted) }

func FleetHostNode(root, region, name, address, peer string, seed []byte) (*Node, error) {
	ca, err := DeriveCA(seed)
	if err != nil {
		return nil, err
	}
	cfg := config{region: region, server: name, founder: true, dir: filepath.Join(root, name), ca: ca,
		terrabaseToken: strings.Repeat("t", 32), clusterHost: address, clusterPort: 6222, clusterAdvertise: address + ":6222", localPort: 4222,
		peersEvery: FleetAdvertiseEvery, peersDir: filepath.Join(root, name+"-peers"), address: func() (string, error) {
			if fleetMuted.Load() {
				return "", errors.New("fleet announcements muted")
			}
			return address, nil
		}}
	cfg.routes = []string{"nats://" + peer + ":6222"}
	return start(cfg)
}

func FleetRefreshEdgeInventory(node *Node) {
	node.edgePublishMu.Lock()
	defer node.edgePublishMu.Unlock()
	node.edgePublished = nil
}

func FleetEdgeInventoryGeneration(node *Node) uint64 {
	if inventory := node.edgeInventory.Load(); inventory != nil {
		return inventory.Generation
	}
	return 0
}

func FleetForgeEdgeInventory(node *Node, state string, older []byte) error {
	current := node.edgeInventory.Load()
	genuine, err := os.ReadFile(filepath.Join(state, edgeInventoryFile))
	if err != nil || current == nil {
		return fmt.Errorf("worker has no persisted inventory: %w", err)
	}
	forged := *current
	forged.Web = maps.Clone(current.Web)
	forged.Web["forged.e2e.test"] = 18101
	forged.Generation, forged.Issued = current.Generation+1, time.Now().UTC()
	payload, err := protocol.EncodeJSON(forged)
	if err != nil {
		return err
	}
	signed := func(signer string) (SignedEdgeInventory, error) {
		chain, signature, err := swarmruntime.SignRegional(signer, EdgeInventoryMessage(payload))
		return SignedEdgeInventory{Inventory: payload, Certificate: chain, Signature: signature}, err
	}
	root, region, other := filepath.Dir(state), node.cfg.region, "sjc"
	if region == other {
		other = "gru"
	}
	worker, err := signed(state)
	if err != nil {
		return err
	}
	foreign, err := signed(filepath.Join(root, "state-ts-"+other+"-1"))
	if err != nil {
		return err
	}
	removed, err := signed(filepath.Join(root, "removed-"+region))
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject:     pkix.Name{CommonName: "ts-" + region + "-1", Organization: []string{"fleet-" + region}, OrganizationalUnit: []string{"swarm-manager"}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	self, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(EdgeInventoryMessage(payload))
	selfSignature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return err
	}
	var tampered SignedEdgeInventory
	if err := protocol.DecodeTolerant(genuine, &tampered, maxWire); err != nil {
		return err
	}
	tampered.Inventory = payload
	attempts := map[string]any{
		"a route signed by a worker certificate":           worker,
		"a self-signed manager certificate":                SignedEdgeInventory{Inventory: payload, Certificate: [][]byte{self}, Signature: selfSignature},
		"another region's manager certificate":             foreign,
		"a manager certificate the region no longer lists": removed,
		"the manager's envelope with a new route":          tampered,
		"a replay of an older manager inventory":           older,
	}
	for attempt, envelope := range attempts {
		data, ok := envelope.([]byte)
		if !ok {
			if data, err = protocol.EncodeJSON(envelope); err != nil {
				return err
			}
		}
		if err := node.conn.Publish(node.edgeInventorySubject(), data); err != nil {
			return err
		}
		if err := node.acceptEdgeInventory(state, data); err == nil {
			return fmt.Errorf("worker accepted %s", attempt)
		}
	}
	after, err := os.ReadFile(filepath.Join(state, edgeInventoryFile))
	if err != nil || !bytes.Equal(after, genuine) || node.edgeInventory.Load().Generation != current.Generation {
		return fmt.Errorf("a refused inventory replaced the persisted one: %w", err)
	}
	return nil
}

func RegionalPeersJourney(root string, health func(context.Context, string, *Node) error) error {
	logrus.SetLevel(logrus.WarnLevel)
	began := time.Now()
	defer func() { fmt.Printf("regional peers lane elapsed: %s\n", time.Since(began).Round(time.Millisecond)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, err := os.MkdirTemp(root, "regional-peers-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	log, err := os.Create(filepath.Join(root, "containerd.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	socket := filepath.Join(root, "containerd.sock")
	runtimeConfig := filepath.Join(root, "containerd.toml")
	configData := fmt.Sprintf("version = 3\n[plugins.'io.containerd.nri.v1.nri']\nsocket_path = %q\n[plugins.'io.containerd.server.v1.ttrpc']\naddress = %q\n", filepath.Join(root, "nri.sock"), filepath.Join(root, "ttrpc.sock"))
	if err := os.WriteFile(runtimeConfig, []byte(configData), 0600); err != nil {
		return err
	}
	daemon := exec.Command("containerd", "--config", runtimeConfig, "--root", filepath.Join(root, "content"), "--state", filepath.Join(root, "runtime"), "--address", socket)
	daemon.Stdout, daemon.Stderr = log, log
	if err := daemon.Start(); err != nil {
		return err
	}
	defer func() {
		_ = daemon.Process.Signal(os.Interrupt)
		_ = daemon.Wait()
	}()
	if err := regionalAwait(ctx, func() bool { _, err := os.Stat(socket); return err == nil }); err != nil {
		data, _ := os.ReadFile(log.Name())
		return fmt.Errorf("containerd socket: %w: %s", err, data)
	}
	managerState := filepath.Join(root, "sjc-swarm")
	executor, err := swarmruntime.NewExecutor(socket, managerState)
	if err != nil {
		return err
	}
	defer executor.Close()
	manager, err := swarmruntime.StartHost(ctx, managerState, executor, "127.0.0.1:4242", "127.0.0.1:4242", swarmruntime.FoundingAdmission("manager", "manager"))
	if err != nil {
		return err
	}
	defer manager.Stop(context.Background())
	control, conn, err := swarmruntime.DialControl(managerState)
	if err != nil {
		return err
	}
	defer conn.Close()
	clusters, err := control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		return err
	}
	address, err := manager.RemoteAddress()
	if err != nil {
		return err
	}
	workerState := filepath.Join(root, "worker-swarm")
	workerExecutor, err := swarmruntime.NewExecutor(socket, workerState)
	if err != nil {
		return err
	}
	defer workerExecutor.Close()
	joining, err := swarmruntime.JoiningAdmission("regional-worker", "regional-worker", address, clusters.Clusters[0].RootCA.JoinTokens.Worker)
	if err != nil {
		return err
	}
	worker, err := swarmruntime.StartHost(ctx, workerState, workerExecutor, "127.0.0.1:0", "127.0.0.1:0", joining)
	if err != nil {
		return err
	}
	defer worker.Stop(context.Background())
	ca, err := DeriveCA([]byte(strings.Repeat("r", 32)))
	if err != nil {
		return err
	}
	ports := make([]int, 6)
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		ports[i] = listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
	}
	cfg := func(region, name, ip string, local, cluster, remote int) config {
		other := "gru"
		if region == "gru" {
			other = "sjc"
		}
		return config{region: region, server: name, nodeID: manager.ID(), founder: true, dir: filepath.Join(root, name), ca: ca, terrabaseToken: strings.Repeat("t", 32),
			clusterHost: "127.0.0.1", clusterPort: cluster, clusterAdvertise: fmt.Sprintf("127.0.0.1:%d", cluster), localPort: local,
			seeds:   map[string][]string{other: {fmt.Sprintf("nats://127.0.0.1:%d", remote)}},
			applier: swarmApplier{state: managerState, region: region}, every: time.Second, peersEvery: 250 * time.Millisecond,
			peersDir: filepath.Join(root, name+"-files"), address: func() (string, error) { return ip, nil }}
	}
	ownCfg := cfg("gru", "gru-founder", "127.0.0.2", ports[0], ports[1], ports[3])
	peerCfg := cfg("sjc", "sjc-founder", "127.0.0.3", ports[2], ports[3], ports[1])
	own, err := start(ownCfg)
	if err != nil {
		return err
	}
	defer own.Close()
	founder, err := start(peerCfg)
	if err != nil {
		return err
	}
	defer func() {
		if founder != nil {
			stopNode(founder)
		}
	}()
	workerName := "regional-worker"
	workerCfg := cfg("sjc", workerName, "127.0.0.4", ports[4], ports[5], ports[3])
	workerCfg.applier = nil
	workerCfg.nodeID = worker.ID()
	workerCfg.seeds = nil
	workerCfg.routes = []string{fmt.Sprintf("nats://127.0.0.1:%d", ports[3])}
	workerAgent, err := start(workerCfg)
	if err != nil {
		return err
	}
	defer func() {
		if workerAgent != nil {
			stopNode(workerAgent)
		}
	}()
	if err := regionalAwait(ctx, func() bool { return len(founder.joinedWorkers()) == 1 && own.server.NumRoutes() > 0 }); err != nil {
		ready, pending, _, membershipErr := peerCfg.applier.(swarmApplier).WorkerStates(context.Background())
		return fmt.Errorf("two regions and a joined worker: %w (ready=%v pending=%v membership=%v routes=%d)", err, ready, pending, membershipErr, own.server.NumRoutes())
	}
	if err := health(ctx, workerState, workerAgent); err != nil {
		return fmt.Errorf("joined worker release health differs from main: %w", err)
	}
	fmt.Println("ok regional peers: same as main, a real joined worker is release-healthy without a manager socket or JetStream; a missing mesh node blocks release")
	for node, expected := range map[*Node]int{own: 1, founder: 1, workerAgent: 0} {
		var metrics bytes.Buffer
		node.writeStoreMetrics(&metrics)
		if !strings.Contains(metrics.String(), fmt.Sprintf("ts_orch_mesh_store_expected %d\n", expected)) {
			return fmt.Errorf("mesh store role differs from the regional applier: %s", metrics.String())
		}
	}
	if err := regionalPlacementJourney(ctx, control, founder); err != nil {
		return err
	}
	writerCfg := ownCfg
	writerCfg.dir = filepath.Join(root, "writer-state")
	if err := os.MkdirAll(writerCfg.dir, 0700); err != nil {
		return err
	}
	writer, err := newPeers(writerCfg)
	if err != nil {
		return err
	}
	if err := writer.track("regional-data", []string{"gru", "sjc"}, true); err != nil && !strings.Contains(err.Error(), "admitted topology") {
		return err
	}
	round := func(want int) error {
		if want == 2 {
			if err := regionalAwait(ctx, func() bool { return regionalLinked(own, founder) && regionalLinked(founder, own) }); err != nil {
				return fmt.Errorf("regional ping routing interest: %w", err)
			}
		}
		up, workers, _ := own.pingPeers(ctx, time.Second)
		if len(up) != want {
			return fmt.Errorf("ping answered for %d regions, want %d", len(up), want)
		}
		if err := writer.admit(up, []string{"gru", "sjc"}); err != nil {
			return err
		}
		return writer.observe(up, workers)
	}
	if err := round(2); err != nil {
		return err
	}
	file := filepath.Join(ownCfg.peersDir, "regional-data", "peers")
	before, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	line := workerName + " sjc 127.0.0.4\n"
	if !bytes.Contains(before, []byte(line)) {
		return fmt.Errorf("joined worker missing before restart: %q", before)
	}
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	var sampleMu sync.Mutex
	var sampleErr error
	sampleCtx, stopSamples := context.WithCancel(ctx)
	samplesDone := make(chan struct{})
	go func() {
		defer close(samplesDone)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-tick.C:
				current, err := os.ReadFile(file)
				stat, statErr := os.Stat(file)
				if err == nil && statErr == nil && bytes.Equal(before, current) && stat.ModTime().Equal(info.ModTime()) {
					continue
				}
				sampleMu.Lock()
				sampleErr = fmt.Errorf("100ms restart sample changed content or mtime: %q, read %v, stat %v", current, err, statErr)
				sampleMu.Unlock()
				return
			}
		}
	}()
	defer func() { stopSamples(); <-samplesDone }()
	stopNode(workerAgent)
	founder.workerMu.Lock()
	lastAnnouncement := founder.announced[workerName]
	lastAnnouncement.at = time.Now().Add(-workerSettleWindow)
	founder.announced[workerName] = lastAnnouncement
	founder.workerMu.Unlock()
	if err := founder.setJoined(ctx); err != nil || len(founder.joinedWorkers()) != 1 {
		return fmt.Errorf("announcement silence removed a ready member: %v", err)
	}
	membershipCA := filepath.Join(managerState, "swarm", "certificates", "swarm-root-ca.crt")
	outageRequest, err := protocol.EncodeJSON(drainRequest{Node: workerName, Task: "restart-task"})
	if err != nil {
		return err
	}
	if err := os.Rename(membershipCA, membershipCA+".unavailable"); err != nil {
		return err
	}
	refreshErr := founder.setJoined(ctx)
	pingErr := round(2)
	outageResponse, drainErr := founder.conn.RequestWithContext(ctx, protocol.MeshDrainPrefix+"sjc", outageRequest)
	var outageReply drainReply
	if drainErr == nil {
		drainErr = protocol.DecodeStrict(outageResponse.Data, &outageReply, maxWire)
	}
	restoreErr := os.Rename(membershipCA+".unavailable", membershipCA)
	if restoreErr != nil {
		return restoreErr
	}
	if refreshErr == nil || pingErr != nil || len(founder.joinedWorkers()) != 1 {
		return fmt.Errorf("control outage lost cached topology or mesh liveness: refresh %v, ping %v", refreshErr, pingErr)
	}
	if drainErr != nil || outageReply.Error != "regional membership unavailable" {
		return fmt.Errorf("control outage accepted a drain: %+v, %v", outageReply, drainErr)
	}
	fmt.Println("ok regional peers: announcement silence warns; failed control lookup preserves peers and cached pings but refuses drains")
	stopNode(founder)
	founder, err = start(peerCfg)
	if err != nil {
		return err
	}
	rounds := time.NewTicker(time.Second)
	defer rounds.Stop()
	for i := range 4 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rounds.C:
		}
		if len(founder.joinedWorkers()) != 1 {
			return errors.New("restarted founder lost its ready worker without a fresh announcement")
		}
		if err := round(2); err != nil {
			return err
		}
		current, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(before, current) {
			return fmt.Errorf("empty reply round %d removed worker: %q, %v", i+1, current, err)
		}
	}
	workerAgent, err = start(workerCfg)
	if err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool { return len(founder.joinedWorkers()) == 1 }); err != nil {
		return err
	}
	if err := round(2); err != nil {
		return err
	}
	stopNode(workerAgent)
	stopNode(founder)
	if err := round(1); err != nil {
		return fmt.Errorf("first missed founder round: %w", err)
	}
	if err := round(1); err == nil || !strings.Contains(err.Error(), "admitted topology") {
		return fmt.Errorf("incomplete founder generation must be rejected: %v", err)
	}
	founder, err = start(peerCfg)
	if err != nil {
		return err
	}
	if err := round(2); err != nil {
		return err
	}
	currentAfterOutage, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, currentAfterOutage) {
		return fmt.Errorf("empty startup reply after refused generation removed workers: %q, %v", currentAfterOutage, err)
	}
	workerAgent, err = start(workerCfg)
	if err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool { return len(founder.joinedWorkers()) == 1 }); err != nil {
		return err
	}
	if err := round(2); err != nil {
		return err
	}
	founder.SetRegionalDrainer(func(_ context.Context, node, task string) error {
		current, err := os.ReadFile(file)
		if err != nil || !bytes.Contains(current, []byte(line)) || node != workerName || task != "restart-task" {
			return fmt.Errorf("regional drain peer proof: %q, %s, %s, %v", current, node, task, err)
		}
		return nil
	})
	cancelled, cancelDrain := context.WithCancel(ctx)
	cancelDrain()
	if err := handoff.DrainTask(cancelled, "restart-task"); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("unattached drainer ignored cancellation: %v", err)
	}
	pendingDrain := make(chan error, 1)
	go func() { pendingDrain <- handoff.DrainTask(ctx, "restart-task") }()
	handoff.SetTaskDrainer(workerAgent.DrainTask)
	if err := <-pendingDrain; err != nil {
		return fmt.Errorf("restarted worker task drain: %w", err)
	}
	stopNode(workerAgent)
	workerAgent, err = start(workerCfg)
	if err != nil {
		return err
	}
	handoff.SetTaskDrainer(workerAgent.DrainTask)
	if err := handoff.DrainTask(ctx, "restart-task"); err != nil {
		return fmt.Errorf("reattached worker task drain: %w", err)
	}
	fmt.Println("ok regional peers: restarted worker waits for drainer attachment and drains through its regional peer; replacement reattaches")
	stopSamples()
	<-samplesDone
	sampleMu.Lock()
	err = sampleErr
	sampleMu.Unlock()
	if err != nil {
		return err
	}
	current, err := os.ReadFile(file)
	stat, statErr := os.Stat(file)
	if err != nil || statErr != nil || !bytes.Equal(before, current) || !stat.ModTime().Equal(info.ModTime()) {
		return errors.New("worker recovery rewrote the peers file")
	}
	fmt.Println("ok regional peers: four rounds without announcements and recovery preserved worker, bytes and mtime at 100ms sampling")
	if err := writer.track("regional-data", []string{"gru"}, true); err != nil {
		return err
	}
	drained, err := os.ReadFile(file)
	if err != nil || bytes.Contains(drained, []byte(" sjc ")) {
		return fmt.Errorf("explicit region removal did not remove its block: %q, %v", drained, err)
	}
	if err := writer.track("regional-data", []string{"gru", "sjc"}, true); err != nil {
		return err
	}
	info, err = os.Stat(file)
	if err != nil {
		return err
	}
	fmt.Println("ok regional peers: missed founder retained its workers, incomplete generation rejected, explicit region removal applied immediately")
	stopNode(workerAgent)
	if err := worker.Stop(context.Background()); err != nil {
		return err
	}
	if _, err := control.RemoveNode(ctx, &api.RemoveNodeRequest{NodeID: worker.ID(), Force: true}); err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool { return len(founder.joinedWorkers()) == 0 }); err != nil {
		return err
	}
	stale, err := protocol.EncodeJSON(nodeAnnouncement{WorkerPeer: WorkerPeer{Node: workerName, Address: "127.0.0.4"}, NodeID: worker.ID()})
	if err != nil {
		return err
	}
	founder.recordWorker(&nats.Msg{Data: stale})
	if err := founder.setJoined(ctx); err != nil || len(founder.joinedWorkers()) != 0 {
		return fmt.Errorf("stale announcement restored removed worker: %w", err)
	}
	registry, err := os.ReadFile(filepath.Join(founder.cfg.dir, "workers.json"))
	if err != nil || bytes.Contains(registry, []byte(worker.ID())) {
		return fmt.Errorf("removed worker identity was not pruned: %q, %v", registry, err)
	}
	if err := round(2); err != nil {
		return err
	}
	current, err = os.ReadFile(file)
	if err != nil || bytes.Contains(current, []byte(line)) {
		return fmt.Errorf("authoritative removal retained worker in peers: %q, %v", current, err)
	}
	request, err := protocol.EncodeJSON(drainRequest{Node: workerName, Task: "restart-task"})
	if err != nil {
		return err
	}
	response, err := founder.conn.RequestWithContext(ctx, protocol.MeshDrainPrefix+"sjc", request)
	if err != nil {
		return err
	}
	var reply drainReply
	if err := protocol.DecodeStrict(response.Data, &reply, maxWire); err != nil || reply.Error != "node not admitted" {
		return fmt.Errorf("removed worker drain accepted: %+v, %v", reply, err)
	}
	fmt.Println("ok regional peers: explicit membership removal drops worker immediately and rejects stale announcements and drains")
	return nil
}

func regionalServiceTasks(ctx context.Context, control api.ControlClient, name string) (*api.Service, []*api.Task, error) {
	services, err := control.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{name}}})
	if err != nil || len(services.Services) != 1 {
		return nil, nil, fmt.Errorf("service %s: %v, %w", name, services, err)
	}
	tasks, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{services.Services[0].ID}}})
	if err != nil {
		return nil, nil, err
	}
	return services.Services[0], tasks.Tasks, nil
}

func regionalPlacementJourney(ctx context.Context, control api.ControlClient, founder *Node) error {
	declare := func(name, host string) swarmruntime.ServiceSpec {
		return swarmruntime.ServiceSpec{Name: name, Image: "docker.io/traefik/whoami@sha256:c2c89736959e8830c3db090e2f54500499ceb0460267f91dce494728d7327770",
			Env: map[string]string{"WHOAMI_PORT_NUMBER": "8099"}, Port: 8099, ReadyPath: "/readyz", Hostnames: []string{host}, Replicas: 1, MilliCPU: 50, MemoryMiB: 32}
	}
	reconcile := func(spec swarmruntime.ServiceSpec, generation int64) error {
		founder.mu.Lock()
		defer founder.mu.Unlock()
		_, err := founder.reconcile(ctx, spec.Name, desiredState{Operator: &Entry{Generation: generation, Spec: &spec}})
		return err
	}
	whoami := declare("whoami", "sjc.mesh.e2e.test")
	existing := whoami
	existing.Generation, existing.Region, existing.Node = 1, "sjc", founder.cfg.server
	rendered, err := existing.SwarmSpec()
	if err != nil {
		return err
	}
	rendered.Task.Placement = &api.Placement{Constraints: []string{"node.role==manager"}}
	if _, err := control.CreateService(ctx, &api.CreateServiceRequest{Spec: rendered}); err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool {
		_, tasks, err := regionalServiceTasks(ctx, control, "whoami")
		return err == nil && slices.ContainsFunc(tasks, func(task *api.Task) bool { return task.NodeID != "" })
	}); err != nil {
		return fmt.Errorf("existing manager-pinned whoami task never placed: %w", err)
	}
	if err := reconcile(whoami, 2); err != nil {
		return fmt.Errorf("whoami update over its manager-pinned task: %w", err)
	}
	placed, shared := map[string]bool{}, ""
	if err := regionalAwait(ctx, func() bool {
		service, tasks, err := regionalServiceTasks(ctx, control, "whoami")
		if err != nil || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas != 2 || service.Spec.Task.Placement == nil || service.Spec.Task.Placement.MaxReplicas != 1 || len(service.Spec.Task.Placement.Constraints) != 0 {
			return false
		}
		live := map[string]int{}
		for _, task := range tasks {
			if task.NodeID == "" {
				continue
			}
			placed[task.NodeID] = true
			if task.DesiredState <= api.TaskStateRunning {
				if live[task.NodeID]++; live[task.NodeID] > 1 {
					shared = task.NodeID
				}
			}
		}
		return len(placed) == 2 || shared != ""
	}); err != nil {
		return fmt.Errorf("updated whoami never placed a task on each node: %v, %w", placed, err)
	}
	if shared != "" {
		return fmt.Errorf("two whoami replicas shared node %s", shared)
	}
	if err := reconcile(declare("ts-auth", "auth.sjc.e2e.test"), 1); err != nil {
		return err
	}
	auth, _, err := regionalServiceTasks(ctx, control, "ts-auth")
	if err != nil {
		return err
	}
	if replicated := auth.Spec.GetReplicated(); replicated == nil || replicated.Replicas != 1 || auth.Spec.Task.Placement == nil || !slices.Equal(auth.Spec.Task.Placement.Constraints, []string{"node.role==manager"}) {
		return fmt.Errorf("ts-auth rendered %v with placement %v, want 1 replica on the manager", replicated, auth.Spec.Task.Placement)
	}
	for _, name := range []string{"whoami", "ts-auth"} {
		if err := swarmruntime.RemoveServiceSpec(ctx, control, name); err != nil {
			return err
		}
	}
	fmt.Println("ok regional placement: a manager-pinned whoami updated in place through SwarmKit to one task per node; ts-auth stays one replica on the manager")
	return nil
}

func regionalAwait(ctx context.Context, ready func() bool) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func regionalLinked(from, to *Node) bool {
	routes, err := from.server.Routez(&server.RoutezOptions{SubscriptionsDetail: true})
	if err != nil {
		return false
	}
	for _, route := range routes.Routes {
		if route.RemoteID != to.server.ID() {
			continue
		}
		for _, sub := range route.SubsDetail {
			if sub.Subject == PingSubject {
				return true
			}
		}
	}
	return false
}
