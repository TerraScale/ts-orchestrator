package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const regionalPeers = 3

func startAuthorityWithRetry(ctx context.Context, js jetstream.JetStream, config authority.Config) (*authority.Runtime, error) {
	for attempt := 1; ; attempt++ {
		runtime, err := authority.Start(ctx, js, config)
		if err == nil || !transientAuthorityStartupError(err) {
			return runtime, err
		}

		timer := time.NewTimer(min(time.Duration(attempt)*250*time.Millisecond, 2*time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func transientAuthorityStartupError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, authority.ErrConflict) ||
		errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, jetstream.ErrNoStreamResponse) {
		return true
	}
	apiErr, ok := errors.AsType[*jetstream.APIError](err)
	if !ok {
		return false
	}
	return apiErr.ErrorCode == 10005 || apiErr.Code >= 500 &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabled) &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount)
}

func TestRegionalAuthorityFailoverAndQuorum(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	cluster := newRegionalCluster(t, ctx)
	if err := cluster.startAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cluster.waitForPeers(ctx); err != nil {
		t.Fatal(err)
	}

	leaseConfig := authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope:         "r3-integration",
		LeaseDuration: 4 * time.Second,
		RenewInterval: 250 * time.Millisecond,
		Replicas:      regionalPeers,
	}
	candidates := make([]*authority.Runtime, regionalPeers)
	candidateIDs := []string{entityid.Derive("test-controller", "one"), entityid.Derive("test-controller", "two"), entityid.Derive("test-controller", "three")}
	startCandidate := func(index int) {
		t.Helper()
		cfg := leaseConfig
		cfg.CandidateID = candidateIDs[index]
		runtime, err := startAuthorityWithRetry(ctx, cluster.nodes[index].JetStream(), cfg)
		if err != nil {
			t.Fatalf("start authority %s: %v", cfg.CandidateID, err)
		}
		candidates[index] = runtime
		t.Cleanup(func() { _ = runtime.Close() })
	}
	stopPeer := func(index int) bool {
		t.Helper()
		candidate := candidates[index]
		if err := cluster.stop(index); err != nil {
			t.Fatalf("stop NATS peer %d: %v", index, err)
		}
		if candidate != nil {
			// The embedded runtime owns both this peer and its NATS client. Once
			// the peer stops, its candidate process has lost that client too.
			candidates[index] = nil
			if err := candidate.Close(); err != nil {
				t.Logf("close authority candidate %s after NATS peer %d stopped: %v", candidateIDs[index], index, err)
			}
		}
		return candidate != nil
	}
	startCandidate(0)
	initial, err := waitForLeader(ctx, candidates, candidateIDs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Epoch == 0 || !initial.Ready {
		t.Fatalf("initial authority snapshot = %+v", initial)
	}
	startCandidate(1)
	startCandidate(2)

	// All candidates share the same durable epoch, but only its holder may pass
	// the production authority guard and append a control mutation.
	if err := waitForSharedLeader(ctx, candidates, candidateIDs, candidateIDs[0], initial.Epoch); err != nil {
		t.Fatal(err)
	}
	if err := waitForStableLeader(ctx, candidates, candidateIDs, candidateIDs[0], initial.Epoch, 2*leaseConfig.LeaseDuration+leaseConfig.RenewInterval); err != nil {
		t.Fatal(err)
	}
	if got := guardPassCount(ctx, candidates, initial.Epoch); got != 1 {
		t.Fatalf("guards accepting epoch %d = %d, want exactly one", initial.Epoch, got)
	}

	const firstSubject = "lab.node-one.worker"
	firstPayload := []byte(`{"generation":1,"digest":"first"}`)
	firstSeq, err := candidates[0].CommitHostMutation(ctx, initial.Epoch, authority.MutationDesired, firstSubject, entityid.Derive("test-operation", "operation-first"), 0, firstPayload)
	if err != nil {
		t.Fatal("commit initial host journal entry:", err)
	}
	replayedSeq, err := candidates[0].CommitHostMutation(ctx, initial.Epoch, authority.MutationDesired, firstSubject, entityid.Derive("test-operation", "operation-first"), 0, firstPayload)
	if err != nil || replayedSeq != firstSeq {
		t.Fatalf("same operation replay returned seq=%d err=%v, original seq=%d", replayedSeq, err, firstSeq)
	}
	if _, err := candidates[0].ReadHostMutation(ctx, authority.MutationDesired, firstSubject); err != nil {
		t.Fatal("read committed host journal entry:", err)
	}

	// Losing the active controller stops renewal. A standby takes the lease at a
	// strictly newer epoch while the three NATS servers remain available.
	deadLeader := candidates[0]
	if err := deadLeader.Close(); err != nil {
		t.Fatal("stop first authority:", err)
	}
	if err := deadLeader.Guard(ctx, initial.Epoch); err == nil {
		t.Fatal("stopped authority candidate still passed its old guard")
	}
	candidates[0] = nil
	next, leaderIndex, err := waitForAnyLeader(ctx, candidates[1:], candidateIDs[1:], initial.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	leaderIndex++
	if next.Epoch <= initial.Epoch {
		t.Fatalf("authority epoch after controller death = %d, want > %d", next.Epoch, initial.Epoch)
	}
	if err := candidates[leaderIndex].Guard(ctx, initial.Epoch); err == nil {
		t.Fatal("standby accepted the expired authority epoch")
	}
	if _, err := candidates[leaderIndex].CommitHostMutation(ctx, initial.Epoch, authority.MutationDesired, "lab.node-two.worker", entityid.Derive("test-operation", "operation-stale"), 0, []byte(`{"generation":1}`)); err == nil {
		t.Fatal("stale authority epoch appended a mutation after takeover")
	}
	if got := guardPassCount(ctx, candidates, next.Epoch); got != 1 {
		t.Fatalf("guards accepting new epoch %d = %d, want exactly one", next.Epoch, got)
	}
	if _, err := candidates[leaderIndex].ReadHostMutation(ctx, authority.MutationDesired, firstSubject); err != nil {
		t.Fatal("authority handoff lost the committed journal entry:", err)
	}

	// Stop the actual RAFT leader for the authority stream, identified through
	// JetStream's StreamInfo. The remaining R3 members keep the journal writable;
	// if the active controller shared the failed cell, a standby takes over.
	failedPeer, err := cluster.controlStreamLeader(ctx)
	if err != nil {
		t.Fatal("read authority control stream leader:", err)
	}
	t.Logf("authority holder candidate index=%d; control stream leader peer index=%d", leaderIndex, failedPeer)
	for peer, node := range cluster.nodes {
		t.Logf("NATS peer %d client URL=%q servers=%v discovered=%v", peer, node.Conn().ConnectedUrl(), node.Conn().Servers(), node.Conn().DiscoveredServers())
	}
	priorStreamLeaderEpoch := next.Epoch
	peerCandidateRestarted := stopPeer(failedPeer)
	// JetStream leader election can outlast the current authority lease. Accept
	// the same epoch only after a live Guard succeeds; if the lease expired,
	// wait for the newer authority term and verify the old term is fenced.
	next, leaderIndex, err = waitForCurrentGuard(ctx, candidates, candidateIDs, priorStreamLeaderEpoch)
	if err != nil {
		if candidates[leaderIndex] != nil {
			logNATSFailoverState(t, cluster, failedPeer, candidates[leaderIndex])
		}
		t.Fatal("authority takeover after control stream leader failure:", err)
	}
	if next.Epoch < priorStreamLeaderEpoch {
		t.Fatalf("authority epoch after control stream leader failure = %d, want >= %d", next.Epoch, priorStreamLeaderEpoch)
	}
	if next.Epoch > priorStreamLeaderEpoch {
		if err := candidates[leaderIndex].Guard(ctx, priorStreamLeaderEpoch); err == nil {
			t.Fatalf("current authority accepted stale epoch %d after advancing to %d", priorStreamLeaderEpoch, next.Epoch)
		}
	}
	if got := guardPassCount(ctx, candidates, next.Epoch); got != 1 {
		t.Fatalf("guards accepting post-failover epoch %d = %d, want exactly one", next.Epoch, got)
	}
	survivorIndex := (failedPeer + 1) % regionalPeers
	stream, err := cluster.nodes[survivorIndex].JetStream().Stream(ctx, authority.ControlStreamName)
	if err != nil {
		t.Fatal("open control stream through surviving peer:", err)
	}
	streamInfo, err := stream.Info(ctx)
	if err != nil {
		t.Fatal("read control stream through surviving peer:", err)
	}
	t.Logf("surviving NATS peer %d reports control stream cluster=%+v", survivorIndex, streamInfo.Cluster)
	const survivingSubject = "lab.node-one.replacement"
	survivingSeq, err := candidates[leaderIndex].CommitHostMutation(ctx, next.Epoch, authority.MutationDesired, survivingSubject, entityid.Derive("test-operation", "operation-one-peer-down"), 0, []byte(`{"generation":2}`))
	if err != nil {
		t.Fatal("R3 mutation with one NATS peer down:", err)
	}
	if err := cluster.start(ctx, failedPeer); err != nil {
		t.Fatal("restart NATS peer:", err)
	}
	if err := cluster.waitForPeers(ctx); err != nil {
		t.Fatal("wait for recovered NATS cluster:", err)
	}
	if peerCandidateRestarted {
		startCandidate(failedPeer)
	}
	streamFailoverEpoch := next.Epoch
	next, leaderIndex, err = waitForCurrentGuard(ctx, candidates, candidateIDs, streamFailoverEpoch)
	if err != nil {
		t.Fatal("authority after control stream peer recovery:", err)
	}
	if next.Epoch < streamFailoverEpoch {
		t.Fatalf("authority epoch after control stream peer recovery = %d, want >= %d", next.Epoch, streamFailoverEpoch)
	}
	if next.Epoch > streamFailoverEpoch {
		if err := candidates[leaderIndex].Guard(ctx, streamFailoverEpoch); err == nil {
			t.Fatalf("authority accepted stale epoch %d after peer recovery advanced to %d", streamFailoverEpoch, next.Epoch)
		}
	}
	if err := waitForSharedLeader(ctx, candidates, candidateIDs, candidateIDs[leaderIndex], next.Epoch); err != nil {
		t.Fatal("authority after control stream peer recovery:", err)
	}
	if next.Epoch == streamFailoverEpoch {
		if seq, err := candidates[leaderIndex].CommitHostMutation(ctx, next.Epoch, authority.MutationDesired, survivingSubject, entityid.Derive("test-operation", "operation-one-peer-down"), 0, []byte(`{"generation":2}`)); err != nil || seq != survivingSeq {
			t.Fatalf("replayed mutation after broker recovery returned seq=%d err=%v, original seq=%d", seq, err, survivingSeq)
		}
	} else if _, err := candidates[leaderIndex].CommitHostMutation(ctx, streamFailoverEpoch, authority.MutationDesired, survivingSubject, entityid.Derive("test-operation", "operation-one-peer-down"), 0, []byte(`{"generation":2}`)); err == nil {
		t.Fatalf("stale authority epoch %d committed after recovery advanced to %d", streamFailoverEpoch, next.Epoch)
	}
	if _, err := candidates[leaderIndex].ReadHostMutation(ctx, authority.MutationDesired, firstSubject); err != nil {
		t.Fatal("broker recovery lost the pre-failure journal entry:", err)
	}
	survivingEntry, err := candidates[leaderIndex].ReadHostMutation(ctx, authority.MutationDesired, survivingSubject)
	if err != nil {
		t.Fatal("broker recovery lost the peer-down mutation:", err)
	}
	if survivingEntry.OperationID != entityid.Derive("test-operation", "operation-one-peer-down") || survivingEntry.Epoch != streamFailoverEpoch || string(survivingEntry.Payload) != `{"generation":2}` {
		t.Fatalf("peer-down journal entry changed after recovery: %+v", survivingEntry)
	}

	// Leave only the authority holder's broker alive. JetStream cannot commit a
	// replicated mutation without its R3 majority. Its bounded publish may have
	// an uncertain acknowledgement, so recovery checks the journal before issuing
	// a new operation under the current authority epoch.
	quorumRecoveryCandidates := make([]bool, regionalPeers)
	for peer := range regionalPeers {
		if peer == leaderIndex {
			continue
		}
		quorumRecoveryCandidates[peer] = stopPeer(peer)
	}
	partitionCtx, partitionCancel := context.WithTimeout(ctx, 2*time.Second)
	_, partitionErr := candidates[leaderIndex].CommitHostMutation(partitionCtx, next.Epoch, authority.MutationDesired, "lab.node-two.worker", entityid.Derive("test-operation", "operation-quorum-loss"), 0, []byte(`{"generation":3}`))
	partitionCancel()
	if partitionErr == nil {
		t.Fatal("R3 mutation succeeded with only one of three NATS peers running")
	}

	for peer := range regionalPeers {
		if peer == leaderIndex {
			continue
		}
		if err := cluster.start(ctx, peer); err != nil {
			t.Fatalf("restart NATS peer %d after quorum loss: %v", peer, err)
		}
	}
	if err := cluster.waitForPeers(ctx); err != nil {
		t.Fatal("wait for NATS quorum recovery:", err)
	}
	for peer, restartCandidate := range quorumRecoveryCandidates {
		if restartCandidate {
			startCandidate(peer)
		}
	}
	partitionEntry, partitionReadErr := candidates[leaderIndex].ReadHostMutation(ctx, authority.MutationDesired, "lab.node-two.worker")
	if partitionReadErr != nil && !errors.Is(partitionReadErr, authority.ErrNotFound) {
		t.Fatal("resolve quorum-loss journal outcome after recovery:", partitionReadErr)
	}
	if partitionReadErr == nil && (partitionEntry.OperationID != entityid.Derive("test-operation", "operation-quorum-loss") || partitionEntry.Epoch != next.Epoch || string(partitionEntry.Payload) != `{"generation":3}`) {
		t.Fatalf("quorum-loss request resolved to unexpected journal entry: %+v", partitionEntry)
	}
	recovered, recoveredIndex, err := waitForCurrentGuard(ctx, candidates, candidateIDs, next.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitForSharedLeader(ctx, candidates, candidateIDs, candidateIDs[recoveredIndex], recovered.Epoch); err != nil {
		t.Fatal("recovered candidates disagree on authority:", err)
	}
	if recovered.Epoch > next.Epoch {
		if err := candidates[recoveredIndex].Guard(ctx, next.Epoch); err == nil {
			t.Fatalf("authority accepted stale epoch %d after quorum recovery advanced to %d", next.Epoch, recovered.Epoch)
		}
	}
	if got, details := guardPassDetails(ctx, candidates, candidateIDs, recovered.Epoch); got != 1 {
		t.Fatalf("guards accepting recovered epoch %d = %d, want exactly one; results=%s", recovered.Epoch, got, strings.Join(details, "; "))
	}
	if seq, err := candidates[recoveredIndex].CommitHostMutation(ctx, recovered.Epoch, authority.MutationDesired, "lab.node-two.recovered", entityid.Derive("test-operation", "operation-quorum-recovery"), 0, []byte(`{"generation":4}`)); err != nil || seq == 0 {
		t.Fatalf("new authority mutation after quorum recovery returned seq=%d err=%v", seq, err)
	}
	if _, err := candidates[recoveredIndex].ReadHostMutation(ctx, authority.MutationDesired, firstSubject); err != nil {
		t.Fatal("quorum recovery lost the committed journal entry:", err)
	}
}

type regionalCluster struct {
	configs []natscell.Config
	nodes   []*natscell.Runtime
}

func newRegionalCluster(t *testing.T, ctx context.Context) *regionalCluster {
	t.Helper()
	ports := reservePorts(t, regionalPeers)
	routes := make([]string, regionalPeers)
	for i, port := range ports {
		routes[i] = "nats-route://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	}
	storeRoot := t.TempDir()
	cluster := &regionalCluster{configs: make([]natscell.Config, regionalPeers), nodes: make([]*natscell.Runtime, regionalPeers)}
	instances := []string{"one", "two", "three"}
	for i := range regionalPeers {
		cluster.configs[i] = natscell.Config{
			Cell: "lab", Instance: instances[i], Replicas: regionalPeers, Lab: true,
			Embedded: &natscell.Embedded{
				Host: "127.0.0.1", Port: -1, RouteHost: "127.0.0.1", RoutePort: ports[i],
				Routes: natscell.PeerRoutes(routes, routes[i]), StoreDir: filepath.Join(storeRoot, fmt.Sprintf("node-%d", i)),
			},
		}
	}
	t.Cleanup(func() {
		for _, node := range cluster.nodes {
			_ = node.Close()
		}
	})
	return cluster
}

func reservePorts(t *testing.T, count int) []int {
	t.Helper()
	ports := make([]int, count)
	for i := range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			_ = listener.Close()
			t.Fatalf("listener address has type %T, want *net.TCPAddr", listener.Addr())
		}
		ports[i] = addr.Port
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return ports
}

func (c *regionalCluster) startAll(ctx context.Context) error {
	for i := range regionalPeers {
		if err := c.start(ctx, i); err != nil {
			return fmt.Errorf("start NATS peer %d: %w", i, err)
		}
	}
	return nil
}

func (c *regionalCluster) start(ctx context.Context, index int) error {
	if c.nodes[index] != nil {
		return fmt.Errorf("NATS peer %d is already running", index)
	}
	runtime, err := natscell.Start(ctx, c.configs[index])
	if err != nil {
		return err
	}
	c.nodes[index] = runtime
	return nil
}

func (c *regionalCluster) stop(index int) error {
	node := c.nodes[index]
	if node == nil {
		return fmt.Errorf("NATS peer %d is not running", index)
	}
	c.nodes[index] = nil
	return node.Close()
}

func (c *regionalCluster) controlStreamLeader(ctx context.Context) (int, error) {
	stream, err := c.nodes[0].JetStream().Stream(ctx, authority.ControlStreamName)
	if err != nil {
		return -1, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return -1, err
	}
	// StreamInfo.Cluster.Replicas excludes the responding server, which is the
	// stream leader for this API response. An R3 stream therefore reports its
	// leader separately and the other two peers in Replicas.
	if info.Cluster == nil || info.Cluster.Leader == "" || len(info.Cluster.Replicas) != regionalPeers-1 || info.Config.Replicas != regionalPeers {
		return -1, fmt.Errorf("control stream is not an R3 group: cluster=%+v replicas=%d", info.Cluster, info.Config.Replicas)
	}
	leaderIndex := slices.IndexFunc(c.configs, func(cfg natscell.Config) bool {
		return info.Cluster.Leader == cfg.Cell+"-"+cfg.Instance
	})
	if leaderIndex < 0 {
		return -1, fmt.Errorf("control stream leader %q is not one of the embedded peers", info.Cluster.Leader)
	}
	peerNames := make(map[string]bool, regionalPeers-1)
	for i, cfg := range c.configs {
		if i != leaderIndex {
			peerNames[cfg.Cell+"-"+cfg.Instance] = true
		}
	}
	for _, replica := range info.Cluster.Replicas {
		if replica == nil || !peerNames[replica.Name] {
			return -1, fmt.Errorf("control stream has unexpected or duplicate replica %+v", replica)
		}
		delete(peerNames, replica.Name)
	}
	if len(peerNames) != 0 {
		return -1, fmt.Errorf("control stream replicas do not cover every non-leader peer: remaining=%v", peerNames)
	}
	return leaderIndex, nil
}

func (c *regionalCluster) waitForPeers(ctx context.Context) error {
	for i, node := range c.nodes {
		if node == nil {
			return fmt.Errorf("NATS peer %d is not running", i)
		}
		if err := node.WaitForCluster(ctx, regionalPeers); err != nil {
			return fmt.Errorf("wait for NATS peer %d: %w", i, err)
		}
	}
	return nil
}

func logNATSFailoverState(t *testing.T, cluster *regionalCluster, failedPeer int, candidate *authority.Runtime) {
	t.Helper()
	retainedCtx, retainedCancel := context.WithTimeout(t.Context(), 2*time.Second)
	_, retainedErr := candidate.ReadHostMutation(retainedCtx, authority.MutationDesired, "lab.node-one.worker")
	retainedCancel()
	t.Logf("authority candidate retained stream read error=%v", retainedErr)
	for peer, node := range cluster.nodes {
		if node == nil || peer == failedPeer {
			continue
		}
		conn := node.Conn()
		accountCtx, accountCancel := context.WithTimeout(t.Context(), time.Second)
		_, accountErr := node.JetStream().AccountInfo(accountCtx)
		accountCancel()

		streamCtx, streamCancel := context.WithTimeout(t.Context(), time.Second)
		stream, streamErr := node.JetStream().Stream(streamCtx, authority.ControlStreamName)
		streamCancel()
		var clusterInfo any
		var infoErr error
		if streamErr == nil {
			infoCtx, infoCancel := context.WithTimeout(t.Context(), time.Second)
			info, err := stream.Info(infoCtx)
			infoCancel()
			infoErr = err
			if err == nil {
				clusterInfo = info.Cluster
			}
		}
		var directSequence uint64
		var directErr error
		if streamErr == nil {
			directCtx, directCancel := context.WithTimeout(t.Context(), 2*time.Second)
			msg, err := stream.GetLastMsgForSubject(directCtx, "ts.control.r3-integration.lease")
			directCancel()
			directErr = err
			if msg != nil {
				directSequence = msg.Sequence
			}
		}
		rawMsg, rawErr := conn.Request("$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG", []byte(`{"last_by_subj":"ts.control.r3-integration.lease"}`), 2*time.Second)
		var rawResponse string
		if rawMsg != nil {
			rawResponse = string(rawMsg.Data)
		}
		t.Logf("survivor peer=%d status=%v URL=%q servers=%v discovered=%v accountErr=%v streamErr=%v streamInfo=%+v infoErr=%v directSeq=%d directErr=%v rawGetErr=%v rawGetResponse=%s",
			peer, conn.Status(), conn.ConnectedUrl(), conn.Servers(), conn.DiscoveredServers(), accountErr, streamErr, clusterInfo, infoErr, directSequence, directErr, rawErr, rawResponse)
	}
}

func waitForLeader(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, index int) (authority.Snapshot, error) {
	deadline := time.NewTicker(50 * time.Millisecond)
	defer deadline.Stop()
	for {
		snapshot := candidates[index].Current()
		if snapshot.Ready && snapshot.Leader && snapshot.CandidateID == candidateIDs[index] && snapshot.Epoch > 0 {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return authority.Snapshot{}, fmt.Errorf("wait for authority %s: %w (last snapshot: %+v)", candidateIDs[index], ctx.Err(), snapshot)
		case <-deadline.C:
		}
	}
}

func waitForSharedLeader(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, leader string, epoch uint64) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		allMatch := true
		snapshots := make([]authority.Snapshot, len(candidates))
		for i, candidate := range candidates {
			if candidate == nil {
				continue
			}
			snapshot := candidate.Current()
			snapshots[i] = snapshot
			if !snapshot.Ready || snapshot.CandidateID != leader || snapshot.Epoch != epoch || snapshot.Leader != (candidateIDs[i] == leader) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for all authority candidates to see leader %s at epoch %d: %w (snapshots: %+v)", leader, epoch, ctx.Err(), snapshots)
		case <-ticker.C:
		}
	}
}

func waitForStableLeader(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, leader string, epoch uint64, duration time.Duration) error {
	leaderIndex := slices.Index(candidateIDs, leader)
	if leaderIndex < 0 || candidates[leaderIndex] == nil {
		return fmt.Errorf("authority leader %s has no active runtime", leader)
	}
	started := time.Now()
	attempt := 0
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		leaderSnapshot := candidates[leaderIndex].Current()
		if !leaderSnapshot.Ready || !leaderSnapshot.Leader || leaderSnapshot.CandidateID != leader || leaderSnapshot.Epoch != epoch {
			return fmt.Errorf("leader changed during renewal window: snapshot=%+v", leaderSnapshot)
		}
		operationID := entityid.Derive("test-operation", leader, fmt.Sprint(attempt))
		payload := []byte(fmt.Sprintf(`{"probe":%d}`, attempt))
		leaderSubject := fmt.Sprintf("lab.%s.probe-%02d", leader, attempt)
		if _, err := candidates[leaderIndex].CommitHostMutation(ctx, epoch, authority.MutationDesired, leaderSubject, operationID, 0, payload); err != nil {
			return fmt.Errorf("leader %s could not append a journal mutation during renewal window: %w", leader, err)
		}
		for i, candidate := range candidates {
			if i == leaderIndex {
				continue
			}
			snapshot := candidate.Current()
			standbySubject := fmt.Sprintf("lab.%s.probe-%02d", candidateIDs[i], attempt)
			standbyOperation := entityid.Derive("test-operation", candidateIDs[i], fmt.Sprint(attempt))
			if _, err := candidate.CommitHostMutation(ctx, epoch, authority.MutationDesired, standbySubject, standbyOperation, 0, payload); err == nil {
				return fmt.Errorf("standby %s appended a journal mutation during renewal window; snapshot=%+v", candidateIDs[i], snapshot)
			}
		}
		if time.Since(started) >= duration {
			return nil
		}
		attempt++
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for authority renewal over %s: %w", duration, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForAnyLeader(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, afterEpoch uint64) (authority.Snapshot, int, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		for i, candidate := range candidates {
			if candidate == nil {
				continue
			}
			snapshot := candidate.Current()
			if snapshot.Ready && snapshot.Leader && snapshot.CandidateID == candidateIDs[i] && snapshot.Epoch > afterEpoch {
				return snapshot, i, nil
			}
		}
		select {
		case <-ctx.Done():
			return authority.Snapshot{}, -1, fmt.Errorf("wait for authority takeover after epoch %d: %w", afterEpoch, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForCurrentGuard(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, minimumEpoch uint64) (authority.Snapshot, int, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastDetails []string
	for {
		lastDetails = lastDetails[:0]
		for i, candidate := range candidates {
			if candidate == nil {
				lastDetails = append(lastDetails, fmt.Sprintf("%s unavailable", candidateIDs[i]))
				continue
			}
			snapshot := candidate.Current()
			if !snapshot.Ready || !snapshot.Leader || snapshot.CandidateID != candidateIDs[i] || snapshot.Epoch < minimumEpoch {
				lastDetails = append(lastDetails, fmt.Sprintf("%s snapshot=%+v (not a current leader at epoch >= %d)", candidateIDs[i], snapshot, minimumEpoch))
				continue
			}
			guardCtx, cancel := context.WithTimeout(ctx, time.Second)
			err := candidate.Guard(guardCtx, snapshot.Epoch)
			cancel()
			if err == nil {
				return snapshot, i, nil
			}
			lastDetails = append(lastDetails, fmt.Sprintf("%s snapshot=%+v guard error=%v", candidateIDs[i], snapshot, err))
		}
		select {
		case <-ctx.Done():
			return authority.Snapshot{}, -1, fmt.Errorf("wait for a Guard-confirmed authority at epoch >= %d: %w (candidates: %s)", minimumEpoch, ctx.Err(), strings.Join(lastDetails, "; "))
		case <-ticker.C:
		}
	}
}

func guardPassCount(ctx context.Context, candidates []*authority.Runtime, epoch uint64) int {
	passed := 0
	for _, candidate := range candidates {
		if candidate != nil && guardWithRetry(ctx, candidate, epoch) == nil {
			passed++
		}
	}
	return passed
}

func guardPassDetails(ctx context.Context, candidates []*authority.Runtime, candidateIDs []string, epoch uint64) (int, []string) {
	passed := 0
	details := make([]string, 0, len(candidates))
	for i, candidate := range candidates {
		if candidate == nil {
			details = append(details, fmt.Sprintf("%s unavailable", candidateIDs[i]))
			continue
		}
		guardCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := candidate.Guard(guardCtx, epoch)
		cancel()
		if err == nil {
			passed++
		}
		details = append(details, fmt.Sprintf("%s snapshot=%+v guard error=%v", candidateIDs[i], candidate.Current(), err))
	}
	return passed, details
}

func guardWithRetry(ctx context.Context, candidate *authority.Runtime, epoch uint64) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := candidate.Guard(ctx, epoch)
		if err == nil || !errors.Is(err, authority.ErrConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry authority guard: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
