package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/vaultrecords"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type metaFleet struct {
	root     string
	regions  []string
	cfgs     map[string]config
	nodes    map[string]*Node
	records  *vaultrecords.Store
	restarts chan string
}

func freePorts(count int) ([]int, error) {
	ports := make([]int, 0, count)
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func newMetaFleet(root string) (*metaFleet, error) {
	regions := Regions("gru")
	ports, err := freePorts(4 * len(regions))
	if err != nil {
		return nil, err
	}
	ca, err := DeriveCA([]byte(strings.Repeat("m", 32)))
	if err != nil {
		return nil, err
	}
	records, err := vaultrecords.New(filepath.Join(root, "vault"))
	if err != nil {
		return nil, err
	}
	fleet := &metaFleet{root: root, regions: regions, cfgs: map[string]config{}, nodes: map[string]*Node{}, records: records, restarts: make(chan string, len(regions))}
	for i, region := range regions {
		if err := PublishSeeds(context.Background(), fleet.records, region, "cluster-"+region, []string{"ts-" + region + "-99"}); err != nil {
			return nil, err
		}
		seeds := map[string][]string{}
		for j, peer := range regions {
			if peer != region {
				seeds[peer] = []string{fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+1]), fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+2]), fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+3])}
			}
		}
		address := fmt.Sprintf("127.0.0.%d", 10+i)
		fleet.cfgs[region] = config{region: region, server: region + "-founder", nodeID: strings.Repeat(string(rune('a'+i)), 25), founder: true,
			cluster: "cluster-" + region, records: fleet.records, restart: func() { fleet.restarts <- region },
			dir: filepath.Join(root, region), ca: ca, terrabaseToken: strings.Repeat("t", 32),
			clusterHost: "127.0.0.1", clusterPort: ports[4*i+1], clusterAdvertise: fmt.Sprintf("127.0.0.1:%d", ports[4*i+1]), localPort: ports[4*i],
			seeds: seeds, applier: swarmApplier{state: filepath.Join(root, region+"-swarm"), region: region}, every: time.Second, peersEvery: 250 * time.Millisecond,
			peersDir: filepath.Join(root, region+"-files"), address: func() (string, error) { return address, nil }}
	}
	return fleet, nil
}

func (f *metaFleet) start(regions ...string) error {
	type started struct {
		region string
		node   *Node
		err    error
	}
	results := make(chan started, len(regions))
	for _, region := range regions {
		go func() {
			node, err := start(f.cfgs[region])
			results <- started{region, node, err}
		}()
	}
	var errs error
	for range regions {
		result := <-results
		if result.err != nil {
			errs = errors.Join(errs, fmt.Errorf("start %s: %w", result.region, result.err))
			continue
		}
		f.nodes[result.region] = result.node
	}
	return errs
}

func (f *metaFleet) stop(regions ...string) {
	for _, region := range regions {
		if node := f.nodes[region]; node != nil {
			stopNode(node)
			delete(f.nodes, region)
		}
	}
}

func metaOf(node *Node) server.RaftzGroup {
	account := node.server.SystemAccount().Name
	status := node.server.Raftz(&server.RaftzOptions{AccountFilter: account, GroupFilter: metaGroup})
	if status == nil {
		return server.RaftzGroup{}
	}
	return (*status)[account][metaGroup]
}

func (f *metaFleet) converged(regions []string) (string, error) {
	leader, known := "", -1
	for _, region := range regions {
		node := f.nodes[region]
		if node == nil {
			return "", fmt.Errorf("%s is not running", region)
		}
		group := metaOf(node)
		if group.Leader == "" || group.Observer || group.Size != len(f.regions) {
			return "", fmt.Errorf("%s: leader %q observer %v size %d", region, group.Leader, group.Observer, group.Size)
		}
		if leader != "" && group.Leader != leader {
			return "", fmt.Errorf("%s follows %s, another member follows %s", region, group.Leader, leader)
		}
		leader = group.Leader
		if group.ID == group.Leader {
			known = 0
			for _, peer := range group.Peers {
				if peer.Known {
					known++
				}
			}
		}
	}
	if known != len(regions)-1 {
		return "", fmt.Errorf("leader %s knows %d metadata peers, want %d", leader, known, len(regions)-1)
	}
	return leader, nil
}

func (f *metaFleet) await(ctx context.Context, what string, regions []string) (string, error) {
	var leader string
	var last error
	err := regionalAwait(ctx, func() bool {
		leader, last = f.converged(regions)
		return last == nil
	})
	if err != nil {
		return "", fmt.Errorf("%s: %w (%v)", what, err, last)
	}
	return leader, nil
}

func (f *metaFleet) leaders() map[string]int {
	leaders := map[string]int{}
	for _, node := range f.nodes {
		if group := metaOf(node); group.Leader == group.ID && group.Leader != "" {
			leaders[group.ID]++
		}
	}
	return leaders
}

func (f *metaFleet) kv(ctx context.Context, region string) (nats.KeyValue, error) {
	node := f.nodes[region]
	var health error
	if err := regionalAwait(ctx, func() bool { health = node.lifecycle.Health(ctx); return health == nil }); err != nil {
		return nil, fmt.Errorf("%s health: %w (%v)", region, err, health)
	}
	js, err := node.fabric.JetStream(nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	if kv, err := js.KeyValue("meta-journey"); err == nil {
		return kv, nil
	}
	return js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "meta-journey", Replicas: len(f.regions)})
}

func MetaBootJourney(root string) error {
	began := time.Now()
	defer func() { fmt.Printf("metadata boot lane elapsed: %s\n", time.Since(began).Round(time.Millisecond)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp(root, "meta-boot-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	fleet, err := newMetaFleet(root)
	if err != nil {
		return err
	}
	defer fleet.stop(fleet.regions...)
	regions := fleet.regions
	alone, rest := regions[len(regions)-1], regions[:len(regions)-1]

	if err := fleet.records.Create(ctx, FounderRecord, encodeRecord(founding{Region: rest[0], Cluster: "cluster-of-a-wiped-cell", Formed: true})); err != nil {
		return err
	}
	if err := fleet.start(rest...); err != nil {
		return err
	}
	var founder string
	select {
	case founder = <-fleet.restarts:
	case <-ctx.Done():
		return fmt.Errorf("a founder record left by a wiped cell was never replaced: %+v", metaOf(fleet.nodes[rest[0]]))
	}
	if record, _, err := readFounding(ctx, fleet.records); err != nil || record != (founding{Region: founder, Cluster: "cluster-" + founder}) {
		return fmt.Errorf("founder record after %s replaced it: %+v, %v", founder, record, err)
	}
	fleet.stop(founder)
	if err := fleet.start(founder); err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool {
		group := metaOf(fleet.nodes[founder])
		return group.Leader == group.ID && group.Leader != ""
	}); err != nil {
		return fmt.Errorf("%s never led the metadata group it claimed: %w (%+v)", founder, err, metaOf(fleet.nodes[founder]))
	}
	select {
	case again := <-fleet.restarts:
		return fmt.Errorf("%s also restarted to found a group after %s claimed the record", again, founder)
	default:
	}
	fmt.Println("ok metadata: a founder record left by a wiped cell is replaced by one compare-and-swap while no server holds metadata;", founder, "restarts and forms the group alone")

	if err := fleet.start(alone); err != nil {
		return err
	}
	leader, err := fleet.await(ctx, "every founder joins the claimed founder's group", regions)
	if err != nil {
		return err
	}
	if count := fleet.leaders(); len(count) != 1 {
		return fmt.Errorf("metadata leaders after first election: %v", count)
	}
	if record, _, err := readFounding(ctx, fleet.records); err != nil || record != (founding{Region: founder, Cluster: "cluster-" + founder, Formed: true}) {
		return fmt.Errorf("founder record after the group formed: %+v, %v", record, err)
	}
	kv, err := fleet.kv(ctx, alone)
	if err != nil {
		return fmt.Errorf("R%d KV after health: %w", len(regions), err)
	}
	if _, err := kv.Put("fleet", []byte("first")); err != nil {
		return err
	}
	fmt.Println("ok metadata: the other founders joined", leader, "for", len(regions), "peers, none replaced the live founder record; health admitted an R3 KV")

	fleet.stop(regions...)
	if err := fleet.start(regions...); err != nil {
		return err
	}
	leader, err = fleet.await(ctx, "every founder restarted together", regions)
	if err != nil {
		return err
	}
	if count := fleet.leaders(); len(count) != 1 {
		return fmt.Errorf("metadata leaders after full restart: %v", count)
	}
	if kv, err = fleet.kv(ctx, regions[0]); err != nil {
		return err
	}
	if entry, err := kv.Get("fleet"); err != nil || string(entry.Value()) != "first" {
		return fmt.Errorf("KV after full restart: %v", err)
	}
	fmt.Println("ok metadata: full-fleet cold restart re-elected", leader, "with the same group and data")
	if err := managerRestartJourney(ctx, fleet); err != nil {
		return err
	}

	fleet.stop(founder)
	if err := os.RemoveAll(fleet.cfgs[founder].dir); err != nil {
		return err
	}
	if err := fleet.start(founder); err != nil {
		return err
	}
	if _, err := fleet.await(ctx, "a founder with an empty log rejoins a reachable group", regions); err != nil {
		return err
	}
	if count := fleet.leaders(); len(count) != 1 {
		return fmt.Errorf("metadata leaders after empty rejoin: %v", count)
	}
	if kv, err = fleet.kv(ctx, founder); err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool {
		js, err := fleet.nodes[founder].fabric.JetStream()
		if err != nil {
			return false
		}
		info, err := js.StreamInfo("KV_meta-journey")
		return err == nil && info.Cluster != nil && len(info.Cluster.Replicas) == len(regions)-1 && !slices.ContainsFunc(info.Cluster.Replicas, func(peer *nats.PeerInfo) bool { return !peer.Current })
	}); err != nil {
		return fmt.Errorf("stream replicas after empty rejoin: %w", err)
	}
	fmt.Println("ok metadata: the founder the record names, with an empty log, joined the existing group instead of forming a second one")

	spec := &swarmruntime.ServiceSpec{Name: "terrabase", Regions: []string{"gru", "sjc", "fra"}}
	generation := time.Now().UnixNano()
	rule := EnvironmentOf("gru").Rollout
	turnWithin := func(region string, wait time.Duration) error {
		turnCtx, stop := context.WithTimeout(ctx, wait)
		defer stop()
		return fleet.nodes[region].awaitTurn(turnCtx, "terrabase", spec, generation)
	}
	decision := func(region string) AdmissionDecision {
		node := fleet.nodes[region]
		node.admissionMu.Lock()
		defer node.admissionMu.Unlock()
		return node.admission["terrabase"]
	}
	if err := turnWithin("sjc", 10*time.Second); err != nil {
		return fmt.Errorf("sjc, first in the order, was not admitted with every founder on it: %w", err)
	}
	for _, region := range []string{"fra", "gru"} {
		if err := turnWithin(region, 3*time.Second); err == nil || decision(region).Earlier != "sjc" {
			return fmt.Errorf("%s was admitted before sjc passed generation %d: %v, %+v", region, generation, err, decision(region))
		}
	}
	fmt.Println("ok order: a spec stored as gru, sjc, fra admits sjc first; fra and gru wait for sjc's verdict")

	fleet.stop("sjc", "fra")
	var stagedMu sync.Mutex
	staged := map[string]stateReply{}
	stage := func(region string, rollout []string, passed bool) {
		reply := stateReply{Region: region, Desired: map[string]desiredState{}, Ready: map[string]int64{}, Rollout: rollout}
		if passed {
			reply.Ready["terrabase"] = generation
		}
		stagedMu.Lock()
		staged[region] = reply
		stagedMu.Unlock()
	}
	responder, err := fleet.nodes["gru"].conn.Subscribe(StateSubject, func(m *nats.Msg) {
		var request struct {
			Nonce string `json:"nonce"`
			View  string `json:"view"`
		}
		if protocol.DecodeTolerant(m.Data, &request, maxWire) != nil || request.View != "" {
			return
		}
		stagedMu.Lock()
		replies := []stateReply{}
		for _, reply := range staged {
			replies = append(replies, reply)
		}
		stagedMu.Unlock()
		for _, reply := range replies {
			reply.Nonce = request.Nonce
			if reply.Ready["terrabase"] == generation {
				reply.Serving = map[string]ServingResult{"terrabase": {Generation: generation, Serving: true, At: time.Now()}}
			}
			if data, err := protocol.EncodeJSON(reply); err == nil {
				_ = m.Respond(data)
			}
		}
	})
	if err != nil {
		return err
	}
	defer responder.Unsubscribe()
	stage("sjc", rule, true)
	stage("fra", nil, false)
	admitted := make(chan error, 1)
	go func() { admitted <- turnWithin("gru", time.Minute) }()
	waitFor := func(evidence string) error {
		return regionalAwait(ctx, func() bool {
			got := decision("gru")
			return got.Generation == generation && got.Earlier == "fra" && got.Evidence == evidence
		})
	}
	if err := waitFor("rollout order not agreed"); err != nil {
		return fmt.Errorf("gru did not wait for fra advertising no rollout order: %w, %+v", err, decision("gru"))
	}
	stage("fra", rule, false)
	if err := waitFor("fresh serving evidence missing"); err != nil {
		return fmt.Errorf("gru did not wait for fra's verdict once fra agreed on the order: %w, %+v", err, decision("gru"))
	}
	stage("fra", rule, true)
	select {
	case err := <-admitted:
		if err != nil || decision("gru").Evidence != "admitted" {
			return fmt.Errorf("gru was not admitted once sjc and fra passed: %v, %+v", err, decision("gru"))
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	fmt.Println("ok order: one generation through the real admission path: gru waited while fra advertised no rollout order, then for fra's verdict, and admitted itself once sjc and fra passed")
	return nil
}

const (
	leaseBucket  = "journey-leases"
	leaseLapse   = 2500 * time.Millisecond
	journeyDrain = 2 * time.Second
)

type leaseAck struct {
	at     time.Time
	server string
}

type leaseWrites struct {
	mu   sync.Mutex
	acks []leaseAck
}

func (w *leaseWrites) first(match func(leaseAck) bool) (leaseAck, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	index := slices.IndexFunc(w.acks, match)
	if index < 0 {
		return leaseAck{}, false
	}
	return w.acks[index], true
}

func (w *leaseWrites) lastBefore(at time.Time) (leaseAck, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	index := slices.IndexFunc(w.acks, func(ack leaseAck) bool { return !ack.at.Before(at) })
	if index == 0 || len(w.acks) == 0 {
		return leaseAck{}, false
	}
	if index < 0 {
		index = len(w.acks)
	}
	return w.acks[index-1], true
}

func (w *leaseWrites) widest(from, to time.Time) (time.Duration, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	last, widest, count := from, time.Duration(0), 0
	for _, ack := range w.acks {
		if ack.at.Before(from) || ack.at.After(to) {
			continue
		}
		widest, last, count = max(widest, ack.at.Sub(last)), ack.at, count+1
	}
	return widest, count
}

func holdLease(ctx context.Context, cfg config, writes *leaseWrites) error {
	conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", cfg.localPort), nats.Token(cfg.terrabaseToken), nats.Name("journey-lease-"+cfg.region),
		nats.IgnoreDiscoveredServers(), nats.MaxReconnects(-1), nats.ReconnectWait(100*time.Millisecond))
	if err != nil {
		return err
	}
	js, err := conn.JetStream(nats.MaxWait(500 * time.Millisecond))
	if err != nil {
		conn.Close()
		return err
	}
	kv, err := js.KeyValue(leaseBucket)
	if err != nil {
		conn.Close()
		return err
	}
	go func() {
		defer conn.Close()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := kv.Put("home."+cfg.region, []byte(time.Now().Format(time.RFC3339Nano))); err == nil {
				ack := leaseAck{at: time.Now(), server: conn.ConnectedServerId()}
				writes.mu.Lock()
				writes.acks = append(writes.acks, ack)
				writes.mu.Unlock()
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return nil
}

func managerRestartJourney(ctx context.Context, fleet *metaFleet) error {
	regions := fleet.regions
	js, err := fleet.nodes[regions[0]].fabric.JetStream(nats.Context(ctx))
	if err != nil {
		return err
	}
	if _, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: leaseBucket, Replicas: len(regions), TTL: 10 * time.Second}); err != nil {
		return fmt.Errorf("lease bucket: %w", err)
	}
	writing, stopWriting := context.WithCancel(ctx)
	defer stopWriting()
	holders := map[string]*leaseWrites{}
	for _, region := range regions {
		holders[region] = &leaseWrites{}
		if err := holdLease(writing, fleet.cfgs[region], holders[region]); err != nil {
			return fmt.Errorf("%s lease holder: %w", region, err)
		}
	}
	anyAck := func(leaseAck) bool { return true }
	if err := regionalAwait(ctx, func() bool {
		return !slices.ContainsFunc(regions, func(region string) bool { _, ok := holders[region].first(anyAck); return !ok })
	}); err != nil {
		return fmt.Errorf("every region renews its lease: %w", err)
	}
	for _, region := range regions {
		var health error
		if err := regionalAwait(ctx, func() bool { health = fleet.nodes[region].lifecycle.Health(ctx); return health == nil }); err != nil {
			return fmt.Errorf("%s health before the manager restart: %w (%v)", region, err, health)
		}
	}
	info, err := js.StreamInfo("KV_" + leaseBucket)
	if err != nil || info.Cluster == nil || !slices.Contains(regions, info.Cluster.Leader) {
		return fmt.Errorf("lease bucket leader: %v", err)
	}
	restarting := info.Cluster.Leader
	stopping := fleet.nodes[restarting]
	retired := stopping.server.ID()
	began := time.Now()
	if err := stopping.PrepareStop(ctx); err != nil {
		groups, _ := json.Marshal(stopping.server.Raftz(&server.RaftzOptions{AccountFilter: FabricAccount}))
		return fmt.Errorf("planned stop of the %s manager: %w; its Raft groups: %s", restarting, err, groups)
	}
	budget, finish := plannedstop.WithBudget(ctx)
	defer finish()
	drained, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		stopping.closeAfterDrain(budget, drained)
	}()
	draining := time.Now()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(journeyDrain):
	}
	shutdown := time.Now()
	close(drained)
	<-closed
	delete(fleet.nodes, restarting)
	if err := fleet.start(restarting); err != nil {
		return err
	}
	replacement := fleet.nodes[restarting].server.ID()
	if _, err := fleet.await(ctx, "the restarted manager rejoins", regions); err != nil {
		return err
	}
	rejoined := time.Now()
	fresh := map[string]func(leaseAck) bool{}
	for _, region := range regions {
		fresh[region] = func(ack leaseAck) bool { return ack.at.After(rejoined) }
	}
	fresh[restarting] = func(ack leaseAck) bool { return ack.server == replacement }
	if err := regionalAwait(ctx, func() bool {
		return !slices.ContainsFunc(regions, func(region string) bool { _, ok := holders[region].first(fresh[region]); return !ok })
	}); err != nil {
		return fmt.Errorf("every region renews through the rejoined fleet, %s through its replacement server: %w", restarting, err)
	}
	stopWriting()
	if _, ok := holders[restarting].first(func(ack leaseAck) bool {
		return ack.server == retired && ack.at.After(draining.Add(journeyDrain/2)) && ack.at.Before(shutdown)
	}); !ok {
		return fmt.Errorf("the %s lease was not renewed through its own manager while that manager drained", restarting)
	}
	var gaps []string
	for _, region := range regions {
		from, ok := holders[region].lastBefore(began)
		if !ok {
			return fmt.Errorf("%s has no renewal before the handoff", region)
		}
		to, _ := holders[region].first(fresh[region])
		widest, count := holders[region].widest(from.at, to.at)
		if widest >= leaseLapse {
			return fmt.Errorf("the %s lease lapsed %s while the %s manager handed off, drained, restarted and rejoined", region, widest, restarting)
		}
		gaps = append(gaps, fmt.Sprintf("%s=%s over %s (%d renewals)", region, widest.Round(time.Millisecond), to.at.Sub(from.at).Round(time.Millisecond), count))
	}
	fmt.Printf("ok manager restart: every region renewed the R3 lease bucket from its last renewal before the %s handoff to a fresh one after the rejoin, %s through its draining manager and then its replacement; widest gaps: %s\n",
		restarting, restarting, strings.Join(gaps, ", "))
	return nil
}
