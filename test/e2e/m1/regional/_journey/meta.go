package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type metaFleet struct {
	root    string
	regions []string
	cfgs    map[string]config
	nodes   map[string]*Node
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
	regions := Regions()
	ports, err := freePorts(4 * len(regions))
	if err != nil {
		return nil, err
	}
	ca, err := DeriveCA([]byte(strings.Repeat("m", 32)))
	if err != nil {
		return nil, err
	}
	fleet := &metaFleet{root: root, regions: regions, cfgs: map[string]config{}, nodes: map[string]*Node{}}
	for i, region := range regions {
		seeds := map[string][]string{}
		for j, peer := range regions {
			if peer != region {
				seeds[peer] = []string{fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+1]), fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+2]), fmt.Sprintf("nats://127.0.0.1:%d", ports[4*j+3])}
			}
		}
		address := fmt.Sprintf("127.0.0.%d", 10+i)
		fleet.cfgs[region] = config{region: region, server: region + "-founder", nodeID: strings.Repeat(string(rune('a'+i)), 25), founder: true,
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

	if err := fleet.start(alone); err != nil {
		return err
	}
	window, closeWindow := context.WithTimeout(ctx, 3*time.Second)
	defer closeWindow()
	if err := regionalAwait(window, func() bool { group := metaOf(fleet.nodes[alone]); return group.Leader != "" || !group.Observer }); err == nil {
		return fmt.Errorf("a lone founder left observer mode or found a leader: %+v", metaOf(fleet.nodes[alone]))
	}
	fleet.stop(alone)
	fmt.Println("ok metadata: a lone fresh founder waits in observer mode and is stopped before any group exists")

	if err := fleet.start(rest...); err != nil {
		return err
	}
	if err := fleet.start(alone); err != nil {
		return err
	}
	leader, err := fleet.await(ctx, "a brand-new fleet with three seeds per region, one founder stopped before any leader", regions)
	if err != nil {
		return err
	}
	if count := fleet.leaders(); len(count) != 1 {
		return fmt.Errorf("metadata leaders after first election: %v", count)
	}
	kv, err := fleet.kv(ctx, alone)
	if err != nil {
		return fmt.Errorf("R%d KV after health: %w", len(regions), err)
	}
	if _, err := kv.Put("fleet", []byte("first")); err != nil {
		return err
	}
	fmt.Println("ok metadata: brand-new fleet with production seeds elected", leader, "with", len(regions), "peers; health admitted an R3 KV")

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

	fleet.stop(alone)
	if err := os.RemoveAll(fleet.cfgs[alone].dir); err != nil {
		return err
	}
	if err := fleet.start(alone); err != nil {
		return err
	}
	if _, err := fleet.await(ctx, "a founder with an empty log rejoins a reachable group", regions); err != nil {
		return err
	}
	if count := fleet.leaders(); len(count) != 1 {
		return fmt.Errorf("metadata leaders after empty rejoin: %v", count)
	}
	if kv, err = fleet.kv(ctx, alone); err != nil {
		return err
	}
	if err := regionalAwait(ctx, func() bool {
		js, err := fleet.nodes[alone].fabric.JetStream()
		if err != nil {
			return false
		}
		info, err := js.StreamInfo("KV_meta-journey")
		return err == nil && info.Cluster != nil && len(info.Cluster.Replicas) == len(regions)-1 && !slices.ContainsFunc(info.Cluster.Replicas, func(peer *nats.PeerInfo) bool { return !peer.Current })
	}); err != nil {
		return fmt.Errorf("stream replicas after empty rejoin: %w", err)
	}
	fmt.Println("ok metadata: a founder with an empty log joined the existing group instead of forming one")
	return nil
}
