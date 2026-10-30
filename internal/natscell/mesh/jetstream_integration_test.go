package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
)

const worstRegionRTT = 184 * time.Millisecond

type delayedChunk struct {
	data []byte
	due  time.Time
}

type latencyProxy struct {
	addr     string
	mu       sync.Mutex
	open     map[net.Conn]struct{}
	refusing bool
}

func startLatencyProxy(t *testing.T, target string, rtt time.Duration) *latencyProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &latencyProxy{addr: listener.Addr().String(), open: map[net.Conn]struct{}{}}
	var conns sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		proxy.sever(true)
		proxy.mu.Lock()
		proxy.open = nil
		proxy.mu.Unlock()
		conns.Wait()
	})
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", target)
			if err != nil {
				client.Close()
				continue
			}
			if !proxy.track(client, upstream) {
				client.Close()
				upstream.Close()
				continue
			}
			conns.Add(2)
			go func() { defer conns.Done(); delayCopy(upstream, client, rtt/2) }()
			go func() { defer conns.Done(); delayCopy(client, upstream, rtt/2) }()
		}
	}()
	return proxy
}

func (p *latencyProxy) track(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open == nil || p.refusing {
		return false
	}
	for _, conn := range conns {
		p.open[conn] = struct{}{}
	}
	return true
}

func (p *latencyProxy) sever(refuse bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refusing = refuse
	for conn := range p.open {
		conn.Close()
		delete(p.open, conn)
	}
}

func (p *latencyProxy) admit() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refusing = false
}

func delayCopy(to, from net.Conn, delay time.Duration) {
	defer to.Close()
	defer from.Close()
	queue := make(chan delayedChunk, 4096)
	go func() {
		defer close(queue)
		for {
			buffer := make([]byte, 32<<10)
			n, err := from.Read(buffer)
			if n > 0 {
				queue <- delayedChunk{data: buffer[:n], due: time.Now().Add(delay)}
			}
			if err != nil {
				return
			}
		}
	}()
	for chunk := range queue {
		time.Sleep(time.Until(chunk.due))
		if _, err := to.Write(chunk.data); err != nil {
			from.Close()
			for range queue {
			}
			return
		}
	}
}

type jetStreamRegion struct {
	cfg     config
	node    *Node
	ingress *latencyProxy
}

func startJetStreamRegions(t *testing.T) ([]string, map[string]*jetStreamRegion) {
	t.Helper()
	regions := Regions()
	ca, err := DeriveCA(bytes.Repeat([]byte{47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2*len(regions))
	ingress := map[string]*latencyProxy{}
	for i, region := range regions {
		ingress[region] = startLatencyProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[2*i])), worstRegionRTT)
	}
	started := map[string]*jetStreamRegion{}
	for i, region := range regions {
		seeds := map[string]string{}
		for _, peer := range regions {
			if peer != region {
				seeds[peer] = "nats://" + ingress[peer].addr
			}
		}
		cfg := config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), clusterHost: "127.0.0.1",
			clusterAdvertise: ingress[region].addr, clusterPort: ports[2*i], localPort: ports[2*i+1],
			seeds: seeds, ca: ca, applier: &fakeApplier{running: map[string]int64{}}, every: time.Hour,
			peersDir: t.TempDir(), peersEvery: time.Hour, address: func() (string, error) { return fmt.Sprintf("10.202.0.%d", i+1), nil },
		}
		node, err := start(cfg)
		if err != nil {
			t.Fatal(err)
		}
		started[region] = &jetStreamRegion{cfg: cfg, node: node, ingress: ingress[region]}
	}
	t.Cleanup(func() {
		for _, region := range started {
			if region.node != nil {
				region.node.Close()
			}
		}
	})
	return regions, started
}

func fabricBucket(t *testing.T, ctx context.Context, node *Node) jetstream.KeyValue {
	t.Helper()
	js, err := jetstream.New(node.fabric)
	if err != nil {
		t.Fatal(err)
	}
	var kv jetstream.KeyValue
	waitFor(t, 60*time.Second, "the leases bucket to answer in "+node.cfg.region, func() error {
		kv, err = js.KeyValue(ctx, "tb-quorum-proof")
		return err
	})
	return kv
}

func waitFor(t *testing.T, limit time.Duration, what string, try func() error) time.Duration {
	t.Helper()
	began := time.Now()
	for {
		err := try()
		if err == nil {
			return time.Since(began)
		}
		if time.Since(began) > limit {
			t.Fatalf("%s within %s: %v", what, limit, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestMeshJetStreamQuorumSpansRegions(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-region JetStream integration runs in the Slow suite")
	}
	ctx := t.Context()
	regions, started := startJetStreamRegions(t)
	home := started[regions[0]].node
	js, err := jetstream.New(home.fabric)
	if err != nil {
		t.Fatal(err)
	}
	formed := waitFor(t, 90*time.Second, "an R3 bucket across the regions", func() error {
		_, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket: "tb-quorum-proof", Replicas: 3, History: 4, LimitMarkerTTL: time.Second, MaxBytes: 8 << 20,
		})
		return err
	})
	t.Logf("R3 bucket created %s after start at %s injected RTT", formed, worstRegionRTT)

	stream, err := js.Stream(ctx, "KV_tb-quorum-proof")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	placed := map[string]bool{}
	placed[serverRegion(info.Cluster.Leader)] = true
	for _, replica := range info.Cluster.Replicas {
		placed[serverRegion(replica.Name)] = true
	}
	if info.Cluster.Name != ClusterName || len(placed) != 3 {
		t.Fatalf("bucket placed on cluster %q in regions %v, want one replica in each of %v", info.Cluster.Name, placed, regions)
	}

	buckets := map[string]jetstream.KeyValue{}
	for _, region := range regions {
		buckets[region] = fabricBucket(t, ctx, started[region].node)
	}
	created := 0
	for _, region := range regions {
		if _, err := buckets[region].Create(ctx, "home.db1", []byte(region)); err == nil {
			created++
		} else if !errors.Is(err, jetstream.ErrKeyExists) {
			t.Fatalf("create from %s: %v", region, err)
		}
	}
	if created != 1 {
		t.Fatalf("%d regions created home.db1, want exactly one", created)
	}
	for _, region := range regions {
		entry, err := buckets[region].Get(ctx, "home.db1")
		if err != nil {
			t.Fatal(err)
		}
		next, err := buckets[region].Update(ctx, "home.db1", []byte(region), entry.Revision())
		if err != nil {
			t.Fatalf("CAS from %s at revision %d: %v", region, entry.Revision(), err)
		}
		if _, err := buckets[region].Update(ctx, "home.db1", []byte("stale"), entry.Revision()); err == nil {
			t.Fatalf("stale CAS from %s at revision %d succeeded", region, entry.Revision())
		}
		for _, reader := range regions {
			waitFor(t, 10*time.Second, reader+" to read revision "+strconv.FormatUint(next, 10), func() error {
				got, err := buckets[reader].Get(ctx, "home.db1")
				if err == nil && (got.Revision() != next || string(got.Value()) != region) {
					err = fmt.Errorf("revision %d value %q", got.Revision(), got.Value())
				}
				return err
			})
		}
	}

	if _, err := buckets[regions[1]].Create(ctx, "lease.ttl", []byte("x"), jetstream.KeyTTL(2*time.Second)); err != nil {
		t.Fatalf("per-key TTL create: %v", err)
	}
	waitFor(t, 15*time.Second, "the TTL key to expire", func() error {
		if _, err := buckets[regions[2]].Get(ctx, "lease.ttl"); !errors.Is(err, jetstream.ErrKeyNotFound) {
			return fmt.Errorf("still readable: %v", err)
		}
		return nil
	})

	info, err = stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lost := serverRegion(info.Cluster.Leader)
	survivors := slices.DeleteFunc(slices.Clone(regions), func(region string) bool { return region == lost })
	if len(survivors) != 2 {
		t.Fatalf("stream leader %q is not one of %v", info.Cluster.Leader, regions)
	}
	for _, region := range regions {
		started[region].ingress.sever(true)
	}
	started[lost].node.Close()
	started[lost].node = nil
	for _, region := range survivors {
		started[region].ingress.admit()
	}
	survivor, err := jetstream.New(started[survivors[0]].node.fabric)
	if err != nil {
		t.Fatal(err)
	}
	var revision uint64
	elected := waitFor(t, 60*time.Second, "a new leader and a CAS with leader "+lost+" cut off", func() error {
		stream, err := survivor.Stream(ctx, "KV_tb-quorum-proof")
		if err != nil {
			return err
		}
		if leader := stream.CachedInfo().Cluster.Leader; leader == "" || serverRegion(leader) == lost {
			return fmt.Errorf("leader %q", leader)
		}
		entry, err := buckets[survivors[0]].Get(ctx, "home.db1")
		if err != nil {
			return err
		}
		revision, err = buckets[survivors[0]].Update(ctx, "home.db1", []byte("quorum-of-two"), entry.Revision())
		return err
	})
	t.Logf("leader %s cut off; %s committed a CAS %s later", lost, survivors[0], elected)
	if _, err := buckets[survivors[1]].Update(ctx, "home.db1", []byte("from-"+survivors[1]), revision); err != nil {
		t.Fatalf("CAS from %s with %s down: %v", survivors[1], lost, err)
	}

	started[lost].ingress.admit()
	restarted, err := start(started[lost].cfg)
	if err != nil {
		t.Fatal(err)
	}
	started[lost].node = restarted
	waitFor(t, 60*time.Second, lost+" to catch up after restart", func() error {
		stream, err := survivor.Stream(ctx, "KV_tb-quorum-proof")
		if err != nil {
			return err
		}
		info := stream.CachedInfo()
		replica := slices.IndexFunc(info.Cluster.Replicas, func(peer *jetstream.PeerInfo) bool { return serverRegion(peer.Name) == lost })
		if replica < 0 || !info.Cluster.Replicas[replica].Current || info.Cluster.Replicas[replica].Lag != 0 {
			return fmt.Errorf("replica in %s not current: %+v", lost, info.Cluster.Replicas)
		}
		if local := localLastSeq(restarted, "KV_tb-quorum-proof"); local != info.State.LastSeq {
			return fmt.Errorf("%s stores up to sequence %d, the stream is at %d", lost, local, info.State.LastSeq)
		}
		return nil
	})
	if rtt := started[survivors[0]].node.RTT(); rtt[survivors[1]] < worstRegionRTT/2 {
		t.Fatalf("route RTT %v does not reflect the injected %s", rtt, worstRegionRTT)
	}
}

func localLastSeq(node *Node, stream string) uint64 {
	jsz, err := node.server.Jsz(&server.JSzOptions{Account: FabricAccount, Streams: true})
	if err != nil {
		return 0
	}
	for _, account := range jsz.AccountDetails {
		for _, detail := range account.Streams {
			if detail.Name == stream {
				return detail.State.LastSeq
			}
		}
	}
	return 0
}

func TestMeshJetStreamStoreFailureFailsStart(t *testing.T) {
	ca, err := DeriveCA(bytes.Repeat([]byte{47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jetstream"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 3)
	_, err = start(config{
		region: "gru", server: "ts-gru-1", dir: dir, clusterHost: "127.0.0.1", clusterPort: ports[0], localPort: ports[1],
		seeds: map[string]string{"sjc": fmt.Sprintf("nats://127.0.0.1:%d", ports[2])}, ca: ca,
		applier: &fakeApplier{running: map[string]int64{}}, every: time.Hour, peersDir: t.TempDir(), peersEvery: time.Hour,
		address: func() (string, error) { return "10.202.0.1", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "JetStream") {
		t.Fatalf("start with an unwritable JetStream store: %v", err)
	}
}
