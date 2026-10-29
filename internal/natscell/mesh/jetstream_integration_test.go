package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const worstRegionRTT = 184 * time.Millisecond

type delayedChunk struct {
	data []byte
	due  time.Time
}

func startLatencyProxy(t *testing.T, target string, rtt time.Duration) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns sync.WaitGroup
	var mu sync.Mutex
	open := map[net.Conn]struct{}{}
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if open == nil {
			conn.Close()
			return false
		}
		open[conn] = struct{}{}
		return true
	}
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range open {
			conn.Close()
		}
		open = nil
		mu.Unlock()
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
			if !track(client) || !track(upstream) {
				client.Close()
				upstream.Close()
				continue
			}
			conns.Add(2)
			go func() { defer conns.Done(); delayCopy(upstream, client, rtt/2) }()
			go func() { defer conns.Done(); delayCopy(client, upstream, rtt/2) }()
		}
	}()
	return listener.Addr().String()
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
	cfg  config
	node *Node
}

func startJetStreamRegions(t *testing.T) ([]string, map[string]*jetStreamRegion) {
	t.Helper()
	regions := Regions()
	ca, err := DeriveCA(bytes.Repeat([]byte{47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2*len(regions))
	ingress := map[string]string{}
	for i, region := range regions {
		ingress[region] = startLatencyProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[2*i])), worstRegionRTT)
	}
	started := map[string]*jetStreamRegion{}
	for i, region := range regions {
		seeds := map[string]string{}
		for _, peer := range regions {
			if peer != region {
				seeds[peer] = "nats://" + ingress[peer]
			}
		}
		cfg := config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), clusterHost: "127.0.0.1",
			clusterAdvertise: ingress[region], clusterPort: ports[2*i], localPort: ports[2*i+1],
			seeds: seeds, ca: ca, applier: &fakeApplier{running: map[string]int64{}}, every: time.Hour,
			peersDir: t.TempDir(), peersEvery: time.Hour, address: func() (string, error) { return fmt.Sprintf("10.202.0.%d", i+1), nil },
		}
		node, err := start(cfg)
		if err != nil {
			t.Fatal(err)
		}
		started[region] = &jetStreamRegion{cfg: cfg, node: node}
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

	lost := regions[2]
	started[lost].node.Close()
	started[lost].node = nil
	var revision uint64
	elected := waitFor(t, 30*time.Second, "CAS with "+lost+" down", func() error {
		entry, err := buckets[regions[0]].Get(ctx, "home.db1")
		if err != nil {
			return err
		}
		revision, err = buckets[regions[0]].Update(ctx, "home.db1", []byte("quorum-of-two"), entry.Revision())
		return err
	})
	t.Logf("CAS from %s committed %s after %s went down", regions[0], elected, lost)
	if _, err := buckets[regions[1]].Update(ctx, "home.db1", []byte("from-"+regions[1]), revision); err != nil {
		t.Fatalf("CAS from %s with %s down: %v", regions[1], lost, err)
	}

	restarted, err := start(started[lost].cfg)
	if err != nil {
		t.Fatal(err)
	}
	started[lost].node = restarted
	rejoined := fabricBucket(t, ctx, restarted)
	waitFor(t, 60*time.Second, lost+" to catch up after restart", func() error {
		entry, err := rejoined.Get(ctx, "home.db1")
		if err == nil && string(entry.Value()) != "from-"+regions[1] {
			err = fmt.Errorf("reads %q at revision %d", entry.Value(), entry.Revision())
		}
		return err
	})
	if rtt := home.RTT(); rtt[regions[1]] < worstRegionRTT/2 {
		t.Fatalf("route RTT %v does not reflect the injected %s", rtt, worstRegionRTT)
	}
}
