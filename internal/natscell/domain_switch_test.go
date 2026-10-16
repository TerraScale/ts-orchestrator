package natscell

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
)

// TestRollingInterRegionMaterialKeepsRegionalDomainAndData replaces link
// material on a production R3 cell one broker at a time. The regional domain,
// stream, KV bucket, object store and durable consumer keep serving through
// every restart, including a return to isolated topology.
func TestRollingInterRegionMaterialKeepsRegionalDomainAndData(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	const domain = "sfo"
	root := t.TempDir()
	region := newTestRegion(t, filepath.Join(root, domain), domain, HubAndSpoke("gru", []string{domain}))
	// The parent never runs: the remote dials a closed port, so only the
	// regional material changes without requiring a reachable peer.
	gru := &testRegion{testRegionKeys: newTestRegionKeys(t)}
	region.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{Peer: "gru", ServerName: testLeafServerName,
		URLs:            []string{fmt.Sprintf("nats-leaf://127.0.0.1:%d", freeClientPort(t))},
		CredentialsFile: gru.childLeafCredentials(t, "sfo-leaf.creds", domain), PeerAccount: gru.interregionID,
		TLS: region.cfg.TLS}}
	// Isolated topology uses plain cell and system claims; linked topology
	// uses the contract-bearing reissues. Both keep the same regional domain.
	writeClaim := func(name string, claim *jwt.AccountClaims) string {
		t.Helper()
		raw, err := claim.Encode(region.operator)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	plainCell := jwt.NewAccountClaims(region.cellID)
	plainCell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	plainCellFile := writeClaim("plain-cell.jwt", plainCell)
	plainSystemFile := writeClaim("plain-system.jwt", jwt.NewAccountClaims(region.systemID))
	routeSecret := filepath.Join(root, "route.secret")
	if err := os.WriteFile(routeSecret, []byte("domain-switch-route-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	brokers := []string{"broker-a", "broker-b", "broker-c"}
	ports := freeClientPorts(t, 6)
	clientPorts, routePorts, routes := ports[:3], ports[3:], make([]string, 3)
	for index := range brokers {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", routePorts[index])
	}
	config := func(index int, withLinks bool) Config {
		cfg := region.cfg
		embedded := *region.cfg.Embedded
		cfg.Embedded, cfg.Instance, cfg.Replicas = &embedded, brokers[index], 3
		embedded.Port, embedded.RouteHost, embedded.RoutePort = clientPorts[index], "127.0.0.1", routePorts[index]
		embedded.Routes = PeerRoutes(routes, routes[index])
		embedded.StoreDir = filepath.Join(root, brokers[index])
		embedded.BrokerIDs = brokers
		embedded.RouteUser, embedded.RoutePasswordFile = "domain-switch", routeSecret
		if !withLinks {
			embedded.InterRegion = nil
			embedded.CellJWTFile, embedded.SystemJWTFile = plainCellFile, plainSystemFile
		}
		return cfg
	}
	runtimes := make([]*Runtime, 3)
	t.Cleanup(func() {
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	start := func(index int, withLinks bool) {
		t.Helper()
		_ = runtimes[index].Close()
		runtimes[index] = nil
		runtime, err := Start(ctx, config(index, withLinks))
		if err != nil {
			t.Fatalf("start %s (link material %v): %v", brokers[index], withLinks, err)
		}
		runtimes[index] = runtime
	}
	js := func(index int) jetstream.JetStream { return runtimes[index].JetStream() }

	var payloads [][]byte
	publish := func(ctx context.Context, index int) {
		t.Helper()
		data := fmt.Appendf(nil, "m%d", len(payloads)+1)
		var ack *jetstream.PubAck
		eventually(ctx, t, "publish "+string(data), func(ctx context.Context) (err error) {
			ack, err = js(index).Publish(ctx, "domain.msg", data, jetstream.WithMsgID(string(data)))
			return err
		})
		payloads = append(payloads, data)
		if ack.Stream != "DOMAIN" || ack.Sequence != uint64(len(payloads)) {
			t.Fatalf("%s via %s acked as %+v", data, brokers[index], ack)
		}
		if ack.Domain != domain {
			t.Fatalf("%s via %s acked with domain %q, want %q", data, brokers[index], ack.Domain, domain)
		}
	}
	keys := map[string]string{}
	put := func(ctx context.Context, index int, key string) {
		t.Helper()
		eventually(ctx, t, "put "+key, func(ctx context.Context) error {
			kv, err := js(index).KeyValue(ctx, "DOMAIN_KV")
			if err == nil {
				_, err = kv.Put(ctx, key, []byte(key))
			}
			return err
		})
		keys[key] = key
	}
	blob := bytes.Repeat([]byte("object-"), 40_000) // three chunks
	next := uint64(1)                               // the durable consumer's next stream sequence
	consume := func(ctx context.Context, index int) {
		t.Helper()
		var msg jetstream.Msg
		eventually(ctx, t, "fetch from WORKER", func(ctx context.Context) error {
			consumer, err := js(index).Consumer(ctx, "DOMAIN", "WORKER")
			if err != nil {
				return err
			}
			batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
			if err != nil {
				return err
			}
			for fetched := range batch.Messages() {
				msg = fetched
			}
			if msg == nil {
				return fmt.Errorf("no message: %v", batch.Error())
			}
			return nil
		})
		// MaxAckPending 1 redelivers next until it is acknowledged, so a lost
		// fetch reply cannot skip it.
		if meta, err := msg.Metadata(); err != nil || meta.Sequence.Stream != next {
			t.Fatalf("WORKER via %s delivered %+v, %v; want stream sequence %d", brokers[index], meta, err, next)
		}
		eventually(ctx, t, "ack", msg.DoubleAck)
		next++
	}

	for index := range brokers {
		start(index, false)
	}
	setup, setupCancel := context.WithTimeout(ctx, time.Minute)
	defer setupCancel()
	for _, runtime := range runtimes {
		waitUntil(t, setup, "full metadata group", func() bool { return runtime.FullClusterReady(3) })
	}
	eventually(setup, t, "create R3 stream", func(ctx context.Context) error {
		_, err := js(0).CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "DOMAIN", Subjects: []string{"domain.>"},
			Replicas: 3, Storage: jetstream.FileStorage})
		return err
	})
	eventually(setup, t, "create R3 KV bucket", func(ctx context.Context) error {
		_, err := js(1).CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "DOMAIN_KV", Replicas: 3,
			Storage: jetstream.FileStorage})
		return err
	})
	eventually(setup, t, "put R3 object", func(ctx context.Context) error {
		store, err := js(2).CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "DOMAIN_OBJ", Replicas: 3,
			Storage: jetstream.FileStorage})
		if err == nil {
			_, err = store.PutBytes(ctx, "blob", blob)
		}
		return err
	})
	eventually(setup, t, "create durable consumer", func(ctx context.Context) error {
		_, err := js(1).CreateOrUpdateConsumer(ctx, "DOMAIN", jetstream.ConsumerConfig{Durable: "WORKER",
			AckPolicy: jetstream.AckExplicitPolicy, AckWait: 5 * time.Second, MaxAckPending: 1})
		return err
	})
	for index := range 10 {
		publish(setup, index%3)
	}
	for index := range 2 {
		put(setup, index, fmt.Sprintf("setup-%d", index))
	}
	for range 4 {
		consume(setup, 0)
	}

	// check runs after every restart: restarted is the broker just started,
	// other one that kept running.
	check := func(phase string, restarted, other int) {
		t.Helper()
		began := time.Now()
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		var leader string
		waitUntil(t, ctx, phase+": one metadata leader over three peers", func() bool {
			leader = ""
			for _, runtime := range runtimes {
				observation, err := runtime.ObserveCluster()
				if err != nil || !runtime.FullClusterReady(3) || observation.MetaSize != 3 || len(observation.Routes) != 2 ||
					observation.MetaLeader == "" || leader != "" && observation.MetaLeader != leader {
					return false
				}
				leader = observation.MetaLeader
			}
			return true
		})
		for _, index := range []int{restarted, other} {
			client := js(index)
			eventually(ctx, t, phase+": stream messages via "+brokers[index], func(ctx context.Context) error {
				stream, err := client.Stream(ctx, "DOMAIN")
				if err != nil {
					return err
				}
				for seq, want := range payloads {
					msg, err := stream.GetMsg(ctx, uint64(seq+1))
					if err != nil {
						return err
					}
					if !bytes.Equal(msg.Data, want) {
						t.Fatalf("%s: message %d via %s = %q, want %q", phase, seq+1, brokers[index], msg.Data, want)
					}
				}
				info, err := stream.Info(ctx)
				if err == nil && info.State.Msgs != uint64(len(payloads)) {
					t.Fatalf("%s: stream via %s holds %d messages, want %d", phase, brokers[index], info.State.Msgs, len(payloads))
				}
				return err
			})
			eventually(ctx, t, phase+": KV keys via "+brokers[index], func(ctx context.Context) error {
				kv, err := client.KeyValue(ctx, "DOMAIN_KV")
				if err != nil {
					return err
				}
				for key, want := range keys {
					entry, err := kv.Get(ctx, key)
					if err != nil {
						return fmt.Errorf("%s: %w", key, err)
					}
					if string(entry.Value()) != want {
						t.Fatalf("%s: KV %s via %s = %q", phase, key, brokers[index], entry.Value())
					}
				}
				return nil
			})
			eventually(ctx, t, phase+": object via "+brokers[index], func(ctx context.Context) error {
				store, err := client.ObjectStore(ctx, "DOMAIN_OBJ")
				if err != nil {
					return err
				}
				data, err := store.GetBytes(ctx, "blob")
				if err == nil && !bytes.Equal(data, blob) {
					t.Fatalf("%s: object via %s has %d bytes, want %d", phase, brokers[index], len(data), len(blob))
				}
				return err
			})
			publish(ctx, index)
			put(ctx, index, phase+"-"+brokers[index])
			consume(ctx, index)
		}
		eventually(ctx, t, phase+": place a new R3 stream", func(ctx context.Context) error {
			stream, err := js(restarted).CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "PLACE_" + phase,
				Subjects: []string{"place." + phase}, Replicas: 3, Storage: jetstream.FileStorage})
			if err == nil {
				_, err = js(restarted).Publish(ctx, "place."+phase, []byte(phase))
			}
			if err == nil {
				err = js(restarted).DeleteStream(ctx, stream.CachedInfo().Config.Name)
			}
			return err
		})
		for index, runtime := range runtimes {
			domainJS, err := jetstream.NewWithDomain(runtime.Conn(), domain)
			if err != nil {
				t.Fatal(err)
			}
			probe, probeCancel := context.WithTimeout(ctx, 2*time.Second)
			info, err := domainJS.AccountInfo(probe)
			probeCancel()
			if err != nil || info.Domain != domain {
				t.Errorf("%s: $JS.%s.API.INFO via %s = %+v, %v", phase, domain, brokers[index], info, err)
			}
		}
		t.Logf("%s: metadata leader %s, checked in %s", phase, leader, time.Since(began).Round(time.Millisecond))
	}

	check("baseline", 0, 1)
	for index := range brokers {
		start(index, true)
		check(fmt.Sprintf("linked-%d", index), index, (index+1)%3)
	}
	start(0, false)
	check("isolated", 0, 1)
}

// eventually retries try, each attempt bounded, until it succeeds; when ctx
// ends it fails the test with the last error.
func eventually(ctx context.Context, t *testing.T, what string, try func(context.Context) error) {
	t.Helper()
	for {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := try(attempt)
		cancel()
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
