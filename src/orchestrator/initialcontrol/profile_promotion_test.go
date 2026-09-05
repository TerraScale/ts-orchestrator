package initialcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type profilePromotionBroker struct {
	name, store string
	port, route int
	s           *server.Server
}

func profilePromotionPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func (b *profilePromotionBroker) start(t *testing.T, cluster bool, peers []*profilePromotionBroker, budget int64) {
	t.Helper()
	accounts := map[string]any{}
	for _, name := range []string{"GRU_CONTROL", "GLOBAL_CONTROL"} {
		accounts[name] = map[string]any{"jetstream": true, "users": []any{map[string]any{"user": name, "password": "profilePromotion-only"}}}
	}
	cfg := map[string]any{"server_name": b.name, "host": "127.0.0.1", "port": b.port, "jetstream": map[string]any{"store_dir": b.store, "max_mem_store": 64 << 20, "max_file_store": budget}, "accounts": accounts}
	if cluster {
		accounts["SYS"] = map[string]any{"users": []any{map[string]any{"user": "sys", "password": "profilePromotion-only"}}}
		cfg["system_account"] = "SYS"
		cfg["server_tags"] = []string{"region:" + map[string]string{"GRU_SOURCE": "gru", "SFO_PEER": "sfo", "FRA_PEER": "fra"}[b.name]}
		routes := []string{}
		for _, p := range peers {
			if p != b {
				routes = append(routes, fmt.Sprintf("nats://127.0.0.1:%d", p.route))
			}
		}
		cfg["cluster"] = map[string]any{"name": "CONTROL", "host": "127.0.0.1", "port": b.route, "routes": routes}
	}
	if !cluster {
		cfg["no_sys_acc"] = true
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "nats.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	opts, e := server.ProcessConfigFile(path)
	if e != nil {
		t.Fatal(e)
	}
	opts.NoSigs = true
	opts.NoLog = true

	b.s, e = server.NewServer(opts)
	if e != nil {
		t.Fatal(e)
	}

	b.s.Start()
	if !b.s.ReadyForConnections(10 * time.Second) {
		t.Fatal("broker listener unavailable", b.name)
	}
}
func (b *profilePromotionBroker) stop() {
	if b.s != nil {
		b.s.Shutdown()
		b.s.WaitForShutdown()
		b.s = nil
	}
}
func (b *profilePromotionBroker) client(t *testing.T, account string) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, e := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", b.port), nats.UserInfo(account, "profilePromotion-only"), nats.Timeout(time.Second), nats.NoReconnect())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(nc.Close)
	js, e := jetstream.New(nc)
	if e != nil {
		t.Fatal(e)
	}
	return nc, js
}

type profilePromotionSnapshot struct {
	info      *jetstream.StreamInfo
	messages  []*jetstream.RawStreamMsg
	consumers map[string]*jetstream.ConsumerInfo
	// Populated only after the pinned server metadata defect is asserted on disk.
	persistedConsumerCreated map[string][]time.Time
}

// consumerCreatedMatches remains strict until the known metadata defect is
// verified. Afterwards it permits only values read from the three stores before
// any restart, never an arbitrary newly observed API timestamp.
func (s profilePromotionSnapshot) consumerCreatedMatches(name string, created time.Time) bool {
	values, recorded := s.persistedConsumerCreated[name]
	if !recorded {
		return created.Equal(s.consumers[name].Created)
	}
	for _, value := range values {
		if created.Equal(value) {
			return true
		}
	}
	return false
}

func profilePromotionConsumerMetadata(t *testing.T, b *profilePromotionBroker, account, stream, consumer string) server.FileConsumerInfo {
	t.Helper()
	path := filepath.Join(b.store, "jetstream", account, "streams", stream, "obs", consumer, server.JetStreamMetaFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var info server.FileConsumerInfo
	if err = json.Unmarshal(data, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func profilePromotionAssertRestoredConsumerMetadata(t *testing.T, source *profilePromotionBroker, snapshots map[string]map[string]profilePromotionSnapshot) {
	t.Helper()
	for account, streams := range snapshots {
		for stream, snapshot := range streams {
			for consumer, original := range snapshot.consumers {
				stored := profilePromotionConsumerMetadata(t, source, account, stream, consumer)
				if !stored.Created.Equal(original.Created) || stored.Replicas != 1 {
					t.Fatalf("restored consumer metadata %s/%s/%s: Created=%s original=%s replicas=%d", account, stream, consumer, stored.Created, original.Created, stored.Replicas)
				}
			}
		}
	}
}

// Pinned v2.14.6 restores Created into consumer memory, but not the file store's
// cached FileConsumerInfo. UpdateConsumer writes that cache during R1->R3 and
// changes GRU's meta.inf Created; peers persist the original assignment Created.
// Assert the defect deterministically so a vendor fix requires explicit review.
func profilePromotionRecordConsumerMetadataDefect(t *testing.T, brokers []*profilePromotionBroker, snapshots map[string]map[string]profilePromotionSnapshot) {
	t.Helper()
	count := 0
	for account, streams := range snapshots {
		for stream, snapshot := range streams {
			snapshot.persistedConsumerCreated = make(map[string][]time.Time)
			for consumer, original := range snapshot.consumers {
				count++
				for _, b := range brokers {
					stored := profilePromotionConsumerMetadata(t, b, account, stream, consumer)
					if stored.Replicas != 3 {
						t.Fatalf("consumer metadata %s/%s replicas=%d", stream, consumer, stored.Replicas)
					}
					if b.name == "GRU_SOURCE" {
						if !stored.Created.After(original.Created) {
							t.Fatalf("expected pinned NATS source Created defect; review upstream behavior: %s/%s stored=%s original=%s", stream, consumer, stored.Created, original.Created)
						}
					} else if !stored.Created.Equal(original.Created) {
						t.Fatalf("peer consumer Created changed: %s %s/%s stored=%s original=%s", b.name, stream, consumer, stored.Created, original.Created)
					}
					t.Logf("known NATS metadata defect %s %s/%s/%s: original=%s persisted=%s", b.name, account, stream, consumer, original.Created, stored.Created)
					snapshot.persistedConsumerCreated[consumer] = append(snapshot.persistedConsumerCreated[consumer], stored.Created)
				}
			}
			streams[stream] = snapshot
		}
	}
	if count != 3 {
		t.Fatalf("expected all 3 original consumers, got %d", count)
	}
}

func profilePromotionRead(t *testing.T, ctx context.Context, js jetstream.JetStream) map[string]profilePromotionSnapshot {
	t.Helper()
	result := map[string]profilePromotionSnapshot{}
	listed := js.ListStreams(ctx)
	for info := range listed.Info() {
		s, e := js.Stream(ctx, info.Config.Name)
		if e != nil {
			t.Fatal(e)
		}
		snap := profilePromotionSnapshot{info: info, consumers: map[string]*jetstream.ConsumerInfo{}}
		for seq := info.State.FirstSeq; seq <= info.State.LastSeq && seq > 0; seq++ {
			m, e := s.GetMsg(ctx, seq)
			if e == jetstream.ErrMsgNotFound {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			snap.messages = append(snap.messages, m)
		}
		consumers := s.ListConsumers(ctx)
		for c := range consumers.Info() {
			snap.consumers[c.Name] = c
		}
		if e = consumers.Err(); e != nil {
			t.Fatal(e)
		}
		result[info.Config.Name] = snap
	}
	if e := listed.Err(); e != nil {
		t.Fatal(e)
	}
	return result
}
func profilePromotionWait(t *testing.T, label string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out", label)
}
func profilePromotionVerify(t *testing.T, ctx context.Context, js jetstream.JetStream, original map[string]profilePromotionSnapshot, r3 bool) {
	t.Helper()
	now := profilePromotionRead(t, ctx, js)
	if len(now) != len(original) {
		t.Fatalf("inventory changed %d != %d", len(now), len(original))
	}
	for name, before := range original {
		after, ok := now[name]
		if !ok {
			t.Fatal("stream missing", name)
		}
		if !after.info.Created.Equal(before.info.Created) {
			t.Fatalf("stream identity recreated %s: %s != %s", name, after.info.Created, before.info.Created)
		}
		expected := before.info.Config
		if r3 {
			expected.Replicas = 3
		}
		if !reflect.DeepEqual(after.info.Config, expected) {
			old, _ := json.Marshal(expected)
			new, _ := json.Marshal(after.info.Config)
			t.Fatalf("profile changed %s\n%s\n%s", name, old, new)
		}
		previousState, currentState := before.info.State, after.info.State
		if currentState.FirstSeq != previousState.FirstSeq || currentState.LastSeq != previousState.LastSeq || currentState.NumDeleted != previousState.NumDeleted || currentState.Msgs != previousState.Msgs || currentState.Bytes != previousState.Bytes {
			t.Fatalf("stream allocator or retained state changed %s: before=%+v after=%+v", name, previousState, currentState)
		}
		if !reflect.DeepEqual(after.messages, before.messages) {
			t.Fatalf("record, headers, timestamp or sequence changed %s", name)
		}
		if len(after.consumers) != len(before.consumers) {
			t.Fatal("consumer inventory changed", name)
		}
		for c, old := range before.consumers {
			current := after.consumers[c]
			expected := old.Config
			if r3 {
				expected.Replicas = 3
			}
			if current == nil || !before.consumerCreatedMatches(c, current.Created) || !reflect.DeepEqual(current.Config, expected) {
				t.Fatal("consumer identity/config changed", name, c)
			}
			if current.Delivered.Consumer != old.Delivered.Consumer || current.Delivered.Stream != old.Delivered.Stream || current.AckFloor.Consumer != old.AckFloor.Consumer || current.AckFloor.Stream != old.AckFloor.Stream || current.NumAckPending != old.NumAckPending {
				t.Fatal("consumer delivery/ack state changed", name, c)
			}
		}
	}
}

// TestInitialProfilesSnapshotRestoreR3Recovery qualifies content recovery only.
// NATS v2.14.6 changes source consumer Created metadata during promotion; the
// focused subtest guards this defect and recovery accepts only recorded values.
// It does not establish TLS, runtime authority, or host handoff readiness. The outage
// phase proves read availability; stopped-process immutability is not fencing.
func TestInitialProfilesSnapshotRestoreR3Recovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	p, e := buildProfiles("gru", "gru-1")
	if e != nil {
		t.Fatal(e)
	}
	budget, e := RequiredStorageBytes("gru", "gru-1")
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("NATS=%s storage budget per server=%d", server.VERSION, budget)
	runDir := t.TempDir()
	brokers := []*profilePromotionBroker{}
	for _, name := range []string{"GRU_SOURCE", "SFO_PEER", "FRA_PEER"} {
		b := &profilePromotionBroker{name: name, store: filepath.Join(runDir, name, "store"), port: profilePromotionPort(t), route: profilePromotionPort(t)}
		brokers = append(brokers, b)
		defer b.stop()
	}
	source := brokers[0]
	defer func() {
		if t.Failed() {
			for _, b := range brokers {
				if b.s != nil {
					j, e := b.s.Jsz(nil)
					raw, _ := json.Marshal(j)
					t.Logf("failure server=%s routes=%d jsz=%s error=%v", b.name, b.s.NumRoutes(), raw, e)
				}
			}
		}
	}()
	source.start(t, false, nil, budget)
	snapshots := map[string]map[string]profilePromotionSnapshot{}
	archives := map[string]map[string]profilePromotionArchive{}
	profiles := map[string]accountProfile{"GRU_CONTROL": p.Regional, "GLOBAL_CONTROL": p.Global}
	for account, profile := range profiles {
		nc, js := source.client(t, account)
		if e = provision(ctx, js, profile, account == "GRU_CONTROL", "gru", "gru-1"); e != nil {
			t.Fatal(e)
		}
		// Exercise the production adapter before fixture writes as well: most
		// initial streams are empty, some already own durable consumers, and the
		// regional protocol object is the only provisioned retained payload.
		initial := profilePromotionRead(t, ctx, js)
		empty := 0
		for name, snapshot := range initial {
			archive := profilePromotionBackup(t, ctx, nc, name)
			if archive.state.Msgs != snapshot.info.State.Msgs || archive.state.FirstSeq != snapshot.info.State.FirstSeq || archive.state.LastSeq != snapshot.info.State.LastSeq || archive.state.Consumers != len(snapshot.consumers) {
				t.Fatalf("initial production snapshot state changed %s/%s", account, name)
			}
			if archive.state.Msgs == 0 {
				empty++
			}
		}
		if empty == 0 {
			t.Fatalf("initial empty inventory was not exercised: %s", account)
		}
		t.Logf("production snapshotter initial %s inventory=%d empty=%d", account, len(initial), empty)
		for _, config := range profile.Streams {
			subject := config.Subjects[0]
			for _, c := range profile.Consumers {
				if c.Stream == config.Name && c.Config.FilterSubject != "" {
					subject = c.Config.FilterSubject
				}
			}
			subject = strings.ReplaceAll(strings.ReplaceAll(subject, ">", "profilePromotion"), "*", "profilePromotion")
			msg := nats.NewMsg(subject)
			msg.Data = []byte("retained:" + account + ":" + config.Name)
			msg.Header.Set("Audit-Identity", config.Name)
			msg.Header.Add("Audit-Multi", "one")
			msg.Header.Add("Audit-Multi", "two")
			if _, e = js.PublishMsg(ctx, msg); e != nil {
				t.Fatal(config.Name, e)
			}
		}
		for _, config := range profile.KV {
			kv, e := js.KeyValue(ctx, config.Bucket)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = kv.Put(ctx, "profilePromotion", []byte("retained:"+config.Bucket)); e != nil {
				t.Fatal(e)
			}
			if _, e = kv.Put(ctx, "profilePromotion-deleted", []byte("retired-value")); e != nil {
				t.Fatal(e)
			}
			if e = kv.Delete(ctx, "profilePromotion-deleted"); e != nil {
				t.Fatal(e)
			}
		}
		for _, config := range profile.Objects {
			obj, e := js.ObjectStore(ctx, config.Bucket)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = obj.PutBytes(ctx, "profilePromotion", []byte("retained:"+config.Bucket)); e != nil {
				t.Fatal(e)
			}
		}
		for _, profileConsumer := range profile.Consumers {
			consumer, e := js.Consumer(ctx, profileConsumer.Stream, profileConsumer.Config.Name)
			if e != nil {
				t.Fatal(e)
			}
			batch, e := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
			if e != nil {
				t.Fatal(e)
			}
			received := 0
			for msg := range batch.Messages() {
				if e = msg.DoubleAck(ctx); e != nil {
					t.Fatal(e)
				}
				received++
			}
			if e = batch.Error(); e != nil {
				t.Fatal(e)
			}
			if received != 1 {
				t.Fatalf("existing consumer %s received no profilePromotion record", profileConsumer.Config.Name)
			}
		}
		snapshots[account] = profilePromotionRead(t, ctx, js)
		for name, snap := range snapshots[account] {
			for cname, consumer := range snap.consumers {
				t.Logf("ORIGINAL CONSUMER %s/%s/%s replicas=%d delivered=%+v ackFloor=%+v", account, name, cname, consumer.Config.Replicas, consumer.Delivered, consumer.AckFloor)
			}
		}

		archives[account] = map[string]profilePromotionArchive{}
		for name := range snapshots[account] {
			archives[account][name] = profilePromotionBackup(t, ctx, nc, name)
			archive := archives[account][name]
			directory := filepath.Join(runDir, "snapshots", account)
			if e = os.MkdirAll(directory, 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(directory, name+".snapshot"), archive.envelope, 0600); e != nil {
				t.Fatal(e)
			}
			metadata, _ := json.Marshal(server.JSApiStreamRestoreRequest{Config: archive.config, State: archive.state})
			if e = os.WriteFile(filepath.Join(directory, name+".json"), metadata, 0600); e != nil {
				t.Fatal(e)
			}
			t.Logf("SNAPSHOT %s/%s envelope_bytes=%d envelope_sha256=%x archive_bytes=%d archive_sha256=%x", account, name, len(archive.envelope), sha256.Sum256(archive.envelope), len(archive.data), sha256.Sum256(archive.data))
		}

		count := 0
		for name, snap := range snapshots[account] {
			count += len(snap.messages)
			t.Logf("original %s/%s records=%d", account, name, len(snap.messages))
		}
		t.Logf("%s original streams=%d records=%d", account, len(snapshots[account]), count)
		nc.Close()
	}
	source.stop()
	originalStore, originalDigest := source.store, ""

	originalDigest = profilePromotionTreeDigest(t, originalStore)
	source.store = filepath.Join(runDir, "GRU_CLUSTER_STORE")

	brokers[1].start(t, true, brokers, budget)
	brokers[2].start(t, true, brokers, budget)

	source.start(t, true, brokers, budget)

	profilePromotionWait(t, "exact healthy3-member metadata cluster", func() bool {
		leader := ""
		leaderReady := false
		for _, b := range brokers {
			j, e := b.s.Jsz(nil)
			if e != nil || j.Meta == nil || j.Meta.Size != 3 || j.Meta.Leader == "" {
				return false
			}
			if leader != "" && leader != j.Meta.Leader {
				return false
			}
			leader = j.Meta.Leader
			if b.name == leader {
				if len(j.Meta.Replicas) != 2 {
					return false
				}
				names := []string{leader}
				for _, r := range j.Meta.Replicas {
					if !r.Current || r.Offline {
						return false
					}
					names = append(names, r.Name)
				}
				sort.Strings(names)
				leaderReady = reflect.DeepEqual(names, []string{"FRA_PEER", "GRU_SOURCE", "SFO_PEER"})
			}
		}
		return leaderReady
	})
	t.Log("exact GRU/SFO/FRA metadata quorum healthy")

	for account, inventory := range archives {
		nc, js := source.client(t, account)
		profilePromotionWait(t, "fresh cluster metadata quorum", func() bool {
			probe, c := context.WithTimeout(ctx, time.Second)
			defer c()
			_, e := js.AccountInfo(probe)
			return e == nil
		})
		for name, archive := range inventory {
			profilePromotionRestore(t, ctx, nc, archive)
			stream, e := js.Stream(ctx, name)
			if e != nil {
				t.Fatal(e)
			}
			info, e := stream.Info(ctx)
			if e != nil {
				t.Fatalf("restored R1 source information %s: %v", name, e)
			}
			if info.Cluster == nil || info.Cluster.Leader != "GRU_SOURCE" {
				t.Fatalf("restored R1 source placement %s: %+v", name, info.Cluster)
			}
			if _, e = js.UpdateStream(ctx, snapshots[account][name].info.Config); e != nil {
				t.Fatal(e)
			}
		}
		nc.Close()
	}
	t.Log("all15 original stream archives restored onto fresh clustered GRU R1 source")

	for account, original := range snapshots {
		nc, js := source.client(t, account)
		restored := profilePromotionRead(t, ctx, js)
		for name, before := range original {
			after := restored[name]

			// Clustered restore assigns a new stream Created timestamp. Preserve
			// that explicit restoration baseline across promotion and restart.
			if !after.info.Created.After(before.info.Created) {
				t.Fatalf("expected restored stream creation timestamp for %s", name)
			}
			t.Logf("restored %s/%s Created: %s -> %s", account, name, before.info.Created, after.info.Created)
			before.info.Created = after.info.Created
			for name, c := range before.consumers {
				if after.consumers[name] == nil || !c.Created.Equal(after.consumers[name].Created) {
					t.Fatalf("consumer creation timestamp changed: %s", name)
				}
			}

			original[name] = before
		}
		nc.Close()
	}

	profilePromotionAssertRestoredConsumerMetadata(t, source, snapshots)

	for account, original := range snapshots {
		nc, js := source.client(t, account)
		lastProbe := ""
		defer func() {
			if t.Failed() {
				t.Log("last retained-stream probe:", lastProbe)
			}
		}()
		profilePromotionWait(t, "retained streams become readable", func() bool {
			probe, c := context.WithTimeout(ctx, 500*time.Millisecond)
			defer c()
			for name := range original {
				s, e := js.Stream(probe, name)
				if e != nil {
					lastProbe = fmt.Sprintf("%s lookup: %v", name, e)
					return false
				}
				info, e := s.Info(probe)
				if e != nil {
					lastProbe = fmt.Sprintf("%s info: %v", name, e)
					return false
				}
				if info.State.Msgs != original[name].info.State.Msgs {
					lastProbe = fmt.Sprintf("%s records got=%d expected=%d", name, info.State.Msgs, original[name].info.State.Msgs)
					return false
				}
			}
			return true
		})
		profilePromotionVerify(t, ctx, js, original, false)
		names := []string{}
		for name := range original {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			cfg := original[name].info.Config
			cfg.Replicas = 3
			if _, e = js.UpdateStream(ctx, cfg); e != nil {
				t.Fatalf("promote %s/%s: %v", account, name, e)
			}
		}
		profilePromotionWait(t, "all exact replicas current", func() bool {
			probe, c := context.WithTimeout(ctx, time.Second)
			defer c()
			for name := range original {
				s, e := js.Stream(probe, name)
				if e != nil {
					return false
				}
				info, e := s.Info(probe)
				if e != nil || info.Cluster == nil || len(info.Cluster.Replicas) != 2 {
					return false
				}
				members := []string{info.Cluster.Leader}
				for _, r := range info.Cluster.Replicas {
					if !r.Current || r.Offline {
						return false
					}
					members = append(members, r.Name)
				}
				sort.Strings(members)
				if !reflect.DeepEqual(members, []string{"FRA_PEER", "GRU_SOURCE", "SFO_PEER"}) {
					return false
				}
			}
			return true
		})
		for streamName, snap := range original {
			for consumerName, c := range snap.consumers {
				cfg := c.Config
				cfg.Replicas = 3
				if _, e = js.UpdateConsumer(ctx, streamName, cfg); e != nil {
					t.Fatalf("promote consumer %s/%s: %v", streamName, consumerName, e)
				}
			}
		}
		profilePromotionWait(t, "all original consumers replicated", func() bool {
			probe, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			for streamName, snap := range original {
				for consumerName := range snap.consumers {
					c, e := js.Consumer(probe, streamName, consumerName)
					if e != nil {
						return false
					}
					info, e := c.Info(probe)
					if e != nil || info.Cluster == nil || len(info.Cluster.Replicas) != 2 {
						return false
					}
					for _, r := range info.Cluster.Replicas {
						if !r.Current || r.Offline {
							return false
						}
					}
				}
			}
			return true
		})
		profilePromotionVerify(t, ctx, js, original, true)
		profilePromotionSemantics(t, ctx, js, profiles[account])
		nc.Close()
		t.Logf("promoted %s: exact GRU/SFO/FRA replicas, in-memory Created/data/headers preserved before restart", account)
	}
	if !t.Run("PinnedNATSConsumerCreatedMetadataDivergence", func(t *testing.T) {
		profilePromotionRecordConsumerMetadataDefect(t, brokers, snapshots)
	}) {
		t.FailNow()
	}
	source.stop()
	for account, original := range snapshots {
		nc, js := brokers[1].client(t, account)
		profilePromotionWaitRecovered(t, ctx, js, original, false)
		profilePromotionVerify(t, ctx, js, original, true)
		profilePromotionSemantics(t, ctx, js, profiles[account])
		nc.Close()
	}
	t.Log("GRU offline: retained records and consumer checkpoints remain readable through SFO/FRA (read availability only)")
	source.start(t, true, brokers, budget)
	// Finish the GRU rejoin before exercising a separate full-cluster restart.
	for account, original := range snapshots {
		nc, js := source.client(t, account)
		profilePromotionWaitRecovered(t, ctx, js, original, true)
		nc.Close()
	}
	for _, b := range brokers {
		b.stop()
	}
	for _, b := range brokers {
		b.start(t, true, brokers, budget)
	}
	for account, original := range snapshots {
		nc, js := source.client(t, account)
		profilePromotionWaitRecovered(t, ctx, js, original, true)
		profilePromotionVerify(t, ctx, js, original, true)
		profilePromotionSemantics(t, ctx, js, profiles[account])
		nc.Close()
	}
	t.Log("full cluster restart: content/checkpoints preserved; consumer Created restricted to recorded divergent metadata")
	for account, original := range snapshots {
		nc, js := source.client(t, account)
		profilePromotionResumeConsumers(t, ctx, js, original)
		nc.Close()
	}
	t.Log("all3 original consumers resume exact next stream/consumer sequence and headers after fullR3restart")

	if digest := profilePromotionTreeDigest(t, originalStore); digest != originalDigest {
		t.Fatal("stopped original standalone store changed")
	}
	t.Log("stopped original standalone file-store digest unchanged:", originalDigest)

}

type profilePromotionArchive struct {
	config   server.StreamConfig
	state    server.StreamState
	data     []byte
	envelope []byte
}

func profilePromotionRestore(t *testing.T, ctx context.Context, nc *nats.Conn, archive profilePromotionArchive) {
	t.Helper()
	config := archive.config
	config.Placement = &server.Placement{Cluster: "CONTROL", Tags: []string{"region:gru"}}
	request, _ := json.Marshal(server.JSApiStreamRestoreRequest{Config: config, State: archive.state})

	var response server.JSApiStreamRestoreResponse
	var reply *nats.Msg
	var e error
	profilePromotionWait(t, "restore placement becomes eligible", func() bool {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		reply, e = nc.RequestWithContext(attempt, fmt.Sprintf(server.JSApiStreamRestoreT, config.Name), request)
		if e != nil {
			t.Fatal(e)
		}
		response = server.JSApiStreamRestoreResponse{}
		if e = json.Unmarshal(reply.Data, &response); e != nil {
			t.Fatal(e)
		}
		if response.Error != nil && response.Error.ErrCode == 10005 {
			return false
		}
		if response.Error != nil || response.DeliverSubject == "" {
			t.Fatalf("restore %s: %s", config.Name, reply.Data)
		}
		return true
	})

	for offset := 0; offset < len(archive.data); offset += 128 << 10 {
		end := offset + (128 << 10)
		if end > len(archive.data) {
			end = len(archive.data)
		}
		if _, e = nc.RequestWithContext(ctx, response.DeliverSubject, archive.data[offset:end]); e != nil {
			t.Fatal(e)
		}
	}
	reply, e = nc.RequestWithContext(ctx, response.DeliverSubject, nil)
	if e != nil {
		t.Fatal(e)
	}
	var final server.JSApiStreamCreateResponse
	if e = json.Unmarshal(reply.Data, &final); e != nil || final.Error != nil {
		t.Fatalf("restore final %s: %s %v", config.Name, reply.Data, e)
	}
}
func profilePromotionTreeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		fmt.Fprint(h, rel)
		h.Write(raw)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func profilePromotionSemantics(t *testing.T, ctx context.Context, js jetstream.JetStream, profile accountProfile) {
	t.Helper()
	for _, config := range profile.KV {
		kv, e := js.KeyValue(ctx, config.Bucket)
		if e != nil {
			t.Fatal(e)
		}
		entry, e := kv.Get(ctx, "profilePromotion")
		if e != nil || string(entry.Value()) != "retained:"+config.Bucket || entry.Revision() != 1 {
			t.Fatalf("KV semantics changed %s: %v", config.Bucket, e)
		}
		if _, e = kv.Get(ctx, "profilePromotion-deleted"); !errors.Is(e, jetstream.ErrKeyNotFound) && !errors.Is(e, jetstream.ErrKeyDeleted) {
			t.Fatalf("KV tombstone lost %s: %v", config.Bucket, e)
		}
	}
	for _, config := range profile.Objects {
		obj, e := js.ObjectStore(ctx, config.Bucket)
		if e != nil {
			t.Fatal(e)
		}
		value, e := obj.GetBytes(ctx, "profilePromotion")
		if e != nil || string(value) != "retained:"+config.Bucket {
			t.Fatalf("object semantics changed %s: %v", config.Bucket, e)
		}
	}
	profilePromotionWait(t, "object reader ephemeral consumers removed", func() bool {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		for _, config := range profile.Objects {
			stream, e := js.Stream(probe, "OBJ_"+config.Bucket)
			if e != nil {
				return false
			}
			names := stream.ConsumerNames(probe)
			count := 0
			for range names.Name() {
				count++
			}
			if names.Err() != nil || count != 0 {
				return false
			}
		}
		return true
	})

}

func profilePromotionResumeConsumers(t *testing.T, ctx context.Context, js jetstream.JetStream, original map[string]profilePromotionSnapshot) {
	t.Helper()
	for streamName, snapshot := range original {
		for name, old := range snapshot.consumers {
			subject := old.Config.FilterSubject
			if subject == "" {
				subject = snapshot.info.Config.Subjects[0]
			}
			subject = strings.ReplaceAll(strings.ReplaceAll(subject, ">", "profilePromotion"), "*", "profilePromotion")
			msg := nats.NewMsg(subject)
			msg.Data = []byte("post-promotion")
			msg.Header.Set("Audit-Resume", name)
			ack, e := js.PublishMsg(ctx, msg)
			if e != nil || ack.Sequence != snapshot.info.State.LastSeq+1 {
				t.Fatalf("next publication sequence %s: %+v %v", streamName, ack, e)
			}
			consumer, e := js.Consumer(ctx, streamName, name)
			if e != nil {
				t.Fatal(e)
			}
			batch, e := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
			if e != nil {
				t.Fatal(e)
			}
			received := 0
			for m := range batch.Messages() {
				meta, e := m.Metadata()
				if e != nil || meta.Sequence.Stream != ack.Sequence || meta.Sequence.Consumer != old.Delivered.Consumer+1 || string(m.Data()) != "post-promotion" || m.Headers().Get("Audit-Resume") != name {
					t.Fatalf("consumer did not resume exact next record %s: %+v %v", name, meta, e)
				}
				if e = m.DoubleAck(ctx); e != nil {
					t.Fatal(e)
				}
				received++
			}
			if e = batch.Error(); e != nil || received != 1 {
				t.Fatalf("resume %s: messages=%d error=%v", name, received, e)
			}
		}
	}
}

func profilePromotionWaitRecovered(t *testing.T, ctx context.Context, js jetstream.JetStream, original map[string]profilePromotionSnapshot, full bool) {
	t.Helper()
	var last error
	defer func() {
		if t.Failed() {
			t.Logf("last recovery observation: %v", last)
		}
	}()
	profilePromotionWait(t, "stream and consumer leadership recovered", func() bool { last = profilePromotionRecovered(ctx, js, original, full); return last == nil })
}
func profilePromotionRecovered(ctx context.Context, js jetstream.JetStream, original map[string]profilePromotionSnapshot, full bool) error {
	// One pass reads all15 streams and3 consumers, rather than one API request.
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ready := func(cluster *jetstream.ClusterInfo) error {
		if cluster == nil || cluster.Leader == "" {
			return fmt.Errorf("leader unavailable")
		}
		if !full {
			return nil
		}
		if len(cluster.Replicas) != 2 {
			return fmt.Errorf("replica count=%d", len(cluster.Replicas))
		}
		names := []string{cluster.Leader}
		for _, r := range cluster.Replicas {
			if !r.Current || r.Offline {
				return fmt.Errorf("peer %s current=%t offline=%t", r.Name, r.Current, r.Offline)
			}
			names = append(names, r.Name)
		}
		sort.Strings(names)
		if !reflect.DeepEqual(names, []string{"FRA_PEER", "GRU_SOURCE", "SFO_PEER"}) {
			return fmt.Errorf("unexpected replica set %v", names)
		}
		return nil
	}
	for name, snapshot := range original {
		stream, e := js.Stream(probe, name)
		if e != nil {
			return fmt.Errorf("stream %s lookup: %w", name, e)
		}
		info, e := stream.Info(probe)
		if e != nil {
			return fmt.Errorf("stream %s info: %w", name, e)
		}
		if info.Config.Replicas != 3 {
			return fmt.Errorf("stream %s replicas=%d", name, info.Config.Replicas)
		}
		if e = ready(info.Cluster); e != nil {
			return fmt.Errorf("stream %s: %w", name, e)
		}
		for consumerName := range snapshot.consumers {
			consumer, e := stream.Consumer(probe, consumerName)
			if e != nil {
				return fmt.Errorf("consumer %s/%s lookup: %w", name, consumerName, e)
			}
			info, e := consumer.Info(probe)
			if e != nil {
				return fmt.Errorf("consumer %s/%s info: %w", name, consumerName, e)
			}
			if !snapshot.consumerCreatedMatches(consumerName, info.Created) || info.Config.Replicas != 3 {
				return fmt.Errorf("consumer %s/%s Created=%s outside recorded metadata or replicas=%d", name, consumerName, info.Created, info.Config.Replicas)
			}
			if e = ready(info.Cluster); e != nil {
				return fmt.Errorf("consumer %s/%s: %w", name, consumerName, e)
			}
		}
	}
	return nil
}
