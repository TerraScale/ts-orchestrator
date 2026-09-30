package natscell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestEmbeddedSingleNodeDurableRestart(t *testing.T) {
	cfg := Config{
		Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := r.JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: "LAB_EVENTS", Subjects: []string{"lab.events"}, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.JetStream().Publish(ctx, "lab.events", []byte("persisted")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	r, err = Start(ctx, cfg)
	if err != nil {
		t.Fatal("restart:", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	stream, err = r.JetStream().Stream(ctx, stream.CachedInfo().Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data) != "persisted" {
		t.Fatalf("durable message = %q", message.Data)
	}
}

func TestEmbeddedStoreLimit(t *testing.T) {
	embedded := &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir()}
	cfg := Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true, Embedded: embedded}
	for _, test := range []struct {
		name  string
		limit int64
		want  int64
	}{
		{name: "default", want: DefaultStoreMaxBytes},
		{name: "configured", limit: 4 << 30, want: 4 << 30},
	} {
		t.Run(test.name, func(t *testing.T) {
			embedded.StoreMaxBytes = test.limit
			options, err := serverOptions(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if options.JetStreamMaxStore != test.want {
				t.Fatalf("JetStream file limit = %d, want %d", options.JetStreamMaxStore, test.want)
			}
		})
	}
	embedded.StoreMaxBytes = -1
	if err := cfg.validate(); err == nil {
		t.Fatal("negative embedded store limit was accepted")
	}
}

func TestControllerNKeyDurablyAcknowledgesDeliveryIntent(t *testing.T) {
	public, seed := newUserIdentity(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	runtime, err := Start(ctx, Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		NKeySeedFile: seed, Embedded: &Embedded{Host: "127.0.0.1", Port: -1,
			StoreDir: t.TempDir(), Users: []NKeyGrant{{PublicKey: public, Role: "controller"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	_, err = runtime.JetStream().CreateStream(ctx, jetstream.StreamConfig{Name: "TS_DELIVERY_INTENTS",
		Subjects: []string{"ts.orch.v1.lab.delivery.intent"}, Retention: jetstream.WorkQueuePolicy,
		Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := runtime.JetStream().CreateConsumer(ctx, "TS_DELIVERY_INTENTS", jetstream.ConsumerConfig{
		Durable: "TS_DELIVERY_WORKER", AckPolicy: jetstream.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := runtime.JetStream().Publish(ctx, "ts.orch.v1.lab.delivery.intent", []byte("accepted"))
	if err != nil {
		t.Fatal(err)
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := message.DoubleAck(ctx); err != nil {
		t.Fatalf("controller could not durably acknowledge delivery intent: %v", err)
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.AckFloor.Stream != ack.Sequence || info.NumAckPending != 0 {
		t.Fatalf("delivery intent remained pending after acknowledgement: ack floor=%d pending=%d", info.AckFloor.Stream, info.NumAckPending)
	}
}

func TestEmbeddedClusterAdvertisesClientPeers(t *testing.T) {
	const peers = 3
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	routePorts := make([]int, peers)
	for index := range routePorts {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		routePorts[index] = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	routes := make([]string, peers)
	for index, port := range routePorts {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", port)
	}
	runtimes := make([]*Runtime, peers)
	for index := range runtimes {
		instance := fmt.Sprintf("peer%d", index)
		runtime, err := Start(ctx, Config{Cell: "lab", Instance: instance, Replicas: peers, Lab: true,
			Embedded: &Embedded{Host: "127.0.0.1", Port: -1, RouteHost: "127.0.0.1", RoutePort: routePorts[index],
				Routes: routes, StoreDir: filepath.Join(t.TempDir(), instance)},
		})
		if err != nil {
			t.Fatal(err)
		}
		runtimes[index] = runtime
		t.Cleanup(func() { _ = runtime.Close() })
	}
	for _, runtime := range runtimes {
		if err := runtime.WaitForCluster(ctx, peers); err != nil {
			for _, peer := range runtimes {
				info, infoErr := peer.server.Jsz(nil)
				if infoErr == nil {
					t.Logf("%s metadata: %+v routes=%d", peer.URL(), info.Meta, peer.peerCount())
					if info.Meta != nil {
						for _, replica := range info.Meta.Replicas {
							t.Logf("%s metadata replica: %+v", peer.URL(), *replica)
						}
					}
				}
			}
			t.Fatal(err)
		}
	}
	for _, runtime := range runtimes {
		for {
			servers := runtime.Conn().Servers()
			if slices.ContainsFunc(runtimes, func(peer *Runtime) bool { return !slices.Contains(servers, peer.URL()) }) {
				if err := ctx.Err(); err != nil {
					t.Fatalf("cluster client URLs were not discovered: %v; known %v", err, servers)
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			break
		}
	}
}

func TestHostNKeyCannotCrossNodeOrUseJetStream(t *testing.T) {
	controllerPublic, controllerSeed := newUserIdentity(t)
	hostPublic, hostSeed := newUserIdentity(t)
	otherPublic, _ := newUserIdentity(t)
	serverConfig := Config{
		Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		NKeySeedFile: controllerSeed,
		Embedded: &Embedded{
			Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "store"),
			Users: []NKeyGrant{
				{PublicKey: controllerPublic, Role: "controller"},
				{PublicKey: hostPublic, Role: "host", Node: "node-one"},
				{PublicKey: otherPublic, Role: "host", Node: "node-two"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	controller, err := Start(ctx, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	host, err := Start(ctx, Config{Cell: "lab", Instance: "host-one", Replicas: 1, Lab: true,
		URL: controller.URL(), NKeySeedFile: hostSeed, ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	observations, err := controller.Conn().SubscribeSync("ts.orch.v1.lab.agent.*.observation.*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observations.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	allowed := "ts.orch.v1.lab.agent." + hostPublic + ".observation.report"
	if err := host.Conn().Publish(allowed, []byte("own")); err != nil {
		t.Fatal(err)
	}
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	message, err := observations.NextMsg(time.Second)
	if err != nil || string(message.Data) != "own" {
		t.Fatalf("own observation was not delivered: %v %v", message, err)
	}
	forbidden := "ts.orch.v1.lab.agent." + otherPublic + ".observation.report"
	_ = host.Conn().Publish(forbidden, []byte("spoof"))
	_ = host.Conn().FlushTimeout(time.Second)
	if _, err := observations.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host published another node's observation: %v", err)
	}
	otherInbox, err := host.Conn().SubscribeSync(inboxPrefix("lab", otherPublic) + ".probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherInbox.Unsubscribe() })
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().Publish(inboxPrefix("lab", otherPublic)+".probe", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := otherInbox.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host subscribed to another node's replies: %v", err)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer probeCancel()
	if _, err := host.JetStream().AccountInfo(probeCtx); err == nil {
		t.Fatal("host accessed JetStream account API")
	}
}

func TestLabTerminalPermissionsAreRoleScoped(t *testing.T) {
	public, _ := newUserIdentity(t)
	controller, err := userPermissions("lab", NKeyGrant{PublicKey: public, Role: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(controller.Subscribe.Allow, "ts.orch.v1.lab.terminal.>") {
		t.Fatal("controller cannot subscribe to terminal requests")
	}
	if !slices.Contains(controller.Subscribe.Allow, "ts.orch.v1.lab.managed-update.prepare") {
		t.Fatal("controller cannot subscribe to managed update requests")
	}
	if !slices.Contains(controller.Subscribe.Allow, "ts.orch.v1.lab.backup.operation") {
		t.Fatal("controller cannot subscribe to backup operation requests")
	}
	operator, err := userPermissions("lab", NKeyGrant{PublicKey: public, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"ts.orch.v1.lab.managed-update.prepare", "ts.orch.v1.lab.backup.operation", "ts.orch.v1.lab.terminal.plan", "ts.orch.v1.lab.terminal.apply", "ts.orch.v1.lab.terminal.status"} {
		if !slices.Contains(operator.Publish.Allow, subject) {
			t.Fatalf("operator cannot publish %s", subject)
		}
	}
	if slices.Contains(operator.Publish.Allow, "ts.orch.v1.lab.terminal.>") ||
		slices.Contains(operator.Subscribe.Allow, "ts.orch.v1.lab.terminal.>") {
		t.Fatal("operator received wildcard terminal permissions")
	}
}

func TestOperatorNKeyCanUseClientAPIsButCannotWriteControllerState(t *testing.T) {
	controllerPublic, controllerSeed := newUserIdentity(t)
	operatorPublic, operatorSeed := newUserIdentity(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	controller, err := Start(ctx, Config{
		Cell: "lab", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "store"),
			Users: []NKeyGrant{{PublicKey: controllerPublic, Role: "controller"}, {PublicKey: operatorPublic, Role: "operator"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	for _, bucket := range []string{"TS_DELIVERY_ADMISSIONS", "TS_DELIVERY_OPERATIONS", "TS_HOST_STATE"} {
		store, err := controller.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Replicas: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PutString(ctx, "probe", "trusted"); err != nil {
			t.Fatal(err)
		}
	}
	objects, err := controller.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "TS_ARTIFACTS", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.JetStream().CreateStream(ctx, jetstream.StreamConfig{Name: "TS_CONTROL_LOG", Subjects: []string{"ts.control.lab.>"}, Replicas: 1, AllowDirect: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.JetStream().Publish(ctx, "ts.control.lab.lease", []byte("test")); err != nil {
		t.Fatal(err)
	}
	operator, err := Start(ctx, Config{Cell: "lab", Instance: "operator", Replicas: 1, Lab: true,
		URL: controller.URL(), NKeySeedFile: operatorSeed, ClientRole: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = operator.Close() })
	for _, bucket := range []string{"TS_DELIVERY_ADMISSIONS", "TS_DELIVERY_OPERATIONS", "TS_HOST_STATE"} {
		store, err := operator.JetStream().KeyValue(ctx, bucket)
		if err != nil {
			t.Fatalf("bind %s: %v", bucket, err)
		}
		entry, err := store.Get(ctx, "probe")
		if err != nil || string(entry.Value()) != "trusted" {
			t.Fatalf("read %s: %v", bucket, err)
		}
		deniedCtx, deniedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
		_, err = store.PutString(deniedCtx, "probe", "forged")
		deniedCancel()
		if err == nil {
			t.Fatalf("operator wrote controller-owned %s", bucket)
		}
	}
	clientObjects, err := operator.JetStream().ObjectStore(ctx, "TS_ARTIFACTS")
	if err != nil {
		t.Fatal(err)
	}
	artifactInfo, err := clientObjects.Put(ctx, jetstream.ObjectMeta{Name: "artifact"}, bytes.NewReader([]byte("content")))
	if err != nil {
		t.Fatalf("operator artifact upload: %v", err)
	}
	artifactStream, err := operator.JetStream().Stream(ctx, "OBJ_TS_ARTIFACTS")
	if err != nil {
		t.Fatalf("bind artifact chunk stream: %v", err)
	}
	chunk, err := artifactStream.GetMsg(ctx, 1, jetstream.WithGetMsgSubject("$O.TS_ARTIFACTS.C."+artifactInfo.NUID))
	if err != nil || chunk == nil || string(chunk.Data) != "content" {
		t.Fatalf("operator direct artifact chunk read: %v, chunk=%v", err, chunk)
	}
	if _, err := objects.GetInfo(ctx, "artifact"); err != nil {
		t.Fatal(err)
	}
	readback, err := clientObjects.Get(ctx, "artifact")
	if err != nil {
		t.Fatalf("operator artifact readback: %v", err)
	}
	contents, err := io.ReadAll(readback)
	readback.Close()
	if err != nil || string(contents) != "content" {
		t.Fatalf("operator artifact readback bytes: %q, %v", contents, err)
	}
	log, err := operator.JetStream().Stream(ctx, "TS_CONTROL_LOG")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.GetLastMsgForSubject(ctx, "ts.control.lab.lease"); err != nil {
		t.Fatalf("operator observe lease: %v", err)
	}
	deniedCtx, deniedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, err = operator.JetStream().Publish(deniedCtx, "ts.control.lab.lease", []byte("forged"))
	deniedCancel()
	if err == nil {
		t.Fatal("operator forged an authority lease")
	}
	requests, err := controller.Conn().SubscribeSync("ts.orch.v1.lab.delivery.artifact.admit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requests.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := operator.Conn().Publish("ts.orch.v1.lab.delivery.artifact.admit", []byte("signed")); err != nil {
		t.Fatal(err)
	}
	if _, err := requests.NextMsg(time.Second); err != nil {
		t.Fatalf("operator artifact claim publish: %v", err)
	}
	backupRequests, err := controller.Conn().Subscribe("ts.orch.v1.lab.backup.operation", func(message *nats.Msg) {
		_ = message.Respond([]byte("accepted"))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backupRequests.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	backupReply, err := operator.Conn().RequestWithContext(ctx, "ts.orch.v1.lab.backup.operation", []byte("signed"))
	if err != nil {
		t.Fatalf("operator backup operation request: %v", err)
	}
	if string(backupReply.Data) != "accepted" ||
		!strings.HasPrefix(backupReply.Subject, inboxPrefix("lab", operatorPublic)+".") {
		t.Fatalf("backup operation response did not use the operator's private inbox: subject=%s body=%q",
			backupReply.Subject, backupReply.Data)
	}
}

func newUserIdentity(t *testing.T) (string, string) {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), "user.nk")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}
