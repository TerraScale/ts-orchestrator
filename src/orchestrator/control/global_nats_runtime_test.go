package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestGlobalNatsRuntimeRequiresCompleteGRUConfiguration(t *testing.T) {
	if _, err := GlobalNatsRuntimeStartAsync(context.Background(), nil); err == nil {
		t.Fatal("nil configuration was accepted")
	}
	configuration := &GlobalNatsRuntimeConfiguration{
		Authority: &GlobalAuthorityNatsConfiguration{
			Url: "tls://127.0.0.1:4222", Authentication: &NatsAuthenticationFiles{PublicKey: "UA"},
			Tls: &NatsTlsFiles{CaFile: "ca", CertificateFile: "authority", KeyFile: "key"}, Replicas: 3, Cell: "gru",
		},
		Cell: "sfo", Instance: "one",
	}
	if _, err := GlobalNatsRuntimeStartAsync(context.Background(), configuration); err == nil {
		t.Fatal("non-GRU authority configuration was accepted")
	}
}

func TestGlobalNatsRuntimeOpenAndValidateRequiresPreProvisionedGlobalState(t *testing.T) {
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server did not become ready")
	}
	client, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	topology, err := NewGlobalNatsTopology(3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := globalNatsRuntimeOpenAndValidate(ctx, client, topology, false, "gru"); err == nil {
		t.Fatal("global runtime accepted a topology that was not provisioned")
	}
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(ctx, GlobalNatsTopologyCellSpecStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("validation created a stream: %v", err)
	}
}

func TestGlobalNatsRuntimeConnectHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	configuration := &GlobalAuthorityNatsConfiguration{
		Url: "tls://127.0.0.1:1", Authentication: &NatsAuthenticationFiles{PublicKey: "UA"},
		Tls: &NatsTlsFiles{CaFile: "ca", CertificateFile: "authority", KeyFile: "key"}, Replicas: 3, Cell: "gru",
	}
	runtimeConfiguration := &GlobalNatsRuntimeConfiguration{Authority: configuration, Cell: "gru", Instance: "one"}
	_, err := GlobalNatsRuntimeStartAsync(ctx, runtimeConfiguration)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

type globalRuntimeTestComponent struct {
	done  chan struct{}
	close func()
}

func (c *globalRuntimeTestComponent) Completion() <-chan struct{} { return c.done }
func (c *globalRuntimeTestComponent) Close() error {
	if c.close != nil {
		c.close()
	}
	return nil
}

func TestGlobalNatsRuntimeCloseIsIdempotentAndReverseOrdered(t *testing.T) {
	order := []string{}
	delivery := &globalRuntimeTestComponent{done: make(chan struct{}), close: func() { order = append(order, "delivery") }}
	runtime := &GlobalNatsRuntime{delivery: delivery, complete: make(chan struct{})}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 1 || order[0] != "delivery" {
		t.Fatalf("close order = %#v", order)
	}
	select {
	case <-runtime.Completion():
	default:
		t.Fatal("completion did not close")
	}
}

func TestGlobalRuntimeOpensDeliveryTopologyWithoutCIStores(t *testing.T) {
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	authorityKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer authorityKey.Wipe()
	authorityPublic, err := authorityKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := GlobalNatsPermissionsCreate("gru", GlobalNatsRoleGlobalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authorityUser := &server.NkeyUser{Nkey: authorityPublic, Permissions: &server.Permissions{
		Publish:   &server.SubjectPermission{Allow: permissions.Publish},
		Subscribe: &server.SubjectPermission{Allow: permissions.Subscribe},
	}}
	var cluster []*server.Server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	route, _ := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
	for i := 0; i < 3; i++ {
		options := &server.Options{SystemAccount: "$SYS", Accounts: []*server.Account{server.NewAccount("$SYS")}, Nkeys: []*server.NkeyUser{{Nkey: public}, authorityUser}, ServerName: fmt.Sprintf("global-delivery-%d", i), Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir(), Cluster: server.ClusterOpts{Name: "global-delivery", Host: "127.0.0.1", Port: -1}}
		options.Routes = []*url.URL{route}
		if i == 0 {
			options.Cluster.Port = port
		}
		instance, err := server.NewServer(options)
		if err != nil {
			t.Fatal(err)
		}
		instance.Start()
		cluster = append(cluster, instance)
		t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	}
	for _, instance := range cluster {
		if !instance.ReadyForConnections(5 * time.Second) {
			t.Fatal("cluster member not ready")
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := false
		for _, instance := range cluster {
			ready = ready || (instance.JetStreamIsLeader() && len(instance.JetStreamClusterPeers()) == 3)
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("global metadata quorum not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := nats.Connect(cluster[0].ClientURL(), nats.Nkey(public, key.Sign))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := NewGlobalNatsTopology(3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, config := range topology.Streams() {
		if _, err := js.CreateStream(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	for _, config := range []jetstream.KeyValueConfig{topology.Leaders(), topology.Cells(), topology.MasterDeliveries()} {
		if _, err := js.CreateKeyValue(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	authorityClient, err := nats.Connect(cluster[0].ClientURL(), nats.Nkey(authorityPublic, authorityKey.Sign))
	if err != nil {
		t.Fatal(err)
	}
	defer authorityClient.Close()
	consumerConfig, err := topology.CellSpecConsumer("gru")
	if err != nil {
		t.Fatal(err)
	}
	if consumerConfig.Durable != consumerConfig.Name || consumerConfig.InactiveThreshold != 0 {
		t.Fatal("global desired consumer must be durable without idle expiry")
	}
	specStream, err := js.Stream(ctx, GlobalNatsTopologyCellSpecStream)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the retired named-ephemeral profile on the real R3 broker.
	ephemeral := consumerConfig
	ephemeral.Durable = ""
	if _, err := specStream.CreateConsumer(ctx, ephemeral); err != nil {
		t.Fatal(err)
	}
	if _, err := globalNatsRuntimeOpenAndValidate(ctx, authorityClient, topology, true, "gru"); err == nil {
		t.Fatal("restricted runtime admitted an ephemeral desired consumer")
	}
	if err := specStream.DeleteConsumer(ctx, consumerConfig.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := specStream.CreateConsumer(ctx, consumerConfig); err != nil {
		t.Fatal(err)
	}
	state, err := globalNatsRuntimeOpenAndValidate(ctx, authorityClient, topology, true, "gru")
	if err != nil {
		t.Fatalf("restricted R3 runtime rejected durable desired consumer: %v", err)
	}
	info, err := state.cellSpec.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !NatsConsumerProfileMatches(info, consumerConfig, GlobalNatsTopologyCellSpecStream) || info.Config.Durable != consumerConfig.Name || info.Config.InactiveThreshold != 0 {
		t.Fatalf("broker desired profile drift: %+v", info.Config)
	}
	if _, err := js.Publish(ctx, consumerConfig.FilterSubject, []byte("desired-one")); err != nil {
		t.Fatal(err)
	}
	message, err := state.cellSpec.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data()) != "desired-one" {
		t.Fatal("wrong desired message")
	}
	if err := message.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	reopenedState, err := globalNatsRuntimeOpenAndValidate(ctx, authorityClient, topology, true, "gru")
	if err != nil {
		t.Fatal(err)
	}
	reopenedInfo, err := reopenedState.cellSpec.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedInfo.AckFloor.Stream != 1 || reopenedInfo.NumAckPending != 0 {
		t.Fatal("durable acknowledgement checkpoint lost on reopen")
	}
	names := js.StreamNames(ctx)
	var actual []string
	for name := range names.Name() {
		actual = append(actual, name)
	}
	if names.Err() != nil {
		t.Fatal(names.Err())
	}
	sort.Strings(actual)
	wanted := []string{"GLOBAL_SPEC", "KV_GLOBAL_CELLS", "KV_GLOBAL_DELIVERIES", "KV_ORCH_LEADERS"}
	if !reflect.DeepEqual(actual, wanted) {
		t.Fatalf("unexpected global streams: %v", actual)
	}
	authorityJS, err := jetstream.New(authorityClient)
	if err != nil {
		t.Fatal(err)
	}
	leaders, err := authorityJS.KeyValue(ctx, "ORCH_LEADERS")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := leaders.Create(ctx, "authority.global", []byte("lease-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaders.Update(ctx, "authority.global", []byte("renewed-lease-fixture"), revision); err != nil {
		t.Fatal(err)
	}
	if _, err := leaders.Get(ctx, "authority.global"); err != nil {
		t.Fatal(err)
	}
	journal, err := authorityJS.KeyValue(ctx, "GLOBAL_DELIVERIES")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Create(ctx, "master.signed-intent", []byte("durable-signed-delivery-fixture")); err != nil {
		t.Fatal(err)
	}
	reopened, err := authorityJS.KeyValue(ctx, "GLOBAL_DELIVERIES")
	if err != nil {
		t.Fatal(err)
	}
	value, err := reopened.Get(ctx, "master.signed-intent")
	if err != nil || string(value.Value()) != "durable-signed-delivery-fixture" {
		t.Fatal("delivery state did not survive reopen")
	}
	var capacity int64
	for _, config := range topology.Streams() {
		capacity += config.MaxBytes
	}
	for _, config := range []jetstream.KeyValueConfig{topology.Leaders(), topology.Cells(), topology.MasterDeliveries()} {
		capacity += config.MaxBytes
	}
	if capacity != 1352<<20 {
		t.Fatalf("global budget=%d; want 1352MiB per replica", capacity)
	}
}
