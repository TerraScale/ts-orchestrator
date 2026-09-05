//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

func TestQualificationNATSRequiresTLSIdentityAndNKey(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	controllerOptions, err := authority.options(authority.controller)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := nats.Connect(server.ClientURL(), controllerOptions...)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	state, err := controller.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatalf("unverified TLS: %+v %v", state, err)
	}
	for name, options := range map[string][]nats.Option{
		"no-credentials":        {nats.Timeout(time.Second), nats.NoReconnect()},
		"no-nkey":               {nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authority.roots, ServerName: authority.serverName, Certificates: []tls.Certificate{authority.controller.tls}}), nats.Timeout(time.Second), nats.NoReconnect()},
		"no-client-certificate": {nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authority.roots, ServerName: authority.serverName}), nats.Nkey(authority.controller.publicKey, authority.controller.pair.Sign), nats.Timeout(time.Second), nats.NoReconnect()},
	} {
		t.Run(name, func(t *testing.T) {
			connection, err := nats.Connect(server.ClientURL(), options...)
			if err == nil {
				connection.Close()
				t.Fatal("incomplete authentication accepted")
			}
		})
	}
	guest := authority.guests["gru-member-1"]
	options, err := authority.options(guest)
	if err != nil {
		t.Fatal(err)
	}
	denied := make(chan error, 4)
	options = append(options, nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	connection, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	other, _ := hostagent.NewNodeId("gru-member-2")
	subject, _ := hostagent.NodeDrainSubject(other)
	_, err = connection.Subscribe(subject, func(*nats.Msg) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-denied:
		if !strings.Contains(err.Error(), "Permissions Violation") {
			t.Fatalf("unexpected refusal: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("guest subscribed to another host's commands")
	}
}

func TestQualificationJetStreamPersistsTransportData(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	options, err := authority.options(authority.controller)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{Name: "VMQ_TRANSPORT_TEST", Subjects: []string{"vmqual.transport.test"}, Storage: jetstream.FileStorage, Replicas: 1, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "vmqual.transport.test", []byte("durable transport record")); err != nil {
		t.Fatal(err)
	}
	store := server.JetStreamConfig().StoreDir
	conn.Close()
	server.Shutdown()
	server.WaitForShutdown()
	restarted, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, Nkeys: authority.users, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{authority.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: authority.roots}, JetStream: true, StoreDir: store})
	if err != nil {
		t.Fatal(err)
	}
	restarted.Start()
	defer func() { restarted.Shutdown(); restarted.WaitForShutdown() }()
	if !restarted.ReadyForConnections(time.Second) {
		t.Fatal("restarted authenticated fixture not ready")
	}
	conn, err = nats.Connect(restarted.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	js, err = jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, "VMQ_TRANSPORT_TEST")
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(ctx, 1)
	if err != nil || string(message.Data) != "durable transport record" {
		t.Fatalf("persisted data unavailable: %+v %v", message, err)
	}
}

func TestQualificationTransportCannotClaimControlQuorum(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	factory := &firecrackerFactory{services: &qualificationRuntimeServices{started: true, nats: server, natsAuthority: authority}}
	runtime, bindings, err := factory.QualificationControlRuntime(context.Background())
	if !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) || runtime != nil || len(bindings) != 0 {
		t.Fatalf("transport was accepted as control proof: %v %+v %v", runtime, bindings, err)
	}
}
