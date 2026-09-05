package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

const localControlSnapshotStream = "VMQUAL_CONTROL_STATE"

type localControlJetStream struct {
	server     *natsserver.Server
	connection *nats.Conn
	storeDir   string
}

func newLocalControlJetStreamSnapshotter(ctx context.Context, objects *localOperationsObjectStore, now func() time.Time) (*restoredrill.NATSJetStreamSnapshotter, *localControlJetStream, error) {
	storeDir, err := os.MkdirTemp("", "vmqual-control-jetstream-")
	if err != nil {
		return nil, nil, err
	}
	instance, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "vmqual-control-snapshot", Host: "127.0.0.1", Port: -1,
		JetStream: true, StoreDir: storeDir, NoLog: true, NoSigs: true,
		MaxConn: 32, MaxPayload: 2 << 20,
	})
	if err != nil {
		_ = os.RemoveAll(storeDir)
		return nil, nil, err
	}
	owner := &localControlJetStream{server: instance, storeDir: storeDir}
	instance.Start()
	if !instance.ReadyForConnections(5 * time.Second) {
		_ = owner.Close()
		return nil, nil, errors.New("vmqual: embedded control JetStream did not become ready")
	}
	connection, err := nats.Connect(instance.ClientURL(), nats.Name("vmqual-control-snapshot"), nats.NoReconnect(), nats.Timeout(5*time.Second))
	if err != nil {
		_ = owner.Close()
		return nil, nil, err
	}
	owner.connection = connection
	js, err := jetstream.New(connection)
	if err != nil {
		_ = owner.Close()
		return nil, nil, err
	}
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: localControlSnapshotStream, Subjects: []string{"vmqual.control.>"},
		Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
	}); err != nil {
		_ = owner.Close()
		return nil, nil, err
	}
	controlDocuments := []struct {
		subject string
		body    []byte
	}{
		{subject: "vmqual.control.estate.regions", body: []byte(`{"generation":3,"regions":["gru","sfo","fra"]}`)},
		{subject: "vmqual.control.estate.hosts", body: []byte(`{"generation":3,"hosts":["gru-member-1","gru-member-2"]}`)},
		{subject: "vmqual.control.authority", body: []byte(`{"acceptedEpoch":3,"mode":"r3"}`)},
	}
	for index, document := range controlDocuments {
		if _, err := js.Publish(ctx, document.subject, document.body, jetstream.WithMsgID(fmt.Sprintf("vmqual-control-%d", index+1))); err != nil {
			_ = owner.Close()
			return nil, nil, err
		}
	}
	snapshotter, err := restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{
		Connection: connection, Stream: localControlSnapshotStream, Store: objects,
		Region: operationsControlRegion, Bucket: operationsControlBucket,
		MaxBytes: 16 << 20, Timeout: 30 * time.Second, Now: now,
	})
	if err != nil {
		_ = owner.Close()
		return nil, nil, err
	}
	return snapshotter, owner, nil
}

func (s *localControlJetStream) Close() error {
	if s == nil {
		return nil
	}
	if s.connection != nil {
		s.connection.Close()
		s.connection = nil
	}
	if s.server != nil {
		s.server.Shutdown()
		s.server.WaitForShutdown()
		s.server = nil
	}
	if s.storeDir != "" {
		err := os.RemoveAll(s.storeDir)
		s.storeDir = ""
		return err
	}
	return nil
}
