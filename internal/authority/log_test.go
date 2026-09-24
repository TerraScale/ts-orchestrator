package authority

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestVerifyControlStreamConfigRejectsMessageEviction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*jetstream.StreamConfig)
	}{
		{name: "max messages", mutate: func(config *jetstream.StreamConfig) { config.MaxMsgs = 100 }},
		{name: "max bytes", mutate: func(config *jetstream.StreamConfig) { config.MaxBytes = 1 << 20 }},
		{name: "max messages per subject", mutate: func(config *jetstream.StreamConfig) { config.MaxMsgsPerSubject = 10 }},
		{name: "max age", mutate: func(config *jetstream.StreamConfig) { config.MaxAge = 1 }},
		{name: "discard new per subject", mutate: func(config *jetstream.StreamConfig) { config.DiscardNewPerSubject = true }},
		{name: "rollup", mutate: func(config *jetstream.StreamConfig) { config.AllowRollup = true }},
		{name: "direct reads", mutate: func(config *jetstream.StreamConfig) { config.AllowDirect = true }},
		{name: "discard policy", mutate: func(config *jetstream.StreamConfig) { config.Discard = jetstream.DiscardNew }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := durableControlStreamConfig()
			test.mutate(&config)
			if err := verifyControlStreamConfig(config, defaultReplicas); err == nil {
				t.Fatal("verifyControlStreamConfig accepted an incompatible or unsafe config")
			}
		})
	}
}

func TestVerifyControlStreamConfigAcceptsDurableControlStream(t *testing.T) {
	if err := verifyControlStreamConfig(durableControlStreamConfig(), defaultReplicas); err != nil {
		t.Fatalf("verifyControlStreamConfig rejected the expected config: %v", err)
	}
}

func durableControlStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              ControlStreamName,
		Subjects:          []string{controlStreamSubject},
		Retention:         jetstream.LimitsPolicy,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: -1,
		Storage:           jetstream.FileStorage,
		Replicas:          defaultReplicas,
		DenyDelete:        true,
		DenyPurge:         true,
		Metadata:          map[string]string{"terrascale-contract": "authority-log-v1"},
	}
}

func TestPlacementIntentIdentityIncludesPartitionAndIgnoresLeaseHistory(t *testing.T) {
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })

	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{
		Scope: "gru", CandidateID: "candidate-a", LeaseDuration: time.Second,
		RenewInterval: 10 * time.Millisecond, Replicas: 1,
	})
	if err != nil {
		t.Fatalf("start authority runtime: %v", err)
	}
	observedStream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatalf("open independent stream observer: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close authority runtime: %v", err)
		}
	})
	epoch := runtime.Current().Epoch
	if epoch == 0 || !runtime.Current().CanMutate() {
		t.Fatalf("runtime did not acquire authority: %+v", runtime.Current())
	}
	if _, err := runtime.CommitHostMutation(ctx, epoch, MutationRegistration, "gru.node-a", "host-operation", 0, []byte("host")); err != nil {
		t.Fatalf("commit host registration for concurrent reads: %v", err)
	}

	firstSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "db-a", "partition-a", "operation-a", 0, []byte("first"))
	if err != nil {
		t.Fatalf("commit first partition: %v", err)
	}
	secondSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "db-a", "partition-b", "operation-b", 0, []byte("second"))
	if err != nil {
		t.Fatalf("commit second partition of the same database: %v", err)
	}
	if secondSequence <= firstSequence {
		t.Fatalf("second partition sequence %d did not follow first %d", secondSequence, firstSequence)
	}
	if _, err := runtime.CommitPlacementIntent(ctx, epoch, "db-a", "partition-a", "operation-c", 0, []byte("stale")); err != ErrConflict {
		t.Fatalf("stale same-partition write returned %v, want ErrConflict", err)
	}

	updatedSequence, err := runtime.CommitPlacementIntent(ctx, epoch, "db-a", "partition-a", "operation-c", firstSequence, []byte("updated"))
	if err != nil {
		t.Fatalf("commit same-partition update at current sequence: %v", err)
	}
	if updatedSequence <= firstSequence {
		t.Fatalf("updated partition sequence %d did not follow first %d", updatedSequence, firstSequence)
	}
	updated, err := runtime.ReadPlacementIntent(ctx, "db-a", "partition-a")
	if err != nil || updated.SubjectKey != "db-a.partition-a" || updated.Sequence != updatedSequence || string(updated.Payload) != "updated" {
		t.Fatalf("read updated partition: entry=%+v err=%v", updated, err)
	}
	independent, err := runtime.ReadPlacementIntent(ctx, "db-a", "partition-b")
	if err != nil || independent.SubjectKey != "db-a.partition-b" || independent.Sequence != secondSequence || string(independent.Payload) != "second" {
		t.Fatalf("read independent partition: entry=%+v err=%v", independent, err)
	}
	reader, err := OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatalf("open shared reader: %v", err)
	}
	info, err := observedStream.Info(ctx)
	if err != nil || info.Config.AllowDirect {
		t.Fatalf("control stream direct-read setting = %v, error = %v; want disabled", info.Config.AllowDirect, err)
	}
	observed, err := Observe(ctx, js, "gru")
	if err != nil || observed.Epoch != epoch {
		t.Fatalf("observe current lease through leader-backed read: snapshot=%+v err=%v", observed, err)
	}

	var readers sync.WaitGroup
	readErrors := make(chan error, 4)
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 8 {
				if entry, err := runtime.ReadHostMutation(ctx, MutationRegistration, "gru.node-a"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("runtime host mutation read returned no committed record"))
					return
				}
				if entry, err := runtime.ReadPlacementIntent(ctx, "db-a", "partition-a"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("runtime placement read returned no committed record"))
					return
				}
				if _, err := runtime.ListPlacementIntents(ctx); err != nil {
					readErrors <- fmt.Errorf("runtime placement list: %w", err)
					return
				}
				if entry, err := reader.ReadHostMutation(ctx, MutationRegistration, "gru.node-a"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("reader host mutation read returned no committed record"))
					return
				}
				if entry, err := reader.ReadPlacementIntent(ctx, "db-a", "partition-b"); err != nil || entry.Sequence == 0 {
					readErrors <- errors.Join(err, errors.New("reader placement read returned no committed record"))
					return
				}
				if _, err := reader.ListPlacementIntents(ctx); err != nil {
					readErrors <- fmt.Errorf("reader placement list: %w", err)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(readErrors)
	for err := range readErrors {
		t.Errorf("concurrent authority read: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		info, err := observedStream.Info(ctx)
		if err != nil {
			t.Fatalf("read authority stream state: %v", err)
		}
		if info.State.Msgs >= 25 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease renewals did not produce enough history: %d messages", info.State.Msgs)
		}
		time.Sleep(5 * time.Millisecond)
	}

	intents, err := runtime.ListPlacementIntents(ctx)
	if err != nil {
		t.Fatalf("list current placement intents after lease renewals: %v", err)
	}
	if len(intents) != 2 || intents[0].SubjectKey != "db-a.partition-a" || intents[1].SubjectKey != "db-a.partition-b" {
		t.Fatalf("listed placement identities = %+v, want both distinct partitions", intents)
	}
}
