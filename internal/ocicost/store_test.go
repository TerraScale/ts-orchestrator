package ocicost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, testJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	want := storeTestReport(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	if err := store.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report round trip = %+v, want %+v", got, want)
	}
}

func TestStoreReportBeforePutIsNoReport(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, testJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Report(ctx); !errors.Is(err, ErrNoReport) {
		t.Fatalf("Report before Put = %v, want ErrNoReport", err)
	}
}

func TestStorePutRejectsInvalidReport(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, testJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	invalid := storeTestReport(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	invalid.Version = 0
	if err := store.Put(ctx, invalid); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("Put invalid report = %v, want ErrInvalidReport", err)
	}
	if _, err := store.Report(ctx); !errors.Is(err, ErrNoReport) {
		t.Fatalf("Report after rejected Put = %v, want ErrNoReport", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "wrong version", mutate: func(r *Report) { r.Version = Version + 1 }},
		{name: "empty cell", mutate: func(r *Report) { r.Cell = "" }},
		{name: "upper-case cell", mutate: func(r *Report) { r.Cell = "GRU" }},
		{name: "empty OCI region", mutate: func(r *Report) { r.OCIRegion = "" }},
		{name: "lower-case currency", mutate: func(r *Report) { r.Currency = "usd" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := validReport()
			tc.mutate(&report)
			if err := store.Put(t.Context(), report); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("Put invalid report = %v, want ErrInvalidReport", err)
			}
			if _, err := store.Report(t.Context()); !errors.Is(err, ErrNoReport) {
				t.Fatalf("Report after rejected Put = %v, want ErrNoReport", err)
			}
		})
	}
}

func TestStoreReportRejectsCorruptValue(t *testing.T) {
	ctx := context.Background()
	js := testJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, reportKey, []byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Report(ctx); err == nil || errors.Is(err, ErrNoReport) {
		t.Fatalf("Report of corrupt value = %v, want a decode error", err)
	}
}

func TestOpenStoreRequiresReplicatedJetStream(t *testing.T) {
	ctx := context.Background()
	if _, err := OpenStore(ctx, nil, 1); err == nil {
		t.Fatal("OpenStore without JetStream succeeded")
	}
	if _, err := OpenStore(ctx, testJetStream(t), 0); err == nil {
		t.Fatal("OpenStore with zero replicas succeeded")
	}
}

// storeTestReport is a valid report observed at observed.
func storeTestReport(observed time.Time) Report {
	return Report{Version: Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "BRL",
		ObservedAt: observed, Through: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC),
		Days: []Day{{Day: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC), Cents: 100}}}
}

func testJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
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
	return js
}
