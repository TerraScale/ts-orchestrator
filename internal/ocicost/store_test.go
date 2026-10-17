package ocicost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestStoreRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	store, err := OpenStore(ctx, testJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	priced := validReport()
	priced.Prices = []Price{{SKU: "B91961", PerUnit: 0.1335}, {SKU: "B93297", PerUnit: 0}}
	empty := Report{Version: Version, Cell: "gru", OCIRegion: "sa-saopaulo-1",
		ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC)}
	for _, test := range []struct {
		name   string
		report Report
		empty  bool
	}{
		{name: "stored report", report: storeTestReport(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))},
		{name: "valid", report: validReport()},
		{name: "valid prices", report: priced},
		{name: "empty without currency passes", report: empty, empty: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := store.Put(ctx, test.report); err != nil {
				t.Fatal(err)
			}
			got, err := store.Report(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.report) {
				t.Fatalf("report round trip = %+v, want %+v", got, test.report)
			}
			if got.Empty() != test.empty {
				t.Fatalf("stored report Empty() = %v, want %v", got.Empty(), test.empty)
			}
		})
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
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
	want := validReport()
	if err := store.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	before, err := store.kv.Get(ctx, reportKey)
	if err != nil {
		t.Fatal(err)
	}
	utc := func(day int) time.Time { return time.Date(2026, time.October, day, 0, 0, 0, 0, time.UTC) }

	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "wrong version", mutate: func(r *Report) { r.Version = Version + 1 }},
		{name: "empty cell", mutate: func(r *Report) { r.Cell = "" }},
		{name: "upper-case cell", mutate: func(r *Report) { r.Cell = "GRU" }},
		{name: "empty OCI region", mutate: func(r *Report) { r.OCIRegion = "" }},
		{name: "lower-case currency", mutate: func(r *Report) { r.Currency = "usd" }},
		{name: "zero observed time", mutate: func(r *Report) { r.ObservedAt = time.Time{} }},
		{name: "through not midnight", mutate: func(r *Report) { r.Through = utc(8).Add(time.Hour) }},
		{name: "through after observed", mutate: func(r *Report) { r.Through = utc(11) }},
		{name: "through not in UTC", mutate: func(r *Report) { r.Through = utc(8).In(time.FixedZone("UTC+0", 0)) }},
		{name: "unsorted days", mutate: func(r *Report) {
			r.Days = []Day{{Day: utc(3)}, {Day: utc(2)}}
		}},
		{name: "duplicate day", mutate: func(r *Report) {
			r.Days = []Day{{Day: utc(2)}, {Day: utc(2)}}
		}},
		{name: "day cents over bound", mutate: func(r *Report) { r.Days[0].Cents = maxCents + 1 }},
		{name: "65 days", mutate: func(r *Report) {
			r.Days = nil
			for index := range 65 {
				r.Days = append(r.Days, Day{Day: time.Date(2026, time.January, 1+index, 0, 0, 0, 0, time.UTC)})
			}
		}},
		{name: "empty line name", mutate: func(r *Report) { r.Services[0].Name = "" }},
		{name: "duplicate service", mutate: func(r *Report) {
			r.Services = append(r.Services, Line{Name: "Block Storage", Cents: 1})
		}},
		{name: "unknown component", mutate: func(r *Report) {
			r.Components = []Line{{Name: "db", Cents: 1}}
		}},
		{name: "cost without currency", mutate: func(r *Report) { r.Currency = "" }},
		{name: "65 prices", mutate: func(r *Report) {
			r.Prices = nil
			for index := range 65 {
				r.Prices = append(r.Prices, Price{SKU: fmt.Sprintf("B%05d", index)})
			}
		}},
		{name: "empty SKU", mutate: func(r *Report) { r.Prices = []Price{{SKU: "", PerUnit: 1}} }},
		{name: "SKU over bound", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: strings.Repeat("x", maxNameBytes+1), PerUnit: 1}}
		}},
		{name: "unsorted prices", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93298", PerUnit: 1}, {SKU: "B93297", PerUnit: 1}}
		}},
		{name: "duplicate price SKU", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: 1}, {SKU: "B93297", PerUnit: 2}}
		}},
		{name: "NaN price", mutate: func(r *Report) { r.Prices = []Price{{SKU: "B93297", PerUnit: math.NaN()}} }},
		{name: "infinite price", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: math.Inf(1)}}
		}},
		{name: "negative price", mutate: func(r *Report) { r.Prices = []Price{{SKU: "B93297", PerUnit: -0.01}} }},
		{name: "price over bound", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: maxUnitPrice + 1}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := validReport()
			tc.mutate(&report)
			if err := store.Put(ctx, report); !errors.Is(err, ErrInvalidReport) {
				t.Errorf("Put invalid report = %v, want ErrInvalidReport", err)
			}
			got, err := store.Report(ctx)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("rejected Put changed stored report: got=%+v err=%v want=%+v", got, err, want)
			}
			after, err := store.kv.Get(ctx, reportKey)
			if err != nil {
				t.Fatal(err)
			}
			if after.Revision() != before.Revision() || !bytes.Equal(after.Value(), before.Value()) {
				t.Fatalf("rejected Put changed persisted value or revision: before=%d after=%d", before.Revision(), after.Revision())
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

// validReport has one day of usage, one service and one tagged component.
func validReport() Report {
	return Report{
		Version:    Version,
		Cell:       "gru",
		OCIRegion:  "sa-saopaulo-1",
		Currency:   "BRL",
		ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC),
		Days:       []Day{{Day: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC), Cents: 267}},
		Services:   []Line{{Name: "Block Storage", Cents: 807}},
		Components: []Line{{Name: "terrabase", Cents: 437}},
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
