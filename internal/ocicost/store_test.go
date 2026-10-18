package ocicost

import (
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

	t.Run("valid", func(t *testing.T) {
		want := validReport()
		if err := store.Put(t.Context(), want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Report(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("report round trip = %+v, want %+v", got, want)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if got.Empty() {
			t.Error("Empty() = true for a report with usage days")
		}
	})

	t.Run("valid prices", func(t *testing.T) {
		want := validReport()
		want.Prices = []Price{{SKU: "B91961", PerUnit: 0.1335}, {SKU: "B93297", PerUnit: 0}}
		if err := store.Put(t.Context(), want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Report(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("report round trip = %+v, want %+v", got, want)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	t.Run("empty without currency passes", func(t *testing.T) {
		want := Report{
			Version:    Version,
			Cell:       "gru",
			OCIRegion:  "sa-saopaulo-1",
			ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
			Through:    time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC),
		}
		if err := store.Put(t.Context(), want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Report(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("report round trip = %+v, want %+v", got, want)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if !got.Empty() {
			t.Error("Empty() = false for a report without days")
		}
	})

	t.Run("summary forecast from independent reader", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		js := testJetStream(t)
		producer, err := OpenStore(ctx, js, 1)
		if err != nil {
			t.Fatal(err)
		}
		want := viewReport()
		if err := producer.Put(ctx, want); err != nil {
			t.Fatal(err)
		}
		conn, err := nats.Connect(js.Conn().ConnectedUrl())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.Close)
		readerJS, err := jetstream.New(conn)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenStore(ctx, readerJS, 1)
		if err != nil {
			t.Fatal(err)
		}
		report, err := reader.Report(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(report, want) {
			t.Fatalf("independent report = %+v, want %+v", report, want)
		}
		view := Summarize(report, viewNow, nil)
		if view.Cell != "gru" || view.OCIRegion != "sa-saopaulo-1" {
			t.Fatalf("view identity = %q %q", view.Cell, view.OCIRegion)
		}
		// 840 this month; the 7 complete days before the 9th average 100 a day,
		// so the month ends at 800 + 100 × 23 days left.
		if view.Forecast.MonthToDateCents != 840 || view.Forecast.RateCents != 100 || view.Forecast.MonthEndCents != 3100 {
			t.Fatalf("forecast = %+v", view.Forecast)
		}
		if len(view.Services) != 2 || view.Services[0].Name != "compute" || len(view.Components) != 2 {
			t.Fatalf("lines = %+v %+v", view.Services, view.Components)
		}
		if view.UntaggedCents != 340 {
			t.Fatalf("untagged = %d, want 840 - 500", view.UntaggedCents)
		}

		t.Run("summary folded lines from independent reader", func(t *testing.T) {
			report := viewReport()
			report.Services = nil
			for index := 1; index <= 20; index++ {
				report.Services = append(report.Services, Line{Name: fmt.Sprintf("svc-%02d", index), Cents: uint64(index)})
			}
			want := report
			if err := producer.Put(ctx, want); err != nil {
				t.Fatal(err)
			}
			report, err := reader.Report(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(report, want) {
				t.Fatalf("independent report = %+v, want %+v", report, want)
			}
			services := Summarize(report, viewNow, nil).Services
			if len(services) != maxViewLines {
				t.Fatalf("services = %d lines, want %d", len(services), maxViewLines)
			}
			if last := services[maxViewLines-1]; last.Name != "Other" || last.Cents != 16+17+18+19+20 {
				t.Fatalf("folded line = %+v, want Other 90", last)
			}
			if services[maxViewLines-2].Name != "svc-15" {
				t.Fatalf("kept lines = ..., %q, want svc-15 last", services[maxViewLines-2].Name)
			}
		})

		t.Run("summary untagged floor from independent reader", func(t *testing.T) {
			report := viewReport()
			report.Components = []Line{{Name: "controller", Cents: 1000}}
			want := report
			if err := producer.Put(ctx, want); err != nil {
				t.Fatal(err)
			}
			report, err := reader.Report(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(report, want) {
				t.Fatalf("independent report = %+v, want %+v", report, want)
			}
			if untagged := Summarize(report, viewNow, nil).UntaggedCents; untagged != 0 {
				t.Fatalf("untagged = %d, want 0 when tags exceed the month", untagged)
			}
		})
	})
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
		{name: "zero observed time", mutate: func(r *Report) { r.ObservedAt = time.Time{} }},
		{name: "through not midnight", mutate: func(r *Report) {
			r.Through = time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC).Add(time.Hour)
		}},
		{name: "through after observed", mutate: func(r *Report) {
			r.Through = time.Date(2026, time.October, 11, 0, 0, 0, 0, time.UTC)
		}},
		{name: "through not in UTC", mutate: func(r *Report) {
			r.Through = time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC).In(time.FixedZone("UTC+0", 0))
		}},
		{name: "unsorted days", mutate: func(r *Report) {
			r.Days = []Day{{Day: time.Date(2026, time.October, 3, 0, 0, 0, 0, time.UTC)}, {Day: time.Date(2026, time.October, 2, 0, 0, 0, 0, time.UTC)}}
		}},
		{name: "duplicate day", mutate: func(r *Report) {
			r.Days = []Day{{Day: time.Date(2026, time.October, 2, 0, 0, 0, 0, time.UTC)}, {Day: time.Date(2026, time.October, 2, 0, 0, 0, 0, time.UTC)}}
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
