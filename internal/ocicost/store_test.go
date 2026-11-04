package ocicost

import (
	"context"
	"fmt"
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
