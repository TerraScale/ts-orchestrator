package ocicost

import (
	"context"
	"errors"
	"testing"
	"time"
)

var collectorTestNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func TestCollectorFollowerDoesNotRead(t *testing.T) {
	store, reader := &stubReportStore{}, &stubReader{}
	c := newStubCollector(store, reader)
	c.Leader = func() bool { return false }
	if wait := c.step(context.Background()); wait != followInterval {
		t.Fatalf("follower waits %v, want %v", wait, followInterval)
	}
	if reader.reads != 0 || store.puts != 0 {
		t.Fatalf("follower read %d times and wrote %d, want neither", reader.reads, store.puts)
	}
}

func TestCollectorLeaderWritesWhenNoReport(t *testing.T) {
	store, reader := &stubReportStore{}, &stubReader{report: storeTestReport(collectorTestNow)}
	c := newStubCollector(store, reader)
	if wait := c.step(context.Background()); wait != Interval {
		t.Fatalf("leader waits %v, want %v", wait, Interval)
	}
	if reader.reads != 1 || store.puts != 1 {
		t.Fatalf("leader read %d times and wrote %d, want 1 each", reader.reads, store.puts)
	}
}

func TestCollectorReusesFreshReport(t *testing.T) {
	store := &stubReportStore{has: true, report: storeTestReport(collectorTestNow.Add(-20 * time.Minute))}
	reader := &stubReader{report: storeTestReport(collectorTestNow)}
	c := newStubCollector(store, reader)
	if wait := c.step(context.Background()); wait != 40*time.Minute {
		t.Fatalf("fresh report waits %v, want 40m", wait)
	}
	if reader.reads != 0 || store.puts != 0 {
		t.Fatalf("fresh report read %d times and wrote %d, want neither", reader.reads, store.puts)
	}
}

func TestCollectorRefreshesStaleReport(t *testing.T) {
	store := &stubReportStore{has: true, report: storeTestReport(collectorTestNow.Add(-2 * time.Hour))}
	reader := &stubReader{report: storeTestReport(collectorTestNow)}
	c := newStubCollector(store, reader)
	if wait := c.step(context.Background()); wait != Interval {
		t.Fatalf("stale report waits %v, want %v", wait, Interval)
	}
	if reader.reads != 1 || store.puts != 1 {
		t.Fatalf("stale report read %d times and wrote %d, want 1 each", reader.reads, store.puts)
	}
}

func TestCollectorRetriesConnectAndKeepsReader(t *testing.T) {
	store := &stubReportStore{}
	reader := &stubReader{report: storeTestReport(collectorTestNow)}
	c := newStubCollector(store, reader)
	connects := 0
	c.Connect = func(context.Context) (Reader, error) {
		connects++
		if connects == 1 {
			return nil, errors.New("usage api down")
		}
		return reader, nil
	}
	if wait := c.step(context.Background()); wait != retryInterval {
		t.Fatalf("failed connect waits %v, want %v", wait, retryInterval)
	}
	if wait := c.step(context.Background()); wait != Interval {
		t.Fatalf("connect retry waits %v, want %v", wait, Interval)
	}
	store.report, store.has = storeTestReport(collectorTestNow.Add(-2*time.Hour)), true
	if wait := c.step(context.Background()); wait != Interval {
		t.Fatalf("second read waits %v, want %v", wait, Interval)
	}
	if connects != 2 || reader.reads != 2 {
		t.Fatalf("connects %d and reads %d, want 2 and 2: the reader is kept after connecting", connects, reader.reads)
	}
}

func TestCollectorRetriesFailedRead(t *testing.T) {
	store, reader := &stubReportStore{}, &stubReader{err: errors.New("usage api timeout")}
	c := newStubCollector(store, reader)
	if wait := c.step(context.Background()); wait != retryInterval {
		t.Fatalf("failed read waits %v, want %v", wait, retryInterval)
	}
	if store.puts != 0 {
		t.Fatalf("failed read wrote %d reports, want none", store.puts)
	}
}

func TestCollectorDropsReadWhenLeadershipLost(t *testing.T) {
	store := &stubReportStore{}
	reader := &stubReader{report: storeTestReport(collectorTestNow)}
	c := newStubCollector(store, reader)
	leads := 0
	c.Leader = func() bool {
		leads++
		return leads == 1
	}
	if wait := c.step(context.Background()); wait != followInterval {
		t.Fatalf("leadership lost during read waits %v, want %v", wait, followInterval)
	}
	if reader.reads != 1 || store.puts != 0 {
		t.Fatalf("read %d times and wrote %d, want 1 read and no write", reader.reads, store.puts)
	}
}

func TestCollectorRunStopsOnCancel(t *testing.T) {
	c := newStubCollector(&stubReportStore{}, &stubReader{})
	c.Leader = func() bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// newStubCollector is a leader collector on a fixed clock.
func newStubCollector(store *stubReportStore, reader *stubReader) *Collector {
	return &Collector{
		Store:  store,
		Leader: func() bool { return true },
		Connect: func(context.Context) (Reader, error) {
			return reader, nil
		},
		Now: func() time.Time { return collectorTestNow },
	}
}

type stubReportStore struct {
	report Report
	has    bool
	puts   int
}

func (s *stubReportStore) Put(_ context.Context, report Report) error {
	s.puts++
	s.report, s.has = report, true
	return nil
}

func (s *stubReportStore) Report(context.Context) (Report, error) {
	if !s.has {
		return Report{}, ErrNoReport
	}
	return s.report, nil
}

type stubReader struct {
	report Report
	err    error
	reads  int
}

func (r *stubReader) Read(context.Context, time.Time) (Report, error) {
	r.reads++
	return r.report, r.err
}
