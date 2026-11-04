package ocicost

import (
	"context"
	"testing"
	"time"
)

var collectorTestNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

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
