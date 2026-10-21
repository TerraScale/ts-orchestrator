package membership

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// An unanswered retirement request is re-rendered before the signer's
// 24-hour observation bound would refuse it, within the same term.
func TestReconcilerRefreshesAnUnansweredRetirementRequest(t *testing.T) {
	clock := testEpoch
	leader := &fakeLeadership{snapshot: leaderSnapshot(6)}
	cell := newFakeCell()
	cell.evidence = map[string]Evidence{}
	requests := &recordingRequests{}
	reconciler, err := New(testTopology(), Dependencies{Leadership: leader, Peers: cell,
		Ledger: cell, Instances: cell, Evidence: cell, Replacer: cell, Requests: requests,
		Now: func() time.Time { return clock }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		if err := reconciler.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	tick()
	clock = clock.Add(RetirementRequestRefresh - time.Minute)
	tick()
	if len(requests.requests) != 1 {
		t.Fatalf("request repeated before its refresh age: %d", len(requests.requests))
	}
	clock = clock.Add(2 * time.Minute)
	tick()
	if len(requests.requests) != 2 || !requests.requests[1].ObservedAt.After(requests.requests[0].ObservedAt) {
		t.Fatalf("stale request was not refreshed: %+v", requests.requests)
	}
}
