package dashboard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
)

type countedRollouts struct {
	rows           []insights.Rollout
	exact          map[string]insights.Rollout
	err            error
	lists, details int
}

type deadlineRollouts struct{ calls int }

func (source *deadlineRollouts) timeout(ctx context.Context) error {
	source.calls++
	readCtx, cancel := context.WithTimeout(ctx, decisionCacheTTL)
	defer cancel()
	<-readCtx.Done()
	return readCtx.Err()
}

func (source *deadlineRollouts) Rollouts(ctx context.Context) ([]insights.Rollout, error) {
	return nil, source.timeout(ctx)
}

func (source *deadlineRollouts) Rollout(ctx context.Context, _ string) (insights.Rollout, error) {
	return insights.Rollout{}, source.timeout(ctx)
}

func TestRolloutDeadlineFailuresRemainCachedAfterLoad(t *testing.T) {
	for _, path := range []string{"/rollouts", "/rollouts/" + entityid.Derive("history-test", "deadline")} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				source := &deadlineRollouts{}
				handler := newTestDashboard(Options{Journal: &Journal{Rollouts: source}}).Handler()
				read := func() {
					if body := get(t, handler, path).Body.String(); !strings.Contains(body, "unavailable") {
						t.Fatal("deadline failure must remain unavailable")
					}
				}
				read()
				read()
				time.Sleep(decisionCacheTTL - time.Nanosecond)
				read()
				if source.calls != 1 {
					t.Fatalf("timeout failure expired before its cache lifetime: got %d provider calls, want 1", source.calls)
				}
				time.Sleep(time.Nanosecond)
				read()
				if source.calls != 2 {
					t.Fatalf("expired timeout failure did not refresh: got %d provider calls, want 2", source.calls)
				}
			})
		})
	}
}

func (source *countedRollouts) Rollouts(context.Context) ([]insights.Rollout, error) {
	source.lists++
	return slices.Clone(source.rows), source.err
}

func (source *countedRollouts) Rollout(_ context.Context, id string) (insights.Rollout, error) {
	source.details++
	if source.err != nil {
		return insights.Rollout{}, source.err
	}
	if record, ok := source.exact[id]; ok {
		return record, nil
	}
	return insights.Rollout{}, ErrRolloutNotFound
}

func TestRolloutHistoryCachesSeparateListAndExactDetailAndRefreshFailures(t *testing.T) {
	id := entityid.Derive("history-test", "old")
	record := insights.Rollout{ID: id, Release: "retained-release", Phase: "preflight", PhaseStarted: testNow.Add(-time.Hour)}
	source := &countedRollouts{rows: []insights.Rollout{record}, exact: map[string]insights.Rollout{id: record}}
	board := newTestDashboard(Options{Journal: &Journal{Rollouts: source}})
	handler := board.Handler()
	for range 3 {
		get(t, handler, "/rollouts")
		get(t, handler, "/rollouts/"+id)
	}
	if source.lists != 1 || source.details != 1 {
		t.Fatalf("uncached provider reads: %d list, %d exact", source.lists, source.details)
	}
	if board.rollouts.limit != 1 || board.rollout.limit != 64 || board.rollouts.ttl != decisionCacheTTL || board.rollout.ttl != decisionCacheTTL {
		t.Fatal("rollout caches lost their bounds")
	}
	expire := func() {
		board.rollouts.mu.Lock()
		for key, entry := range board.rollouts.entries {
			entry.at = time.Now().Add(-decisionCacheTTL)
			board.rollouts.entries[key] = entry
		}
		board.rollouts.mu.Unlock()
		board.rollout.mu.Lock()
		for key, entry := range board.rollout.entries {
			entry.at = time.Now().Add(-decisionCacheTTL)
			board.rollout.entries[key] = entry
		}
		board.rollout.mu.Unlock()
	}
	record.Phase, record.Done = "complete", true
	record.PhaseStarted = testNow
	source.rows, source.exact[id] = []insights.Rollout{record}, record
	expire()
	for _, path := range []string{"/rollouts", "/rollouts/" + id} {
		body := get(t, handler, path).Body.String()
		if !strings.Contains(body, `<span class="pill s-ok">complete</span>`) || !strings.Contains(body, testNow.Format(time.RFC3339)) {
			t.Errorf("completion cache refresh failed on %s", path)
		}
	}
	if source.lists != 2 || source.details != 2 {
		t.Fatal("completion did not refresh both caches")
	}
	source.err = errors.New("secret upstream details")
	expire()
	for range 3 {
		for _, path := range []string{"/rollouts", "/rollouts/" + id} {
			body := get(t, handler, path).Body.String()
			if !strings.Contains(body, "unavailable") || strings.Contains(body, `<span class="pill s-ok">complete</span>`) || strings.Contains(body, "secret upstream") {
				t.Errorf("failed refresh reused or leaked data on %s", path)
			}
		}
	}
	if source.lists != 3 || source.details != 3 {
		t.Fatal("provider failures were not cached")
	}
	source.err = nil
	expire()
	// Exact detail must work when discovery omits the record entirely.
	source.rows = nil
	list := get(t, handler, "/rollouts").Body.String()
	if !strings.Contains(list, "latest 64 release generations plus active") || !strings.Contains(list, "No recorded release rollout") {
		t.Fatal("empty list lost its regional window label")
	}
	if body := get(t, handler, "/rollouts/"+id).Body.String(); !strings.Contains(body, `<span class="pill s-ok">complete</span>`) {
		t.Fatal("detail scanned recent list instead of exact ID")
	}
	for index := range 65 {
		get(t, handler, "/rollouts/"+entityid.Derive("history-test", fmt.Sprint(index)))
	}
	if len(board.rollout.entries) > 64 || source.lists != 4 {
		t.Fatal("exact cache grew without bound or detail loaded the list")
	}
}

func TestRolloutDetailDistinguishesMissingProviderRecordAndFailure(t *testing.T) {
	id := entityid.Derive("history-test", "missing")
	for _, test := range []struct {
		name     string
		provider RolloutSource
		want     string
	}{
		{"unattached", nil, "rollout record provider is not attached"},
		{"missing", fakeRollouts{}, "No retained rollout record or managed update has this ID"},
		{"failed", failingRollouts{}, "Rollout records are unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			board := newTestDashboard(Options{Journal: &Journal{Rollouts: test.provider}})
			body := get(t, board.Handler(), "/rollouts/"+id).Body.String()
			if !strings.Contains(body, test.want) || strings.Contains(body, "secret upstream") {
				t.Fatalf("detail lost truthful absence/failure state: want %s", test.want)
			}
		})
	}
	managed := "0000000000HAAS49GS9KYXGSQT"
	for _, provider := range []RolloutSource{nil, fakeRollouts{}, failingRollouts{}} {
		board := newTestDashboard(Options{Journal: &Journal{Rollouts: provider}, Snapshots: fixedSnapshots{snapshot: memberSnapshot()}})
		body := get(t, board.Handler(), "/rollouts/"+managed).Body.String()
		for _, want := range []string{"Managed TerraBase update</h2>", "sha256:feedface", "1 of 3 seats", "done 1, pending 2", `value="333"`} {
			if !strings.Contains(body, want) {
				t.Errorf("managed-update detail lost independent placement evidence: want %q", want)
			}
		}
		_, failed := provider.(failingRollouts)
		if failed {
			if !strings.Contains(body, "Unavailable right now: rollouts") || strings.Contains(body, "secret upstream") || strings.Contains(body, "this rollout’s phase is unknown") {
				t.Fatal("managed-update view lost the sanitized release-provider warning or claims placement progress is unknown")
			}
		}
	}
}
