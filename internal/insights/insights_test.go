package insights

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(step time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(step)
	c.mu.Unlock()
}

type fakeCluster struct {
	mu       sync.Mutex
	snapshot observability.ClusterSnapshot
	err      error
}

func (cluster *fakeCluster) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	return cluster.snapshot, cluster.err
}

func (cluster *fakeCluster) set(snapshot observability.ClusterSnapshot) {
	cluster.mu.Lock()
	cluster.snapshot = snapshot
	cluster.mu.Unlock()
}

func controller(name string, leader bool) observability.MemberSnapshot {
	return observability.MemberSnapshot{Member: name, Role: "controller", Ready: true, BuildVersion: "v1",
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, OwnerID: "0000000000KZ5R9PYPCAJ654M2", Epoch: 3}}
}

func healthy() observability.ClusterSnapshot {
	return observability.ClusterSnapshot{Cell: "gru", Expected: []string{"c1", "c2", "c3"},
		Members: []observability.MemberSnapshot{controller("c1", true), controller("c2", false), controller("c3", false)}}
}

func find(insights []Insight, rule string) *Insight {
	for index := range insights {
		if insights[index].Rule == rule {
			return &insights[index]
		}
	}
	return nil
}

func TestEngineLifecycleOpenEscalateResolve(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	cluster := &fakeCluster{snapshot: healthy()}
	engine := NewEngine(Config{Region: "GRU", Cluster: cluster, Now: c.Now})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := engine.Subscribe(ctx, 8)

	if evaluation := engine.Evaluate(ctx); len(evaluation.Insights) != 0 {
		t.Fatalf("healthy cell raised %+v", evaluation.Insights)
	}
	degraded := healthy()
	degraded.Members, degraded.Missing = degraded.Members[:2], []string{"c3"}
	cluster.set(degraded)
	c.Advance(time.Minute)
	evaluation := engine.Evaluate(ctx)
	quorum := find(evaluation.Insights, "quorum_at_risk")
	if quorum == nil || quorum.Severity != SeverityWarning || quorum.Region != "gru" || quorum.Entity.Region != "gru" ||
		len(quorum.Evidence) == 0 || quorum.Evidence[0].Threshold == nil || *quorum.Evidence[0].Threshold != 2 {
		t.Fatalf("quorum insight = %+v", quorum)
	}
	opened := <-live
	if opened.Type != ChangeOpened || opened.Insight.Key != quorum.Key {
		t.Fatalf("change = %+v", opened)
	}
	firstSeen := quorum.FirstSeen

	critical := healthy()
	critical.Members, critical.Missing = critical.Members[:1], []string{"c2", "c3"}
	cluster.set(critical)
	c.Advance(time.Minute)
	evaluation = engine.Evaluate(ctx)
	quorum = find(evaluation.Insights, "quorum_at_risk")
	if quorum.Severity != SeverityCritical || !quorum.FirstSeen.Equal(firstSeen) || evaluation.Counts.Critical != 1 {
		t.Fatalf("escalated = %+v", quorum)
	}
	if change := <-live; change.Type != ChangeEscalated {
		t.Fatalf("change = %+v", change)
	}

	cluster.set(healthy())
	c.Advance(time.Minute)
	if evaluation := engine.Evaluate(ctx); len(evaluation.Insights) != 0 {
		t.Fatalf("recovered cell still raises %+v", evaluation.Insights)
	}
	if change := <-live; change.Type != ChangeResolved {
		t.Fatalf("change = %+v", change)
	}
	changes := engine.Changes(firstSeen)
	if len(changes) != 3 {
		t.Fatalf("changes = %d", len(changes))
	}
	if later := engine.Changes(c.Now().Add(time.Second)); len(later) != 0 {
		t.Fatalf("later changes = %d", len(later))
	}
}

type localSource struct{ snapshot observability.MemberSnapshot }

func (source localSource) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.snapshot, nil
}

func TestHandler(t *testing.T) {
	engine := NewEngine(Config{Region: "gru", Cluster: &fakeCluster{snapshot: healthy()}})
	engine.Evaluate(t.Context())
	handler := Handler(engine, Summarizer{Insights: engine, Scope: "GRU"})
	for path, want := range map[string]int{
		"/v1/insights":             http.StatusOK,
		"/v1/summary":              http.StatusOK,
		"/v1/summary?window=24h":   http.StatusOK,
		"/v1/summary?window=1s":    http.StatusBadRequest,
		"/v1/summary?window=never": http.StatusBadRequest,
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != want {
			t.Fatalf("%s = %d %s", path, recorder.Code, recorder.Body)
		}
	}
}
