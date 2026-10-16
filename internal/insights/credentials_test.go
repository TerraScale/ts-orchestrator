package insights

import (
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func credentialInsights(evaluation Evaluation) map[string]Insight {
	out := map[string]Insight{}
	for _, insight := range evaluation.Insights {
		if insight.Rule == "certificate_expiring" {
			out[insight.Entity.ID] = insight
		}
	}
	return out
}

// Every member's credentials reach the insights through the cell-wide
// snapshot. A member that does not answer, or whose credential section
// fails, keeps its expiry open; only a renewed credential resolves it.
func TestCellCredentialExpiry(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	c := &clock{now: now}
	expiring := func(name, kind string, left time.Duration) observability.CredentialView {
		return observability.CredentialView{Name: name, Kind: kind, NotAfter: now.Add(left)}
	}
	snapshot := healthy()
	snapshot.Members[0].Credentials = []observability.CredentialView{
		expiring("nats server tls", "tls", 2*24*time.Hour),
		expiring("nats cell account jwt", "nats-jwt", 10*24*time.Hour),
		expiring("terrabase member ca", "tls", 300*24*time.Hour)}
	snapshot.Members[1].Credentials = []observability.CredentialView{expiring("nats server tls", "tls", -time.Hour)}
	cluster := &fakeCluster{snapshot: snapshot}
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Now: c.Now})

	found := credentialInsights(engine.Evaluate(t.Context()))
	if len(found) != 3 {
		t.Fatalf("want three expiring credentials, got %+v", found)
	}
	tls := found["c1/nats server tls"]
	if tls.Severity != SeverityCritical || tls.Title != "Expiring tls: c1 nats server tls" || tls.Entity.Href != memberHref("c1") {
		t.Fatalf("two days left must be critical and name its member: %+v", tls)
	}
	if found["c1/nats cell account jwt"].Severity != SeverityWarning {
		t.Fatalf("ten days left must warn: %+v", found["c1/nats cell account jwt"])
	}
	if expired := found["c2/nats server tls"]; expired.Severity != SeverityCritical || expired.Score <= tls.Score {
		t.Fatalf("an expired credential must rank above one about to expire: %+v", expired)
	}

	// Partition: c2 does not answer. Its expiry stays open; it was not
	// observed, not renewed.
	partitioned := healthy()
	partitioned.Members = []observability.MemberSnapshot{snapshot.Members[0], snapshot.Members[2]}
	partitioned.Missing = []string{"c2"}
	cluster.set(partitioned)
	c.Advance(time.Minute)
	evaluation := engine.Evaluate(t.Context())
	if found := credentialInsights(evaluation); len(found) != 3 {
		t.Fatalf("the missing member's credential must stay open: %+v", found)
	}
	if !slices.Contains(evaluation.Unavailable, "member c2") {
		t.Fatalf("the missing member must be reported: %v", evaluation.Unavailable)
	}

	// c2 answers with a renewed certificate while c1's credential section
	// fails with a partial list. c2 resolves on its own; c1's unlisted JWT
	// stays open.
	failing := healthy()
	failing.Members[0].Credentials = []observability.CredentialView{expiring("nats server tls", "tls", 2*24*time.Hour)}
	failing.Members[0].Errors = map[string]string{"credentials": "unavailable"}
	failing.Members[1].Credentials = []observability.CredentialView{expiring("nats server tls", "tls", 60*24*time.Hour)}
	cluster.set(failing)
	c.Advance(time.Minute)
	evaluation = engine.Evaluate(t.Context())
	found = credentialInsights(evaluation)
	if _, open := found["c2/nats server tls"]; open || len(found) != 2 || found["c1/nats cell account jwt"].Rule == "" {
		t.Fatalf("c2 must resolve and c1's unobserved JWT stay open: %+v", found)
	}
	if !slices.Contains(evaluation.Unavailable, "member c1 section credentials") {
		t.Fatalf("the failed section must name its member: %v", evaluation.Unavailable)
	}

	// c1 renews everything.
	renewed := healthy()
	renewed.Members[0].Credentials = []observability.CredentialView{
		expiring("nats server tls", "tls", 60*24*time.Hour),
		expiring("nats cell account jwt", "nats-jwt", 60*24*time.Hour)}
	cluster.set(renewed)
	c.Advance(time.Minute)
	if found := credentialInsights(engine.Evaluate(t.Context())); len(found) != 0 {
		t.Fatalf("renewed credentials must resolve: %+v", found)
	}
}
