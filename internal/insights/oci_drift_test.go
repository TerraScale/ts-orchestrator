package insights

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

type fakeOCIResources struct {
	mu        sync.Mutex
	resources []OCIResource
	err       error
}

func (f *fakeOCIResources) OCIResources(context.Context) ([]OCIResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resources, f.err
}

func (f *fakeOCIResources) set(resources []OCIResource, err error) {
	f.mu.Lock()
	f.resources, f.err = resources, err
	f.mu.Unlock()
}

func ociFixture(observedAt time.Time) []OCIResource {
	return []OCIResource{
		{Key: "GRU/nsg-rules/controller", Policy: "enforce", Found: true, Drift: []string{"add-rule x"}, ObservedAt: observedAt},
		{Key: "GRU/bucket-protection/backups", Policy: "report", Found: true, Drift: []string{"versioning a", "tag b"},
			ObservedAt: observedAt},
		{Key: "GRU/route-table-rules/private", Policy: "enforce", Found: true, Foreign: true, ObservedAt: observedAt},
		{Key: "GRU/security-list-rules/private", Policy: "enforce", ObservedAt: observedAt,
			Error: "apply: replace security list rules: " + strings.Repeat("x", 400)},
		{Key: "GRU/nlb-backends/public", Policy: "enforce", Found: true, InSync: true, ObservedAt: observedAt},
		// The pass applied a correction; its drift is what was just fixed.
		{Key: "GRU/nsg-rules/applied", Policy: "enforce", Found: true, Applied: true, Drift: []string{"add-rule y"},
			ObservedAt: observedAt},
	}
}

func TestOCIDriftInsightsNeedARepeatedObservation(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	provider := &fakeOCIResources{resources: ociFixture(c.now.Add(-time.Second))}
	engine := NewEngine(Config{Region: "gru", OCIResources: provider, Now: c.Now})
	first := engine.Evaluate(t.Context())
	if len(first.Insights) != 1 || first.Insights[0].Key != entityid.Derive("insight", "gru", "oci_drift:foreign:GRU/route-table-rules/private") {
		t.Fatalf("only the foreign object fires at once: %+v", first.Insights)
	}
	// Re-reading the same observation past the threshold is not evidence
	// that the failure or drift persists: no pass ran since.
	for range 5 {
		c.Advance(5 * time.Minute)
		if evaluation := engine.Evaluate(t.Context()); len(evaluation.Insights) != 1 {
			t.Fatalf("an unchanged observation fired: %+v", evaluation.Insights)
		}
	}
	// A later pass observes the same conditions again.
	provider.set(ociFixture(c.now), nil)
	c.Advance(time.Second)
	evaluation := engine.Evaluate(t.Context())
	byKey := map[string]Insight{}
	for _, insight := range evaluation.Insights {
		byKey[insight.Key] = insight
	}
	if len(byKey) != 4 {
		t.Fatalf("insights=%+v", evaluation.Insights)
	}
	if byKey[entityid.Derive("insight", "gru", "oci_drift:drift:GRU/nsg-rules/controller")].Severity != SeverityWarning ||
		byKey[entityid.Derive("insight", "gru", "oci_drift:drift:GRU/bucket-protection/backups")].Severity != SeverityInfo {
		t.Fatalf("severities=%+v", byKey)
	}
	failing := byKey[entityid.Derive("insight", "gru", "oci_drift:error:GRU/security-list-rules/private")]
	if text := failing.Evidence[0].Text; len(text) > maxOCIErrorText+len("…") {
		t.Fatalf("error evidence is not bounded: %d bytes", len(text))
	}

	// An unreadable provider keeps the open insights instead of resolving them.
	provider.set(nil, errors.New("kv down"))
	c.Advance(time.Minute)
	if blind := engine.Evaluate(t.Context()); len(blind.Insights) != 4 {
		t.Fatalf("blind pass resolved insights: %+v", blind.Insights)
	}
	// Converged resources resolve.
	provider.set([]OCIResource{{Key: "GRU/nsg-rules/controller", Policy: "enforce", Found: true, InSync: true,
		ObservedAt: c.now}}, nil)
	if resolved := engine.Evaluate(t.Context()); len(resolved.Insights) != 0 {
		t.Fatalf("resolved=%+v", resolved.Insights)
	}
}

func TestOCIDriftStaleObservationsAreUnknown(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	stale := ociFixture(now.Add(-4 * time.Hour))
	got := evaluate(t, ociDrift, &Inputs{Now: now, OCIResources: stale})
	if len(got) != 1 || got[0].Key != "oci_drift:stale" || got[0].Severity != SeverityInfo ||
		!strings.Contains(got[0].Title, "6 OCI reconcile observations are stale") {
		t.Fatalf("got=%+v", got)
	}
}
