package insights

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestOCIDriftInsightsGateOnDurationAndPolicy(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	resources := []OCIResource{
		{Key: "GRU/nsg-rules/controller", Policy: "enforce", Found: true, Drift: []string{"add-rule x"}},
		{Key: "GRU/bucket-protection/backups", Policy: "report", Found: true, Drift: []string{"versioning a", "tag b"}},
		{Key: "GRU/route-table-rules/private", Policy: "enforce", Found: true, Foreign: true},
		{Key: "GRU/security-list-rules/private", Policy: "enforce", Error: "apply: replace security list rules: " + strings.Repeat("x", 400)},
		{Key: "GRU/nlb-backends/public", Policy: "enforce", Found: true, InSync: true},
	}
	provider := &fakeOCIResources{resources: resources}
	engine := NewEngine(Config{Region: "gru", OCIResources: provider, Now: c.Now})
	first := engine.Evaluate(t.Context())
	if len(first.Insights) != 1 || first.Insights[0].Key != "oci_drift:foreign:GRU/route-table-rules/private" {
		t.Fatalf("only the foreign object fires at once: %+v", first.Insights)
	}
	c.Advance(11 * time.Minute)
	evaluation := engine.Evaluate(t.Context())
	byKey := map[string]Insight{}
	for _, insight := range evaluation.Insights {
		byKey[insight.Key] = insight
	}
	if len(byKey) != 4 {
		t.Fatalf("insights=%+v", evaluation.Insights)
	}
	if byKey["oci_drift:drift:GRU/nsg-rules/controller"].Severity != SeverityWarning ||
		byKey["oci_drift:drift:GRU/bucket-protection/backups"].Severity != SeverityInfo {
		t.Fatalf("severities=%+v", byKey)
	}
	failing := byKey["oci_drift:error:GRU/security-list-rules/private"]
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
	provider.set([]OCIResource{{Key: "GRU/nsg-rules/controller", Policy: "enforce", Found: true, InSync: true}}, nil)
	if resolved := engine.Evaluate(t.Context()); len(resolved.Insights) != 0 {
		t.Fatalf("resolved=%+v", resolved.Insights)
	}
}
