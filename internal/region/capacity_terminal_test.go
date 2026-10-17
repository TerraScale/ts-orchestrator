package region

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestPositiveTerminalObservationRetainsUnknownOriginalAcceptance(t *testing.T) {
	at := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	wire := PoolWireRecord{RequestSHA256: strings.Repeat("a", 64), IfMatch: "original-etag", FirstAttemptAt: at, LastAttemptAt: at,
		ExpiresAt: at.Add(time.Minute), Attempts: 1, EverUnknown: true}
	observed := PoolTerminalObservation{ResourceID: "original-resource", Request: wire, LifecycleState: "TERMINATED",
		ResponseSHA256: strings.Repeat("b", 64), ETag: "terminal-etag", TerminalObservedAt: at.Add(2 * time.Minute)}
	if err := validatePoolTerminal(&observed, observed.ResourceID, &wire, observed.TerminalObservedAt); err != nil {
		t.Fatalf("positive original terminal observation after dispatch expiry was rejected: %v", err)
	}
	if !observed.Request.AcceptedAt.IsZero() || observed.Request.WorkRequestID != "" {
		t.Fatal("terminal observation invented original SDK acceptance or work request")
	}
	for _, test := range []struct {
		name   string
		change func(*PoolTerminalObservation)
	}{
		{"another resource", func(o *PoolTerminalObservation) { o.ResourceID = "replacement" }},
		{"another request", func(o *PoolTerminalObservation) { o.Request.RequestSHA256 = strings.Repeat("c", 64) }},
		{"another conditional wire", func(o *PoolTerminalObservation) { o.Request.IfMatch = "replacement" }},
		{"another dispatch", func(o *PoolTerminalObservation) { o.Request.Attempts++ }},
		{"absence instead of terminal", func(o *PoolTerminalObservation) { o.LifecycleState = "404" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := observed
			test.change(&changed)
			if validatePoolTerminal(&changed, observed.ResourceID, &wire, changed.TerminalObservedAt) == nil {
				t.Fatal("terminal evidence rebound original resource, wire or positive outcome")
			}
		})
	}
	wire.EverUnknown = false
	observed.Request = wire
	if validatePoolTerminal(&observed, observed.ResourceID, &wire, observed.TerminalObservedAt) == nil {
		t.Fatal("a rejected/undispatched request acquired terminal outcome authority")
	}
	wire.PendingAttemptID = entityid.New()
	observed.Request = wire
	if err := validatePoolTerminal(&observed, observed.ResourceID, &wire, observed.TerminalObservedAt); err != nil {
		t.Fatalf("original pending unknown dispatch could not retain positive outcome: %v", err)
	}
}

func TestTerminalObservationCannotBeRewrittenOrSharedThroughSnapshots(t *testing.T) {
	child, _, updated := protectedChildFixture()
	child.InstanceTerminal = &PoolTerminalObservation{ResourceID: child.InstanceID, TerminalObservedAt: updated}
	child.DrainSource = &PoolDrainSourcePin{ReceiptSHA256: strings.Repeat("d", 64), VerifiedAt: updated}
	previous := FoundationRecord{PoolChildren: map[string]PoolChildRecord{child.OperationID: child}}
	next := previous
	next.cloneCapacity()
	next.PoolChildren[child.OperationID].InstanceTerminal.ResourceID = "replacement"
	if previous.PoolChildren[child.OperationID].InstanceTerminal.ResourceID != child.InstanceID {
		t.Fatal("snapshot changed protected original terminal history")
	}
	if next.retainCapacity(previous) == nil {
		t.Fatal("original positive terminal observation was replaced")
	}
	next = previous
	next.cloneCapacity()
	next.PoolChildren[child.OperationID].DrainSource.Identity.Environment = "replacement"
	if previous.PoolChildren[child.OperationID].DrainSource.Identity.Environment != "" {
		t.Fatal("snapshot changed original independently verified signed-source identity")
	}
	if next.retainCapacity(previous) == nil {
		t.Fatal("original consumed signed-source identity was replaced")
	}
	old, changed := *child.Launch, *child.Launch
	changed.ExpiresAt = updated
	if retainPoolWire(&old, &changed) {
		t.Fatal("successor source introduced a new expiry for an original provider wire")
	}
}
