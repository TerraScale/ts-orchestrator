package region

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestCapacityTransitionRetainsChildIdentityAndUnknownHistory(t *testing.T) {
	child, _, _ := protectedChildFixture()
	child.PublicCAPEM, child.AvailabilityDomains = []byte("original public CA"), []string{"original AD"}
	child.Node, child.Descriptor = "ts-gru-4", "original canonical descriptor"
	child.Launch.EverUnknown = true
	previous := FoundationRecord{PoolChildren: map[string]PoolChildRecord{child.OperationID: child}}
	for _, mutation := range []struct {
		name   string
		change func(*FoundationRecord)
	}{
		{"prune original child", func(r *FoundationRecord) { delete(r.PoolChildren, child.OperationID) }},
		{"replace original child", func(r *FoundationRecord) {
			c := r.PoolChildren[child.OperationID]
			c.InstanceID += "replacement"
			r.PoolChildren[child.OperationID] = c
		}},
		{"replace original home birth epoch", func(r *FoundationRecord) {
			c := r.PoolChildren[child.OperationID]
			c.BirthEpoch++
			r.PoolChildren[child.OperationID] = c
		}},
		{"replace original boot", func(r *FoundationRecord) {
			c := r.PoolChildren[child.OperationID]
			c.BootVolumeID += "replacement"
			r.PoolChildren[child.OperationID] = c
		}},
		{"replace retry token", func(r *FoundationRecord) { r.PoolChildren[child.OperationID].Launch.RetryToken = "replacement" }},
		{"erase unknown attempt", func(r *FoundationRecord) { r.PoolChildren[child.OperationID].Launch.EverUnknown = false }},
		{"regress ready child", func(r *FoundationRecord) {
			c := r.PoolChildren[child.OperationID]
			c.Stage = PoolChildBorn
			r.PoolChildren[child.OperationID] = c
		}},
		{"replace public CA", func(r *FoundationRecord) { r.PoolChildren[child.OperationID].PublicCAPEM[0]++ }},
		{"replace original placement", func(r *FoundationRecord) { r.PoolChildren[child.OperationID].AvailabilityDomains[0] = "replacement AD" }},
		{"replace boot identity", func(r *FoundationRecord) {
			c := r.PoolChildren[child.OperationID]
			c.Descriptor = "replacement"
			r.PoolChildren[child.OperationID] = c
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			next := previous
			next.cloneCapacity()
			mutation.change(&next)
			if err := next.retainCapacity(previous); err == nil {
				t.Fatal("accepted loss or replacement of original protected evidence")
			}
		})
	}
	next := previous
	next.cloneCapacity()
	c := next.PoolChildren[child.OperationID]
	c.Stage, c.RemovalOperationID, c.DrainAuthoritySHA256 = PoolChildDraining, entityid.New(), strings.Repeat("d", 64)
	next.PoolChildren[child.OperationID] = c
	if err := next.retainCapacity(previous); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityTransitionRetainsUnresolvedFinancialHolds(t *testing.T) {
	op := entityid.New()
	host := capacityledger.Host{Receipt: capacityledger.Receipt{OperationID: op, QuoteSHA256: strings.Repeat("a", 64)}}
	previous := FoundationRecord{CapacityLedger: &capacityledger.Ledger{Version: capacityledger.Version, Hosts: []capacityledger.Host{host}}}
	for _, mutation := range []struct {
		name   string
		change func(*FoundationRecord)
	}{
		{"remove ledger", func(r *FoundationRecord) { r.CapacityLedger = nil }},
		{"remove unresolved hold", func(r *FoundationRecord) { r.CapacityLedger.Hosts = nil }},
		{"rewrite original tariff", func(r *FoundationRecord) { r.CapacityLedger.Hosts[0].Receipt.QuoteSHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			next := previous
			next.cloneCapacity()
			mutation.change(&next)
			if err := next.retainCapacity(previous); err == nil {
				t.Fatal("accepted erased or repriced unresolved financial hold")
			}
		})
	}
	next := previous
	next.cloneCapacity()
	next.CapacityLedger.Hosts[0].RequestSHA256 = strings.Repeat("c", 64)
	next.CapacityLedger.Hosts[0].StartedAt = time.Now().UTC()
	if err := next.retainCapacity(previous); err != nil {
		t.Fatal(err)
	}
	previous = next
	next = previous
	next.cloneCapacity()
	next.CapacityLedger.Hosts[0].RequestSHA256 = strings.Repeat("d", 64)
	if err := next.retainCapacity(previous); err == nil {
		t.Fatal("replaced original financial request after preparation")
	}
}

func TestProtectedWireTransitionRetainsAttemptsAndPositiveResults(t *testing.T) {
	child, _, _ := protectedChildFixture()
	old := *child.Launch
	old.PendingAttemptID, old.AcceptedAt = entityid.New(), time.Time{}
	next := old
	next.PendingAttemptID, next.EverUnknown = "", true
	if !retainPoolWire(&old, &next) {
		t.Fatal("rejected completion of the same unknown attempt")
	}
	next.PendingAttemptID = entityid.New()
	if retainPoolWire(&old, &next) {
		t.Fatal("changed wire identity without recording another attempt")
	}
	next.Attempts++
	if !retainPoolWire(&old, &next) {
		t.Fatal("rejected a separately recorded exact original retry")
	}
	old = *child.Attach
	next = old
	next.WorkRequestID = "ocid1.workrequest.oc1..replacement"
	if retainPoolWire(&old, &next) {
		t.Fatal("replaced positive original work request")
	}
}

func TestCapacityTransitionRetainsConditionalConfigurationPoint(t *testing.T) {
	child, _, _ := protectedChildFixture()
	operation := entityid.New()
	wire := *child.Attach
	wire.IfMatch = "original-etag"
	pool := PoolResourceRecord{PoolID: child.PoolID, PoolName: "original-pool", ConfigurationUpdates: map[string]PoolConfigurationUpdateRecord{
		operation: {ConfigurationID: child.ConfigurationID, Request: wire},
	}}
	previous := FoundationRecord{CapacityPools: map[string]PoolResourceRecord{pool.PoolID: pool}}
	for _, mutation := range []struct {
		name   string
		change func(*FoundationRecord)
	}{
		{"prune point", func(r *FoundationRecord) { delete(r.CapacityPools[pool.PoolID].ConfigurationUpdates, operation) }},
		{"replace configuration", func(r *FoundationRecord) {
			point := r.CapacityPools[pool.PoolID].ConfigurationUpdates[operation]
			point.ConfigurationID += "replacement"
			r.CapacityPools[pool.PoolID].ConfigurationUpdates[operation] = point
		}},
		{"replace conditional request", func(r *FoundationRecord) {
			point := r.CapacityPools[pool.PoolID].ConfigurationUpdates[operation]
			point.Request.IfMatch = "replacement-etag"
			r.CapacityPools[pool.PoolID].ConfigurationUpdates[operation] = point
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			next := previous
			next.cloneCapacity()
			mutation.change(&next)
			if err := next.retainCapacity(previous); err == nil {
				t.Fatal("accepted lost or replaced original pool configuration point")
			}
		})
	}
	next := previous
	next.cloneCapacity()
	next.CapacityPools[pool.PoolID].ConfigurationUpdates[entityid.New()] = PoolConfigurationUpdateRecord{ConfigurationID: child.ConfigurationID, Request: wire}
	if err := next.retainCapacity(previous); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityTransitionRetainsOriginalQuarantineExpiry(t *testing.T) {
	child, _, updated := protectedChildFixture()
	operation := entityid.New()
	original := FoundationRecord{PoolQuarantines: map[string]PoolQuarantineRecord{operation: {
		OperationID: operation, ExpiresAt: updated, Detach: child.Attach,
	}}}
	next := original
	next.cloneCapacity()
	quarantine := next.PoolQuarantines[operation]
	quarantine.ExpiresAt = quarantine.ExpiresAt.Add(time.Minute)
	next.PoolQuarantines[operation] = quarantine
	if err := next.retainCapacity(original); err == nil {
		t.Fatal("successor call extended the original quarantine permission lifetime")
	}
}
