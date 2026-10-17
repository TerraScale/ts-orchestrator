package rootcapacity

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func TestGrowthObservationMatchesOriginalLaunchWireBeforeNewAttach(t *testing.T) {
	a := attempt{receipt: budget.Reservation{OperationID: "original", CompartmentID: "original-compartment"}}
	a.recipe.Metadata = map[string]string{"base": "signed"}
	a.recipe.AvailabilityDomains = []string{"original-AD"}
	a.recipe.SubnetID = "original-subnet"
	child := region.PoolChildRecord{ConfigurationID: "original-configuration", AvailabilityDomain: "original-AD", Node: "original-node", Descriptor: "original-descriptor"}
	const path = "/instanceConfigurations/{instanceConfigurationId}/actions/launch"
	original, err := prepareWire(a.launchRequest(child), http.MethodPost, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := matchGrowthRequest(a.launchRequest(child), http.MethodPost, path, original); err != nil {
		t.Fatal("mechanical request binding rejected identical SDK bytes", err)
	}
	child.AvailabilityDomain = "replacement-AD"
	if err := matchGrowthRequest(a.launchRequest(child), http.MethodPost, path, original); err == nil {
		t.Fatal("new attach admission accepted a launch tuple with changed original placement")
	}
	if !original.AcceptedAt.IsZero() || original.WorkRequestID != "" || original.Attempts != 0 {
		t.Fatal("mechanical wire comparison fabricated provider acceptance or work completion")
	}
}

// These fixtures exercise the finite window and retained wire selection only.
// They are not signed authority, SDK producer results, or runtime admission.
func TestGrowthWindowKeepsEveryOriginalCap(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	binding := strings.Repeat("a", 64)
	for i, name := range []string{"admitted caller source", "credential material source", "worker and source", "original receipt"} {
		t.Run(name, func(t *testing.T) {
			caps := []time.Time{now.Add(time.Minute), now.Add(time.Minute), now.Add(time.Minute), now.Add(time.Minute)}
			caps[i] = now.Add(5 * time.Second)
			deadline, err := growthSourceWindow(now, binding, caps, nil)
			if err != nil || !deadline.Equal(caps[i]) {
				t.Fatalf("lost original %s cap: %v, %v", name, deadline, err)
			}
			if _, err := growthSourceWindow(deadline, binding, caps, nil); err == nil {
				t.Fatal("expiry boundary allowed a new growth dispatch")
			}
			caps[i] = time.Time{}
			if _, err := growthSourceWindow(now, binding, caps, nil); err == nil {
				t.Fatal("missing original cap became fresh finite authority")
			}
		})
	}
}

func TestNewGrowthPhaseKeepsOriginalSourceWithoutExtendingSavedWire(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	binding := strings.Repeat("a", 64)
	configuration := region.PoolWireRecord{GrowthAuthority: region.PoolGrowthAuthority{SourceSHA256: binding, BindingSHA256: "original-admission", ExpiresAt: now.Add(time.Minute)}, ExpiresAt: now.Add(-time.Second), EverUnknown: true}
	pool := region.PoolWireRecord{GrowthAuthority: region.PoolGrowthAuthority{SourceSHA256: binding, ExpiresAt: now.Add(30 * time.Second)}, ExpiresAt: now.Add(8 * time.Second)}
	wires := []*region.PoolWireRecord{&configuration, &pool}
	deadline, err := growthSourceWindow(now, binding, []time.Time{now.Add(time.Hour)}, wires)
	if err != nil || !deadline.Equal(pool.GrowthAuthority.ExpiresAt) || !configuration.EverUnknown || !configuration.AcceptedAt.IsZero() {
		t.Fatalf("new phase lost original source cap or fabricated an earlier result: %v", err)
	}
	if _, err := growthRetryWindow(now, "original-admission", now.Add(time.Hour), &configuration); err == nil {
		t.Fatal("new phase's admission renewed an expired original wire")
	}
	if _, err := growthSourceWindow(now, strings.Repeat("b", 64), []time.Time{now.Add(time.Hour)}, wires); err == nil {
		t.Fatal("successor source started a later phase within the old source deadline")
	}
	if _, err := growthSourceWindow(deadline, binding, []time.Time{now.Add(time.Hour)}, wires); err == nil {
		t.Fatal("fresh proof extended the earlier source's expiry")
	}
	for _, legacy := range []region.PoolWireRecord{
		{ExpiresAt: now.Add(time.Minute)},
		{GrowthAuthority: region.PoolGrowthAuthority{SourceSHA256: binding}},
		{},
	} {
		before := legacy
		if _, err := growthSourceWindow(now, binding, []time.Time{now.Add(time.Minute)}, []*region.PoolWireRecord{&legacy}); err == nil {
			t.Fatal("legacy wire without genuine original authority became retryable")
		}
		if legacy != before {
			t.Fatal("window validation retroactively minted a legacy pin")
		}
	}
}

func TestSavedGrowthRetryNeverAdoptsSuccessorAdmissionOrDeadline(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	wire := region.PoolWireRecord{GrowthAuthority: region.PoolGrowthAuthority{BindingSHA256: "original-admission"}, ExpiresAt: now.Add(5 * time.Second), EverUnknown: true}
	deadline, err := growthRetryWindow(now, "original-admission", now.Add(time.Hour), &wire)
	if err != nil || !deadline.Equal(wire.ExpiresAt) || !wire.EverUnknown || !wire.AcceptedAt.IsZero() {
		t.Fatalf("saved retry changed original expiry or ambiguity: %v", err)
	}
	for _, binding := range []string{"", "new-session", "new-credentials", "new-HOME"} {
		if _, err := growthRetryWindow(now, binding, now.Add(time.Hour), &wire); err == nil {
			t.Fatal("saved wire adopted successor admission within its old finite deadline")
		}
	}
	if _, err := growthRetryWindow(wire.ExpiresAt, "original-admission", now.Add(time.Hour), &wire); err == nil {
		t.Fatal("fresh call deadline renewed expired wire")
	}
	wire.ExpiresAt = time.Time{}
	if _, err := growthRetryWindow(now, "original-admission", now.Add(time.Hour), &wire); err == nil {
		t.Fatal("legacy zero deadline became new retry authority")
	}
}

func TestNewPhaseRequiresFreshTerminalReadbackBeyondSavedAcceptance(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	request := region.PoolWireRecord{RequestSHA256: "original-pool-wire", AcceptedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second),
		GrowthAuthority: region.PoolGrowthAuthority{SourceSHA256: "original-source", ExpiresAt: now.Add(time.Minute)}}
	a := attempt{receipt: budget.Reservation{OperationID: "original"}, record: region.FoundationRecord{
		CapacityCreates: map[string]region.PoolCreateRecord{"original:pool": {Request: request}},
	}}
	if err := a.growthPredecessorsComplete(); err == nil {
		t.Fatal("saved acceptance without actual terminal readback unlocked a new phase")
	}
	// This hand-seeded marker tests the gate only. Production creates it only
	// after exact terminal SDK predicates and a final original-source guard.
	a.growthReadbacks = map[string]bool{request.RequestSHA256: true}
	if err := a.growthPredecessorsComplete(); err != nil {
		t.Fatal("old transient call expiry blocked a distinct phase with completed predecessor", err)
	}
	if _, err := growthSourceWindow(now, "original-source", []time.Time{now.Add(time.Minute)}, a.growthWires()); err != nil {
		t.Fatal("valid original source cap was replaced by the completed wire's expired call cap", err)
	}
	create := a.record.CapacityCreates["original:pool"]
	create.Request.AcceptedAt = time.Time{}
	create.Request.EverUnknown = true
	a.record.CapacityCreates["original:pool"] = create
	if err := a.growthPredecessorsComplete(); err == nil {
		t.Fatal("readback marker invented acceptance for the unknown saved wire")
	}
}

func TestGrowthRetainsOriginalBirthEpochWithoutRetrofittingLegacySource(t *testing.T) {
	a := attempt{receipt: budget.Reservation{OperationID: "original"}, record: region.FoundationRecord{
		CapacityCreates: map[string]region.PoolCreateRecord{"original:configuration": {Request: region.PoolWireRecord{
			GrowthAuthority: region.PoolGrowthAuthority{BirthEpoch: 7},
		}}},
	}}
	a.original.Epoch = 11
	if epoch, err := a.growthBirthEpoch(); err != nil || epoch != 7 {
		t.Fatal("a separately admitted phase replaced original HOME birth epoch", epoch, err)
	}
	a.record.PoolChildren = map[string]region.PoolChildRecord{"original": {BirthEpoch: 11}}
	if _, err := a.growthBirthEpoch(); err == nil {
		t.Fatal("current HOME epoch substituted for protected original birth")
	}
	delete(a.record.CapacityCreates, "original:configuration")
	if _, err := a.growthBirthEpoch(); err == nil {
		t.Fatal("legacy never-launched child retroactively acquired an original source pin")
	}
}

func TestGrowthWiresIncludeAllFivePhasesOnlyForOriginalOperation(t *testing.T) {
	wire := func(name string) region.PoolWireRecord { return region.PoolWireRecord{RequestSHA256: name} }
	a := attempt{receipt: budget.Reservation{OperationID: "original"}, record: region.FoundationRecord{
		CapacityCreates: map[string]region.PoolCreateRecord{
			"original:configuration": {Request: wire("configuration")},
			"original:pool":          {Request: wire("pool")},
			"another:configuration":  {Request: wire("foreign")},
		},
		CapacityPools: map[string]region.PoolResourceRecord{"pool": {ConfigurationUpdates: map[string]region.PoolConfigurationUpdateRecord{
			"original": {Request: wire("point")}, "another": {Request: wire("foreign")},
		}}},
		PoolChildren: map[string]region.PoolChildRecord{
			"original": {Launch: new(wire("launch")), Attach: new(wire("attach")), Detach: new(wire("retirement"))},
			"another":  {Launch: new(wire("foreign"))},
		},
	}}
	wires := a.growthWires()
	seen := map[string]bool{}
	for _, saved := range wires {
		if seen[saved.RequestSHA256] || !growthKind(saved.RequestSHA256) {
			t.Fatal("growth inherited a duplicate, unrelated operation, or cleanup wire")
		}
		seen[saved.RequestSHA256] = true
	}
	if len(wires) != 5 {
		t.Fatalf("inherited %d phases; want all five", len(wires))
	}
}
