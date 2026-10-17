package region

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func TestRegionalTrustFloorAcquisitionRetainsOriginalLifetime(t *testing.T) {
	original, cancelOriginal := context.WithDeadline(t.Context(), time.Now().Add(20*time.Second))
	defer cancelOriginal()
	acquisition, cancelAcquisition := context.WithDeadline(original, time.Now().Add(time.Second))
	defer cancelAcquisition()
	materialExpiry := time.Now().Add(10 * time.Second)
	operation, cancel, expires, err := regionalTrustFloorReadContext(acquisition, original, materialExpiry)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := operation.Deadline()
	acquisitionDeadline, _ := acquisition.Deadline()
	if !ok || !deadline.Equal(acquisitionDeadline) || !expires.Equal(materialExpiry) {
		t.Fatal("floor acquisition dropped its current operation cap or retained the temporary deadline")
	}
	cancelAcquisition()
	if !errors.Is(operation.Err(), context.Canceled) || original.Err() != nil || !expires.Equal(materialExpiry) {
		t.Fatal("temporary acquisition cancellation changed the original retained lifetime")
	}

	operation, cancelJoined, expires, err := regionalTrustFloorReadContext(t.Context(), original, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer cancelJoined()
	originalDeadline, _ := original.Deadline()
	if !expires.Equal(originalDeadline) {
		t.Fatal("floor proof exceeded the original reader deadline")
	}
	cancelOriginal()
	select {
	case <-operation.Done():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}

func TestRegionalTrustFloorAcquisitionRejectsExpiredSources(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []struct {
		operation context.Context
		original  context.Context
		expires   time.Time
	}{
		{t.Context(), t.Context(), time.Time{}},
		{t.Context(), t.Context(), time.Now().Add(-time.Second)},
		{canceled, t.Context(), time.Now().Add(time.Second)},
		{t.Context(), canceled, time.Now().Add(time.Second)},
	} {
		if _, cancel, _, err := regionalTrustFloorReadContext(input.operation, input.original, input.expires); err == nil {
			cancel()
			t.Fatal("floor acquisition accepted an absent, expired or canceled original source")
		}
	}
}

func TestRegionalControlZeroProofsRefuseAuthority(t *testing.T) {
	ctx := t.Context()
	if _, err := OpenRegionalTrustFloor(ctx, nil, nil, "GRU"); err == nil {
		t.Fatal("missing concrete OCI and independent roots opened a regional floor")
	}
	proof := VerifiedRegionalTrustFloor{}
	if err := proof.Guard(ctx); err == nil {
		t.Fatal("zero read handle passed its guard")
	}
	if err := proof.CheckAdoptedSources(ctx, time.Time{}, 0, nil, time.Time{}, 0, nil); err == nil {
		t.Fatal("zero read handle admitted public source")
	}
	creation := VerifiedBrokerCreation{}
	for name, call := range map[string]func() error{
		"prepare roots": func() error { return creation.PrepareRootPublication(ctx, nil) },
		"prepare spec":  func() error { return creation.PrepareSpecPublication(ctx, nil) },
		"adopt roots":   func() error { return creation.AdoptRootPublication(ctx, nil) },
		"adopt controls": func() error {
			return AdoptRegionalControlSources(ctx, nil, nil, bootstrapstart.AcceptedIdentity{}, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("absent concrete authority permitted publication or adoption")
			}
		})
	}
	for _, resolver := range []FoundationResolver{{}, {Footprint: (*SignedFootprint)(nil)}} {
		if _, err := regionalControlPurposeExpiry(ctx, resolver, "GRU"); err == nil {
			t.Fatal("unsigned resolver supplied regional-control-lineage authority")
		}
	}
}

func TestRegionalTrustFloorInfoCannotMutateRetainedGenesis(t *testing.T) {
	// This private metadata fixture confers no positive read or write proof.
	proof := VerifiedRegionalTrustFloor{info: RegionalTrustFloorInfo{Cell: "GRU", Broker: RuntimeBrokerCreation{Genesis: &RuntimeBrokerGenesis{MarkerSHA256: "retained"}},
		Floor: RuntimeTrustFloor{RootRevision: 10}}}
	info := proof.Info()
	info.Broker.Genesis.MarkerSHA256 = "replaced"
	info.Floor.RootRevision = 1
	if got := proof.Info(); got.Broker.Genesis.MarkerSHA256 != "retained" || got.Floor.RootRevision != 10 {
		t.Fatal("public metadata changed private retained source")
	}
	if err := proof.Guard(t.Context()); err == nil {
		t.Fatal("public metadata fabricated authenticated source")
	}
}

func TestUncommittedBrokerCannotAdvanceTrustFloor(t *testing.T) {
	before := &RuntimeLineageRecord{Broker: &RuntimeBrokerCreation{}, TrustFloor: &RuntimeTrustFloor{RootRevision: 0}}
	after := &RuntimeLineageRecord{Broker: &RuntimeBrokerCreation{Genesis: &RuntimeBrokerGenesis{}}, TrustFloor: &RuntimeTrustFloor{RootRevision: 1}}
	if err := retainBrokerLineage(before, after); err == nil {
		t.Fatal("broker genesis commit also advanced its uncommitted public floor")
	}
}
