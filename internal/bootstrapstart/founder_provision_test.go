package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestInitialSeedAdmissionInvokesFloorBeforeMarkerAndRestartNeverReinitializes(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.ledger.state.Intent.Mode = bootstrap.IntentModeExternalSeed
	calls := 0
	fixture.gate.InitialFounderFloor = func(_ context.Context, marker AcceptedInstall, at time.Time) error {
		calls++
		if marker.Slot != marker.SeedSlot || marker.HeadAttempt != 1 || at.IsZero() {
			t.Fatalf("unverified initial seed floor inputs: %+v, %s", marker, at)
		}
		if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("marker persisted before durable floor: %v", err)
		}
		return nil
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil || calls != 1 {
		t.Fatalf("initial floor callback: calls=%d err=%v", calls, err)
	}
	if _, err := fixture.gate.AdmitRestart(t.Context()); err != nil || calls != 1 {
		t.Fatalf("restart reinitialized initial floor: calls=%d err=%v", calls, err)
	}
}

func TestInitialSeedAdmissionFloorFailureLeavesNoAcceptedMarker(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.ledger.state.Intent.Mode = bootstrap.IntentModeExternalSeed
	fixture.gate.InitialFounderFloor = func(context.Context, AcceptedInstall, time.Time) error {
		return ErrFounderProvision
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("failed floor provision admitted seed: %v", err)
	}
	if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed floor provision left accepted marker: %v", err)
	}
}

func TestInitialSeedAdmissionRequiresFloorProvisioner(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.gate.InitialFounderFloor = nil
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("seed admitted without durable floor provisioner: %v", err)
	}
	if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("seed without floor left accepted marker: %v", err)
	}
}

func TestFreshSeedProvisionValidatesSelectionBeforeDurableFloor(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	floor := testFounderFloor(t)
	reader, err := NewCurrentFounderAuthorityReader(fixture.baked, fixture.accepted, fixture.objects, floor)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.provisionInitial(t.Context(), fixture.now, uint32(os.Getuid()), uint32(os.Getgid()), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := floor.Check(1, fixture.current.SelectionSHA256); err != nil {
		t.Fatalf("durable first selector floor: %v", err)
	}
	if _, err := reader.ReadCurrent(t.Context(), fixture.now); err != nil {
		t.Fatalf("restart with provisioned floor: %v", err)
	}
	if err := reader.provisionInitial(t.Context(), fixture.now, uint32(os.Getuid()), uint32(os.Getgid()), func() error { return nil }); err != nil {
		t.Fatalf("exact replay after floor-before-marker crash: %v", err)
	}
}

func TestFreshSeedProvisionRejectsConflictingPreexistingFloor(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	floor := testFounderFloor(t)
	if err := floor.Initialize(1, digestWire([]byte("different signed selector"))); err != nil {
		t.Fatal(err)
	}
	reader, err := NewCurrentFounderAuthorityReader(fixture.baked, fixture.accepted, fixture.objects, floor)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.provisionInitial(t.Context(), fixture.now, uint32(os.Getuid()), uint32(os.Getgid()), func() error { return nil }); !errors.Is(err, ErrFounderProvision) {
		t.Fatalf("conflicting durable floor was reset: %v", err)
	}
}

func TestFreshSeedProvisionRechecksExpiryAtPublication(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	selectionWire := fixture.signSelection(t, fixture.selection, fixture.now.Add(-10*time.Second))
	key := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
		"deployment-a", "GRU", "production")
	fixture.objects.items[key] = selectionWire
	floor := testFounderFloor(t)
	reader, err := NewCurrentFounderAuthorityReader(fixture.baked, fixture.accepted, fixture.objects, floor)
	if err != nil {
		t.Fatal(err)
	}
	entryTime := fixture.now.Add(-15 * time.Second)
	if err := reader.provisionInitial(t.Context(), entryTime, uint32(os.Getuid()), uint32(os.Getgid()),
		func() error { return nil }); !errors.Is(err, ErrFounderProvision) {
		t.Fatalf("selector expired after entry time but before publication: %v", err)
	}
	if _, err := os.Stat(floor.directory + "/" + founderSelectionFloorName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired selector initialized floor: %v", err)
	}
}

func TestFreshSeedProvisionHoldsChangedPlanAndLaterGeneration(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	tests := []struct {
		name   string
		change func(*founderSelectionFixture)
	}{
		{"later generation", func(f *founderSelectionFixture) {
			f.selection.Generation = 2
			f.publish(t, f.selection)
		}},
		{"wrong selected seed", func(f *founderSelectionFixture) {
			f.accepted.ManifestSHA256 = digestWire([]byte("other seed"))
		}},
		{"missing immutable peer", func(f *founderSelectionFixture) {
			for key := range f.objects.items {
				if key == f.domain.LedgerBucket+"/"+FounderImmutableObjectName(f.domain,
					"deployment-a", "GRU", "production", digestWire(f.manifests["controller-a"])) {
					delete(f.objects.items, key)
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := *fixture.founderSelectionFixture
			copy.objects = &founderSelectionObjects{items: make(map[string][]byte), reads: make(map[string]int)}
			for key, value := range fixture.objects.items {
				copy.objects.items[key] = value
			}
			test.change(&copy)
			floor := testFounderFloor(t)
			reader, err := NewCurrentFounderAuthorityReader(copy.baked, copy.accepted, copy.objects, floor)
			if err == nil {
				err = reader.provisionInitial(t.Context(), copy.now, uint32(os.Getuid()), uint32(os.Getgid()), func() error { return nil })
			}
			if err == nil {
				t.Fatal("invalid initial selection provisioned a floor")
			}
			if _, err := os.Stat(floor.directory + "/" + founderSelectionFloorName); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid selection left a floor: %v", err)
			}
		})
	}
}
