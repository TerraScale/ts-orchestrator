package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestFounderRuntimeRefusesLaunchIntoSeedFaultDomain(t *testing.T) {
	fixture, caller, _, fake := newUnreservedFounderRuntimeFixture(t)
	caller.placement = func(context.Context) (bootstrap.ControllerPlacement, error) {
		return bootstrap.ControllerPlacement{AvailabilityDomain: "Abcd:SA-SAOPAULO-1-AD-1",
			FaultDomain: fixture.plan.Peers[0].FaultDomain}, nil
	}
	err := caller.runPeer(t.Context(), fixture.plan.Peers[0].Slot)
	if !errors.Is(err, bootstrap.ErrControllerAntiAffinity) {
		t.Fatalf("co-located founder launch was not refused: %v", err)
	}
	caller.placement = func(context.Context) (bootstrap.ControllerPlacement, error) {
		return bootstrap.ControllerPlacement{}, errors.New("imds unavailable")
	}
	if err := caller.runPeer(t.Context(), fixture.plan.Peers[0].Slot); err == nil {
		t.Fatal("founder launched without a seed placement")
	}
	caller.placement = nil
	if err := caller.runPeer(t.Context(), fixture.plan.Peers[0].Slot); !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("founder launched without a placement source: %v", err)
	}
	if fake.launches != 0 {
		t.Fatalf("refused anti-affinity still launched %d instances", fake.launches)
	}
	caller.placement = testSeedPlacement
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("found %s in a distinct fault domain: %v", row.Slot, err)
		}
	}
	if fake.launches != len(fixture.plan.Peers) {
		t.Fatalf("launches = %d", fake.launches)
	}
}

func TestFounderPeersCompleteFactBindsExactSeedInstall(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	floor := fixture.floor
	if floor.PeersComplete(fixture.accepted) {
		t.Fatal("absent completion fact reads complete")
	}
	if err := floor.MarkPeersComplete(fixture.accepted); err != nil {
		t.Fatal(err)
	}
	if !floor.PeersComplete(fixture.accepted) {
		t.Fatal("durable completion fact was not read back")
	}
	replacement := fixture.accepted
	replacement.InstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.replacement"
	if floor.PeersComplete(replacement) {
		t.Fatal("completion fact applied to a replacement seed instance")
	}
	reanchored := fixture.accepted
	last := reanchored.AnchorSHA256[len(reanchored.AnchorSHA256)-1]
	flipped := byte('0')
	if last == '0' {
		flipped = '1'
	}
	reanchored.AnchorSHA256 = reanchored.AnchorSHA256[:len(reanchored.AnchorSHA256)-1] + string(flipped)
	if floor.PeersComplete(reanchored) {
		t.Fatal("completion fact applied to a different anchor")
	}
	peer := fixture.accepted
	peer.Slot = "controller-a"
	if floor.PeersComplete(peer) || floor.MarkPeersComplete(peer) == nil {
		t.Fatal("a managed peer used the seed completion fact")
	}
	path := filepath.Join(floor.directory, founderPeersCompleteName)
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if floor.PeersComplete(fixture.accepted) {
		t.Fatal("malformed completion fact reads complete")
	}
}

// A completed seed records the fact once; its next restart needs no ledger.
func TestFounderRuntimeCompletedSeedRestartsWithoutOCI(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	calls := 0
	completed := func(context.Context, BakedInputs, AcceptedInstall) (bool, error) {
		calls++
		return true, nil
	}
	if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
		fixture.floor, completed, testSeedPlacement); err != nil || calls != 1 {
		t.Fatalf("first completed run: err=%v calls=%d", err, calls)
	}
	offline := func(context.Context, BakedInputs, AcceptedInstall) (bool, error) {
		t.Fatal("seed restart read the OCI ledger despite a durable completion fact")
		return false, errors.New("unreachable")
	}
	if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
		fixture.floor, offline, testSeedPlacement); err != nil {
		t.Fatalf("offline seed restart: %v", err)
	}
	if err := os.Remove(filepath.Join(fixture.floor.directory, founderSelectionFloorName)); err != nil {
		t.Fatal(err)
	}
	if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
		fixture.floor, offline, testSeedPlacement); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("completion fact bypassed the durable selection floor: %v", err)
	}
}
