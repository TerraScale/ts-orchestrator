package app

import (
	"context"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

var errReachedPlacement = errors.New("reached the placement check")

type stubPlacementReader struct{ calls int }

func (reader *stubPlacementReader) ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error) {
	reader.calls++
	return authority.LogEntry{}, errReachedPlacement
}

type stubMemberReader struct{ state placement.MemberState }

func (reader stubMemberReader) ReadMember(context.Context, string, string, string) (placement.VersionedMemberState, error) {
	return placement.VersionedMemberState{State: reader.state, Revision: 3}, nil
}

// Material is delivered to the seat's exact current durable host attempt,
// including the next attempt after a replacement, and never to a superseded
// one (#127 12097).
func TestManagedMaterialFollowsTheCurrentDurableHostAttempt(t *testing.T) {
	binding := host.ManagedMemberBinding{Scope: host.MemberScope{MemberID: "0000000000WM3QQGQPMW5X58P9"}, HostAttempt: 2}
	oci := host.ManagedOCIBinding{InstanceID: "ocid1.instance.oc1..replacement", CreateKey: "00000000005TNNS4T26SFB7M25"}
	desired := host.Desired{ManagedMember: &host.ManagedMemberLaunch{Member: binding, OCI: oci,
		Runtime: &host.ManagedRuntimePins{}}}
	registration := host.Registration{Node: "replacement-node", ManagedMember: &binding, ManagedOCI: &oci,
		ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "0000000000KJ432RJ85B7APRW2", SeatID: "00000000000E5NVMSGX0D07DPA"}}
	current := placement.MemberState{HostAttempt: 2, HostNode: "replacement-node",
		InstanceID: "ocid1.instance.oc1..replacement", CreateKey: "00000000005TNNS4T26SFB7M25"}

	placements := &stubPlacementReader{}
	provider := admittedManagedMaterialProvider(managedmaterial.PreparationService{}, placements, stubMemberReader{state: current},
		managedmaterial.CredentialService{}, nil)
	if _, err := provider(t.Context(), desired, registration); !errors.Is(err, errReachedPlacement) {
		t.Fatalf("the current replacement attempt was refused before placement: %v", err)
	}

	superseded := current
	superseded.HostAttempt = 3
	placements = &stubPlacementReader{}
	provider = admittedManagedMaterialProvider(managedmaterial.PreparationService{}, placements, stubMemberReader{state: superseded},
		managedmaterial.CredentialService{}, nil)
	if _, err := provider(t.Context(), desired, registration); err == nil || errors.Is(err, errReachedPlacement) || placements.calls != 0 {
		t.Fatalf("a superseded attempt passed the attempt check: %v", err)
	}
}
