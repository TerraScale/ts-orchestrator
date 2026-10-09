package app

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
)

func TestCredentialStatusRequiresBothCurrentNativeReports(t *testing.T) {
	expected := [2]managedmaterial.InitialMember{
		{SeatID: "000000000077F1R6E1XPKAC2D4", MemberID: "0000000000WM3QQGQPMW5X58P9", Incarnation: "00000000000098d853d969b1111c1c73"},
		{SeatID: "0000000000GXPF5F560P92PC00", MemberID: "0000000000N9X5GQEQJ9NA9A7V", Incarnation: "000000000000eddc37bb7e610f0b20e6"},
	}
	listed := make([]host.HostStatus, 2)
	for index, member := range expected {
		binding := host.ManagedMemberBinding{Scope: host.MemberScope{
			MemberID: member.MemberID, Incarnation: member.Incarnation,
		}}
		listed[index] = host.HostStatus{Verified: true, Registration: host.Registration{
			Node: member.MemberID,
			ManagedPlacement: &host.ManagedPlacementBinding{
				DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: member.SeatID,
			},
			ManagedMember: &binding,
		}, Reports: []host.Report{{State: "running", Managed: &host.ManagedRuntimeReport{
			Member: binding, ClientCredentialGeneration: 2,
		}}}}
	}
	check := func(hosts []host.HostStatus, want bool) {
		t.Helper()
		applied, members := credentialMembersApplied(expected, 2, hosts, "0000000000WVSMBJNMAWCDJBSK", "0000000000Z3WK359G2W66CVT8")
		if applied != want {
			t.Fatalf("applied=%t, want %t; members=%+v", applied, want, members)
		}
	}
	check(listed[:1], false)
	check(listed, true)
	behind := append([]host.HostStatus(nil), listed...)
	behind[1].Reports = []host.Report{{State: "running", Managed: &host.ManagedRuntimeReport{
		Member: *behind[1].Registration.ManagedMember, ClientCredentialGeneration: 1,
	}}}
	check(behind, false)
	duplicate := append(append([]host.HostStatus(nil), listed...), listed[0])
	check(duplicate, false)
	stale := append([]host.HostStatus(nil), listed...)
	stale[1].Reports = nil // ListHosts removes expired or unbound process observations.
	check(stale, false)
}
