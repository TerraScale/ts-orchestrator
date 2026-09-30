package app

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
)

func TestCredentialStatusRequiresBothCurrentNativeReports(t *testing.T) {
	expected := [2]managedmaterial.InitialMember{
		{SeatID: "seat-a", MemberID: "member-a", Incarnation: "incarnation-a"},
		{SeatID: "seat-b", MemberID: "member-b", Incarnation: "incarnation-b"},
	}
	listed := make([]host.HostStatus, 2)
	for index, member := range expected {
		binding := host.ManagedMemberBinding{Scope: host.MemberScope{
			MemberID: member.MemberID, Incarnation: member.Incarnation,
		}}
		listed[index] = host.HostStatus{Verified: true, Registration: host.Registration{
			Node: member.MemberID,
			ManagedPlacement: &host.ManagedPlacementBinding{
				DatabaseID: "database-a", PartitionID: "partition-a", SeatID: member.SeatID,
			},
			ManagedMember: &binding,
		}, Reports: []host.Report{{State: "running", Managed: &host.ManagedRuntimeReport{
			Member: binding, ClientCredentialGeneration: 2,
		}}}}
	}
	check := func(hosts []host.HostStatus, want bool) {
		t.Helper()
		applied, members := credentialMembersApplied(expected, 2, hosts, "database-a", "partition-a")
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
