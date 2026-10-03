package app

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// A member replaced after losing its host serves from host attempt N+1 with
// the same roster row; backups of its partition must keep working.
func TestBackupRosterFollowsAReplacedMembersCurrentHostAttempt(t *testing.T) {
	intent := testManagedPlacementIntent()
	if len(intent.CanonicalRoster.Rows) == 0 {
		t.Fatal("test intent has no roster")
	}
	row := intent.CanonicalRoster.Rows[0]
	states := backupAdmissionServingStates(intent, []string{"managed-host-a-2", "managed-host-b"})
	states[0].State.HostAttempt = 2
	member, found := backupServingMember(intent, row, states, "terrabase")
	if !found || member.Node != "managed-host-a-2" || member.MemberID != row.MemberID || member.Role != "terrabase" {
		t.Fatalf("replaced member = %+v, %v; want it serving on its attempt-2 host", member, found)
	}

	for name, mutate := range map[string]func(*placement.MemberState){
		"no host attempt":         func(state *placement.MemberState) { state.HostAttempt = 0 },
		"replacement not serving": func(state *placement.MemberState) { state.Stage = placement.StagePreparedHost },
		"lost host cleared":       func(state *placement.MemberState) { state.HostNode = "" },
		"older intent":            func(state *placement.MemberState) { state.IntentGeneration-- },
	} {
		changed := backupAdmissionServingStates(intent, []string{"managed-host-a-2", "managed-host-b"})
		changed[0].State.HostAttempt = 2
		mutate(&changed[0].State)
		if member, found := backupServingMember(intent, row, changed, "terrabase"); found {
			t.Errorf("%s: selected %+v", name, member)
		}
	}
}
