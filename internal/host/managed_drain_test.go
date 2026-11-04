//go:build linux

package host

import (
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
)

func TestManagedDrainCommandBindsDesiredAndNativeProcess(t *testing.T) {
	registration, desired, _ := managedContractFixture()
	desired.ManagedMember.Runtime = &ManagedRuntimePins{
		ReplicationPeerMemberID: "01HW000000E008000000000002",
	}
	command := ManagedDrainCommand{
		OperationID: "0H248H248H248H248H248H248H", Node: desired.Node, Role: desired.Role,
		Epoch: 2, DesiredGeneration: desired.Generation, ExpectedETag: "etag-current",
		Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID,
		AttachmentID:    desired.ManagedMember.AttachmentID,
		ExpectedProcess: memberstatus.Process{PID: 1234, StartNonce: "00000000000064eeb57eb73c4a8035be"},
		Survivor: memberstatus.Survivor{MemberID: desired.ManagedMember.Runtime.ReplicationPeerMemberID,
			Incarnation: "33333333333333333333333333333333"},
		SourceSequence: 12,
	}
	if !command.matchesDesired(desired, registration) {
		t.Fatal("exact command did not match the signed desired")
	}
	newLeader := command
	newLeader.Epoch++
	if !sameManagedDrainOperation(command, newLeader) {
		t.Fatal("leader change changed the durable member drain operation")
	}
	newLeader.OperationID = "00000000000000000000000009"
	if sameManagedDrainOperation(command, newLeader) {
		t.Fatal("new operation reused an existing member drain command")
	}
	for _, change := range []func(*ManagedDrainCommand){
		func(c *ManagedDrainCommand) { c.ExpectedProcess.StartNonce = strings.Repeat("4", 32)[:31] },
		func(c *ManagedDrainCommand) { c.Survivor.MemberID = c.Member.Scope.MemberID },
		func(c *ManagedDrainCommand) { c.VolumeID = "ocid1.volume.other" },
		func(c *ManagedDrainCommand) { c.Member.Scope.Incarnation = strings.Repeat("4", 32) },
		func(c *ManagedDrainCommand) { c.Authority.Epoch++ },
		func(c *ManagedDrainCommand) { c.OCI.InstanceID = "ocid1.instance.other" },
	} {
		altered := command
		change(&altered)
		if altered.matchesDesired(desired, registration) {
			t.Fatalf("retargeted managed drain command was admitted: %+v", altered)
		}
	}
}
