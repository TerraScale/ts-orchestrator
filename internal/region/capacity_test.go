package region

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func protectedChildFixture() (PoolChildRecord, capacityledger.Host, time.Time) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	launch := PoolWireRecord{RequestSHA256: strings.Repeat("a", 64), RetryToken: "original-launch", FirstAttemptAt: at, LastAttemptAt: at, Attempts: 1, AcceptedAt: at.Add(time.Second)}
	attach := PoolWireRecord{RequestSHA256: strings.Repeat("b", 64), RetryToken: "original-attach", FirstAttemptAt: at.Add(2 * time.Second), LastAttemptAt: at.Add(2 * time.Second), Attempts: 1,
		AcceptedAt: at.Add(3 * time.Second), WorkRequestID: "ocid1.workrequest.oc1..attach", WorkCompletedAt: at.Add(4 * time.Second)}
	child := PoolChildRecord{OperationID: entityid.New(), Stage: PoolChildReady, Launch: &launch, Attach: &attach,
		InstanceID: "ocid1.instance.oc1..original", BootVolumeID: "ocid1.bootvolume.oc1..original", BootAttachmentID: "ocid1.bootvolumeattachment.oc1..original",
		BornAt: launch.AcceptedAt, ReadyAt: at.Add(5 * time.Second)}
	host := capacityledger.Host{RequestSHA256: launch.RequestSHA256, StartedAt: launch.FirstAttemptAt, BornAt: child.BornAt, InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID}
	return child, host, at.Add(time.Minute)
}

func TestProtectedChildRequiresOriginalBirthAttachAndTerminalEvidence(t *testing.T) {
	child, host, updated := protectedChildFixture()
	if err := child.validate(host, updated); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		change func(*PoolChildRecord)
	}{
		{"foreign instance", func(c *PoolChildRecord) { c.InstanceID = "ocid1.instance.oc1..replacement" }},
		{"foreign boot", func(c *PoolChildRecord) { c.BootVolumeID = "ocid1.bootvolume.oc1..replacement" }},
		{"missing original launch", func(c *PoolChildRecord) { c.Launch = nil }},
		{"membership without attach result", func(c *PoolChildRecord) { c.Attach = nil }},
		{"unfinished attach work request", func(c *PoolChildRecord) { c.Attach = new(*c.Attach); c.Attach.WorkCompletedAt = time.Time{} }},
		{"retirement by membership absence", func(c *PoolChildRecord) { c.Stage = PoolChildRetired }},
		{"termination before detach", func(c *PoolChildRecord) { c.Terminate = new(*c.Launch) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			copy := child
			mutation.change(&copy)
			if err := copy.validate(host, updated); err == nil {
				t.Fatal("accepted incomplete or rebound child lifecycle")
			}
		})
	}
}

func TestProtectedBirthCanCheckpointBeforeBootButCannotAttach(t *testing.T) {
	child, host, updated := protectedChildFixture()
	child.Stage, child.Attach, child.ReadyAt = PoolChildBorn, nil, time.Time{}
	child.BootVolumeID, child.BootAttachmentID = "", ""
	host.InstanceID, host.BootVolumeID, host.BornAt = "", "", time.Time{}
	if err := child.validate(host, updated); err != nil {
		t.Fatal(err)
	}
	child.Stage = PoolChildAttachPrepared
	if err := child.validate(host, updated); err == nil {
		t.Fatal("advanced before exact original boot observation")
	}
	child.InstanceID = ""
	child.Stage = PoolChildLaunchUnknown
	child.Launch = new(*child.Launch)
	child.Launch.AcceptedAt, child.BornAt = time.Time{}, time.Time{}
	child.Launch.EverUnknown = true
	if err := child.validate(host, updated); err != nil {
		t.Fatal(err)
	}
	child.Stage, child.Terminate = PoolChildReserved, new(*child.Launch)
	if err := child.validate(host, updated); err == nil {
		t.Fatal("unknown original launch acquired termination authority")
	}
}

func TestCapacitySnapshotDoesNotShareMutableRequests(t *testing.T) {
	child, _, _ := protectedChildFixture()
	original := FoundationRecord{PoolChildren: map[string]PoolChildRecord{child.OperationID: child}}
	copy := original
	copy.cloneCapacity()
	changed := copy.PoolChildren[child.OperationID]
	changed.Launch.RetryToken = "changed"
	copy.PoolChildren[child.OperationID] = changed
	if original.PoolChildren[child.OperationID].Launch.RetryToken != "original-launch" {
		t.Fatal("returned snapshot changed original protected replay token")
	}
}
