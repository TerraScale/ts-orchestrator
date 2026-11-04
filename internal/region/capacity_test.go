package region

import (
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func protectedChildFixture() (PoolChildRecord, capacityledger.Host, time.Time) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	launch := PoolWireRecord{RequestSHA256: strings.Repeat("a", 64), RetryToken: "original-launch", FirstAttemptAt: at, LastAttemptAt: at, Attempts: 1, AcceptedAt: at.Add(time.Second)}
	attach := PoolWireRecord{RequestSHA256: strings.Repeat("b", 64), RetryToken: "original-attach", FirstAttemptAt: at.Add(2 * time.Second), LastAttemptAt: at.Add(2 * time.Second), Attempts: 1,
		AcceptedAt: at.Add(3 * time.Second), WorkRequestID: "ocid1.workrequest.oc1..attach", WorkCompletedAt: at.Add(4 * time.Second)}
	child := PoolChildRecord{OperationID: entityid.New(), Stage: PoolChildReady, BirthEpoch: 7, Launch: &launch, Attach: &attach,
		InstanceID: "ocid1.instance.oc1..original", BootVolumeID: "ocid1.bootvolume.oc1..original", BootAttachmentID: "ocid1.bootvolumeattachment.oc1..original",
		BornAt: launch.AcceptedAt, ReadyAt: at.Add(5 * time.Second)}
	host := capacityledger.Host{RequestSHA256: launch.RequestSHA256, StartedAt: launch.FirstAttemptAt, BornAt: child.BornAt, InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID}
	return child, host, at.Add(time.Minute)
}
