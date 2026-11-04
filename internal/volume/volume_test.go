package volume

import (
	"time"
)

const testZone = "Uocm:SA-SAOPAULO-1-AD-1"

// m1 and m2 are machine IDs.
const m1, m2 = "0000000000NDAHWBAS9TWA2688", "0000000000010GG0W1SYDN4G5Z"

var created = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func testVolume(id string) Volume {
	return Volume{SchemaVersion: SchemaVersion, ID: id, App: "terrabase", Name: "data", Region: "gru", Zone: testZone,
		SizeGB: 50, VPUsPerGB: DefaultVPUsPerGB, SnapshotRetentionDays: DefaultSnapshotRetentionDays,
		CreatedAt: created, Status: Status{State: StateCreating}}
}
