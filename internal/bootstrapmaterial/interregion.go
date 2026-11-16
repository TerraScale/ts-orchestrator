package bootstrapmaterial

import (
	"time"
)

// PrivatePeerReceiptKind and PrivatePeerReceiptPass identify the reviewed
// private-peer foundation readback (ociregion InspectPrivatePeer).

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
