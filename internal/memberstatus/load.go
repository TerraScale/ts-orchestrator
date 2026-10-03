package memberstatus

import (
	"errors"
	"math"
)

// Load is the optional TerraBase load block of a member status. It is
// operational telemetry for the autoscaler and the dashboard, never
// lifecycle evidence: nothing that admits, retires or fences a member reads
// it. A TerraBase release without the block simply omits it.
type Load struct {
	// Connections is the number of open client connections.
	Connections uint64 `json:"connections"`
	// StorageBytes is the logical size of the member's stored data.
	StorageBytes uint64 `json:"storage_bytes"`
	// ReplicationLagSeq is how many source events the slowest authenticated
	// peer has not applied yet.
	ReplicationLagSeq uint64 `json:"replication_lag_seq"`
	// WriteQPS is the committed write rate over TerraBase's own window.
	WriteQPS float64 `json:"write_qps"`
}

// Bounds keep a misbehaving process from publishing absurd values.
const (
	MaxLoadConnections  = 1 << 24
	MaxLoadStorageBytes = 1 << 50
	MaxLoadLagSeq       = 1 << 48
	MaxLoadWriteQPS     = 1e9
)

var ErrInvalidLoad = errors.New("invalid member load block")

// Validate rejects non-finite, negative or out-of-range load values.
func (l Load) Validate() error {
	if l.Connections > MaxLoadConnections || l.StorageBytes > MaxLoadStorageBytes ||
		l.ReplicationLagSeq > MaxLoadLagSeq || math.IsNaN(l.WriteQPS) || math.IsInf(l.WriteQPS, 0) ||
		l.WriteQPS < 0 || l.WriteQPS > MaxLoadWriteQPS {
		return ErrInvalidLoad
	}
	return nil
}
