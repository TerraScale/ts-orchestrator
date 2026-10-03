package memberstatus

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
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

// loadFields are the counters a load block must carry; a missing counter
// never reads as zero load.
var loadFields = []string{"connections", "storage_bytes", "replication_lag_seq", "write_qps"}

// DecodeLoad parses a raw load block. Any problem (malformed JSON, a value
// of the wrong type or out of range such as a negative counter or 1e400, a
// missing counter, an unknown member, or null) yields nil instead of an
// error: the block is telemetry, never evidence, so it can never fail the
// status that carries it, and a newer TerraBase that adds a counter only
// loses its telemetry until this build learns the field.
func DecodeLoad(raw []byte) *Load {
	if len(raw) == 0 {
		return nil
	}
	var load Load
	if decodeRequired(raw, &load, loadFields...) != nil || load.Validate() != nil {
		return nil
	}
	return &load
}

// splitLoad removes the optional top-level "load" member from a status body
// and returns it separately, so the lifecycle evidence is decoded strictly
// while the telemetry block is decoded leniently. A body that is not a JSON
// object, or has duplicate names, is returned unchanged for the strict
// decoder to refuse.
func splitLoad(body []byte) (evidence, load []byte) {
	var root map[string]jsontext.Value
	if err := json.Unmarshal(body, &root); err != nil {
		return body, nil
	}
	raw, present := root["load"]
	if !present {
		return body, nil
	}
	delete(root, "load")
	evidence, err := json.Marshal(root)
	if err != nil {
		return body, nil
	}
	return evidence, raw
}
