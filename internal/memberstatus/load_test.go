package memberstatus

import (
	"strings"
	"testing"
)

// The optional load block is split off before the strict evidence decode,
// so no value inside it can fail the status, while the evidence itself
// stays strict.
func TestSplitLoadKeepsEvidenceStrictAndLoadLenient(t *testing.T) {
	const evidence = `{"schema_version":2,"receiver_only":false`
	for name, load := range map[string]string{
		"negative counter": `{"connections":-1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		"overflowing qps":  `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1e400}`,
		"string counter":   `{"connections":"1","storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		"incomplete":       `{"connections":1}`,
		"unknown member":   `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1,"extra":1}`,
		"out of range":     `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":-1}`,
		"null":             `null`,
		"array":            `[]`,
	} {
		rest, raw := splitLoad([]byte(evidence + `,"load":` + load + `}`))
		if strings.Contains(string(rest), "load") || string(raw) != load {
			t.Errorf("%s: split = %s / %s", name, rest, raw)
		}
		var status Status
		if err := decodeRequired(rest, &status, "schema_version", "receiver_only"); err != nil {
			t.Errorf("%s: evidence failed with the load block removed: %v", name, err)
		}
		if got := DecodeLoad(raw); got != nil {
			t.Errorf("%s: load accepted: %+v", name, got)
		}
	}
	rest, raw := splitLoad([]byte(evidence + `,"load":{"connections":4,"storage_bytes":5,"replication_lag_seq":6,"write_qps":7.5}}`))
	if got := DecodeLoad(raw); got == nil || *got != (Load{Connections: 4, StorageBytes: 5, ReplicationLagSeq: 6, WriteQPS: 7.5}) {
		t.Fatalf("valid load = %+v", got)
	}
	var status Status
	if err := decodeRequired(rest, &status, "schema_version"); err != nil || status.Load != nil {
		t.Fatalf("evidence = %+v, %v", status, err)
	}
	// Without a block, and for bodies the strict decoder must refuse, the
	// body passes through unchanged.
	for _, body := range []string{evidence + `}`, `[1]`, `{"load":1,"load":2}`} {
		if rest, raw := splitLoad([]byte(body)); string(rest) != body || raw != nil {
			t.Errorf("%s: split = %s / %s", body, rest, raw)
		}
	}
	if DecodeLoad(nil) != nil {
		t.Fatal("absent load decoded")
	}
}
