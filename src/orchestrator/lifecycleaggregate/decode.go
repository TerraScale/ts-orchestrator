package lifecycleaggregate

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// DecodeSample rejects absent protective facts, rather than converting them to
// Go zero values that could authorize deletion. Transport must authenticate the
// sample to the expected accepted region before calling this function.
func DecodeSample(raw []byte) (Sample, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return Sample{}, ErrIncomplete
	}
	var fields map[string]jsontext.Value
	if json.Unmarshal(raw, &fields) != nil {
		return Sample{}, ErrIncomplete
	}
	for _, field := range []string{"schemaVersion", "organizationId", "projectId", "databaseId", "region", "placementRevision", "writerEpoch", "observedAt", "lastAuthorizedRequestAt", "deletionProtection", "accessRevoked", "usageStoppedAt", "retainUntil", "generation"} {
		value, found := fields[field]
		if !found {
			return Sample{}, ErrIncomplete
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && field != "lastAuthorizedRequestAt" && field != "usageStoppedAt" && field != "retainUntil" {
			return Sample{}, ErrIncomplete
		}
	}
	var sample Sample
	if json.Unmarshal(raw, &sample, json.RejectUnknownMembers(true)) != nil {
		return Sample{}, ErrIncomplete
	}
	return sample, nil
}
