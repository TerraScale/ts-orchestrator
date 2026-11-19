package releasegate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"time"
)

const (
	MaxRecordSize = 64 << 10

	GateMissing    = "missing"
	GateUnreadable = "unreadable"
	GateUnsigned   = "unsigned"
	GateBaking     = "baking"
)

type StagingRecord struct {
	Binaries map[string]string `json:"binaries"`
	BakeFor  time.Duration     `json:"bake_for"`
	Region   string            `json:"region"`
	Tag      string            `json:"tag"`
	Done     time.Time         `json:"done"`
	Baked    time.Time         `json:"baked"`
	Signed   time.Time         `json:"signed"`
}

type SignedRecord struct {
	Record    []byte `json:"record"`
	Signature []byte `json:"signature"`
}

func (v Verifier) staging(ctx context.Context, target Target) (string, string) {
	staging := scope.Staging
	fetch, cancel := context.WithTimeout(ctx, FetchWait)
	defer cancel()
	request, err := http.NewRequestWithContext(fetch, http.MethodGet, gateURL(target.Tag), nil)
	if err != nil {
		return GateUnreadable, err.Error()
	}
	response, err := v.Client.Do(request)
	if err != nil {
		return GateUnreadable, err.Error()
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return GateMissing, staging.Label + " has published no baked completion of " + target.Tag
	case response.StatusCode != http.StatusOK:
		return GateUnreadable, gateURL(target.Tag) + " answered " + response.Status
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxRecordSize+1))
	if err != nil {
		return GateUnreadable, err.Error()
	}
	if len(body) > MaxRecordSize {
		return GateUnsigned, fmt.Sprintf("record is over %d bytes", MaxRecordSize)
	}
	var envelope SignedRecord
	if err := json.Unmarshal(body, &envelope); err != nil {
		return GateUnsigned, "record is not a signed record: " + err.Error()
	}
	digest := sha256.Sum256(envelope.Record)
	if !ecdsa.VerifyASN1(v.StagingKey, digest[:], envelope.Signature) {
		return GateUnsigned, "signature does not verify with staging.signer_public_key"
	}
	var record StagingRecord
	if err := json.Unmarshal(envelope.Record, &record); err != nil {
		return GateUnsigned, "signed record is damaged: " + err.Error()
	}
	if record.Region != staging.Label || record.Tag != target.Tag {
		return GateUnsigned, fmt.Sprintf("signed record is for %s %s, not %s %s", record.Region, record.Tag, staging.Label, target.Tag)
	}
	if !maps.Equal(record.Binaries, target.Binaries) || len(record.Binaries) == 0 {
		return GateUnsigned, "signed staging completion names another binary digest"
	}
	if record.Done.IsZero() || record.BakeFor <= 0 || record.Baked.Sub(record.Done) < record.BakeFor || record.Signed.Before(record.Baked) {
		return GateBaking, fmt.Sprintf("%s baked %s for %s, under %s", staging.Label, target.Tag, record.Baked.Sub(record.Done), record.BakeFor)
	}
	if record.Signed.IsZero() || record.Signed.After(time.Now().Add(time.Minute)) {
		return GateUnsigned, "completion signing time is invalid"
	}
	return "", ""
}
