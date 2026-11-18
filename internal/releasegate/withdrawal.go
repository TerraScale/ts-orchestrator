package releasegate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const WithdrawalSuffix = ".rollback"
const GateWithdrawn = "withdrawn"

type Withdrawal struct {
	Region string    `json:"region"`
	Tag    string    `json:"tag"`
	Signed time.Time `json:"signed"`
	Reason string    `json:"reason"`
}

func (v Verifier) withdrawal(ctx context.Context, tag string) error {
	fetch, cancel := context.WithTimeout(ctx, FetchWait)
	defer cancel()
	request, err := http.NewRequestWithContext(fetch, http.MethodGet, gateURL(tag+WithdrawalSuffix), nil)
	if err != nil {
		return err
	}
	response, err := v.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("withdrawal read: %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxRecordSize+1))
	if err != nil {
		return err
	}
	var envelope SignedRecord
	if len(data) > MaxRecordSize || json.Unmarshal(data, &envelope) != nil {
		return errors.New("withdrawal is not a signed record")
	}
	digest := sha256.Sum256(envelope.Record)
	if !ecdsa.VerifyASN1(v.StagingKey, digest[:], envelope.Signature) {
		return errors.New("withdrawal signature does not verify")
	}
	var record Withdrawal
	if json.Unmarshal(envelope.Record, &record) != nil || record.Region != scope.Staging.Label || record.Tag != tag || record.Signed.IsZero() || record.Signed.After(time.Now().Add(time.Minute)) || record.Reason == "" {
		return errors.New("withdrawal scope or signing time is invalid")
	}
	return &Refusal{Code: GateWithdrawn, Reason: fmt.Sprintf("staging rolled back %s: %s", tag, record.Reason)}
}
