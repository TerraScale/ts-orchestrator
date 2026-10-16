package oci

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// CapacityRequest is immutable evidence of one actual pool update, recorded
// before the SDK call. It grants no spending or complete resource-set authority.
type CapacityRequest struct {
	OperationID          string    `json:"operationId"`
	RecipeSHA256         string    `json:"recipeSha256"`
	LogicalScopeSHA256   string    `json:"logicalScopeSha256"`
	ResolvedScopeSHA256  string    `json:"resolvedScopeSha256"`
	BindingSHA256        string    `json:"bindingSha256,omitempty"`
	GrantSHA256          string    `json:"grantSha256"`
	GrantGeneration      uint64    `json:"grantGeneration"`
	TenancyID            string    `json:"tenancyId"`
	Region               Region    `json:"region"`
	CompartmentID        string    `json:"compartmentId"`
	PoolID               string    `json:"poolId"`
	RequestSHA256        string    `json:"requestSha256"`
	RetryToken           string    `json:"retryToken"`
	IfMatch              string    `json:"ifMatch"`
	Currency             string    `json:"currency"`
	ReservedMonthlyCents uint64    `json:"reservedMonthlyCents"`
	QuoteSHA256          string    `json:"quoteSha256"`
	TargetSize           uint32    `json:"targetSize"`
	StartedAt            time.Time `json:"startedAt"`
}

func (r CapacityRequest) validate() error {
	if !entityid.Valid(r.OperationID) || r.GrantGeneration == 0 || !strings.HasPrefix(r.TenancyID, "ocid1.tenancy.") ||
		!strings.HasPrefix(r.CompartmentID, "ocid1.compartment.") || !strings.HasPrefix(r.PoolID, "ocid1.instancepool.") ||
		r.ReservedMonthlyCents == 0 || r.Currency != "USD" && r.Currency != "BRL" || r.StartedAt.IsZero() || r.StartedAt.Location() != time.UTC ||
		r.IfMatch == "" || len(r.IfMatch) > 1024 || strings.ContainsAny(r.IfMatch, "\r\n") || r.RetryToken == "" || len(r.RetryToken) > 64 || strings.ContainsAny(r.RetryToken, " \t\r\n") {
		return errors.New("capacity SDK request lacks its exact immutable scope, financial receipt or request identity")
	}
	if _, err := r.Region.OCIRegion(); err != nil {
		return err
	}
	for _, value := range []string{r.RecipeSHA256, r.LogicalScopeSHA256, r.ResolvedScopeSHA256, r.GrantSHA256, r.RequestSHA256, r.QuoteSHA256} {
		if !capacityDigest(value) {
			return errors.New("capacity SDK request digest is invalid")
		}
	}
	if r.BindingSHA256 == "" {
		if r.LogicalScopeSHA256 != r.ResolvedScopeSHA256 {
			return errors.New("resolved capacity scope requires the exact verified binding digest")
		}
	} else if !capacityDigest(r.BindingSHA256) {
		return errors.New("capacity SDK request binding digest is invalid")
	}
	return nil
}

func capacityDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == value
}

// RecordCapacityRequest checkpoints the exact request once. An ambiguous KV
// write is recovered only through exact bytes; none of its identity is renewed.
func (journal *KVJournal) RecordCapacityRequest(ctx context.Context, request CapacityRequest) error {
	if journal == nil {
		return errors.New("capacity SDK request requires a durable OCI journal")
	}
	if err := request.validate(); err != nil {
		return err
	}
	entry := journalEntry{SchemaVersion: journalSchema, Kind: "capacity-request", CapacityRequest: request}
	wire, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := capacityRequestKey(request.OperationID)
	if _, err := journal.kv.Create(ctx, key, wire); err == nil {
		return nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	} else {
		current, readErr := journal.read(ctx, key)
		if readErr == nil && current.Kind == entry.Kind && current.CapacityRequest == request {
			return nil
		}
		return fmt.Errorf("capacity SDK request was not established as the exact immutable operation: %w", errors.Join(err, readErr))
	}
}

func (journal *KVJournal) GetCapacityRequest(ctx context.Context, operationID string) (CapacityRequest, bool, error) {
	if journal == nil || !entityid.Valid(operationID) {
		return CapacityRequest{}, false, errors.New("capacity SDK request requires its exact operation ID and durable journal")
	}
	entry, err := journal.read(ctx, capacityRequestKey(operationID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return CapacityRequest{}, false, nil
	}
	if err != nil {
		return CapacityRequest{}, false, err
	}
	if entry.Kind != "capacity-request" || entry.CapacityRequest.OperationID != operationID || entry.CapacityRequest.validate() != nil {
		return CapacityRequest{}, false, errors.New("capacity SDK request journal binding is corrupt")
	}
	return entry.CapacityRequest, true, nil
}

func capacityRequestKey(operationID string) string {
	return entityid.Derive("oci-capacity-request", operationID)
}
