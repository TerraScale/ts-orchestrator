package oci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	PoolCreateConfiguration = "configuration"
	PoolCreatePool          = "pool"
)

// PoolCreateRequest retains the original admitted create, before its SDK call.
// Its grant metadata is provenance; consumers independently verify signed authority.
type PoolCreateRequest struct {
	OperationID          string    `json:"operationId"`
	Kind                 string    `json:"kind"`
	RecipeSHA256         string    `json:"recipeSha256"`
	LogicalScopeSHA256   string    `json:"logicalScopeSha256"`
	ResolvedScopeSHA256  string    `json:"resolvedScopeSha256"`
	BindingSHA256        string    `json:"bindingSha256,omitempty"`
	GrantSHA256          string    `json:"grantSha256"`
	GrantGeneration      uint64    `json:"grantGeneration"`
	TenancyID            string    `json:"tenancyId"`
	Region               Region    `json:"region"`
	CompartmentID        string    `json:"compartmentId"`
	Role                 string    `json:"role"`
	Architecture         string    `json:"architecture"`
	Shape                string    `json:"shape"`
	ConfigurationID      string    `json:"configurationId,omitempty"`
	ConfigurationSHA256  string    `json:"configurationSha256"`
	PlacementSHA256      string    `json:"placementSha256,omitempty"`
	RequestSHA256        string    `json:"requestSha256"`
	RetryToken           string    `json:"retryToken"`
	Currency             string    `json:"currency"`
	ReservedMonthlyCents uint64    `json:"reservedMonthlyCents"`
	QuoteSHA256          string    `json:"quoteSha256"`
	StartedAt            time.Time `json:"startedAt"`
}

type PoolCreateResult struct {
	OperationID  string `json:"operationId"`
	Kind         string `json:"kind"`
	ResourceID   string `json:"resourceId"`
	OpcRequestID string `json:"opcRequestId"`
}

func (r PoolCreateRequest) validate() error {
	// Reuse the exact original receipt validation without inventing a pool ID.
	base := CapacityRequest{OperationID: r.OperationID, RecipeSHA256: r.RecipeSHA256, LogicalScopeSHA256: r.LogicalScopeSHA256,
		ResolvedScopeSHA256: r.ResolvedScopeSHA256, BindingSHA256: r.BindingSHA256, GrantSHA256: r.GrantSHA256, GrantGeneration: r.GrantGeneration,
		TenancyID: r.TenancyID, Region: r.Region, CompartmentID: r.CompartmentID,
		RequestSHA256: r.RequestSHA256, RetryToken: r.RetryToken, Currency: r.Currency,
		ReservedMonthlyCents: r.ReservedMonthlyCents, QuoteSHA256: r.QuoteSHA256, StartedAt: r.StartedAt}
	if err := base.validateReceipt(); err != nil {
		return err
	}
	if !capacityDigest(r.ConfigurationSHA256) || r.Shape == "" || r.Architecture != "arm64" && r.Architecture != "amd64" ||
		r.Role != "manager" && r.Role != "container" && r.Role != "wasm" {
		return errors.New("pool create lacks exact configuration, role or architecture provenance")
	}
	switch r.Kind {
	case PoolCreateConfiguration:
		if r.ConfigurationID != "" || r.PlacementSHA256 != "" {
			return errors.New("configuration create cannot claim an existing resource or pool placement")
		}
	case PoolCreatePool:
		if !strings.HasPrefix(r.ConfigurationID, "ocid1.instanceconfiguration.") || !capacityDigest(r.PlacementSHA256) {
			return errors.New("pool create requires exact original configuration and placement")
		}
	default:
		return errors.New("unknown protected pool create kind")
	}
	return nil
}

func poolCreateKey(operationID, kind string) string {
	return entityid.Derive("oci-pool-create", operationID, kind)
}

func poolCreateResultKey(operationID, kind string) string {
	return entityid.Derive("oci-pool-create-result", operationID, kind)
}

func poolResourceKey(resourceID string) string {
	return entityid.Derive("oci-pool-resource", resourceID)
}

func (journal *KVJournal) RecordPoolCreateRequest(ctx context.Context, request PoolCreateRequest) error {
	if journal == nil {
		return errors.New("pool create requires a protected durable journal")
	}
	if err := request.validate(); err != nil {
		return err
	}
	if request.Kind == PoolCreatePool {
		configuration, _, found, err := journal.GetPoolCreateResource(ctx, request.ConfigurationID)
		if err != nil || !found || !samePoolAuthority(configuration, request) {
			return fmt.Errorf("pool create lacks matching original configuration authority: %w", errors.Join(err, errors.New("protected original configuration required")))
		}
	}
	return journal.writePoolEntry(ctx, poolCreateKey(request.OperationID, request.Kind), journalEntry{
		SchemaVersion: journalSchema, Kind: "pool-create-request", PoolCreateRequest: request})
}

func (journal *KVJournal) GetPoolCreateRequest(ctx context.Context, operationID, kind string) (PoolCreateRequest, bool, error) {
	if journal == nil || !entityid.Valid(operationID) || kind != PoolCreateConfiguration && kind != PoolCreatePool {
		return PoolCreateRequest{}, false, errors.New("pool create lookup requires exact operation and kind")
	}
	entry, err := journal.read(ctx, poolCreateKey(operationID, kind))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolCreateRequest{}, false, nil
	}
	if err != nil {
		return PoolCreateRequest{}, false, err
	}
	if entry.Kind != "pool-create-request" || entry.PoolCreateRequest.OperationID != operationID || entry.PoolCreateRequest.Kind != kind || entry.PoolCreateRequest.validate() != nil {
		return PoolCreateRequest{}, false, errors.New("protected pool create request is corrupt")
	}
	return entry.PoolCreateRequest, true, nil
}

// RecordPoolCreateResult accepts a positive SDK create response, never a list,
// name, tag or body match. Replaying it repairs an interrupted resource index.
func (journal *KVJournal) RecordPoolCreateResult(ctx context.Context, operationID, kind, resourceID, opcRequestID string) error {
	_, found, err := journal.GetPoolCreateRequest(ctx, operationID, kind)
	if err != nil || !found {
		return errors.Join(err, errors.New("positive pool result requires its original protected request"))
	}
	prefix := "ocid1.instanceconfiguration."
	if kind == PoolCreatePool {
		prefix = "ocid1.instancepool."
	}
	if !strings.HasPrefix(resourceID, prefix) || opcRequestID == "" || len(opcRequestID) > 1024 || strings.ContainsAny(opcRequestID, "\r\n") {
		return errors.New("positive pool result lacks exact SDK resource and request identity")
	}
	result := PoolCreateResult{OperationID: operationID, Kind: kind, ResourceID: resourceID, OpcRequestID: opcRequestID}
	if original, found, err := journal.GetPoolCreateResult(ctx, operationID, kind); err != nil {
		return err
	} else if found {
		if original.ResourceID != resourceID {
			return errors.New("pool create result cannot replace its original returned resource")
		}
		result = original
	}
	entry := journalEntry{SchemaVersion: journalSchema, Kind: "pool-create-result", PoolCreateResult: result}
	if err := journal.writePoolEntry(ctx, poolCreateResultKey(operationID, kind), entry); err != nil {
		return err
	}
	return journal.writePoolEntry(ctx, poolResourceKey(resourceID), entry)
}

func (journal *KVJournal) GetPoolCreateResult(ctx context.Context, operationID, kind string) (PoolCreateResult, bool, error) {
	if _, found, err := journal.GetPoolCreateRequest(ctx, operationID, kind); err != nil || !found {
		return PoolCreateResult{}, false, err
	}
	entry, err := journal.read(ctx, poolCreateResultKey(operationID, kind))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolCreateResult{}, false, nil
	}
	if err != nil {
		return PoolCreateResult{}, false, err
	}
	result := entry.PoolCreateResult
	if entry.Kind != "pool-create-result" || result.OperationID != operationID || result.Kind != kind || result.ResourceID == "" || result.OpcRequestID == "" {
		return PoolCreateResult{}, false, errors.New("protected original pool result is corrupt")
	}
	return result, true, nil
}

func (journal *KVJournal) GetPoolCreateResource(ctx context.Context, resourceID string) (PoolCreateRequest, PoolCreateResult, bool, error) {
	if journal == nil || resourceID == "" {
		return PoolCreateRequest{}, PoolCreateResult{}, false, errors.New("original pool resource requires its protected journal and exact ID")
	}
	entry, err := journal.read(ctx, poolResourceKey(resourceID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolCreateRequest{}, PoolCreateResult{}, false, nil
	}
	if err != nil {
		return PoolCreateRequest{}, PoolCreateResult{}, false, err
	}
	result := entry.PoolCreateResult
	if entry.Kind != "pool-create-result" || result.ResourceID != resourceID {
		return PoolCreateRequest{}, PoolCreateResult{}, false, errors.New("original pool resource index is corrupt")
	}
	original, found, err := journal.GetPoolCreateResult(ctx, result.OperationID, result.Kind)
	if err != nil || !found || original != result {
		return PoolCreateRequest{}, PoolCreateResult{}, false, errors.Join(err, errors.New("pool resource differs from original positive create response"))
	}
	request, found, err := journal.GetPoolCreateRequest(ctx, result.OperationID, result.Kind)
	return request, result, found, err
}

func (journal *KVJournal) writePoolEntry(ctx context.Context, key string, entry journalEntry) error {
	wire, err := json.Marshal(entry, json.Deterministic(true))
	if err != nil {
		return err
	}
	if _, err := journal.kv.Create(ctx, key, wire); err == nil {
		return nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	} else {
		current, readErr := journal.read(ctx, key)
		encoded, encodeErr := json.Marshal(current, json.Deterministic(true))
		if readErr == nil && encodeErr == nil && bytes.Equal(encoded, wire) {
			return nil
		}
		return fmt.Errorf("protected pool receipt conflicts with immutable original: %w", errors.Join(err, readErr, encodeErr))
	}
}

func samePoolAuthority(a, b PoolCreateRequest) bool {
	return a.RecipeSHA256 == b.RecipeSHA256 && a.LogicalScopeSHA256 == b.LogicalScopeSHA256 && a.ResolvedScopeSHA256 == b.ResolvedScopeSHA256 &&
		a.BindingSHA256 == b.BindingSHA256 && a.GrantSHA256 == b.GrantSHA256 && a.GrantGeneration == b.GrantGeneration && a.TenancyID == b.TenancyID &&
		a.Region == b.Region && a.CompartmentID == b.CompartmentID && a.Role == b.Role && a.Architecture == b.Architecture && a.Shape == b.Shape && a.ConfigurationSHA256 == b.ConfigurationSHA256
}

func PoolConfigurationSHA256(details core.InstanceConfigurationInstanceDetails) (string, error) {
	if details == nil {
		return "", errors.New("exact SDK configuration details are absent")
	}
	// SDK readback normalizes omitted polymorphic slices; normalize creates
	// through that same decoder before comparing their exact configuration.
	wire, err := json.Marshal(struct {
		InstanceDetails core.InstanceConfigurationInstanceDetails `json:"instanceDetails"`
	}{details})
	if err != nil {
		return "", err
	}
	var normalized core.InstanceConfiguration
	if err := json.Unmarshal(wire, &normalized); err != nil {
		return "", err
	}
	return poolPayloadSHA256(normalized.InstanceDetails)
}

func PoolPlacementSHA256(placements []core.CreateInstancePoolPlacementConfigurationDetails) (string, error) {
	if len(placements) == 0 || len(placements) > 16 {
		return "", errors.New("exact SDK pool placements are absent or exceed bound")
	}
	return poolPayloadSHA256(placements)
}

func poolPayloadSHA256(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}
