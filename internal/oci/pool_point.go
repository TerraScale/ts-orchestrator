package oci

import (
	"context"
	"errors"
	"strings"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// PoolPointRequest pins a reconfiguration separately from growth in the same
// action. TargetSize is the observed precondition; the request leaves size alone.
type PoolPointRequest struct {
	Request             CapacityRequest `json:"request"`
	ConfigurationID     string          `json:"configurationId"`
	ConfigurationSHA256 string          `json:"configurationSha256"`
	PlacementSHA256     string          `json:"placementSha256"`
}

// PoolPointResult records SDK acceptance, not asynchronous completion. Only a
// fresh exact SDK readback can establish the requested configuration and size.
type PoolPointResult struct {
	OperationID             string `json:"operationId"`
	PoolID                  string `json:"poolId"`
	OpcRequestID            string `json:"opcRequestId"`
	ObservedConfigurationID string `json:"observedConfigurationId"`
	ObservedSize            uint32 `json:"observedSize"`
}

func (r PoolPointRequest) validate() error {
	if err := r.Request.validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(r.ConfigurationID, "ocid1.instanceconfiguration.") || !capacityDigest(r.ConfigurationSHA256) ||
		!capacityDigest(r.PlacementSHA256) || r.Request.TargetSize > 9 {
		return errors.New("pool point request lacks exact original configuration, placement or bounded precondition")
	}
	return nil
}

func poolPointKey(operationID string) string { return entityid.Derive("oci-pool-point", operationID) }
func poolPointResultKey(operationID string) string {
	return entityid.Derive("oci-pool-point-result", operationID)
}

func (journal *KVJournal) RecordPoolPointRequest(ctx context.Context, request PoolPointRequest) error {
	if journal == nil {
		return errors.New("pool point request requires the original durable journal")
	}
	if err := request.validate(); err != nil {
		return err
	}
	configuration, _, found, err := journal.GetPoolCreateResource(ctx, request.ConfigurationID)
	if err != nil || !found || !capacityMatchesPool(request.Request, configuration) || configuration.ConfigurationSHA256 != request.ConfigurationSHA256 {
		return errors.Join(err, errors.New("pool point configuration differs from original scoped creation receipt"))
	}
	pool, _, found, err := journal.GetPoolCreateResource(ctx, request.Request.PoolID)
	if err != nil || !found || pool.Kind != PoolCreatePool || pool.TenancyID != configuration.TenancyID || pool.Region != configuration.Region ||
		pool.CompartmentID != configuration.CompartmentID || pool.Role != configuration.Role || pool.Architecture != configuration.Architecture || pool.Shape != configuration.Shape {
		return errors.Join(err, errors.New("pool point resource differs from original pool capacity identity"))
	}
	return journal.writePoolEntry(ctx, poolPointKey(request.Request.OperationID), journalEntry{SchemaVersion: journalSchema, Kind: "pool-point-request", PoolPointRequest: request})
}

func (journal *KVJournal) GetPoolPointRequest(ctx context.Context, operationID string) (PoolPointRequest, bool, error) {
	if journal == nil || !entityid.Valid(operationID) {
		return PoolPointRequest{}, false, errors.New("pool point lookup requires exact durable operation")
	}
	entry, err := journal.read(ctx, poolPointKey(operationID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolPointRequest{}, false, nil
	}
	if err != nil {
		return PoolPointRequest{}, false, err
	}
	request := entry.PoolPointRequest
	if entry.Kind != "pool-point-request" || request.Request.OperationID != operationID || request.validate() != nil {
		return PoolPointRequest{}, false, errors.New("original pool point request is corrupt")
	}
	return request, true, nil
}

func (journal *KVJournal) RecordPoolPointResult(ctx context.Context, operationID string, response core.UpdateInstancePoolResponse) error {
	request, found, err := journal.GetPoolPointRequest(ctx, operationID)
	if err != nil || !found {
		return errors.Join(err, errors.New("pool point SDK acceptance requires exact original request"))
	}
	if response.Id == nil || *response.Id != request.Request.PoolID || response.OpcRequestId == nil || *response.OpcRequestId == "" ||
		response.InstanceConfigurationId == nil || !strings.HasPrefix(*response.InstanceConfigurationId, "ocid1.instanceconfiguration.") ||
		response.CompartmentId == nil || *response.CompartmentId != request.Request.CompartmentID || response.Size == nil || *response.Size < 0 || *response.Size > 9 {
		return errors.New("pool point SDK acceptance differs from original scoped pool or lacks response identity")
	}
	result := PoolPointResult{OperationID: operationID, PoolID: request.Request.PoolID, OpcRequestID: *response.OpcRequestId,
		ObservedConfigurationID: *response.InstanceConfigurationId, ObservedSize: uint32(*response.Size)}
	if original, found, err := journal.GetPoolPointResult(ctx, operationID); err != nil {
		return err
	} else if found {
		result = original
	}
	return journal.writePoolEntry(ctx, poolPointResultKey(operationID), journalEntry{SchemaVersion: journalSchema, Kind: "pool-point-result", PoolPointResult: result})
}

func (journal *KVJournal) GetPoolPointResult(ctx context.Context, operationID string) (PoolPointResult, bool, error) {
	request, found, err := journal.GetPoolPointRequest(ctx, operationID)
	if err != nil || !found {
		return PoolPointResult{}, false, err
	}
	entry, err := journal.read(ctx, poolPointResultKey(operationID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolPointResult{}, false, nil
	}
	if err != nil {
		return PoolPointResult{}, false, err
	}
	result := entry.PoolPointResult
	if entry.Kind != "pool-point-result" || result.OperationID != operationID || result.PoolID != request.Request.PoolID || result.OpcRequestID == "" ||
		!strings.HasPrefix(result.ObservedConfigurationID, "ocid1.instanceconfiguration.") || result.ObservedSize > 9 {
		return PoolPointResult{}, false, errors.New("original pool point SDK acceptance is corrupt")
	}
	return result, true, nil
}
