package oci

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type CapacityResult struct {
	OperationID     string `json:"operationId"`
	PoolID          string `json:"poolId"`
	ConfigurationID string `json:"configurationId"`
	TargetSize      uint32 `json:"targetSize"`
	OpcRequestID    string `json:"opcRequestId"`
}

func capacityResultKey(operationID string) string {
	return entityid.Derive("oci-capacity-result", operationID)
}

// RecordCapacityResult retains only a positive SDK response to the exact saved
// request. Current state or a matching tag cannot establish a missing result.
func (journal *KVJournal) RecordCapacityResult(ctx context.Context, operationID string, response core.UpdateInstancePoolResponse) error {
	request, found, err := journal.GetCapacityRequest(ctx, operationID)
	if err != nil || !found {
		return errors.Join(err, errors.New("positive capacity result requires its original request"))
	}
	if response.Id == nil || *response.Id != request.PoolID || response.Size == nil || *response.Size < 1 || uint32(*response.Size) != request.TargetSize ||
		response.InstanceConfigurationId == nil || response.OpcRequestId == nil || *response.OpcRequestId == "" {
		return errors.New("positive capacity result differs from original pool and target or lacks SDK identity")
	}
	configuration, _, found, err := journal.GetPoolCreateResource(ctx, *response.InstanceConfigurationId)
	if err != nil || !found || !capacityMatchesPool(request, configuration) {
		return errors.Join(err, errors.New("positive capacity result lacks matching protected original configuration"))
	}
	result := CapacityResult{OperationID: operationID, PoolID: request.PoolID, ConfigurationID: *response.InstanceConfigurationId,
		TargetSize: request.TargetSize, OpcRequestID: *response.OpcRequestId}
	if original, found, err := journal.GetCapacityResult(ctx, operationID); err != nil {
		return err
	} else if found {
		if original.PoolID != result.PoolID || original.ConfigurationID != result.ConfigurationID || original.TargetSize != result.TargetSize {
			return errors.New("capacity result differs from original accepted effect")
		}
		result = original
	}
	return journal.writePoolEntry(ctx, capacityResultKey(operationID), journalEntry{SchemaVersion: journalSchema, Kind: "capacity-result", CapacityResult: result})
}

func (journal *KVJournal) GetCapacityResult(ctx context.Context, operationID string) (CapacityResult, bool, error) {
	request, found, err := journal.GetCapacityRequest(ctx, operationID)
	if err != nil || !found {
		return CapacityResult{}, false, err
	}
	entry, err := journal.read(ctx, capacityResultKey(operationID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return CapacityResult{}, false, nil
	}
	if err != nil {
		return CapacityResult{}, false, err
	}
	result := entry.CapacityResult
	if entry.Kind != "capacity-result" || result.OperationID != operationID || result.PoolID != request.PoolID || result.TargetSize != request.TargetSize ||
		!strings.HasPrefix(result.ConfigurationID, "ocid1.instanceconfiguration.") || result.OpcRequestID == "" {
		return CapacityResult{}, false, errors.New("protected capacity result is corrupt")
	}
	return result, true, nil
}

func capacityMatchesPool(request CapacityRequest, origin PoolCreateRequest) bool {
	return origin.Kind == PoolCreateConfiguration && request.RecipeSHA256 == origin.RecipeSHA256 && request.LogicalScopeSHA256 == origin.LogicalScopeSHA256 &&
		request.ResolvedScopeSHA256 == origin.ResolvedScopeSHA256 && request.BindingSHA256 == origin.BindingSHA256 && request.GrantSHA256 == origin.GrantSHA256 &&
		request.GrantGeneration == origin.GrantGeneration && request.TenancyID == origin.TenancyID && request.Region == origin.Region && request.CompartmentID == origin.CompartmentID
}

// ErrPoolCreationLineagePending preserves admission until a provider-authenticated
// child creation result is linked to independently protected original authority.
var ErrPoolCreationLineagePending = errors.New("pool instance admission pending: authenticated original-operation child creation lineage and independent result authority are unavailable")

// VerifiedPoolInstance is reserved for original creation authority, not current
// membership. The pinned pool API provides no authenticated child-ID lineage,
// so current pool observations cannot mint this proof.
type VerifiedPoolInstance struct {
	instanceID, poolID, configurationID                 string
	recipeSHA256, grantDigest, cell, role, architecture string
	generation                                          uint64
	expiresAt                                           time.Time
}

func (p VerifiedPoolInstance) IsVerified() bool                 { return false }
func (p VerifiedPoolInstance) InstanceID() string               { return p.instanceID }
func (p VerifiedPoolInstance) PoolID() string                   { return p.poolID }
func (p VerifiedPoolInstance) ConfigurationID() string          { return p.configurationID }
func (p VerifiedPoolInstance) RecipeSHA256() string             { return p.recipeSHA256 }
func (p VerifiedPoolInstance) GrantDigest() string              { return p.grantDigest }
func (p VerifiedPoolInstance) Generation() uint64               { return p.generation }
func (p VerifiedPoolInstance) Cell() string                     { return p.cell }
func (p VerifiedPoolInstance) Role() string                     { return p.role }
func (p VerifiedPoolInstance) Architecture() string             { return p.architecture }
func (p VerifiedPoolInstance) ExpiresAt() time.Time             { return p.expiresAt }
func (p VerifiedPoolInstance) Revalidate(context.Context) error { return ErrPoolCreationLineagePending }

func (journal *KVJournal) VerifyPoolInstance(ctx context.Context, factory *ociclient.Factory, instanceID string) (VerifiedPoolInstance, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedPoolInstance{}, err
	}
	if journal == nil || factory == nil || !strings.HasPrefix(instanceID, "ocid1.instance.") {
		return VerifiedPoolInstance{}, errors.New("pool instance creation authority requires exact instance, journal and authenticated SDK factory")
	}
	return VerifiedPoolInstance{}, ErrPoolCreationLineagePending
}
