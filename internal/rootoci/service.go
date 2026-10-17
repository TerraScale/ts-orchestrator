package rootoci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootvolumeclient"
)

const OperationAuthorizeNetBirdIntent Operation = "authorize_netbird_intent"

// Backends are all required; every domain remains always on.
type Backends struct {
	Readers           Reader
	Foundations       Foundation
	Credentials       Credentials
	Capacity          Pool
	NetBird           NetBird
	Releases          Releases
	Volumes           VolumeReader
	Workloads         WorkloadCredentials
	Backups           VolumeBackups
	ContainerMaterial ContainerMaterial
}

type Service struct{ backends Backends }

func NewService(backends Backends) (*Service, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	if !validBackends(backends) {
		return nil, ErrInvalid
	}
	return &Service{backends: backends}, nil
}

func validBackends(backends Backends) bool {
	for _, backend := range []any{backends.Readers, backends.Foundations, backends.Credentials, backends.Capacity, backends.NetBird, backends.Releases, backends.Volumes, backends.Workloads, backends.Backups, backends.ContainerMaterial} {
		if !validDependency(backend) {
			return false
		}
	}
	return true
}

func validDependency(backend any) bool {
	if backend == nil {
		return false
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	}
	return true
}

func (service *Service) validRequest(request wireRequest) bool {
	if request.Operation.ReadOnly() {
		return validReadRequest(request)
	}
	if len(request.Payload) > 16<<10 && request.Operation != OperationDeliverControllerGeneration && request.Operation != OperationMaterializeContainer {
		return false
	}
	switch request.Operation {
	case OperationReconcileFoundation:
		var input ReconcileFoundationRequest
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) &&
			(input.CurrentGrantDigest == "" || validDigest(input.CurrentGrantDigest)) &&
			(input.ExpectedOperationID == "" || validSelector(input.ExpectedOperationID))
	case OperationEnsureSource:
		var input SourceRequest
		if decodePayload(request.Payload, &input) != nil || !validSelector(input.Cell) {
			return false
		}
		switch input.Kind {
		case SourceRegional, SourceHomeLink:
			return input.RecipientCell == ""
		case SourceSpokeLink:
			return validSelector(input.RecipientCell) && input.RecipientCell != input.Cell
		default:
			return false
		}
	case OperationDeliverControllerGeneration:
		var input DeliverControllerGenerationRequest
		return decodePayload(request.Payload, &input) == nil && len(input.Chain) > 0 && len(input.Chain) <= MaxGenerationChainBytes
	case OperationAdvancePoolChild:
		var input PoolChildExpectation
		return decodePayload(request.Payload, &input) == nil && validPoolChild(input)
	case OperationRetirePoolChild:
		var input PoolRetirementExpectation
		return decodePayload(request.Payload, &input) == nil && validPoolChild(input.Child) &&
			validSelector(input.InstanceID) && validSelector(input.RemovalOperationID) && optionalDigest(input.DrainSHA256)
	case OperationQuarantinePoolChild:
		var input PoolQuarantineExpectation
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.PoolID) &&
			validSelector(input.InstanceID) && validSelector(input.OperationID) && optionalDigest(input.PurposeSHA256) &&
			validDigest(input.GrantSHA256) && input.Generation > 0 && input.Epoch > 0
	case OperationObservePoolChild:
		var input PoolChildObservation
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.InstanceID) &&
			optionalSelector(input.OperationID) && optionalSelector(input.PoolID) && optionalSelector(input.ConfigurationID) &&
			optionalDigest(input.RecipeSHA256) && optionalDigest(input.GrantSHA256)
	case OperationAuthorizeNetBirdIntent:
		var input NetBirdIntentRequest
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.OperationID) &&
			validSelector(input.RuntimeID) && validSelector(input.OwnerID) && input.Epoch > 0 &&
			input.LeaseRevision > 0 && !input.ExpiresAt.IsZero() && time.Now().Before(input.ExpiresAt)
	case OperationReconcileContainerStatus:
		var input ContainerStatusRequest
		return decodePayload(request.Payload, &input) == nil && entityid.Valid(input.OperationID) && validDigest(input.ExpectedFingerprint)
	case OperationReconcileOrchestratorStatus:
		var input OrchestratorStatusRequest
		return decodePayload(request.Payload, &input) == nil && validDigest(input.ExpectedChannelSHA256)
	case OperationNativeRelease:
		var input NativeReleaseRequest
		return decodePayload(request.Payload, &input) == nil && validNativeRole(input.Role)
	case OperationReleaseBinaryChunk:
		var input ReleaseBinaryChunkRequest
		return decodePayload(request.Payload, &input) == nil && validDigest(input.Digest) &&
			input.Offset >= 0 && input.Offset <= releasechannel.MaxServiceBinaryBytes
	case OperationNativeReleaseBinaryChunk:
		var input NativeReleaseBinaryChunkRequest
		return decodePayload(request.Payload, &input) == nil && validNativeRole(input.Role) && validDigest(input.ExpectedClaimSHA256) &&
			input.Offset >= 0 && input.Offset <= releasechannel.MaxServiceBinaryBytes
	case OperationReconcileNativeServiceStatus:
		var input NativeServiceStatusRequest
		return decodePayload(request.Payload, &input) == nil && validNativeRole(input.Role) && validDigest(input.ExpectedClaimSHA256)
	case OperationInspectVolumeMount:
		var input rootvolumeclient.InspectRequest
		return decodePayload(request.Payload, &input) == nil && input.Valid()
	case OperationObserveTerminatedInstance:
		var input rootvolumeclient.TerminatedRequest
		return decodePayload(request.Payload, &input) == nil && input.Valid()
	case OperationReconcileVolumeBackups:
		return decodePayload(request.Payload, new(struct{})) == nil
	case OperationMaterializeContainer:
		if len(request.Payload) > (64<<10)+128 {
			return false
		}
		var input MaterializeContainerRequest
		if decodePayload(request.Payload, &input) != nil {
			return false
		}
		wire, err := json.Marshal(input.Evidence.Request)
		return err == nil && len(wire) <= 64<<10
	case OperationObserveContainerGeneration:
		var input ObserveContainerGenerationRequest
		return decodePayload(request.Payload, &input) == nil && validSelector(input.TaskID) && len(input.TaskID) <= 25
	case OperationMaterializeNativeCanary:
		var input NativeCanaryRequest
		return decodePayload(request.Payload, &input) == nil && entityid.Valid(input.OperationID) && validNativeNode(input.Node)
	case OperationContainerEvidence, OperationRetainedContainerEvidence:
		var input ContainerEvidenceRequest
		return decodePayload(request.Payload, &input) == nil && entityid.Valid(input.OperationID) && validDigest(input.ExpectedFingerprint) &&
			validDigest(input.EvidenceSHA256) && input.Offset >= 0 && input.Offset < release.MaxProductionEvidenceBytes
	case OperationContainerAllocation, OperationRetainedContainerAllocation:
		var input ContainerAllocationRequest
		return decodePayload(request.Payload, &input) == nil && entityid.Valid(input.OperationID) && validDigest(input.ExpectedFingerprint)
	default:
		return false
	}
}

func optionalSelector(value string) bool { return value == "" || validSelector(value) }
func optionalDigest(value string) bool   { return value == "" || validDigest(value) }
func validNativeRole(role string) bool   { return role == "terrabase" || role == "ts-auth" }

func validNativeNode(node string) bool {
	if node == "" || len(node) > 63 || node[0] < 'a' || node[0] > 'z' {
		return false
	}
	for _, character := range node {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validResponseExpiry(expiresAt time.Time, call Call) bool {
	return time.Now().Before(expiresAt) && !expiresAt.After(call.Deadline())
}

func validReleaseBinaryChunk(chunk ReleaseBinaryChunk, offset int64, call Call) bool {
	return chunk.Size > 0 && chunk.Size <= releasechannel.MaxServiceBinaryBytes && offset >= 0 && offset <= chunk.Size &&
		int64(len(chunk.Data)) == min(int64(ReleaseBinaryChunkBytes), chunk.Size-offset) &&
		validDigest(chunk.Digest) && validResponseExpiry(chunk.ExpiresAt, call)
}

func validPoolChild(input PoolChildExpectation) bool {
	return validSelector(input.Cell) && validSelector(input.OperationID) && validSelector(input.ReservationID) &&
		validDigest(input.RecipeSHA256) && optionalSelector(input.PoolID) && optionalSelector(input.ConfigurationID) &&
		validDigest(input.GrantSHA256) && input.Generation > 0 && input.Epoch > 0
}

func (service *Service) dispatch(ctx context.Context, call Call, request wireRequest) (any, error) {
	if service == nil || !service.validRequest(request) {
		return nil, ErrInvalid
	}
	if err := call.Guard(ctx); err != nil {
		return nil, err
	}
	if request.Operation.ReadOnly() {
		return dispatchRead(ctx, service.backends.Readers, call, request)
	}
	switch request.Operation {
	case OperationReconcileFoundation:
		var input ReconcileFoundationRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Foundations.ReconcileFoundation(ctx, call, input)
	case OperationEnsureSource:
		var input SourceRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Foundations.EnsureSource(ctx, call, input)
	case OperationDeliverControllerGeneration:
		var input DeliverControllerGenerationRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Credentials.DeliverControllerGeneration(ctx, call, input)
	case OperationAdvancePoolChild:
		var input PoolChildExpectation
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Capacity.AdvancePoolChild(ctx, call, input)
	case OperationRetirePoolChild:
		var input PoolRetirementExpectation
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Capacity.RetirePoolChild(ctx, call, input)
	case OperationQuarantinePoolChild:
		var input PoolQuarantineExpectation
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Capacity.QuarantinePoolChild(ctx, call, input)
	case OperationObservePoolChild:
		var input PoolChildObservation
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Capacity.ObservePoolChild(ctx, call, input)
	case OperationAuthorizeNetBirdIntent:
		var input NetBirdIntentRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.NetBird.AuthorizeNetBirdIntent(ctx, call, input)
	case OperationReconcileContainerStatus:
		var input ContainerStatusRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Releases.ReconcileContainerStatus(ctx, call, input)
	case OperationReconcileOrchestratorStatus:
		var input OrchestratorStatusRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		receipt, err := service.backends.Releases.ReconcileOrchestratorStatus(ctx, call, input)
		if err != nil {
			return nil, err
		}
		wire, err := json.Marshal(receipt)
		if err != nil || len(wire) > releasechannel.MaxValueBytes || !validResponseExpiry(receipt.ExpiresAt, call) {
			return nil, ErrUnavailable
		}
		return receipt, nil
	case OperationNativeRelease:
		var input NativeReleaseRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		observation, err := service.backends.Releases.NativeRelease(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if !validResponseExpiry(observation.ExpiresAt, call) || len(observation.Claim) > releasechannel.MaxServiceClaimBytes {
			return nil, ErrUnavailable
		}
		if observation.Found {
			digest := sha256.Sum256(observation.Claim)
			if len(observation.Claim) == 0 || observation.ClaimSHA256 != hex.EncodeToString(digest[:]) {
				return nil, ErrUnavailable
			}
		} else if len(observation.Claim) != 0 || observation.ClaimSHA256 != "" {
			return nil, ErrUnavailable
		}
		return observation, nil
	case OperationReleaseBinaryChunk:
		var input ReleaseBinaryChunkRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		chunk, err := service.backends.Releases.ReleaseBinaryChunk(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if chunk.Digest != input.Digest || !validReleaseBinaryChunk(chunk, input.Offset, call) {
			return nil, ErrUnavailable
		}
		return chunk, nil
	case OperationNativeReleaseBinaryChunk:
		var input NativeReleaseBinaryChunkRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		chunk, err := service.backends.Releases.NativeReleaseBinaryChunk(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if !validReleaseBinaryChunk(chunk, input.Offset, call) {
			return nil, ErrUnavailable
		}
		return chunk, nil
	case OperationReconcileNativeServiceStatus:
		var input NativeServiceStatusRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		receipt, err := service.backends.Releases.ReconcileNativeServiceStatus(ctx, call, input)
		if err != nil {
			return nil, err
		}
		wire, err := json.Marshal(receipt)
		if err != nil || len(wire) > releasechannel.MaxValueBytes || !validResponseExpiry(receipt.ExpiresAt, call) {
			return nil, ErrUnavailable
		}
		return receipt, nil
	case OperationInspectVolumeMount:
		var input rootvolumeclient.InspectRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Volumes.InspectVolumeMount(ctx, call, input)
	case OperationObserveTerminatedInstance:
		var input rootvolumeclient.TerminatedRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Volumes.ObserveTerminatedInstance(ctx, call, input)
	case OperationReconcileVolumeBackups:
		return service.backends.Backups.ReconcileVolumeBackups(ctx, call)
	case OperationMaterializeContainer:
		var input MaterializeContainerRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Workloads.MaterializeContainer(ctx, call, input)
	case OperationObserveContainerGeneration:
		var input ObserveContainerGenerationRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return service.backends.Workloads.ObserveContainerGeneration(ctx, call, input)
	case OperationMaterializeNativeCanary:
		var input NativeCanaryRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		receipt, err := service.backends.Workloads.MaterializeNativeCanary(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if len(receipt.Value) == 0 || len(receipt.Value) > 16<<10 || !validResponseExpiry(receipt.ExpiresAt, call) {
			return nil, ErrUnavailable
		}
		return receipt, nil
	case OperationContainerEvidence:
		var input ContainerEvidenceRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		chunk, err := service.backends.ContainerMaterial.ContainerEvidence(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if len(chunk.Data) == 0 || len(chunk.Data) > ContainerEvidenceChunkBytes || chunk.TotalBytes <= 0 || chunk.TotalBytes > release.MaxProductionEvidenceBytes ||
			chunk.Offset != input.Offset || chunk.Offset >= chunk.TotalBytes || int64(len(chunk.Data)) > chunk.TotalBytes-chunk.Offset {
			return nil, ErrUnavailable
		}
		return chunk, nil
	case OperationContainerAllocation:
		var input ContainerAllocationRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		observation, err := service.backends.ContainerMaterial.ContainerAllocation(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if len(observation.Data) == 0 || len(observation.Data) > release.MaxWorkerFamilyEvidenceBytes {
			return nil, ErrUnavailable
		}
		return observation, nil
	case OperationRetainedContainerEvidence:
		var input RetainedContainerEvidenceRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		chunk, err := service.backends.ContainerMaterial.RetainedContainerEvidence(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if len(chunk.Data) == 0 || len(chunk.Data) > ContainerEvidenceChunkBytes || chunk.TotalBytes <= 0 || chunk.TotalBytes > release.MaxProductionEvidenceBytes ||
			chunk.Offset != input.Offset || chunk.Offset >= chunk.TotalBytes || int64(len(chunk.Data)) > chunk.TotalBytes-chunk.Offset {
			return nil, ErrUnavailable
		}
		return chunk, nil
	case OperationRetainedContainerAllocation:
		var input RetainedContainerAllocationRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		observation, err := service.backends.ContainerMaterial.RetainedContainerAllocation(ctx, call, input)
		if err != nil {
			return nil, err
		}
		if len(observation.Data) == 0 || len(observation.Data) > release.MaxWorkerFamilyEvidenceBytes {
			return nil, ErrUnavailable
		}
		return observation, nil
	default:
		return nil, ErrInvalid
	}
}
