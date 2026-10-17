package rootoci

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"os"
	"reflect"
	"time"
)

const OperationAuthorizeNetBirdIntent Operation = "authorize_netbird_intent"

// Backends are all required; every domain remains always on.
type Backends struct {
	Readers     Reader
	Foundations Foundation
	Credentials Credentials
	Capacity    Pool
	NetBird     NetBird
	Releases    Releases
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
	for _, backend := range []any{backends.Readers, backends.Foundations, backends.Credentials, backends.Capacity, backends.NetBird, backends.Releases} {
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
	if len(request.Payload) > 16<<10 && request.Operation != OperationDeliverControllerGeneration {
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
			validSelector(input.InstanceID) && validSelector(input.RemovalOperationID) && validDigest(input.DrainSHA256)
	case OperationQuarantinePoolChild:
		var input PoolQuarantineExpectation
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.PoolID) &&
			validSelector(input.InstanceID) && validSelector(input.OperationID) && validDigest(input.PurposeSHA256) &&
			validDigest(input.GrantSHA256) && input.Generation > 0 && input.Epoch > 0
	case OperationObservePoolChild:
		var input PoolChildObservation
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.InstanceID) &&
			optionalSelector(input.OperationID) && optionalSelector(input.PoolID) && optionalSelector(input.ConfigurationID) &&
			optionalDigest(input.RecipeSHA256) && optionalDigest(input.GrantSHA256)
	case OperationAuthorizeNetBirdIntent:
		var input NetBirdIntentRequest
		return decodePayload(request.Payload, &input) == nil && validSelector(input.Cell) && validSelector(input.OperationID) &&
			validSelector(input.RuntimeID) && validSelector(input.OwnerID) && input.IntentRevision > 0 && input.Epoch > 0 &&
			input.LeaseRevision > 0 && !input.ExpiresAt.IsZero() && time.Now().Before(input.ExpiresAt)
	case OperationReconcileContainerStatus:
		var input ContainerStatusRequest
		return decodePayload(request.Payload, &input) == nil && entityid.Valid(input.OperationID) && validDigest(input.ExpectedFingerprint)
	default:
		return false
	}
}

func optionalSelector(value string) bool { return value == "" || validSelector(value) }
func optionalDigest(value string) bool   { return value == "" || validDigest(value) }
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
	default:
		return nil, ErrInvalid
	}
}
