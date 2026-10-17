package rootoci

import (
	"context"
	"io"
	"os"
	"strings"
)

// QualificationService has no mutation backends. Its real reader and mandatory
// authorizer retain the signed purpose proof and privately supervised child.
type QualificationService struct{ readers Reader }

func NewQualificationService(readers Reader) (*QualificationService, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	if !validDependency(readers) {
		return nil, ErrInvalid
	}
	return &QualificationService{readers: readers}, nil
}

func ListenQualification(ctx context.Context, service *QualificationService, authorize Authorize, controllerGID uint32) (io.Closer, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || service == nil || service.readers == nil || authorize == nil || controllerGID == 0 {
		return nil, ErrUnauthorized
	}
	return listen(ctx, service, authorize, controllerGID)
}

func (service *QualificationService) validRequest(request wireRequest) bool {
	return request.Operation.ReadOnly() && validReadRequest(request)
}

func (service *QualificationService) dispatch(ctx context.Context, call Call, request wireRequest) (any, error) {
	if service == nil || !service.validRequest(request) {
		return nil, ErrInvalid
	}
	if err := call.Guard(ctx); err != nil {
		return nil, err
	}
	return dispatchRead(ctx, service.readers, call, request)
}

func validReadRequest(request wireRequest) bool {
	if len(request.Payload) > 16<<10 {
		return false
	}
	if request.Operation == OperationObserveImage {
		var input ImageRequest
		return decodePayload(request.Payload, &input) == nil && validSelector(input.ImageID) && strings.HasPrefix(input.ImageID, "ocid1.image.")
	}
	return request.Operation.ReadOnly() && decodePayload(request.Payload, new(struct{})) == nil
}

func dispatchRead(ctx context.Context, readers Reader, call Call, request wireRequest) (any, error) {
	switch request.Operation {
	case OperationInventory:
		return readers.Inventory(ctx, call)
	case OperationObserveLocalInstance:
		return readers.ObserveLocalInstance(ctx, call)
	case OperationObserveFleet:
		return readers.ObserveFleet(ctx, call)
	case OperationCosts:
		return readers.Costs(ctx, call)
	case OperationReleaseChannel:
		return readers.ReleaseChannel(ctx, call)
	case OperationObserveImage:
		var input ImageRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return readers.ObserveImage(ctx, call, input)
	default:
		return nil, ErrInvalid
	}
}
