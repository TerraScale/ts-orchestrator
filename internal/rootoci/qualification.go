package rootoci

import (
	"context"
	"strings"
)

// QualificationService has no mutation backends. Its real reader and mandatory
// authorizer retain the signed purpose proof and privately supervised child.
type QualificationService struct{ readers Reader }

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
