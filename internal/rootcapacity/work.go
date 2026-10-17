package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/workrequests"
)

// A membership observation never replaces the original successful work request.
func (a *attempt) workCompleted(ctx context.Context, wire *region.PoolWireRecord, resourceID string) (bool, error) {
	if wire == nil || wire.AcceptedAt.IsZero() || wire.WorkRequestID == "" {
		return false, errors.New("provider action has no original positive work request")
	}
	if !wire.WorkCompletedAt.IsZero() {
		return true, nil
	}
	client, err := a.factory.WorkRequests()
	if err != nil {
		return false, err
	}
	response, err := client.GetWorkRequest(a.readContext(ctx), workrequests.GetWorkRequestRequest{WorkRequestId: new(wire.WorkRequestID)})
	if err != nil {
		return false, err
	}
	if value(response.Id) != wire.WorkRequestID || value(response.CompartmentId) != a.record.CapacityPools[resourceID].CompartmentID ||
		!slices.ContainsFunc(response.Resources, func(resource workrequests.WorkRequestResource) bool { return value(resource.Identifier) == resourceID }) {
		return false, errors.New("work request readback differs from exact protected action and pool")
	}
	switch response.Status {
	case workrequests.WorkRequestStatusSucceeded:
		wire.WorkCompletedAt = time.Now().UTC()
		return true, nil
	case workrequests.WorkRequestStatusFailed, workrequests.WorkRequestStatusCanceled:
		return false, fmt.Errorf("original protected work request ended in %s", response.Status)
	default:
		return false, nil
	}
}
