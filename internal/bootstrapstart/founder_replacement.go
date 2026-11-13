package bootstrapstart

import (
	"context"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// ObserveLifecycle returns the OCI lifecycle state of one exact instance
// OCID without requiring an attached VNIC, so a TERMINATED instance is still
// observable. A missing instance is an error, never TERMINATED.
func (observer *OCIInstanceObserver) ObserveLifecycle(ctx context.Context, instanceID string) (string, error) {
	if observer == nil || observer.compute == nil || !instanceIDRE.MatchString(instanceID) {
		return "", ErrInstanceObservation
	}
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	response, err := observer.compute.GetInstance(readCtx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return "", fmt.Errorf("GetInstance controller slot: %w", err)
	}
	if value(response.Id) != instanceID || response.LifecycleState == "" {
		return "", ErrInstanceObservation
	}
	return string(response.LifecycleState), nil
}
