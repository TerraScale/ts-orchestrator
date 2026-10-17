//go:build linux

package rootoci

import (
	"context"
	"time"
)

const OperationMaterializeNativeCanary Operation = "materialize_native_canary"

// NativeCanaryRequest selects a retained native operation and its actual host.
// Root derives the credential from the current signed release fence.
type NativeCanaryRequest struct {
	OperationID string `json:"operation_id"`
	Node        string `json:"node"`
	Baseline    bool   `json:"baseline,omitzero"`
}

type NativeCanaryReceipt struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (client *Client) MaterializeNativeCanary(ctx context.Context, request NativeCanaryRequest) (NativeCanaryReceipt, error) {
	var result NativeCanaryReceipt
	err := client.invoke(ctx, OperationMaterializeNativeCanary, request, &result)
	return result, err
}
