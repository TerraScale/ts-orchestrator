//go:build linux

package rootoci

import (
	"context"
	"time"
)

const (
	OperationIssueFunctionTaskMaterial        Operation = "issue_function_task_material"
	OperationIssueFunctionObservationIdentity Operation = "issue_function_observation_identity"
)

// FunctionTaskRequest selects actual task records; root derives every grant.
type FunctionTaskRequest struct {
	TaskID string `json:"task_id"`
}

// FunctionTaskMaterialReceipt contains only the fixed five-file task packet.
type FunctionTaskMaterialReceipt struct {
	Value     []byte    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

type FunctionObservationIdentityReceipt struct {
	Certificate []byte    `json:"certificate"`
	Key         []byte    `json:"key"`
	CA          []byte    `json:"ca"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (client *Client) IssueFunctionTaskMaterial(ctx context.Context, request FunctionTaskRequest) (FunctionTaskMaterialReceipt, error) {
	var result FunctionTaskMaterialReceipt
	err := client.invoke(ctx, OperationIssueFunctionTaskMaterial, request, &result)
	return result, err
}

func (client *Client) IssueFunctionObservationIdentity(ctx context.Context, request FunctionTaskRequest) (FunctionObservationIdentityReceipt, error) {
	var result FunctionObservationIdentityReceipt
	err := client.invoke(ctx, OperationIssueFunctionObservationIdentity, request, &result)
	return result, err
}
