//go:build linux

package rootoci

import (
	"context"
	"time"
)

const (
	OperationReadFunctionTaskMaterial         Operation = "read_function_task_material"
	OperationRetireExpiredFunctionMaterial    Operation = "retire_expired_function_material"
	ExpiredFunctionTaskMaterial                         = "expired_function_task_material"
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

// FunctionRetirementRequest admits one finite root-owned cleanup purpose.
type FunctionRetirementRequest struct {
	Purpose string `json:"purpose"`
}

// Object receipts stay in root's audit log; the IPC reply has a fixed bound.
type FunctionRetirementReceipt struct {
	Count     int       `json:"count"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (client *Client) ReadFunctionTaskMaterial(ctx context.Context, request FunctionTaskRequest) (FunctionTaskMaterialReceipt, error) {
	var result FunctionTaskMaterialReceipt
	err := client.invoke(ctx, OperationReadFunctionTaskMaterial, request, &result)
	return result, err
}

func (client *Client) RetireExpiredFunctionMaterial(ctx context.Context, request FunctionRetirementRequest) (FunctionRetirementReceipt, error) {
	var result FunctionRetirementReceipt
	err := client.invoke(ctx, OperationRetireExpiredFunctionMaterial, request, &result)
	return result, err
}
