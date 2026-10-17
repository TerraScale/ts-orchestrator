package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type functionIssuerClient struct{ client *rootoci.Client }

func (issuer functionIssuerClient) IssueFunctionTaskMaterial(ctx context.Context, taskID string) ([]byte, error) {
	receipt, err := issuer.client.IssueFunctionTaskMaterial(ctx, rootoci.FunctionTaskRequest{TaskID: taskID})
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(receipt.ExpiresAt) || len(receipt.Value) == 0 || len(receipt.Value) > 16<<10 {
		clear(receipt.Value)
		return nil, functionmaterial.ErrMaterial
	}
	return receipt.Value, nil
}

func (issuer functionIssuerClient) IssueFunctionObservationIdentity(ctx context.Context, taskID string) (certificate, key, ca []byte, err error) {
	receipt, err := issuer.client.IssueFunctionObservationIdentity(ctx, rootoci.FunctionTaskRequest{TaskID: taskID})
	if err != nil {
		return nil, nil, nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(receipt.ExpiresAt) || len(receipt.Certificate) == 0 || len(receipt.Key) == 0 || len(receipt.CA) == 0 {
		clear(receipt.Key)
		return nil, nil, nil, functionmaterial.ErrMaterial
	}
	return receipt.Certificate, receipt.Key, receipt.CA, nil
}

func (issuer functionIssuerClient) ReadFunctionTaskMaterial(ctx context.Context, taskID string) ([]byte, error) {
	receipt, err := issuer.client.ReadFunctionTaskMaterial(ctx, rootoci.FunctionTaskRequest{TaskID: taskID})
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(receipt.ExpiresAt) || len(receipt.Value) == 0 || len(receipt.Value) > 16<<10 {
		clear(receipt.Value)
		return nil, functionmaterial.ErrMaterial
	}
	return receipt.Value, nil
}

func (issuer functionIssuerClient) RetireExpiredFunctionMaterial(ctx context.Context) (int, error) {
	receipt, err := issuer.client.RetireExpiredFunctionMaterial(ctx, rootoci.FunctionRetirementRequest{Purpose: rootoci.ExpiredFunctionTaskMaterial})
	if err != nil {
		return 0, err
	}
	if ctx.Err() != nil || !time.Now().Before(receipt.ExpiresAt) || receipt.Count < 0 || receipt.Count > 32000 {
		return 0, functionmaterial.ErrMaterial
	}
	return receipt.Count, nil
}
