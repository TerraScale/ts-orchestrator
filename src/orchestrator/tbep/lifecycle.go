package tbep

import (
	"context"
	"errors"

	"google.golang.org/grpc/metadata"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// LifecycleClient is the authenticated member-scoped TBEP lifecycle port.
// Requests carry the durable accepted placement proof; this client never
// constructs or substitutes that proof.
type LifecycleClient struct {
	transport *Client
	rpc       pb.LifecycleControlServiceClient
}

func NewLifecycle(config Config) (*LifecycleClient, error) {
	transport, err := newClient(config, true)
	if err != nil {
		return nil, err
	}
	return &LifecycleClient{transport: transport, rpc: pb.NewLifecycleControlServiceClient(transport.conn)}, nil
}

func (c *LifecycleClient) Close() error {
	if c == nil || c.transport == nil {
		return nil
	}
	return c.transport.Close()
}

func (c *LifecycleClient) call(ctx context.Context, operation string, request *pb.LifecycleControlRequest, invoke func(context.Context, *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error)) (*pb.LifecycleControlResponse, error) {
	if c == nil || c.transport == nil || request == nil || request.Context == nil || request.OperationId != operation {
		return nil, errors.New("TBEP lifecycle request is incomplete or operation identity differs")
	}
	if err := validateLifecycleContext(request.Context); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	response, err := invoke(metadata.NewOutgoingContext(ctx, c.transport.scope.Copy()), request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.OperationId != operation || response.Status != pb.LifecycleStatus_LIFECYCLE_STATUS_APPLIED && response.Status != pb.LifecycleStatus_LIFECYCLE_STATUS_ALREADY_APPLIED {
		return nil, errors.New("TBEP lifecycle returned an invalid mutation receipt")
	}
	return response, nil
}

func validateLifecycleContext(context *pb.LifecycleControlContext) error {
	if context == nil || context.Environment == "" || context.Tenant == "" || context.Project == "" || context.Database == "" || context.Region == "" || context.Member == "" || context.PlacementRevision == 0 || context.AuthorityEpoch == 0 || context.AuthorityLease == "" || len(context.AuthoritySignature) == 0 {
		return errors.New("TBEP lifecycle context is incomplete")
	}
	return nil
}

func (c *LifecycleClient) EnsureSnapshot(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return c.call(ctx, request.GetOperationId(), request, func(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.rpc.EnsureSnapshot(ctx, request)
	})
}
func (c *LifecycleClient) VerifySnapshotPlacement(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return c.call(ctx, request.GetOperationId(), request, func(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.rpc.VerifySnapshotPlacement(ctx, request)
	})
}
func (c *LifecycleClient) CloseDatabase(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return c.call(ctx, request.GetOperationId(), request, func(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.rpc.CloseDatabase(ctx, request)
	})
}
func (c *LifecycleClient) StopNativeBackup(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return c.call(ctx, request.GetOperationId(), request, func(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.rpc.StopNativeBackup(ctx, request)
	})
}
func (c *LifecycleClient) DeleteOwnedData(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return c.call(ctx, request.GetOperationId(), request, func(ctx context.Context, request *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.rpc.DeleteOwnedData(ctx, request)
	})
}

func (c *LifecycleClient) Reactivate(ctx context.Context, request *pb.LifecycleReactivateRequest) (*pb.LifecycleControlResponse, error) {
	if c == nil || c.transport == nil || request == nil || request.Request == nil || request.Request.Context == nil {
		return nil, errors.New("TBEP lifecycle restore request is incomplete")
	}
	if err := validateLifecycleContext(request.Request.Context); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	response, err := c.rpc.Reactivate(metadata.NewOutgoingContext(ctx, c.transport.scope.Copy()), request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.OperationId != request.Request.OperationId || response.Status != pb.LifecycleStatus_LIFECYCLE_STATUS_APPLIED && response.Status != pb.LifecycleStatus_LIFECYCLE_STATUS_ALREADY_APPLIED {
		return nil, errors.New("TBEP lifecycle returned an invalid restore receipt")
	}
	return response, nil
}
