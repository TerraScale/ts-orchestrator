package manager

import (
	"bytes"
	"context"
	"errors"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReadOnlyControlClient projects existing control reads onto this manager's
// applied store. The owner must retain and validate its original authority.
func (m *Manager) ReadOnlyControlClient(guard func(context.Context) error) (*ControlReader, error) {
	if m == nil || m.raftNode == nil || guard == nil {
		return nil, errors.New("read-only control requires a manager and owner guard")
	}
	return &ControlReader{
		server: controlapi.NewServer(m.raftNode.MemoryStore(), nil, nil, nil, nil),
		guard:  guard,
		store:  m.raftNode.MemoryStore(),
	}, nil
}

var _ api.ControlReader = (*ControlReader)(nil)

// ControlReader exposes only guarded applied-store reads.
type ControlReader struct {
	store  *store.MemoryStore
	server *controlapi.Server
	guard  func(context.Context) error
}

func readControl[T any](ctx context.Context, client *ControlReader, read func() (*T, error)) (*T, error) {
	if client == nil || client.server == nil || client.store == nil || client.guard == nil {
		return nil, errors.New("read-only control source unavailable")
	}
	if ctx == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := client.guard(ctx); err != nil {
		return nil, err
	}
	response, err := read()
	if guardErr := client.guard(ctx); guardErr != nil {
		return nil, guardErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}

func (c *ControlReader) GetNode(ctx context.Context, request *api.GetNodeRequest, _ ...grpc.CallOption) (*api.GetNodeResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.GetNodeResponse, error) { return c.server.GetNode(ctx, request) })
}

func (c *ControlReader) ListNodes(ctx context.Context, request *api.ListNodesRequest, _ ...grpc.CallOption) (*api.ListNodesResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.ListNodesResponse, error) { return c.server.ListNodes(ctx, request) })
}

func (c *ControlReader) GetTask(ctx context.Context, request *api.GetTaskRequest, _ ...grpc.CallOption) (*api.GetTaskResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.GetTaskResponse, error) { return c.server.GetTask(ctx, request) })
}

func (c *ControlReader) ListTasks(ctx context.Context, request *api.ListTasksRequest, _ ...grpc.CallOption) (*api.ListTasksResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.ListTasksResponse, error) { return c.server.ListTasks(ctx, request) })
}

func (c *ControlReader) GetService(ctx context.Context, request *api.GetServiceRequest, _ ...grpc.CallOption) (*api.GetServiceResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.GetServiceResponse, error) { return c.server.GetService(ctx, request) })
}

func (c *ControlReader) ListServices(ctx context.Context, request *api.ListServicesRequest, _ ...grpc.CallOption) (*api.ListServicesResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.ListServicesResponse, error) { return c.server.ListServices(ctx, request) })
}

func (c *ControlReader) GetConfig(ctx context.Context, request *api.GetConfigRequest, _ ...grpc.CallOption) (*api.GetConfigResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.GetConfigResponse, error) { return c.server.GetConfig(ctx, request) })
}

func (c *ControlReader) ListConfigs(ctx context.Context, request *api.ListConfigsRequest, _ ...grpc.CallOption) (*api.ListConfigsResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "read-only control requires a request")
	}
	return readControl(ctx, c, func() (*api.ListConfigsResponse, error) { return c.server.ListConfigs(ctx, request) })
}

// ClusterIdentity contains only the public trust material used to bind a node
// certificate to this manager's current cluster.
type ClusterIdentity struct {
	ID         string
	RootCACert []byte
}

// ClusterIdentity returns the sole applied cluster without its join tokens or
// private keys, retaining the same owner and epoch guards as all other reads.
func (c *ControlReader) ClusterIdentity(ctx context.Context) (*ClusterIdentity, error) {
	return readControl(ctx, c, func() (*ClusterIdentity, error) {
		var clusters []*api.Cluster
		var err error
		c.store.View(func(tx store.ReadTx) { clusters, err = store.FindClusters(tx, store.All) })
		if err != nil {
			return nil, err
		}
		if len(clusters) != 1 || clusters[0] == nil || clusters[0].ID == "" || len(clusters[0].RootCA.CACert) == 0 {
			return nil, errors.New("read-only control requires one current cluster identity")
		}
		return &ClusterIdentity{ID: clusters[0].ID, RootCACert: bytes.Clone(clusters[0].RootCA.CACert)}, nil
	})
}
