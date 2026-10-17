package api

import (
	"context"

	"google.golang.org/grpc"
)

// ControlReader contains only the store reads needed by privileged local
// verifiers. It grants no mutation, secret access, or socket authentication.
type ControlReader interface {
	GetNode(context.Context, *GetNodeRequest, ...grpc.CallOption) (*GetNodeResponse, error)
	ListNodes(context.Context, *ListNodesRequest, ...grpc.CallOption) (*ListNodesResponse, error)
	GetTask(context.Context, *GetTaskRequest, ...grpc.CallOption) (*GetTaskResponse, error)
	ListTasks(context.Context, *ListTasksRequest, ...grpc.CallOption) (*ListTasksResponse, error)
	GetService(context.Context, *GetServiceRequest, ...grpc.CallOption) (*GetServiceResponse, error)
	ListServices(context.Context, *ListServicesRequest, ...grpc.CallOption) (*ListServicesResponse, error)
	GetConfig(context.Context, *GetConfigRequest, ...grpc.CallOption) (*GetConfigResponse, error)
	ListConfigs(context.Context, *ListConfigsRequest, ...grpc.CallOption) (*ListConfigsResponse, error)
}
