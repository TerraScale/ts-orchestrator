//go:build linux

package swarmruntime

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const workerPrepareMethod = "/terrascale.swarmruntime.WorkerManagement/Prepare"
const workerAdmitMethod = "/terrascale.swarmruntime.WorkerManagement/Admit"

type workerAdmitRequest struct {
	Query   WorkerRegistrationQuery     `json:"query"`
	Binding hostenroll.SwarmNodeBinding `json:"binding"`
}

// PrepareEnrolledWorker asks the root manager for a worker-only Vault projection.
// The manager independently verifies current registration, OCI and enrollment.
func PrepareEnrolledWorker(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, query WorkerRegistrationQuery) ([]byte, error) {
	return workerManagementCall(ctx, accepted, workerPrepareMethod, query)
}

// AdmitEnrolledWorker carries the host-and-Swarm-key binding proof, never labels.
func AdmitEnrolledWorker(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, query WorkerRegistrationQuery, binding hostenroll.SwarmNodeBinding) error {
	_, err := workerManagementCall(ctx, accepted, workerAdmitMethod, workerAdmitRequest{Query: query, Binding: binding})
	return err
}

func workerManagementCall(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, method string, request any) ([]byte, error) {
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		return nil, err
	}
	binding, err := acceptedBinding(accepted)
	if err != nil {
		return nil, err
	}
	_, _, connection, err := dialManagementAt(ctx, managementSocket, 0, binding)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	response := new(wrapperspb.BytesValue)
	if err := connection.Invoke(ctx, method, &wrapperspb.BytesValue{Value: wire}, response); err != nil {
		return nil, err
	}
	return response.Value, nil
}

type workerManagementRPC interface {
	Prepare(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Admit(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}
type workerManagementServer struct{ node *Node }

func (s *workerManagementServer) Prepare(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var query WorkerRegistrationQuery
	if err := protocol.DecodeStrict(request.Value, &query, 128<<10); err != nil {
		return nil, denied()
	}
	if query.Swarm != nil {
		return nil, denied()
	}
	wire, err := s.node.PrepareEnrolledWorker(ctx, query)
	if err != nil {
		return nil, err
	}
	return &wrapperspb.BytesValue{Value: wire}, nil
}
func (s *workerManagementServer) Admit(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var admission workerAdmitRequest
	if err := protocol.DecodeStrict(request.Value, &admission, 128<<10); err != nil {
		return nil, denied()
	}
	if admission.Query.Swarm != nil {
		return nil, denied()
	}
	if err := s.node.AdmitEnrolledWorker(ctx, admission.Query, admission.Binding); err != nil {
		return nil, err
	}
	return new(wrapperspb.BytesValue), nil
}
func registerWorkerManagement(server *grpc.Server, node *Node) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "terrascale.swarmruntime.WorkerManagement",
		HandlerType: (*workerManagementRPC)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Prepare", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).Prepare(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerPrepareMethod}, handler)
			}},
			{MethodName: "Admit", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).Admit(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerAdmitMethod}, handler)
			}},
		},
	}, &workerManagementServer{node: node})
}
